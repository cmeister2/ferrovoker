//! Native asynchronous, bounded downloads of browser revocation snapshots.

use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use reqwest::{Client, Response};

use crate::download::{
    ONECRL_CHAIN_HOST, component_download, is_onecrl_chain_url, signature_chain_url,
    validate_download,
};
use crate::onecrl_signature::{
    AuthenticatedOneCrl, MAX_CERTIFICATE_CHAIN_BYTES, PRODUCTION_TRUST, PreparedOneCrl, unix_now,
};
use crate::{CRLSET_UPDATE_URL, CrlSet, Error, ONECRL_URL, OneCrl, Result};

/// Default maximum response and decompressed CRLSet size, in bytes.
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Default total timeout for feed and certificate-chain requests.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);

/// Downloads browser revocation snapshots with a reusable asynchronous client.
///
/// Network operations yield to the caller's Tokio runtime. Responses and
/// extracted CRLSets are bounded to 64 MiB by default. A server's `Backoff`
/// header prevents subsequent requests through this instance until the interval
/// expires. Concurrent requests already in flight cannot be recalled.
///
/// Chrome's advertised component digest and pinned CRX3 publisher signatures
/// are checked before extraction. Mozilla content signatures are verified
/// against the pinned production signing root and OneCRL leaf identity.
#[derive(Debug)]
pub struct AsyncDownloader {
    /// Reusable asynchronous HTTP connection pool and transport configuration.
    client: Client,
    /// Chain client isolated from caller-supplied headers and cookies.
    chain_client: Client,
    /// Maximum bytes accepted for responses and extracted CRLSet payloads.
    max_bytes: u64,
    /// Server-requested interval during which new requests are prohibited.
    backoff: Mutex<Option<Backoff>>,
}

/// A backoff interval tracked with monotonic time and bounded arithmetic.
#[derive(Debug)]
struct Backoff {
    /// Local monotonic instant when the server requested backoff.
    started: Instant,
    /// Server-requested delay before another request may be started.
    duration: Duration,
}

impl AsyncDownloader {
    /// Creates an HTTPS-only asynchronous client with timeouts and gzip support.
    ///
    /// Requests have a 60-second total timeout, a 10-second connection timeout,
    /// and an application/version `User-Agent`. Protocol retries are disabled.
    ///
    /// # Errors
    ///
    /// Returns an error if HTTP transport or TLS configuration cannot be built.
    pub fn new() -> Result<Self> {
        let client = Client::builder()
            .https_only(true)
            .timeout(DEFAULT_TIMEOUT)
            .connect_timeout(Duration::from_secs(10))
            .retry(reqwest::retry::never())
            .gzip(true)
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()?;
        Self::with_client(client)
    }

    /// Uses a caller-configured client for feed and component downloads.
    ///
    /// The caller controls TLS, redirects, timeouts, and Mozilla's required
    /// application/version `User-Agent` for those requests. OneCRL certificate
    /// chains use a separate client without caller-supplied headers or cookies;
    /// redirects remain on Mozilla's production content-signature CDN.
    ///
    /// # Errors
    ///
    /// Returns an error if the isolated certificate-chain client cannot be built.
    pub fn with_client(client: Client) -> Result<Self> {
        Self::with_client_and_chain_timeout(client, DEFAULT_TIMEOUT)
    }

    /// Uses a caller-configured client and sets the isolated chain request timeout.
    ///
    /// This is equivalent to [`Self::with_client`], except `chain_timeout`
    /// controls the total timeout for Mozilla certificate-chain requests.
    ///
    /// # Errors
    ///
    /// Returns an error if the isolated certificate-chain client cannot be built.
    pub fn with_client_and_chain_timeout(client: Client, chain_timeout: Duration) -> Result<Self> {
        Ok(Self {
            client,
            chain_client: onecrl_chain_client(chain_timeout)?,
            max_bytes: DEFAULT_MAX_BYTES,
            backoff: Mutex::new(None),
        })
    }

    /// Sets the response and extracted CRLSet size limit in bytes.
    ///
    /// OneCRL certificate chains retain an independent 1 MiB upper bound.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Fetches the complete production Mozilla OneCRL changeset.
    ///
    /// # Errors
    ///
    /// Returns an error for HTTP failures, active backoff, oversized responses,
    /// or malformed OneCRL data, invalid publisher certificates, or an invalid
    /// Mozilla content signature.
    pub async fn fetch_onecrl(&self) -> Result<OneCrl> {
        self.fetch_onecrl_from(ONECRL_URL).await
    }

    /// Fetches a complete production-signed OneCRL changeset from another endpoint.
    ///
    /// Use a mirror of Mozilla's production Remote Settings
    /// `changeset?_expected=...` endpoint without `_since`. The same pinned
    /// production root and OneCRL leaf identity are always required; this method
    /// does not trust development collections or merge incremental changes.
    /// Signing-chain URLs must use Mozilla's pinned production CDN on HTTPS/443.
    ///
    /// # Errors
    ///
    /// Returns an error for HTTP failures, active backoff, oversized responses,
    /// or malformed OneCRL data, invalid publisher certificates, or an invalid
    /// Mozilla content signature.
    pub async fn fetch_onecrl_from(&self, url: &str) -> Result<OneCrl> {
        Ok(self.fetch_authenticated_onecrl_from(url).await?.snapshot)
    }

    /// Fetch and retain the publisher evidence required by the managed cache.
    ///
    /// # Errors
    ///
    /// Returns the network, format, size, backoff, certificate, publisher, and
    /// content-signature errors described by [`Self::fetch_onecrl_from`].
    pub(crate) async fn fetch_authenticated_onecrl(&self) -> Result<AuthenticatedOneCrl> {
        self.fetch_authenticated_onecrl_from(ONECRL_URL).await
    }

    /// Authenticate a complete changeset and retain its response and selected chain.
    ///
    /// # Errors
    ///
    /// Returns an error when the changeset, every advertised chain download, or
    /// every supported publisher signature fails validation.
    async fn fetch_authenticated_onecrl_from(&self, url: &str) -> Result<AuthenticatedOneCrl> {
        let response = Arc::new(self.download(url, false).await?);
        let preparation_response = Arc::clone(&response);
        let prepared = tokio::task::spawn_blocking(move || {
            PreparedOneCrl::from_response(&preparation_response)
        })
        .await
        .map_err(|_| Error::InvalidFormat("OneCRL preparation task failed"))??;
        let prepared = Arc::new(prepared);
        let mut last_error = Error::InvalidOneCrlSignature;
        for index in 0..prepared.candidate_count() {
            let x5u = prepared
                .candidate_x5u(index)
                .ok_or(Error::InvalidOneCrlSignature)?
                .to_owned();
            let chain_url = match signature_chain_url(&x5u) {
                Ok(url) => url,
                Err(error) => {
                    last_error = error;
                    continue;
                }
            };
            let chain = match self.download_dependency(chain_url.as_str(), true).await {
                Ok(chain) => chain,
                Err(error) => {
                    last_error = error;
                    continue;
                }
            };
            let verification = Arc::clone(&prepared);
            let verified = tokio::task::spawn_blocking(move || {
                let unix_time = unix_now()?;
                verification.verify_candidate(index, &chain, PRODUCTION_TRUST, unix_time)?;
                Ok::<_, Error>(chain)
            })
            .await
            .map_err(|_| Error::InvalidFormat("OneCRL signature verification task failed"))?;
            match verified {
                Ok(certificate_chain) => {
                    let prepared = Arc::try_unwrap(prepared)
                        .map_err(|_| Error::InvalidFormat("OneCRL preparation still in use"))?;
                    let response =
                        Arc::try_unwrap(response).unwrap_or_else(|shared| shared.as_ref().clone());
                    return Ok(prepared.finish(response, certificate_chain));
                }
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    /// Downloads and extracts Google's current complete CRLSet component.
    ///
    /// # Errors
    ///
    /// Returns an error for HTTP failures, active backoff, invalid metadata,
    /// unsafe component URLs, size or digest mismatches, invalid CRX/ZIP
    /// containers, or malformed CRLSet payloads.
    pub async fn fetch_crlset(&self) -> Result<CrlSet> {
        self.fetch_crlset_from(CRLSET_UPDATE_URL).await
    }

    /// Fetches a full CRLSet through a specified Omaha update metadata endpoint.
    ///
    /// Metadata must offer the matching component with `status="ok"`, an HTTPS
    /// component URL, an exact size, and a SHA-256 digest. This verifies download
    /// integrity against the metadata. CRX3 signatures then authenticate the
    /// container against Chrome's pinned CRLSet component signing key.
    ///
    /// # Errors
    ///
    /// Returns an error for HTTP failures, active backoff, invalid metadata,
    /// unsafe component URLs, size or digest mismatches, invalid CRX/ZIP
    /// containers, or malformed CRLSet payloads.
    pub async fn fetch_crlset_from(&self, url: &str) -> Result<CrlSet> {
        let metadata = self.download(url, false).await?;
        let component = component_download(&metadata, self.max_bytes)?;
        let bytes = self.download(component.url.as_str(), true).await?;
        validate_download(&bytes, &component)?;
        CrlSet::from_signed_crx(bytes, self.max_bytes)
    }

    /// Reads a bounded response and records server backoff before status checks.
    ///
    /// # Errors
    ///
    /// Returns an error for active backoff, HTTP or body failures, unexpected
    /// statuses, an unsafe final component URL, or an oversized body.
    async fn download(&self, url: &str, require_https: bool) -> Result<Vec<u8>> {
        self.download_with_backoff(&self.client, url, require_https, None, true, self.max_bytes)
            .await
    }

    /// Download a response required to finish authenticating an accepted response.
    ///
    /// This dependent request bypasses backoff already recorded from the parent
    /// changeset; that backoff still applies to the next top-level operation.
    ///
    /// # Errors
    ///
    /// Returns HTTP, redirect-policy, or response-size errors.
    async fn download_dependency(&self, url: &str, require_https: bool) -> Result<Vec<u8>> {
        self.download_with_backoff(
            &self.chain_client,
            url,
            require_https,
            Some(ONECRL_CHAIN_HOST),
            false,
            self.max_bytes.min(MAX_CERTIFICATE_CHAIN_BYTES as u64),
        )
        .await
    }

    /// Download one bounded response with optional top-level backoff handling.
    ///
    /// # Errors
    ///
    /// Returns active backoff, HTTP, redirect-policy, or response-size errors.
    async fn download_with_backoff(
        &self,
        client: &Client,
        url: &str,
        require_https: bool,
        required_host: Option<&str>,
        apply_backoff: bool,
        maximum: u64,
    ) -> Result<Vec<u8>> {
        if apply_backoff {
            self.ensure_no_backoff()?;
        }
        let response = client.get(url).send().await?;
        if apply_backoff {
            self.record_backoff(&response);
        }
        let mut response = response.error_for_status()?;
        if !response.status().is_success() {
            return Err(Error::InvalidFormat("unexpected HTTP response status"));
        }
        if require_https && response.url().scheme() != "https" {
            return Err(Error::InvalidFormat("download response must use HTTPS"));
        }
        if required_host.is_some_and(|host| {
            response.url().host_str() != Some(host)
                || response.url().port_or_known_default() != Some(443)
        }) {
            return Err(Error::InvalidFormat(
                "OneCRL certificate-chain response left Mozilla's production CDN",
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > maximum)
        {
            return Err(Error::SizeLimit(maximum));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() as u64 > maximum.saturating_sub(bytes.len() as u64) {
                return Err(Error::SizeLimit(maximum));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    /// Locks backoff state, recovering it if another holder panicked.
    fn backoff_state(&self) -> MutexGuard<'_, Option<Backoff>> {
        self.backoff
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Rejects new requests during a previously announced backoff interval.
    ///
    /// # Errors
    ///
    /// Returns the remaining delay in seconds, rounded up, while backoff is active.
    fn ensure_no_backoff(&self) -> Result<()> {
        let mut state = self.backoff_state();
        if let Some(backoff) = state.as_ref() {
            if let Some(remaining) = backoff.duration.checked_sub(backoff.started.elapsed())
                && !remaining.is_zero()
            {
                let seconds = remaining
                    .as_secs()
                    .saturating_add(u64::from(remaining.subsec_nanos() != 0));
                return Err(Error::Backoff(seconds));
            }
            *state = None;
        }
        Ok(())
    }

    /// Records a valid server backoff header without shortening an active delay.
    fn record_backoff(&self, response: &Response) {
        let Some(seconds) = response
            .headers()
            .get("Backoff")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
        else {
            return;
        };
        let duration = Duration::from_secs(seconds);
        let mut state = self.backoff_state();
        if state.as_ref().is_some_and(|backoff| {
            backoff
                .duration
                .checked_sub(backoff.started.elapsed())
                .is_some_and(|remaining| remaining >= duration)
        }) {
            return;
        }
        *state = Some(Backoff {
            started: Instant::now(),
            duration,
        });
    }
}

/// Build an isolated asynchronous client for Mozilla content-signing chains.
///
/// # Errors
///
/// Returns an error if reqwest cannot initialize its HTTPS transport.
fn onecrl_chain_client(timeout: Duration) -> Result<Client> {
    let redirect = reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() < 10 && is_onecrl_chain_url(attempt.url()) {
            attempt.follow()
        } else {
            attempt.stop()
        }
    });
    Ok(Client::builder()
        .https_only(true)
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .retry(reqwest::retry::never())
        .gzip(true)
        .redirect(redirect)
        .user_agent(concat!(
            env!("CARGO_PKG_NAME"),
            "/",
            env!("CARGO_PKG_VERSION")
        ))
        .build()?)
}

#[cfg(test)]
#[path = "../tests/unit/async_download.rs"]
mod tests;
