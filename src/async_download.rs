//! Native asynchronous, bounded downloads of browser revocation snapshots.

use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use reqwest::{Client, Response};

use crate::download::{component_download, validate_download};
use crate::{CRLSET_UPDATE_URL, CrlSet, Error, ONECRL_URL, OneCrl, Result};

/// Default maximum response and decompressed CRLSet size, in bytes.
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Downloads browser revocation snapshots with a reusable asynchronous client.
///
/// Network operations yield to the caller's Tokio runtime. Responses and
/// extracted CRLSets are bounded to 64 MiB by default. A server's `Backoff`
/// header prevents subsequent requests through this instance until the interval
/// expires. Concurrent requests already in flight cannot be recalled.
///
/// Chrome's advertised component digest and pinned CRX3 publisher signatures
/// are checked before extraction. Mozilla content signatures remain unverified.
#[derive(Debug)]
pub struct AsyncDownloader {
    /// Reusable asynchronous HTTP connection pool and transport configuration.
    client: Client,
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
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(10))
            .retry(reqwest::retry::never())
            .gzip(true)
            .user_agent(concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()?;
        Ok(Self::with_client(client))
    }

    /// Uses a caller-configured asynchronous client, including its proxy policy.
    ///
    /// The caller controls TLS, redirects, timeouts, and Mozilla's required
    /// application/version `User-Agent`. CRLSet component URLs and their final
    /// response URLs must still use HTTPS.
    #[must_use]
    pub fn with_client(client: Client) -> Self {
        Self {
            client,
            max_bytes: DEFAULT_MAX_BYTES,
            backoff: Mutex::new(None),
        }
    }

    /// Sets the response and extracted CRLSet size limit in bytes.
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
    /// or malformed OneCRL data.
    pub async fn fetch_onecrl(&self) -> Result<OneCrl> {
        self.fetch_onecrl_from(ONECRL_URL).await
    }

    /// Fetches a complete OneCRL changeset from a caller-specified endpoint.
    ///
    /// Use a Remote Settings `changeset?_expected=...` endpoint without `_since`;
    /// this downloader does not merge incremental changes into a local store.
    ///
    /// # Errors
    ///
    /// Returns an error for HTTP failures, active backoff, oversized responses,
    /// or malformed OneCRL data.
    pub async fn fetch_onecrl_from(&self, url: &str) -> Result<OneCrl> {
        OneCrl::from_slice(&self.download(url, false).await?)
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
        self.ensure_no_backoff()?;
        let response = self.client.get(url).send().await?;
        self.record_backoff(&response);
        let mut response = response.error_for_status()?;
        if !response.status().is_success() {
            return Err(Error::InvalidFormat("unexpected HTTP response status"));
        }
        if require_https && response.url().scheme() != "https" {
            return Err(Error::InvalidFormat("component response must use HTTPS"));
        }
        if response
            .content_length()
            .is_some_and(|length| length > self.max_bytes)
        {
            return Err(Error::SizeLimit(self.max_bytes));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if chunk.len() as u64 > self.max_bytes.saturating_sub(bytes.len() as u64) {
                return Err(Error::SizeLimit(self.max_bytes));
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

#[cfg(test)]
#[path = "../tests/unit/async_download.rs"]
mod tests;
