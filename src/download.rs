//! Blocking, bounded download clients for Mozilla OneCRL and Chrome CRLSets.

use std::io::Read;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use reqwest::blocking::{Client, Response};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::onecrl_signature::{
    AuthenticatedOneCrl, MAX_CERTIFICATE_CHAIN_BYTES, PRODUCTION_TRUST, PreparedOneCrl, unix_now,
};
use crate::{CRLSET_COMPONENT_ID, CRLSET_UPDATE_URL, CrlSet, Error, ONECRL_URL, OneCrl, Result};

/// Default maximum size of any response or decompressed CRLSet, in bytes.
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Default total timeout for feed and certificate-chain requests.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(60);
/// Only host allowed to serve production OneCRL content-signing chains.
pub(super) const ONECRL_CHAIN_HOST: &str = "content-signature-2.cdn.mozilla.net";

/// Downloads browser revocation data using a reusable blocking HTTP client.
///
/// Responses and decompressed CRLSets are bounded to 64 MiB by default. A
/// server's `Backoff` header prevents subsequent requests through this instance
/// until the requested interval has elapsed. Chrome CRX3 signatures authenticate
/// the pinned component publisher. Mozilla content signatures authenticate
/// OneCRL against its pinned production root and signing identity.
#[derive(Debug)]
pub struct Downloader {
    /// Reusable HTTP connection pool and transport configuration.
    client: Client,
    /// Chain client isolated from caller-supplied headers and cookies.
    chain_client: Client,
    /// Maximum bytes accepted for each response and extracted CRLSet.
    max_bytes: u64,
    /// Latest server-requested interval during which requests are prohibited.
    backoff: Mutex<Option<Backoff>>,
}

/// A backoff interval represented without adding untrusted seconds to `Instant`.
#[derive(Debug)]
struct Backoff {
    /// Local monotonic time when the response requested backoff.
    started: Instant,
    /// Server-requested number of seconds to avoid further requests.
    duration: Duration,
}

impl Downloader {
    /// Creates an HTTPS-only client with application identification and timeouts.
    ///
    /// Requests have a 60-second total timeout and a 10-second connection timeout.
    /// Gzip transport is enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if the HTTP client or TLS configuration cannot be built.
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
    /// The caller controls transport policy, redirects, timeouts, and the
    /// application/version `User-Agent` required by Mozilla for those requests.
    /// OneCRL certificate chains use a separate client without caller-supplied
    /// headers or cookies; redirects remain on Mozilla's production CDN.
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

    /// Sets the limit for response bodies and decompressed CRLSet payloads.
    ///
    /// OneCRL certificate chains retain an independent 1 MiB upper bound.
    #[must_use]
    pub fn with_max_bytes(mut self, max_bytes: u64) -> Self {
        self.max_bytes = max_bytes;
        self
    }

    /// Fetches a complete OneCRL changeset from Mozilla's production service.
    ///
    /// # Errors
    ///
    /// Returns an error for network or HTTP failures, an active backoff interval,
    /// an oversized response, malformed OneCRL data, or a content-signature or
    /// publisher verification failure.
    pub fn fetch_onecrl(&self) -> Result<OneCrl> {
        self.fetch_onecrl_from(ONECRL_URL)
    }

    /// Fetches a complete production-signed OneCRL changeset from a specified URL.
    ///
    /// Use a mirror of Mozilla's production Remote Settings
    /// `changeset?_expected=...` endpoint without a `_since` filter. The same
    /// pinned production root and OneCRL leaf identity are always required; this
    /// method does not trust development collections or merge incremental changes.
    /// Signing-chain URLs must use Mozilla's pinned production CDN on HTTPS/443.
    ///
    /// # Errors
    ///
    /// Returns an error for network or HTTP failures, an active backoff interval,
    /// an oversized response, malformed OneCRL data, or a content-signature or
    /// publisher verification failure.
    pub fn fetch_onecrl_from(&self, url: &str) -> Result<OneCrl> {
        Ok(self.fetch_authenticated_onecrl_from(url)?.snapshot)
    }

    /// Authenticate a complete changeset and retain its response and selected chain.
    ///
    /// # Errors
    ///
    /// Returns an error when the changeset, every advertised chain download, or
    /// every supported publisher signature fails validation.
    fn fetch_authenticated_onecrl_from(&self, url: &str) -> Result<AuthenticatedOneCrl> {
        let response = self.download(url, false)?;
        let prepared = PreparedOneCrl::from_response(&response)?;
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
            let chain = match self.download_dependency(chain_url.as_str(), true) {
                Ok(chain) => chain,
                Err(error) => {
                    last_error = error;
                    continue;
                }
            };
            let unix_time = unix_now()?;
            match prepared.verify_candidate(index, &chain, PRODUCTION_TRUST, unix_time) {
                Ok(()) => return Ok(prepared.finish(response, chain)),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }

    /// Downloads and extracts Google's current complete CRLSet component.
    ///
    /// # Errors
    ///
    /// Returns an error for HTTP failures, active backoff, malformed update
    /// metadata, an unsafe component URL, length or hash mismatch, size limits,
    /// invalid CRX/ZIP containers, or malformed CRLSet data.
    pub fn fetch_crlset(&self) -> Result<CrlSet> {
        self.fetch_crlset_from(CRLSET_UPDATE_URL)
    }

    /// Downloads a CRLSet using a specified Omaha update metadata URL.
    ///
    /// The matching component must be offered with `status="ok"`, an HTTPS
    /// codebase, an exact byte size, and a SHA-256 hash. Hashes validate download
    /// integrity against the metadata. CRX3 signatures then authenticate the
    /// container against Chrome's pinned CRLSet component signing key.
    ///
    /// # Errors
    ///
    /// Returns an error for HTTP failures, active backoff, malformed update
    /// metadata, an unsafe component URL, length or hash mismatch, size limits,
    /// invalid CRX/ZIP containers, or malformed CRLSet data.
    pub fn fetch_crlset_from(&self, url: &str) -> Result<CrlSet> {
        let metadata = self.download(url, false)?;
        let component = component_download(&metadata, self.max_bytes)?;
        let bytes = self.download(component.url.as_str(), true)?;
        validate_download(&bytes, &component)?;
        CrlSet::from_signed_crx(bytes, self.max_bytes)
    }

    /// Downloads a response, recording server backoff even for HTTP errors.
    ///
    /// # Errors
    ///
    /// Returns an error for active backoff, request or body failures, HTTP error
    /// statuses, unexpected redirects, or declared/actual bodies above the cap.
    fn download(&self, url: &str, require_https: bool) -> Result<Vec<u8>> {
        self.download_with_backoff(&self.client, url, require_https, None, true, self.max_bytes)
    }

    /// Download a response required to finish authenticating an accepted response.
    ///
    /// This dependent request bypasses backoff already recorded from the parent
    /// changeset; that backoff still applies to the next top-level operation.
    ///
    /// # Errors
    ///
    /// Returns HTTP, redirect-policy, or response-size errors.
    fn download_dependency(&self, url: &str, require_https: bool) -> Result<Vec<u8>> {
        self.download_with_backoff(
            &self.chain_client,
            url,
            require_https,
            Some(ONECRL_CHAIN_HOST),
            false,
            self.max_bytes.min(MAX_CERTIFICATE_CHAIN_BYTES as u64),
        )
    }

    /// Download one bounded response with optional top-level backoff handling.
    ///
    /// # Errors
    ///
    /// Returns active backoff, HTTP, redirect-policy, or response-size errors.
    fn download_with_backoff(
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
        let response = client.get(url).send()?;
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
        (&mut response)
            .take(maximum.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > maximum {
            return Err(Error::SizeLimit(maximum));
        }
        Ok(bytes)
    }

    /// Locks backoff state, recovering state from any poisoned mutex.
    fn backoff_state(&self) -> MutexGuard<'_, Option<Backoff>> {
        self.backoff
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Refuses requests while a previously received backoff interval is active.
    ///
    /// # Errors
    ///
    /// Returns the remaining backoff seconds, rounded up, while it is active.
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

    /// Records a valid server backoff header without shortening an active wait.
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

/// Parse a safe HTTPS certificate-chain URL from untrusted feed metadata.
///
/// # Errors
///
/// Returns an invalid-format error unless the URL uses the pinned production
/// chain host over HTTPS on port 443 without embedded credentials.
pub(super) fn signature_chain_url(value: &str) -> Result<reqwest::Url> {
    let url = reqwest::Url::parse(value)
        .map_err(|_| Error::InvalidFormat("invalid OneCRL certificate-chain URL"))?;
    if !is_onecrl_chain_url(&url) {
        return Err(Error::InvalidFormat(
            "OneCRL certificate-chain URL must use Mozilla's production CDN over HTTPS",
        ));
    }
    Ok(url)
}

/// Return whether a URL stays inside the pinned production chain origin.
pub(super) fn is_onecrl_chain_url(url: &reqwest::Url) -> bool {
    url.scheme() == "https"
        && url.host_str() == Some(ONECRL_CHAIN_HOST)
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
}

/// Build an isolated client that cannot follow a chain redirect to another origin.
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

/// Omaha response containing applications, including the CRLSet component.
#[derive(Debug, Deserialize)]
struct UpdateResponse {
    /// Application updates offered by the response.
    #[serde(rename = "app", default)]
    apps: Vec<UpdateApp>,
}

/// Update status and metadata for a single Omaha application.
#[derive(Debug, Deserialize)]
struct UpdateApp {
    /// Extension-style application identifier.
    #[serde(rename = "@appid")]
    id: String,
    /// Success or failure status for the application lookup.
    #[serde(rename = "@status", default)]
    status: String,
    /// Optional offered component update.
    #[serde(rename = "updatecheck")]
    update: Option<UpdateCheck>,
}

/// Omaha metadata describing the offered CRX archive.
#[derive(Debug, Deserialize)]
struct UpdateCheck {
    /// Whether an update was successfully offered.
    #[serde(rename = "@status", default)]
    status: String,
    /// Download location of the CRX archive.
    #[serde(rename = "@codebase")]
    codebase: Option<String>,
    /// Hexadecimal SHA-256 digest of the complete CRX archive.
    #[serde(rename = "@hash_sha256")]
    hash_sha256: Option<String>,
    /// Complete CRX archive size in bytes.
    #[serde(rename = "@size")]
    size: Option<u64>,
}

/// Validated download location and integrity requirements for a CRX archive.
#[derive(Debug)]
pub(crate) struct ComponentDownload {
    /// Validated HTTPS URL with no embedded credentials.
    pub(crate) url: reqwest::Url,
    /// Expected SHA-256 digest of the complete CRX archive.
    sha256: [u8; 32],
    /// Expected number of bytes in the complete CRX archive.
    size: u64,
}

/// Extracts and validates the CRLSet component's Omaha update metadata.
///
/// # Errors
///
/// Returns an error for invalid XML, missing or ambiguous component metadata,
/// failed update statuses, unsafe URLs, malformed hashes, or excessive sizes.
pub(crate) fn component_download(bytes: &[u8], max_bytes: u64) -> Result<ComponentDownload> {
    let response: UpdateResponse = quick_xml::de::from_reader(bytes)?;
    let mut apps = response
        .apps
        .into_iter()
        .filter(|app| app.id == CRLSET_COMPONENT_ID);
    let app = apps.next().ok_or(Error::InvalidFormat(
        "update response has no CRLSet component",
    ))?;
    if apps.next().is_some() {
        return Err(Error::InvalidFormat("duplicate CRLSet update metadata"));
    }
    if app.status != "ok" {
        return Err(Error::InvalidFormat("CRLSet application status is not ok"));
    }
    let update = app
        .update
        .ok_or(Error::InvalidFormat("missing CRLSet update check"))?;
    if update.status != "ok" {
        return Err(Error::InvalidFormat("CRLSet update status is not ok"));
    }
    let codebase = update
        .codebase
        .ok_or(Error::InvalidFormat("missing CRLSet download URL"))?;
    let url = reqwest::Url::parse(&codebase)
        .map_err(|_| Error::InvalidFormat("invalid CRLSet download URL"))?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(Error::InvalidFormat(
            "CRLSet download URL must use HTTPS without credentials",
        ));
    }
    let sha256 = parse_sha256(
        &update
            .hash_sha256
            .ok_or(Error::InvalidFormat("missing CRLSet SHA-256 hash"))?,
    )?;
    let size = update
        .size
        .ok_or(Error::InvalidFormat("missing CRLSet download size"))?;
    if size > max_bytes {
        return Err(Error::SizeLimit(max_bytes));
    }
    Ok(ComponentDownload { url, sha256, size })
}

/// Decodes a fixed-length ASCII hexadecimal SHA-256 digest.
///
/// # Errors
///
/// Returns an error unless the string contains exactly 64 hexadecimal digits.
fn parse_sha256(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        return Err(Error::InvalidFormat("invalid CRLSet SHA-256 hash"));
    }
    let mut digest = [0; 32];
    for (output, [high, low]) in digest.iter_mut().zip(hex.as_bytes().as_chunks::<2>().0) {
        let high = hex_digit(*high).ok_or(Error::InvalidFormat("invalid CRLSet SHA-256 hash"))?;
        let low = hex_digit(*low).ok_or(Error::InvalidFormat("invalid CRLSet SHA-256 hash"))?;
        *output = (high << 4) | low;
    }
    Ok(digest)
}

/// Converts an ASCII hexadecimal digit into its numeric value.
fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
        _ => None,
    }
}

/// Checks downloaded CRX bytes against the update response's size and digest.
///
/// This is the transport-integrity stage. Both downloaders then call
/// [`CrlSet::from_signed_crx`] to require a valid signature from the pinned
/// CRLSet publisher before extracting or returning a payload.
///
/// # Errors
///
/// Returns an error if the byte count or SHA-256 digest does not match.
pub(crate) fn validate_download(bytes: &[u8], component: &ComponentDownload) -> Result<()> {
    if bytes.len() as u64 != component.size {
        return Err(Error::InvalidFormat(
            "CRX download size does not match metadata",
        ));
    }
    let actual: [u8; 32] = Sha256::digest(bytes).into();
    if actual != component.sha256 {
        return Err(Error::HashMismatch);
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/download.rs"]
mod tests;
