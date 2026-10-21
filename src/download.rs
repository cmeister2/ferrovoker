//! Blocking, bounded download clients for Mozilla OneCRL and Chrome CRLSets.

use std::io::Read;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use reqwest::blocking::{Client, Response};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::{CRLSET_COMPONENT_ID, CRLSET_UPDATE_URL, CrlSet, Error, ONECRL_URL, OneCrl, Result};

/// Default maximum size of any response or decompressed CRLSet, in bytes.
const DEFAULT_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// Downloads browser revocation data using a reusable blocking HTTP client.
///
/// Responses and decompressed CRLSets are bounded to 64 MiB by default. A
/// server's `Backoff` header prevents subsequent requests through this instance
/// until the requested interval has elapsed. Chrome CRX3 signatures authenticate
/// the pinned component publisher. Mozilla content signatures remain unverified.
#[derive(Debug)]
pub struct Downloader {
    /// Reusable HTTP connection pool and transport configuration.
    client: Client,
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

    /// Uses a caller-configured client, for example with a custom proxy.
    ///
    /// The caller controls transport policy, redirects, timeouts, and the
    /// application/version `User-Agent` required by Mozilla. Component download
    /// URLs and their final response URLs must still use HTTPS.
    pub fn with_client(client: Client) -> Self {
        Self {
            client,
            max_bytes: DEFAULT_MAX_BYTES,
            backoff: Mutex::new(None),
        }
    }

    /// Sets the limit for response bodies and decompressed CRLSet payloads.
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
    /// an oversized response, or malformed OneCRL data.
    pub fn fetch_onecrl(&self) -> Result<OneCrl> {
        self.fetch_onecrl_from(ONECRL_URL)
    }

    /// Fetches a complete OneCRL changeset from a specified URL.
    ///
    /// Use the Remote Settings `changeset?_expected=...` endpoint without a
    /// `_since` filter; this method does not merge incremental changes locally.
    ///
    /// # Errors
    ///
    /// Returns an error for network or HTTP failures, an active backoff interval,
    /// an oversized response, or malformed OneCRL data.
    pub fn fetch_onecrl_from(&self, url: &str) -> Result<OneCrl> {
        OneCrl::from_slice(&self.download(url, false)?)
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
        self.ensure_no_backoff()?;
        let response = self.client.get(url).send()?;
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
        (&mut response)
            .take(self.max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > self.max_bytes {
            return Err(Error::SizeLimit(self.max_bytes));
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
