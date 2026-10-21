//! Browser revocation feeds and certificate checks for Rust and C.
//!
//! With the default `download` feature, `ferrovoker::fetch().await` loads both
//! feeds, caches them in the OS cache directory, and keeps a combined index
//! refreshed in the background for as long as its handle is retained.
//!
//! Chrome downloads and cached CRX containers are authenticated against the
//! pinned CRLSet signing key. Mozilla content signatures remain unverified.
//! Feed entries are matched using [`RevocationSet`]. Feed transport, integrity,
//! authenticity, freshness, and certificate validation are distinct concerns.
//! The `rustls` feature adds a verifier that applies these checks after normal
//! chain and hostname verification. The `ffi` feature exports the C interface.
//!
//! ```no_run
//! # #[cfg(feature = "download")]
//! # async fn example() -> ferrovoker::Result<()> {
//! let revocations = ferrovoker::fetch().await?;
//! # Ok(())
//! # }
//! ```
//!
//! Lower-level parsing is also available for applications managing their own
//! authenticated snapshots:
//!
//! ```no_run
//! use ferrovoker::{OneCrl, RevocationSet};
//!
//! let snapshot = OneCrl::from_slice(&std::fs::read("onecrl.json")?)?;
//! let revocations = RevocationSet::from_snapshots(Some(&snapshot), None)?;
//! let leaf = std::fs::read("server.der")?;
//! let status = revocations.check_chain(&[leaf.as_slice()], 1_792_540_800)?;
//! println!("{status:?}");
//! # Ok::<(), ferrovoker::Error>(())
//! ```

#[cfg(feature = "download")]
mod async_download;
#[cfg(feature = "download")]
mod cache;
#[cfg(feature = "download")]
mod crx;
#[cfg(feature = "download")]
mod download;
mod revocation;

#[cfg(feature = "rustls")]
pub mod rustls;

#[cfg(feature = "ffi")]
pub mod ffi;

#[cfg(test)]
#[path = "../tests/unit/feeds.rs"]
mod tests;

#[cfg(feature = "download")]
pub use async_download::AsyncDownloader;
#[cfg(feature = "download")]
pub use cache::{CacheConfig, Revocations, fetch};
#[cfg(feature = "download")]
pub use download::Downloader;
pub use revocation::{
    CertificateRevocations, IssuerIdentity, RevocationMatch, RevocationReason, RevocationSet,
    RevocationStatus,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Mozilla's production OneCRL changeset, cached according to the service TTL.
pub const ONECRL_URL: &str = "https://firefox.settings.services.mozilla.com/v2/buckets/security-state/collections/onecrl/changeset?_expected=0";

/// Chrome's full CRLSet component update endpoint.
pub const CRLSET_UPDATE_URL: &str = "https://clients2.google.com/service/update2/crx?x=id%3Dhfnkpimlhhgieaddgfemjhofmfblmnib%26v%3D%26uc%26acceptformat%3Dcrx3&tag=force_full";

/// Chrome's full CRLSet component identifier.
pub const CRLSET_COMPONENT_ID: &str = "hfnkpimlhhgieaddgfemjhofmfblmnib";

/// Result returned by feed parsing and downloading operations.
pub type Result<T> = std::result::Result<T, Error>;

/// A shared source of certificate revocation checks, either fixed or refreshed.
///
/// Implementations must check one consistent snapshot per call and preserve
/// normal TLS verification in the surrounding application. The Rustls adapter
/// accepts both offline [`RevocationSet`] values and managed cache handles.
pub trait RevocationProvider: std::fmt::Debug + Send + Sync {
    /// Check certificates, using trusted supplemental issuer identities as needed.
    ///
    /// The built-in providers accept one DER, PEM CERTIFICATE, or base64 DER
    /// certificate per chain entry and preserve input positions in match indexes.
    ///
    /// # Errors
    ///
    /// Returns errors for invalid certificates, expired feeds, or an unusably
    /// stale managed snapshot. Additional provider-specific failures may occur.
    fn check_chain_with_issuers(
        &self,
        chain: &[&[u8]],
        issuers: &[IssuerIdentity],
        unix_time: u64,
    ) -> Result<RevocationStatus>;
}

impl RevocationProvider for RevocationSet {
    /// Check an immutable offline snapshot with supplemental issuer identities.
    ///
    /// # Errors
    ///
    /// Returns errors for malformed certificates or an expired CRLSet.
    fn check_chain_with_issuers(
        &self,
        chain: &[&[u8]],
        issuers: &[IssuerIdentity],
        unix_time: u64,
    ) -> Result<RevocationStatus> {
        RevocationSet::check_chain_with_issuers(self, chain, issuers, unix_time)
    }
}

/// A download, integrity, or feed-format failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An HTTP request or status code failed.
    #[cfg(feature = "download")]
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// Reading or writing bytes failed.
    #[error("I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Feed JSON could not be decoded.
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// Chrome's update response could not be decoded.
    #[cfg(feature = "download")]
    #[error("invalid update XML: {0}")]
    Xml(#[from] quick_xml::DeError),
    /// The component archive is invalid.
    #[cfg(feature = "download")]
    #[error("invalid component ZIP: {0}")]
    Zip(#[from] zip::result::ZipError),
    /// A required feed field, framing value, or URL is invalid.
    #[error("invalid feed format: {0}")]
    InvalidFormat(&'static str),
    /// A response or extracted payload exceeds the configured byte limit.
    #[error("download or extracted payload exceeds {0} bytes")]
    SizeLimit(u64),
    /// The downloaded component does not match the advertised SHA-256.
    #[error("component SHA-256 does not match the update response")]
    HashMismatch,
    /// A CRX3 proof or its signed component identifier is invalid.
    #[cfg(feature = "download")]
    #[error("invalid CRX3 publisher signature or signed component identity")]
    InvalidCrxSignature,
    /// No valid proof uses the pinned Chrome CRLSet component signing key.
    #[cfg(feature = "download")]
    #[error("CRX3 is not signed by the pinned CRLSet publisher")]
    UntrustedCrxPublisher,
    /// Mozilla has requested that this downloader delay further requests.
    #[error("Remote Settings requested backoff; retry after {0} seconds")]
    Backoff(u64),
    /// A chain entry is not one complete DER, PEM, or base64 DER X.509 certificate.
    #[error("invalid certificate or certificate chain (expected DER, PEM, or base64 DER)")]
    InvalidCertificate,
    /// The CRLSet's advertised validity deadline has passed.
    #[error("the CRLSet has expired")]
    ExpiredCrlSet,
    /// A managed snapshot exceeded its configured maximum age.
    #[error("the cached revocation snapshot is too old")]
    StaleSnapshot,
    /// An OS cache directory could not be determined.
    #[cfg(feature = "download")]
    #[error("no OS cache directory is available; configure a cache directory")]
    CacheUnavailable,
    /// Managed async loading requires an active Tokio runtime.
    #[cfg(feature = "download")]
    #[error("managed revocation loading requires an active Tokio runtime")]
    RuntimeRequired,
}

/// A complete OneCRL changeset, including signature metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OneCrl {
    /// Timestamp of the published collection, in milliseconds since the epoch.
    pub timestamp: u64,
    /// Collection metadata, including Mozilla's content signature.
    pub metadata: Value,
    /// Records in the complete snapshot.
    pub changes: Vec<OneCrlRecord>,
}

impl OneCrl {
    /// Decode a complete Remote Settings changeset.
    ///
    /// Unknown record fields are retained. Tombstones and unsupported identifier
    /// combinations are rejected because this API represents complete snapshots.
    /// Identifier strings remain opaque; their base64 and DER are not validated.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid JSON, missing required fields, tombstones,
    /// or records lacking exactly one supported revocation identifier pair.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        let snapshot: Self = serde_json::from_slice(bytes)?;
        for record in &snapshot.changes {
            record.validate()?;
        }
        Ok(snapshot)
    }
}

/// A OneCRL record with its original base64 identifiers and metadata.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OneCrlRecord {
    /// Remote Settings record identifier.
    pub id: String,
    /// Timestamp of the record's latest modification.
    pub last_modified: u64,
    /// Whether Mozilla enables this revocation record.
    pub enabled: bool,
    /// Base64-encoded DER issuer name for an issuer/serial revocation.
    #[serde(rename = "issuerName", skip_serializing_if = "Option::is_none")]
    pub issuer_name: Option<String>,
    /// Base64-encoded serial number for an issuer/serial revocation.
    #[serde(rename = "serialNumber", skip_serializing_if = "Option::is_none")]
    pub serial_number: Option<String>,
    /// Base64-encoded DER subject name for a subject/key revocation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    /// Base64-encoded public-key hash for a subject/key revocation.
    #[serde(rename = "pubKeyHash", skip_serializing_if = "Option::is_none")]
    pub public_key_hash: Option<String>,
    /// Additional fields, such as approval details and schema version.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl OneCrlRecord {
    /// Check that the record represents one supported revocation form.
    ///
    /// # Errors
    ///
    /// Returns an error for tombstones or missing/ambiguous identifier pairs.
    fn validate(&self) -> Result<()> {
        let identifiers_valid = matches!(
            (
                &self.issuer_name,
                &self.serial_number,
                &self.subject,
                &self.public_key_hash
            ),
            (Some(_), Some(_), None, None) | (None, None, Some(_), Some(_))
        );
        if self.extra.get("deleted").and_then(Value::as_bool) == Some(true) || !identifiers_valid {
            return Err(Error::InvalidFormat("invalid OneCRL revocation record"));
        }
        Ok(())
    }
}

/// An unpacked Chrome CRLSet and its decoded header.
///
/// [`Self::from_bytes`] parses caller-supplied data without authenticating it.
/// With the `download` feature, `from_signed_crx` verifies the signed container
/// against Chrome's pinned component key before extracting its payload.
#[derive(Clone, Debug)]
pub struct CrlSet {
    /// The original `crl-set` payload, suitable for saving as a binary file.
    pub bytes: Vec<u8>,
    /// Metadata from the payload's length-prefixed JSON header.
    pub header: CrlSetHeader,
    /// Original authenticated container, retained for verification on cache reload.
    #[cfg(feature = "download")]
    pub(crate) signed_crx: Option<Vec<u8>>,
}

impl CrlSet {
    /// Decode the header of an unpacked CRLSet payload.
    ///
    /// The revocation body is preserved without interpreting its entries. This
    /// method does not verify a publisher signature; use `from_signed_crx` to
    /// authenticate a complete CRX3 container.
    ///
    /// # Errors
    ///
    /// Returns an error if the length prefix or header is truncated, the JSON
    /// is invalid, or the content type or format version is unsupported.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let prefix: [u8; 2] = bytes
            .get(..2)
            .ok_or(Error::InvalidFormat("missing CRLSet header length"))?
            .try_into()
            .map_err(|_| Error::InvalidFormat("invalid CRLSet header length"))?;
        let end = 2 + usize::from(u16::from_le_bytes(prefix));
        let header: CrlSetHeader = serde_json::from_slice(
            bytes
                .get(2..end)
                .ok_or(Error::InvalidFormat("truncated CRLSet header"))?,
        )?;
        if header.content_type != "CRLSet" || header.version != 0 {
            return Err(Error::InvalidFormat(
                "unsupported CRLSet content type or version",
            ));
        }
        Ok(Self {
            bytes,
            header,
            #[cfg(feature = "download")]
            signed_crx: None,
        })
    }

    /// Authenticate and extract a CRLSet from a complete CRX3 container.
    ///
    /// Verification requires Chrome's pinned CRLSet component signing key, a
    /// matching signed component identity, and valid CRX3 signatures over the
    /// signed header and full archive. Legacy CRX2 containers are rejected.
    /// `max_bytes` bounds both the container and its extracted CRLSet payload.
    /// This authenticates the publisher, without providing rollback protection.
    ///
    /// # Errors
    ///
    /// Returns an error for size limits, malformed CRX/protobuf/key data,
    /// invalid signatures, an untrusted signing key, extraction failures, or
    /// an invalid CRLSet header.
    #[cfg(feature = "download")]
    pub fn from_signed_crx(bytes: Vec<u8>, max_bytes: u64) -> Result<Self> {
        if bytes.len() as u64 > max_bytes {
            return Err(Error::SizeLimit(max_bytes));
        }
        let payload = crx::extract_crl_set(&bytes, max_bytes)?;
        Self::retain_signed_crx(bytes, payload)
    }

    /// Authenticate a container with an internally selected publisher trust anchor.
    ///
    /// The managed cache supplies the built-in pin; tests supply a disposable
    /// signing key. No public configuration can change the managed publisher pin.
    ///
    /// # Errors
    ///
    /// Returns the authentication, size, extraction, and format errors described
    /// by [`Self::from_signed_crx`].
    #[cfg(feature = "download")]
    pub(crate) fn from_signed_crx_with_key(
        bytes: Vec<u8>,
        max_bytes: u64,
        key_hash: &[u8; 32],
    ) -> Result<Self> {
        if bytes.len() as u64 > max_bytes {
            return Err(Error::SizeLimit(max_bytes));
        }
        let payload = crx::extract_crl_set_with_key(&bytes, max_bytes, key_hash)?;
        Self::retain_signed_crx(bytes, payload)
    }

    /// Retain the original container after its signatures have been verified.
    ///
    /// # Errors
    ///
    /// Returns an error if the authenticated payload has an invalid CRLSet header.
    #[cfg(feature = "download")]
    fn retain_signed_crx(bytes: Vec<u8>, payload: Vec<u8>) -> Result<Self> {
        let mut snapshot = Self::from_bytes(payload)?;
        snapshot.signed_crx = Some(bytes);
        Ok(snapshot)
    }
}

/// Metadata in the CRLSet's JSON header.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CrlSetHeader {
    /// Payload content type, which must be `CRLSet`.
    #[serde(rename = "ContentType")]
    pub content_type: String,
    /// Binary format version, currently zero.
    #[serde(rename = "Version")]
    pub version: u64,
    /// Monotonically increasing CRLSet sequence number.
    #[serde(rename = "Sequence")]
    pub sequence: u64,
    /// Remaining header fields, including blocked SPKIs and expiry if present.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}
