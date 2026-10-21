//! Mozilla Remote Settings content-signature verification for OneCRL.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use ring::signature::{self, UnparsedPublicKey};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use webpki::{EndEntityCert, KeyUsage};
use x509_parser::extensions::GeneralName;
use x509_parser::pem::Pem;

use crate::{Error, OneCrl, Result};

/// Maximum number of advertised signatures tried during a signing-key rotation.
const MAX_SIGNATURES: usize = 8;
/// Maximum accepted length of one certificate-chain URL.
const MAX_X5U_BYTES: usize = 2048;
/// Maximum certificates accepted in one leaf-first content-signing chain.
const MAX_CERTIFICATES: usize = 8;
/// Maximum certificate-chain response retained in the persistent cache.
pub(crate) const MAX_CERTIFICATE_CHAIN_BYTES: usize = 1024 * 1024;
/// DER value bytes for id-kp-codeSigning (1.3.6.1.5.5.7.3.3).
const CODE_SIGNING_EKU: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x03];
/// Domain identity Mozilla assigns to OneCRL signing certificates.
const ONECRL_SIGNER: &str = "onecrl.content-signature.mozilla.org";
/// SHA-256 of Mozilla's production content-signing root certificate DER.
const ONECRL_ROOT_SHA256: [u8; 32] = [
    0xc8, 0xa8, 0x0e, 0x9a, 0xfa, 0xef, 0x4e, 0x21, 0x9b, 0x6f, 0xb5, 0xd7, 0xa7, 0x1d, 0x0f, 0x10,
    0x12, 0x23, 0xba, 0xc5, 0x00, 0x1a, 0xc2, 0x8f, 0x9b, 0x0d, 0x43, 0xdc, 0x59, 0xa1, 0x06, 0xdb,
];
/// Certificate-signature algorithms used by Mozilla's pinned production chain.
///
/// Keeping this list local prevents unrelated downstream `webpki` features from
/// silently widening the publisher trust policy.
static CERTIFICATE_SIGNATURE_ALGORITHMS:
    &[&dyn rustls_pki_types::SignatureVerificationAlgorithm] = &[
    webpki::ring::ECDSA_P384_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384,
    webpki::ring::RSA_PKCS1_2048_8192_SHA384_ABSENT_PARAMS,
];

/// Trust policy used for a Mozilla content-signing certificate.
#[derive(Clone, Copy, Debug)]
pub(crate) struct OneCrlTrust {
    /// Hash of the only accepted root certificate.
    pub(crate) root_sha256: [u8; 32],
    /// Exact DNS subject alternative name required on the signing leaf.
    pub(crate) signer_name: &'static str,
}

/// Production OneCRL publisher identity, fixed independently of feed metadata.
pub(crate) const PRODUCTION_TRUST: OneCrlTrust = OneCrlTrust {
    root_sha256: ONECRL_ROOT_SHA256,
    signer_name: ONECRL_SIGNER,
};

/// One parsed snapshot together with the bytes needed to authenticate it again.
#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedOneCrl {
    /// Typed snapshot derived from the authenticated response.
    pub(crate) snapshot: OneCrl,
    /// Original changeset response containing signed record values and metadata.
    pub(crate) response: Vec<u8>,
    /// Leaf-first PEM certificate chain selected during signature rotation.
    pub(crate) certificate_chain: Vec<u8>,
}

/// Parsed snapshot and canonical message shared by signing-key rotation attempts.
#[derive(Debug)]
pub(crate) struct PreparedOneCrl {
    /// Typed snapshot parsed once from the original response.
    snapshot: OneCrl,
    /// Context-prefixed canonical collection bytes.
    message: Vec<u8>,
    /// Supported signature entries in publisher rotation order.
    candidates: Vec<ContentSignature>,
}

/// Signature information needed by a downloader before cryptographic verification.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct ContentSignature {
    /// URL of the leaf-first signing certificate chain.
    pub(crate) x5u: String,
    /// URL-safe base64 P-384 signature over canonical collection data.
    signature: String,
    /// Content-signature mode, which must identify fixed-width P-384 ECDSA.
    mode: String,
}

/// Signature-bearing subset of Remote Settings collection metadata.
#[derive(Debug, Deserialize)]
struct SignatureMetadata {
    /// Current list supporting publisher key rotation.
    #[serde(default)]
    signatures: Vec<ContentSignature>,
    /// Legacy single signature used only when the current list is absent.
    #[serde(default)]
    signature: Option<ContentSignature>,
}

/// Untyped signed fields from a complete changeset response.
#[derive(Debug, Deserialize)]
struct SignedChangeset {
    /// Collection timestamp used as a string in the signed envelope.
    timestamp: u64,
    /// Collection records kept as JSON to preserve signed null and numeric values.
    changes: Vec<Value>,
    /// Publisher signature metadata.
    metadata: SignatureMetadata,
}

impl AuthenticatedOneCrl {
    /// Authenticate one response against any supported metadata signature and a saved chain.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata, records, certificates, publisher
    /// identity, canonical payload, or content signature.
    pub(crate) fn from_saved(
        response: Vec<u8>,
        certificate_chain: Vec<u8>,
        trust: OneCrlTrust,
        unix_time: u64,
    ) -> Result<Self> {
        let prepared = PreparedOneCrl::from_response(&response)?;
        let mut last_error = Error::InvalidOneCrlSignature;
        for index in 0..prepared.candidate_count() {
            match prepared.verify_candidate(index, &certificate_chain, trust, unix_time) {
                Ok(()) => return Ok(prepared.finish(response, certificate_chain)),
                Err(error) => last_error = error,
            }
        }
        Err(last_error)
    }
}

impl PreparedOneCrl {
    /// Parse and canonicalize one response once before trying rotation candidates.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed records or metadata, excessive signature
    /// entries, unsupported signatures, or unrepresentable canonical JSON.
    pub(crate) fn from_response(response: &[u8]) -> Result<Self> {
        let changeset: SignedChangeset = serde_json::from_slice(response)?;
        let SignedChangeset {
            timestamp,
            changes,
            metadata,
        } = changeset;
        let candidates = supported_candidates(metadata)?;
        let message = signed_message(timestamp, changes)?;
        let snapshot = OneCrl::from_slice(response)?;
        Ok(Self {
            snapshot,
            message,
            candidates,
        })
    }

    /// Return the number of supported signatures available for rotation.
    pub(crate) fn candidate_count(&self) -> usize {
        self.candidates.len()
    }

    /// Return one candidate's untrusted certificate-chain URL.
    pub(crate) fn candidate_x5u(&self, index: usize) -> Option<&str> {
        self.candidates
            .get(index)
            .map(|candidate| candidate.x5u.as_str())
    }

    /// Verify one rotation candidate against its downloaded publisher chain.
    ///
    /// # Errors
    ///
    /// Returns a publisher error for an invalid chain or identity, and a
    /// signature error for a malformed or invalid P-384 signature.
    pub(crate) fn verify_candidate(
        &self,
        index: usize,
        certificate_chain: &[u8],
        trust: OneCrlTrust,
        unix_time: u64,
    ) -> Result<()> {
        let candidate = self
            .candidates
            .get(index)
            .ok_or(Error::InvalidOneCrlSignature)?;
        let certificates = parse_certificate_chain(certificate_chain)?;
        verify_certificate_chain(&certificates, trust, unix_time)?;
        let decoded_signature = URL_SAFE
            .decode(&candidate.signature)
            .map_err(|_| Error::InvalidOneCrlSignature)?;
        if decoded_signature.len() != 96 {
            return Err(Error::InvalidOneCrlSignature);
        }
        let (_, leaf) = x509_parser::parse_x509_certificate(certificates[0].as_ref())
            .map_err(|_| Error::UntrustedOneCrlPublisher)?;
        UnparsedPublicKey::new(
            &signature::ECDSA_P384_SHA384_FIXED,
            leaf.public_key().subject_public_key.data.as_ref(),
        )
        .verify(&self.message, &decoded_signature)
        .map_err(|_| Error::InvalidOneCrlSignature)
    }

    /// Combine verified proof bytes with the snapshot parsed from those bytes.
    pub(crate) fn finish(
        self,
        response: Vec<u8>,
        certificate_chain: Vec<u8>,
    ) -> AuthenticatedOneCrl {
        AuthenticatedOneCrl {
            snapshot: self.snapshot,
            response,
            certificate_chain,
        }
    }
}

/// Select bounded, supported rotation candidates without trusting identity claims.
///
/// # Errors
///
/// Returns an error for excessive entries or when no supported fixed-width
/// P-384 signature has a bounded certificate-chain URL.
fn supported_candidates(metadata: SignatureMetadata) -> Result<Vec<ContentSignature>> {
    let advertised = if metadata.signatures.is_empty() {
        metadata.signature.into_iter().collect()
    } else {
        metadata.signatures
    };
    if advertised.len() > MAX_SIGNATURES {
        return Err(Error::InvalidFormat(
            "OneCRL advertises too many content signatures",
        ));
    }
    let supported: Vec<_> = advertised
        .into_iter()
        .filter(|entry| {
            entry.mode == "p384ecdsa"
                && !entry.x5u.is_empty()
                && entry.x5u.len() <= MAX_X5U_BYTES
                && entry.signature.len() == 128
        })
        .collect();
    if supported.is_empty() {
        return Err(Error::InvalidOneCrlSignature);
    }
    Ok(supported)
}

/// Return the current Unix second without accepting a pre-epoch system clock.
///
/// # Errors
///
/// Returns an invalid-format error when the system clock predates the Unix epoch.
pub(crate) fn unix_now() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| Error::InvalidFormat("system clock is before the Unix epoch"))
}

/// Parse a bounded, leaf-first PEM chain containing only certificate blocks.
///
/// # Errors
///
/// Returns a publisher error for malformed PEM, non-certificate blocks, too
/// many certificates, trailing certificate DER, or an implausible chain length.
fn parse_certificate_chain(bytes: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    if bytes.len() > MAX_CERTIFICATE_CHAIN_BYTES {
        return Err(Error::SizeLimit(MAX_CERTIFICATE_CHAIN_BYTES as u64));
    }
    let mut certificates = Vec::new();
    for block in Pem::iter_from_buffer(bytes) {
        let block = block.map_err(|_| Error::UntrustedOneCrlPublisher)?;
        if block.label != "CERTIFICATE" || certificates.len() == MAX_CERTIFICATES {
            return Err(Error::UntrustedOneCrlPublisher);
        }
        let (remaining, _) = x509_parser::parse_x509_certificate(&block.contents)
            .map_err(|_| Error::UntrustedOneCrlPublisher)?;
        if !remaining.is_empty() {
            return Err(Error::UntrustedOneCrlPublisher);
        }
        certificates.push(CertificateDer::from(block.contents));
    }
    if certificates.len() < 2 {
        return Err(Error::UntrustedOneCrlPublisher);
    }
    Ok(certificates)
}

/// Validate the publisher chain, pinned root, time, EKU, key usages, and leaf SAN.
///
/// # Errors
///
/// Returns a publisher error when any certificate or identity constraint fails.
fn verify_certificate_chain(
    certificates: &[CertificateDer<'_>],
    trust: OneCrlTrust,
    unix_time: u64,
) -> Result<()> {
    let root = certificates.last().ok_or(Error::UntrustedOneCrlPublisher)?;
    if <[u8; 32]>::from(Sha256::digest(root.as_ref())) != trust.root_sha256 {
        return Err(Error::UntrustedOneCrlPublisher);
    }
    let (_, parsed_root) = x509_parser::parse_x509_certificate(root.as_ref())
        .map_err(|_| Error::UntrustedOneCrlPublisher)?;
    let seconds = i64::try_from(unix_time).map_err(|_| Error::UntrustedOneCrlPublisher)?;
    let time = x509_parser::time::ASN1Time::from_timestamp(seconds)
        .map_err(|_| Error::UntrustedOneCrlPublisher)?;
    if !parsed_root.validity().is_valid_at(time) || !parsed_root.is_ca() {
        return Err(Error::UntrustedOneCrlPublisher);
    }
    require_ca_key_usage(&parsed_root)?;

    let leaf_der = &certificates[0];
    let leaf = EndEntityCert::try_from(leaf_der).map_err(|_| Error::UntrustedOneCrlPublisher)?;
    let anchor =
        webpki::anchor_from_trusted_cert(root).map_err(|_| Error::UntrustedOneCrlPublisher)?;
    let anchors = [anchor];
    let verified_path = leaf
        .verify_for_usage(
            CERTIFICATE_SIGNATURE_ALGORITHMS,
            &anchors,
            &certificates[1..certificates.len() - 1],
            UnixTime::since_unix_epoch(Duration::from_secs(unix_time)),
            KeyUsage::required(CODE_SIGNING_EKU),
            None,
            None,
        )
        .map_err(|_| Error::UntrustedOneCrlPublisher)?;
    let advertised_intermediates = &certificates[1..certificates.len() - 1];
    let verified_intermediates: Vec<_> = verified_path.intermediate_certificates().collect();
    if verified_intermediates.len() != advertised_intermediates.len()
        || verified_intermediates
            .iter()
            .zip(advertised_intermediates)
            .any(|(verified, advertised)| verified.der().as_ref() != advertised.as_ref())
    {
        return Err(Error::UntrustedOneCrlPublisher);
    }
    let name =
        ServerName::try_from(trust.signer_name).map_err(|_| Error::UntrustedOneCrlPublisher)?;
    leaf.verify_is_valid_for_subject_name(&name)
        .map_err(|_| Error::UntrustedOneCrlPublisher)?;

    let (_, parsed_leaf) = x509_parser::parse_x509_certificate(leaf_der.as_ref())
        .map_err(|_| Error::UntrustedOneCrlPublisher)?;
    let has_exact_san =
        parsed_leaf
            .subject_alternative_name()
            .map_err(|_| Error::UntrustedOneCrlPublisher)?
            .is_some_and(|extension| {
                extension.value.general_names.iter().any(
                    |name| matches!(name, GeneralName::DNSName(dns) if *dns == trust.signer_name),
                )
            });
    let has_digital_signature = parsed_leaf
        .key_usage()
        .map_err(|_| Error::UntrustedOneCrlPublisher)?
        .is_some_and(|extension| extension.value.digital_signature());
    if !has_exact_san || !has_digital_signature {
        return Err(Error::UntrustedOneCrlPublisher);
    }
    for intermediate in &certificates[1..certificates.len() - 1] {
        let (_, parsed) = x509_parser::parse_x509_certificate(intermediate.as_ref())
            .map_err(|_| Error::UntrustedOneCrlPublisher)?;
        require_ca_key_usage(&parsed)?;
    }
    Ok(())
}

/// Require a CA certificate and a compatible keyCertSign extension when present.
///
/// # Errors
///
/// Returns a publisher error for a non-CA or a CA whose key usage prohibits
/// certificate signing.
fn require_ca_key_usage(certificate: &x509_parser::certificate::X509Certificate<'_>) -> Result<()> {
    let key_usage = certificate
        .key_usage()
        .map_err(|_| Error::UntrustedOneCrlPublisher)?;
    if !certificate.is_ca() || key_usage.is_some_and(|extension| !extension.value.key_cert_sign()) {
        return Err(Error::UntrustedOneCrlPublisher);
    }
    Ok(())
}

/// Construct Mozilla's canonical, context-prefixed signed message.
///
/// # Errors
///
/// Returns a signature error for non-object records, missing string record IDs,
/// or values that the canonical JSON serializer cannot represent.
fn signed_message(timestamp: u64, mut changes: Vec<Value>) -> Result<Vec<u8>> {
    for record in &mut changes {
        let object = record
            .as_object_mut()
            .ok_or(Error::InvalidOneCrlSignature)?;
        if !object.get("id").is_some_and(Value::is_string) {
            return Err(Error::InvalidOneCrlSignature);
        }
        object.remove("deleted");
        if object.get("attachment").is_some_and(Value::is_null) {
            object.remove("attachment");
        }
    }
    changes.sort_by(|left, right| {
        left["id"]
            .as_str()
            .expect("record IDs were validated")
            .cmp(right["id"].as_str().expect("record IDs were validated"))
    });
    let canonical = canonical_json::to_string(&json!({
        "data": changes,
        "last_modified": timestamp.to_string(),
    }))
    .map_err(|_| Error::InvalidOneCrlSignature)?;
    let mut message = b"Content-Signature:\0".to_vec();
    message.extend_from_slice(canonical.as_bytes());
    Ok(message)
}

#[cfg(test)]
#[path = "../tests/unit/onecrl_support.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "../tests/unit/onecrl_signature.rs"]
mod tests;
