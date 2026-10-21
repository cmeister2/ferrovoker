//! Regression coverage for a real CRLSet-blocked eMudhra intermediate.

use std::sync::Arc;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use ferrovoker::{CrlSet, RevocationMatch, RevocationReason, RevocationSet, RevocationStatus};
use serde_json::json;
use sha2::{Digest as _, Sha256};
use x509_parser::parse_x509_certificate;

/// Leaf issued with the compromised intermediate key before that key was discarded.
const LEAF_PEM: &[u8] = include_bytes!("fixtures/emudra/leaf.pem");

/// Public eMudhra intermediate certificate whose P-384 private scalar is four.
const INTERMEDIATE_PEM: &[u8] = include_bytes!("fixtures/emudra/intermediate.pem");

/// Chrome's block for the intermediate's complete DER SubjectPublicKeyInfo.
const BLOCKED_SPKI: &str = "Y+zv7kMdSVI7wRNsTnLQIGpHcIbK9gbNXPAlaGwQnPg=";

/// A time when both fixture certificates are valid: 2027-01-01 00:00:00 UTC.
const VERIFICATION_TIME: u64 = 1_798_761_600;

/// Decode the single certificate in a fixture PEM document.
fn pem_der(pem: &[u8]) -> Vec<u8> {
    let pem = std::str::from_utf8(pem).expect("ASCII PEM fixture");
    let encoded = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<String>();
    STANDARD
        .decode(encoded)
        .expect("base64 certificate fixture")
}

/// Build the minimal CRLSet header containing Chrome's real eMudhra SPKI block.
fn blocked_revocations() -> Arc<RevocationSet> {
    let header = serde_json::to_vec(&json!({
        "ContentType": "CRLSet",
        "Version": 0,
        "Sequence": 1,
        "BlockedSPKIs": [BLOCKED_SPKI],
    }))
    .expect("CRLSet header JSON");
    let mut bytes = u16::try_from(header.len())
        .expect("short CRLSet fixture header")
        .to_le_bytes()
        .to_vec();
    bytes.extend(header);
    let snapshot = CrlSet::from_bytes(bytes).expect("CRLSet fixture");
    Arc::new(
        RevocationSet::from_snapshots(None, Some(&snapshot)).expect("revocation index fixture"),
    )
}

/// A leaf issued by the compromised CA is rejected when its intermediate is supplied.
#[test]
fn rejects_chain_through_compromised_intermediate() {
    let leaf_der = pem_der(LEAF_PEM);
    let intermediate_der = pem_der(INTERMEDIATE_PEM);
    let (_, leaf) = parse_x509_certificate(&leaf_der).expect("leaf certificate fixture");
    let (_, intermediate) =
        parse_x509_certificate(&intermediate_der).expect("intermediate certificate fixture");

    assert_eq!(leaf.issuer().as_raw(), intermediate.subject().as_raw());
    leaf.verify_signature(Some(intermediate.public_key()))
        .expect("leaf signature from compromised intermediate");
    assert_eq!(
        STANDARD.encode(Sha256::digest(intermediate.public_key().raw)),
        BLOCKED_SPKI
    );

    let revocations = blocked_revocations();
    assert_eq!(
        revocations
            .check_chain(&[LEAF_PEM, INTERMEDIATE_PEM], VERIFICATION_TIME)
            .expect("valid certificate fixtures"),
        RevocationStatus::Revoked(RevocationMatch {
            certificate_index: 1,
            reason: RevocationReason::CrlSetBlockedSpki,
        })
    );
    assert_eq!(
        revocations
            .check_chain(&[LEAF_PEM], VERIFICATION_TIME)
            .expect("valid leaf fixture"),
        RevocationStatus::NotListed
    );
}

/// The current authenticated production CRLSet retains the real eMudhra block.
#[cfg(feature = "download")]
#[tokio::test]
#[ignore = "contacts Google's production component-update service"]
async fn production_crlset_rejects_compromised_intermediate() {
    let snapshot = ferrovoker::AsyncDownloader::new()
        .expect("HTTP client")
        .fetch_crlset()
        .await
        .expect("authenticated production CRLSet");
    let revocations =
        RevocationSet::from_snapshots(None, Some(&snapshot)).expect("production revocation index");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time after Unix epoch")
        .as_secs();
    assert_eq!(
        revocations
            .check_chain(&[LEAF_PEM, INTERMEDIATE_PEM], now)
            .expect("fresh production CRLSet"),
        RevocationStatus::Revoked(RevocationMatch {
            certificate_index: 1,
            reason: RevocationReason::CrlSetBlockedSpki,
        })
    );
}
