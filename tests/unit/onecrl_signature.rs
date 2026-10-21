//! Mozilla OneCRL content-signature verification regressions.

use serde_json::{Value, json};

use super::test_support::{
    TEST_SIGNER_NAME, TEST_UNIX_TIME, signed_snapshot, signed_snapshot_with_name,
    signed_snapshot_with_server_eku, signed_snapshot_with_unrelated_intermediate,
};
use super::*;

/// Return out-of-order records containing fields excluded during signing.
fn records() -> Vec<Value> {
    vec![
        json!({
            "id": "z-record",
            "last_modified": 20,
            "enabled": true,
            "issuerName": "aXNzdWVy",
            "serialNumber": "AQ==",
            "deleted": false,
            "attachment": null,
            "details": {"second": 2, "first": 1},
        }),
        json!({
            "id": "a-record",
            "last_modified": 10,
            "enabled": true,
            "subject": "c3ViamVjdA==",
            "pubKeyHash": "a2V5",
        }),
    ]
}

/// Fresh P-384 material verifies when records require canonical sorting.
#[test]
fn authenticates_runtime_generated_snapshot_with_canonical_sorting() {
    let fixture = signed_snapshot(1_800_000_123, records());
    let authenticated = fixture.authenticated();
    assert_eq!(authenticated.snapshot.timestamp, 1_800_000_123);
    assert_eq!(authenticated.snapshot.changes[0].id, "z-record");
    assert_eq!(authenticated.snapshot.changes[1].id, "a-record");
}

/// Successive cache publications share one process-local root pin and chain.
#[test]
fn ordinary_fixtures_share_runtime_generated_trust() {
    let first = signed_snapshot(1_800_000_123, records());
    let second = signed_snapshot(1_800_000_124, records());
    assert_eq!(first.trust.root_sha256, second.trust.root_sha256);
    assert_eq!(first.chain, second.chain);
    let authenticated =
        AuthenticatedOneCrl::from_saved(second.response, second.chain, first.trust, TEST_UNIX_TIME)
            .expect("later fixture uses the configured trust pin");
    assert_eq!(authenticated.snapshot.timestamp, 1_800_000_124);
}

/// Content changes after signing invalidate the signature.
#[test]
fn rejects_tampered_record() {
    let fixture = signed_snapshot(1_800_000_123, records());
    let mut response: Value = serde_json::from_slice(&fixture.response).expect("fixture JSON");
    response["changes"][0]["enabled"] = json!(false);
    let result = AuthenticatedOneCrl::from_saved(
        serde_json::to_vec(&response).expect("tampered JSON serializes"),
        fixture.chain,
        fixture.trust,
        TEST_UNIX_TIME,
    );
    assert!(matches!(result, Err(Error::InvalidOneCrlSignature)));
}

/// Damaging the advertised fixed-width P-384 proof is detected.
#[test]
fn rejects_tampered_signature() {
    let fixture = signed_snapshot(1_800_000_123, records());
    let mut response: Value = serde_json::from_slice(&fixture.response).expect("fixture JSON");
    response["metadata"]["signatures"][0]["signature"] = json!("not-a-signature");
    let result = AuthenticatedOneCrl::from_saved(
        serde_json::to_vec(&response).expect("tampered JSON serializes"),
        fixture.chain,
        fixture.trust,
        TEST_UNIX_TIME,
    );
    assert!(matches!(result, Err(Error::InvalidOneCrlSignature)));
}

/// A valid chain under a different root cannot substitute for the pinned root.
#[test]
fn rejects_wrong_root_pin() {
    let fixture = signed_snapshot(1_800_000_123, records());
    let mut trust = fixture.trust;
    trust.root_sha256[0] ^= 1;
    let result =
        AuthenticatedOneCrl::from_saved(fixture.response, fixture.chain, trust, TEST_UNIX_TIME);
    assert!(matches!(result, Err(Error::UntrustedOneCrlPublisher)));
}

/// A content-signing leaf must carry the exact expected DNS SAN.
#[test]
fn rejects_wrong_leaf_identity() {
    let fixture = signed_snapshot_with_name(1_800_000_123, records(), "other-signer.test");
    assert_eq!(fixture.trust.signer_name, TEST_SIGNER_NAME);
    let result = AuthenticatedOneCrl::from_saved(
        fixture.response,
        fixture.chain,
        fixture.trust,
        TEST_UNIX_TIME,
    );
    assert!(matches!(result, Err(Error::UntrustedOneCrlPublisher)));
}

/// A TLS server certificate is not accepted for Remote Settings code signing.
#[test]
fn rejects_leaf_without_code_signing_eku() {
    let fixture = signed_snapshot_with_server_eku(1_800_000_123, records());
    let result = AuthenticatedOneCrl::from_saved(
        fixture.response,
        fixture.chain,
        fixture.trust,
        TEST_UNIX_TIME,
    );
    assert!(matches!(result, Err(Error::UntrustedOneCrlPublisher)));
}

/// Every certificate must be valid at the caller's verification time.
#[test]
fn rejects_chain_outside_certificate_validity() {
    let fixture = signed_snapshot(1_800_000_123, records());
    let result = AuthenticatedOneCrl::from_saved(fixture.response, fixture.chain, fixture.trust, 1);
    assert!(matches!(result, Err(Error::UntrustedOneCrlPublisher)));
}

/// The supplied chain must be the exact leaf-to-root path, without ignored CAs.
#[test]
fn rejects_unrelated_extra_intermediate() {
    let fixture = signed_snapshot_with_unrelated_intermediate(1_800_000_123, records());
    let result = AuthenticatedOneCrl::from_saved(
        fixture.response,
        fixture.chain,
        fixture.trust,
        TEST_UNIX_TIME,
    );
    assert!(matches!(result, Err(Error::UntrustedOneCrlPublisher)));
}

/// Verification continues past a stale rotation entry to a valid signature.
#[test]
fn accepts_later_signature_during_key_rotation() {
    let fixture = signed_snapshot(1_800_000_123, records());
    let mut response: Value = serde_json::from_slice(&fixture.response).expect("fixture JSON");
    let valid = response["metadata"]["signatures"][0].clone();
    let mut invalid = valid.clone();
    invalid["signature"] = Value::String("A".repeat(128));
    response["metadata"]["signatures"] = json!([invalid, valid]);

    let authenticated = AuthenticatedOneCrl::from_saved(
        serde_json::to_vec(&response).expect("rotation JSON serializes"),
        fixture.chain,
        fixture.trust,
        TEST_UNIX_TIME,
    )
    .expect("later rotation signature authenticates");
    assert_eq!(authenticated.snapshot.changes.len(), 2);
}

/// Legacy single-signature metadata remains verifiable during migration.
#[test]
fn accepts_legacy_single_signature_metadata() {
    let fixture = signed_snapshot(1_800_000_123, records());
    let mut response: Value = serde_json::from_slice(&fixture.response).expect("fixture JSON");
    response["metadata"]["signature"] = response["metadata"]["signatures"][0].clone();
    response["metadata"]
        .as_object_mut()
        .expect("metadata object")
        .remove("signatures");
    AuthenticatedOneCrl::from_saved(
        serde_json::to_vec(&response).expect("legacy JSON serializes"),
        fixture.chain,
        fixture.trust,
        TEST_UNIX_TIME,
    )
    .expect("legacy signature authenticates");
}

/// Signature metadata must name Mozilla's fixed P-384 content-signing mode.
#[test]
fn rejects_missing_or_unsupported_signature_mode() {
    let fixture = signed_snapshot(1_800_000_123, records());
    let original: Value = serde_json::from_slice(&fixture.response).expect("fixture JSON");

    let mut missing = original.clone();
    missing["metadata"]["signatures"][0]
        .as_object_mut()
        .expect("signature metadata is an object")
        .remove("mode");
    assert!(
        AuthenticatedOneCrl::from_saved(
            serde_json::to_vec(&missing).expect("missing-mode JSON serializes"),
            fixture.chain.clone(),
            fixture.trust,
            TEST_UNIX_TIME,
        )
        .is_err()
    );

    let mut unsupported = original;
    unsupported["metadata"]["signatures"][0]["mode"] = json!("other");
    assert!(matches!(
        AuthenticatedOneCrl::from_saved(
            serde_json::to_vec(&unsupported).expect("unsupported-mode JSON serializes"),
            fixture.chain,
            fixture.trust,
            TEST_UNIX_TIME,
        ),
        Err(Error::InvalidOneCrlSignature)
    ));
}

/// Rotation metadata is bounded before URLs or signatures are decoded.
#[test]
fn rejects_excessive_signature_metadata() {
    let fixture = signed_snapshot(1_800_000_123, records());
    let original: Value = serde_json::from_slice(&fixture.response).expect("fixture JSON");
    let valid = original["metadata"]["signatures"][0].clone();

    let mut excessive = original.clone();
    excessive["metadata"]["signatures"] = Value::Array(vec![valid.clone(); MAX_SIGNATURES + 1]);
    assert!(matches!(
        AuthenticatedOneCrl::from_saved(
            serde_json::to_vec(&excessive).expect("excessive JSON serializes"),
            fixture.chain.clone(),
            fixture.trust,
            TEST_UNIX_TIME,
        ),
        Err(Error::InvalidFormat(_))
    ));

    for (field, value) in [
        ("signature", "A".repeat(129)),
        (
            "x5u",
            format!("https://example.test/{}", "a".repeat(MAX_X5U_BYTES)),
        ),
    ] {
        let mut oversized = original.clone();
        oversized["metadata"]["signatures"][0][field] = Value::String(value);
        assert!(matches!(
            AuthenticatedOneCrl::from_saved(
                serde_json::to_vec(&oversized).expect("oversized JSON serializes"),
                fixture.chain.clone(),
                fixture.trust,
                TEST_UNIX_TIME,
            ),
            Err(Error::InvalidOneCrlSignature)
        ));
    }
}
