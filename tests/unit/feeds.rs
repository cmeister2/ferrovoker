//! Regression tests for browser revocation-feed framing and record preservation.

use super::{CrlSet, Error, OneCrl};
use serde_json::{Value, json};

/// Build a complete OneCRL snapshot around the supplied records.
fn onecrl_snapshot(records: Vec<Value>) -> Value {
    json!({
        "timestamp": 1_791_111_222_333_u64,
        "metadata": {
            "signature": {"signature": "test-signature", "x5u": "https://example.com/chain.pem"},
            "futureMetadata": {"nested": [true, 17, null]}
        },
        "changes": records
    })
}

/// Build one enabled issuer/serial record with additional publisher fields.
fn issuer_record() -> Value {
    json!({
        "id": "issuer-serial-record",
        "last_modified": 1_791_111_222_000_u64,
        "enabled": true,
        "issuerName": "MAMxAQ==",
        "serialNumber": "AQ==",
        "details": {"bug": "https://bugzilla.mozilla.org/show_bug.cgi?id=1"},
        "futureRecordField": ["retained", {"value": 42}]
    })
}

/// Build one disabled subject/key-hash record.
fn subject_record() -> Value {
    json!({
        "id": "subject-key-record",
        "last_modified": 1_791_111_221_000_u64,
        "enabled": false,
        "subject": "MAMxAQ==",
        "pubKeyHash": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "schema": 3
    })
}

/// Build a supported CRLSet header, including unknown publisher metadata.
fn crlset_header() -> Value {
    json!({
        "ContentType": "CRLSet",
        "Version": 0,
        "Sequence": 1234,
        "BlockedSPKIs": ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
        "NotAfter": 1_800_000_000,
        "FutureHeaderField": {"padding": "x".repeat(256)}
    })
}

/// Frame raw header bytes and an opaque body with CRLSet's little-endian length.
///
/// # Panics
///
/// Panics if a test supplies a header longer than the CRLSet format permits.
fn crlset_bytes(header: &[u8], body: &[u8]) -> Vec<u8> {
    let length = u16::try_from(header.len()).expect("test header fits a u16");
    let mut bytes = length.to_le_bytes().to_vec();
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(body);
    bytes
}

/// Both identifier forms, disabled records and arbitrary metadata survive a round trip.
#[test]
fn onecrl_preserves_identifiers_disabled_records_and_metadata() {
    let original = onecrl_snapshot(vec![issuer_record(), subject_record()]);
    let parsed = OneCrl::from_slice(original.to_string().as_bytes()).expect("valid snapshot");

    assert_eq!(parsed.timestamp, 1_791_111_222_333);
    assert_eq!(parsed.changes.len(), 2);
    assert!(parsed.changes[0].enabled);
    assert_eq!(parsed.changes[0].issuer_name.as_deref(), Some("MAMxAQ=="));
    assert_eq!(parsed.changes[0].serial_number.as_deref(), Some("AQ=="));
    assert!(parsed.changes[0].subject.is_none());
    assert!(parsed.changes[0].public_key_hash.is_none());
    assert!(!parsed.changes[1].enabled);
    assert!(parsed.changes[1].issuer_name.is_none());
    assert!(parsed.changes[1].serial_number.is_none());
    assert_eq!(parsed.changes[1].subject.as_deref(), Some("MAMxAQ=="));
    assert_eq!(
        parsed.changes[1].public_key_hash,
        original["changes"][1]["pubKeyHash"]
            .as_str()
            .map(str::to_owned)
    );
    assert_eq!(parsed.metadata, original["metadata"]);
    assert_eq!(
        parsed.changes[0].extra["futureRecordField"],
        original["changes"][0]["futureRecordField"]
    );
    assert_eq!(
        serde_json::to_value(parsed).expect("serializable snapshot"),
        original
    );
}

/// An empty complete collection is valid and keeps its timestamp and signature metadata.
#[test]
fn onecrl_accepts_an_empty_complete_snapshot() {
    let original = onecrl_snapshot(vec![]);
    let parsed = OneCrl::from_slice(original.to_string().as_bytes()).expect("empty snapshot");
    assert!(parsed.changes.is_empty());
    assert_eq!(parsed.metadata, original["metadata"]);
}

/// A tombstone cannot be mistaken for an active snapshot record even when identifiers remain.
#[test]
fn onecrl_rejects_tombstones() {
    let mut tombstone = issuer_record();
    tombstone["deleted"] = json!(true);
    let snapshot = onecrl_snapshot(vec![tombstone]);
    assert!(matches!(
        OneCrl::from_slice(snapshot.to_string().as_bytes()),
        Err(Error::InvalidFormat(_))
    ));

    let minimal = onecrl_snapshot(vec![
        json!({"id": "deleted", "last_modified": 7, "deleted": true}),
    ]);
    assert!(OneCrl::from_slice(minimal.to_string().as_bytes()).is_err());
}

/// Each missing identifier half and a record with no identifiers fail validation.
#[test]
fn onecrl_rejects_partial_or_missing_identifiers() {
    for (record, field) in [
        (issuer_record(), "issuerName"),
        (issuer_record(), "serialNumber"),
        (subject_record(), "subject"),
        (subject_record(), "pubKeyHash"),
    ] {
        let mut incomplete = record;
        incomplete
            .as_object_mut()
            .expect("record object")
            .remove(field);
        let snapshot = onecrl_snapshot(vec![incomplete]);
        assert!(
            matches!(
                OneCrl::from_slice(snapshot.to_string().as_bytes()),
                Err(Error::InvalidFormat(_))
            ),
            "missing {field}"
        );
    }
    let missing = onecrl_snapshot(vec![
        json!({"id": "empty", "last_modified": 7, "enabled": true}),
    ]);
    assert!(matches!(
        OneCrl::from_slice(missing.to_string().as_bytes()),
        Err(Error::InvalidFormat(_))
    ));
}

/// A valid pair accompanied by either partial or complete identifiers of the other form fails.
#[test]
fn onecrl_rejects_ambiguous_identifiers() {
    let mut both = issuer_record();
    both["subject"] = subject_record()["subject"].clone();
    both["pubKeyHash"] = subject_record()["pubKeyHash"].clone();
    let mut issuer_with_subject = issuer_record();
    issuer_with_subject["subject"] = subject_record()["subject"].clone();
    let mut subject_with_serial = subject_record();
    subject_with_serial["serialNumber"] = issuer_record()["serialNumber"].clone();
    for record in [both, issuer_with_subject, subject_with_serial] {
        let snapshot = onecrl_snapshot(vec![record]);
        assert!(matches!(
            OneCrl::from_slice(snapshot.to_string().as_bytes()),
            Err(Error::InvalidFormat(_))
        ));
    }
}

/// Required envelope and record fields cannot silently default in a complete snapshot.
#[test]
fn onecrl_rejects_missing_required_fields() {
    for field in ["timestamp", "metadata", "changes"] {
        let mut snapshot = onecrl_snapshot(vec![issuer_record()]);
        snapshot
            .as_object_mut()
            .expect("snapshot object")
            .remove(field);
        assert!(
            matches!(
                OneCrl::from_slice(snapshot.to_string().as_bytes()),
                Err(Error::Json(_))
            ),
            "missing envelope {field}"
        );
    }
    for field in ["id", "last_modified", "enabled"] {
        let mut record = issuer_record();
        record.as_object_mut().expect("record object").remove(field);
        let snapshot = onecrl_snapshot(vec![record]);
        assert!(
            matches!(
                OneCrl::from_slice(snapshot.to_string().as_bytes()),
                Err(Error::Json(_))
            ),
            "missing record {field}"
        );
    }
}

/// Invalid JSON and incompatible required-field types fail before records are accepted.
#[test]
fn onecrl_rejects_invalid_json_and_field_types() {
    assert!(matches!(OneCrl::from_slice(b"{"), Err(Error::Json(_))));
    for (field, value) in [
        ("enabled", json!("true")),
        ("issuerName", json!(17)),
        ("last_modified", json!(-1)),
    ] {
        let mut record = issuer_record();
        record[field] = value;
        let snapshot = onecrl_snapshot(vec![record]);
        assert!(matches!(
            OneCrl::from_slice(snapshot.to_string().as_bytes()),
            Err(Error::Json(_))
        ));
    }
}

/// Little-endian framing accepts long headers and retains every original body byte.
#[test]
fn crlset_preserves_header_metadata_and_opaque_body() {
    let header = crlset_header();
    let body = [0, 255, 1, 127, 0, 128];
    let bytes = crlset_bytes(header.to_string().as_bytes(), &body);
    let parsed = CrlSet::from_bytes(bytes.clone()).expect("valid CRLSet framing");
    assert_eq!(parsed.bytes, bytes);
    assert_eq!(parsed.header.sequence, 1234);
    assert_eq!(
        serde_json::to_value(parsed.header).expect("serializable header"),
        header
    );
}

/// Missing length bytes and a declared header longer than the available bytes fail safely.
#[test]
fn crlset_rejects_truncated_length_prefix_and_header() {
    for bytes in [vec![], vec![1], vec![5, 0, b'{', b'}']] {
        assert!(matches!(
            CrlSet::from_bytes(bytes),
            Err(Error::InvalidFormat(_))
        ));
    }
}

/// Framing cannot hide invalid JSON or omit required CRLSet header fields.
#[test]
fn crlset_rejects_invalid_json_and_missing_header_fields() {
    for header in [b"{".as_slice(), b"".as_slice(), b"null".as_slice()] {
        assert!(matches!(
            CrlSet::from_bytes(crlset_bytes(header, &[])),
            Err(Error::Json(_))
        ));
    }
    for field in ["ContentType", "Version", "Sequence"] {
        let mut header = crlset_header();
        header.as_object_mut().expect("header object").remove(field);
        assert!(
            matches!(
                CrlSet::from_bytes(crlset_bytes(header.to_string().as_bytes(), &[])),
                Err(Error::Json(_))
            ),
            "missing {field}"
        );
    }
}

/// Unknown content types and binary format versions are rejected explicitly.
#[test]
fn crlset_rejects_unsupported_content_type_and_version() {
    for (field, value) in [("ContentType", json!("OtherFeed")), ("Version", json!(1))] {
        let mut header = crlset_header();
        header[field] = value;
        assert!(matches!(
            CrlSet::from_bytes(crlset_bytes(header.to_string().as_bytes(), &[])),
            Err(Error::InvalidFormat(_))
        ));
    }
}
