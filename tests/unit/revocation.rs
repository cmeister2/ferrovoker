//! Generated-certificate tests for feed identifiers and malformed input.

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, PublicKeyData};
use serde_json::json;

use super::*;

/// DER test certificates ordered leaf first and root last.
struct Chain {
    /// Leaf with serial 128, requiring an ASN.1 sign-padding byte.
    leaf: Vec<u8>,
    /// Complete leaf SPKI emitted directly by the certificate generator.
    leaf_spki: Vec<u8>,
    /// Self-signed issuer with a different subject and public key.
    root: Vec<u8>,
}

impl Chain {
    /// Issue a fresh leaf certificate from a generated test CA.
    ///
    /// # Panics
    ///
    /// Panics if the test's fixed certificate parameters cannot be generated.
    fn generate() -> Self {
        let mut root = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
        root.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root.distinguished_name
            .push(DnType::CommonName, "Test root");
        root.serial_number = Some(7_u64.into());
        let root_key = KeyPair::generate().expect("CA key");
        let root_der = root.self_signed(&root_key).expect("CA certificate");
        let issuer = Issuer::new(root, root_key);
        let mut leaf =
            CertificateParams::new(vec!["example.test".into()]).expect("leaf parameters");
        leaf.distinguished_name
            .push(DnType::CommonName, "Test leaf");
        leaf.serial_number = Some(128_u64.into());
        let leaf_key = KeyPair::generate().expect("leaf key");
        let leaf_der = leaf
            .signed_by(&leaf_key, &issuer)
            .expect("leaf certificate");
        Self {
            leaf: leaf_der.der().to_vec(),
            leaf_spki: leaf_key.subject_public_key_info(),
            root: root_der.der().to_vec(),
        }
    }

    /// Borrow the generated certificates as the library's chain argument.
    fn as_slices(&self) -> [&[u8]; 2] {
        [&self.leaf, &self.root]
    }
}

/// Encodes PEM and bare base64 with all six forms of ASCII whitespace.
fn text_encodings(der: &[u8]) -> [Vec<u8>; 2] {
    let encoded = STANDARD.encode(der);
    let base64: Vec<u8> = encoded
        .as_bytes()
        .chunks(61)
        .flat_map(|chunk| chunk.iter().chain(b" \t\n\r\x0b\x0c").copied())
        .collect();
    let mut pem = b"\r\n\t\x0b-----BEGIN CERTIFICATE-----\r\n".to_vec();
    pem.extend_from_slice(&base64);
    pem.extend_from_slice(b"-----END CERTIFICATE-----\r\n\x0c");
    [pem, base64]
}

/// Parse a generated certificate for constructing an independent feed fixture.
///
/// # Panics
///
/// Panics if the generated certificate is not parseable.
fn certificate(der: &[u8]) -> X509Certificate<'_> {
    parse_x509_certificate(der)
        .expect("generated certificate")
        .1
}

/// Create a complete collection around a fixture's revocation records.
///
/// # Panics
///
/// Panics if fixture JSON does not describe a supported OneCRL collection.
fn onecrl(records: Vec<Value>) -> OneCrl {
    OneCrl::from_slice(
        json!({"timestamp": 1, "metadata": {}, "changes": records})
            .to_string()
            .as_bytes(),
    )
    .expect("OneCRL fixture")
}

/// Build Mozilla's issuer/serial record using the certificate's raw bytes.
fn issuer_record(cert: &X509Certificate<'_>) -> Value {
    json!({
        "id": "issuer-serial", "last_modified": 1, "enabled": true,
        "issuerName": STANDARD.encode(cert.issuer().as_raw()),
        "serialNumber": STANDARD.encode(cert.raw_serial())
    })
}

/// Build Mozilla's subject/public-key record using complete SPKI DER.
fn subject_record(cert: &X509Certificate<'_>) -> Value {
    json!({
        "id": "subject-key", "last_modified": 1, "enabled": true,
        "subject": STANDARD.encode(cert.subject().as_raw()),
        "pubKeyHash": STANDARD.encode(sha256(cert.public_key().raw))
    })
}

/// Create a complete binary CRLSet from additional header fields and a body.
///
/// # Panics
///
/// Panics if the fixture header does not fit its two-byte length prefix or is
/// not an object, or the fixture cannot be framed as a supported CRLSet.
fn crlset(extra: Value, body: &[u8]) -> CrlSet {
    let mut header = json!({"ContentType": "CRLSet", "Version": 0, "Sequence": 1});
    header
        .as_object_mut()
        .expect("header object")
        .extend(extra.as_object().expect("extra object").clone());
    let header = header.to_string();
    let mut bytes = u16::try_from(header.len())
        .expect("short header")
        .to_le_bytes()
        .to_vec();
    bytes.extend_from_slice(header.as_bytes());
    bytes.extend_from_slice(body);
    CrlSet::from_bytes(bytes).expect("CRLSet fixture")
}

/// Encode one issuer group with the specified unsigned serial-number bytes.
///
/// # Panics
///
/// Panics if a fixture has more serials or longer serials than its framing permits.
fn serial_group(issuer_spki_hash: [u8; 32], serials: &[&[u8]]) -> Vec<u8> {
    let mut bytes = issuer_spki_hash.to_vec();
    bytes.extend_from_slice(
        &u32::try_from(serials.len())
            .expect("serial count")
            .to_le_bytes(),
    );
    for serial in serials {
        bytes.push(u8::try_from(serial.len()).expect("serial length"));
        bytes.extend_from_slice(serial);
    }
    bytes
}

/// The combined index can be shared by concurrent TLS clients.
#[test]
fn index_is_send_and_sync() {
    /// Require the thread-sharing bounds at compile time.
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<RevocationSet>();
}

/// A caller must choose at least one feed, even if that feed is empty.
#[test]
fn requires_one_feed() {
    assert!(matches!(
        RevocationSet::from_snapshots(None, None),
        Err(Error::InvalidFormat(_))
    ));
    let snapshot = onecrl(vec![]);
    let set = RevocationSet::from_snapshots(Some(&snapshot), None).expect("empty snapshot");
    assert_eq!(
        set.check_chain(&Chain::generate().as_slices(), 1)
            .expect("chain"),
        RevocationStatus::NotListed
    );
}

/// Mozilla serial identifiers preserve ASN.1 sign padding exactly.
#[test]
fn onecrl_issuer_serial_preserves_padding() {
    let chain = Chain::generate();
    let leaf = certificate(&chain.leaf);
    assert_eq!(leaf.raw_serial(), &[0, 128]);
    let mut record = issuer_record(&leaf);
    let snapshot = onecrl(vec![record.clone()]);
    let set = RevocationSet::from_snapshots(Some(&snapshot), None).expect("index");
    assert_eq!(
        set.check_chain(&chain.as_slices(), 1).expect("chain"),
        RevocationStatus::Revoked(RevocationMatch {
            certificate_index: 0,
            reason: RevocationReason::OneCrlIssuerSerial,
        })
    );
    record["serialNumber"] = json!(STANDARD.encode([128]));
    let snapshot = onecrl(vec![record]);
    let set = RevocationSet::from_snapshots(Some(&snapshot), None).expect("index");
    assert_eq!(
        set.check_chain(&chain.as_slices(), 1).expect("chain"),
        RevocationStatus::NotListed
    );
}

/// Mozilla public-key hashes include the complete SPKI wrapper and metadata.
#[test]
fn onecrl_subject_key_hashes_complete_spki_der() {
    let chain = Chain::generate();
    let leaf = certificate(&chain.leaf);
    let mut record = subject_record(&leaf);
    assert_eq!(leaf.public_key().raw, chain.leaf_spki);
    record["pubKeyHash"] = json!(STANDARD.encode(sha256(&chain.leaf_spki)));
    let snapshot = onecrl(vec![record.clone()]);
    let set = RevocationSet::from_snapshots(Some(&snapshot), None).expect("index");
    assert_eq!(
        set.check_chain(&[chain.leaf.as_slice()], 1).expect("chain"),
        RevocationStatus::Revoked(RevocationMatch {
            certificate_index: 0,
            reason: RevocationReason::OneCrlSubjectPublicKey,
        })
    );
    record["pubKeyHash"] =
        json!(STANDARD.encode(sha256(leaf.public_key().subject_public_key.data.as_ref())));
    let snapshot = onecrl(vec![record]);
    let set = RevocationSet::from_snapshots(Some(&snapshot), None).expect("index");
    assert_eq!(
        set.check_chain(&chain.as_slices(), 1).expect("chain"),
        RevocationStatus::NotListed
    );
}

/// Disabled Mozilla entries are ignored, including their opaque base64 values.
#[test]
fn ignores_disabled_onecrl_entries() {
    let chain = Chain::generate();
    let mut record = issuer_record(&certificate(&chain.leaf));
    record["enabled"] = json!(false);
    record["issuerName"] = json!("invalid base64!");
    let snapshot = onecrl(vec![record]);
    let set = RevocationSet::from_snapshots(Some(&snapshot), None).expect("disabled record");
    assert_eq!(
        set.check_chain(&chain.as_slices(), 1).expect("chain"),
        RevocationStatus::NotListed
    );
}

/// Enabled identifiers cannot silently fail to match because their encoding is corrupt.
#[test]
fn rejects_malformed_onecrl_identifiers() {
    let chain = Chain::generate();
    let leaf = certificate(&chain.leaf);
    for (mut record, field, value) in [
        (issuer_record(&leaf), "issuerName", "bad!"),
        (issuer_record(&leaf), "serialNumber", ""),
        (subject_record(&leaf), "subject", "bad!"),
        (subject_record(&leaf), "pubKeyHash", "AQ=="),
    ] {
        record[field] = json!(value);
        let snapshot = onecrl(vec![record]);
        assert!(matches!(
            RevocationSet::from_snapshots(Some(&snapshot), None),
            Err(Error::InvalidFormat(_))
        ));
    }
}

/// Blocked SPKIs and blocked interception keys both reject any chain certificate.
#[test]
fn blocks_spki_hashes_including_interception() {
    let chain = Chain::generate();
    let root_hash = STANDARD.encode(sha256(certificate(&chain.root).public_key().raw));
    for field in ["BlockedSPKIs", "BlockedInterceptionSPKIs"] {
        let snapshot = crlset(json!({field: [root_hash]}), &[]);
        let set = RevocationSet::from_snapshots(None, Some(&snapshot)).expect("index");
        assert_eq!(
            set.check_chain(&chain.as_slices(), 1).expect("chain"),
            RevocationStatus::Revoked(RevocationMatch {
                certificate_index: 1,
                reason: RevocationReason::CrlSetBlockedSpki,
            })
        );
    }
}

/// A known interception key is informational unless explicitly blocked.
#[test]
fn known_interception_alone_does_not_revoke() {
    let chain = Chain::generate();
    let hash = STANDARD.encode(sha256(certificate(&chain.leaf).public_key().raw));
    let snapshot = crlset(json!({"KnownInterceptionSPKIs": [hash]}), &[]);
    let set = RevocationSet::from_snapshots(None, Some(&snapshot)).expect("index");
    assert_eq!(
        set.check_chain(&chain.as_slices(), 1).expect("chain"),
        RevocationStatus::NotListed
    );
}

/// Subject restrictions permit only listed SPKIs and can block all keys for a name.
#[test]
fn limited_subjects_hash_complete_subject_and_spki_der() {
    let chain = Chain::generate();
    let leaf = certificate(&chain.leaf);
    let subject = STANDARD.encode(sha256(leaf.subject().as_raw()));
    let spki = STANDARD.encode(sha256(leaf.public_key().raw));
    for (allowed, expected) in [
        (json!([spki]), RevocationStatus::NotListed),
        (
            json!([STANDARD.encode([0; 32])]),
            RevocationStatus::Revoked(RevocationMatch {
                certificate_index: 0,
                reason: RevocationReason::CrlSetLimitedSubject,
            }),
        ),
        (
            json!([]),
            RevocationStatus::Revoked(RevocationMatch {
                certificate_index: 0,
                reason: RevocationReason::CrlSetLimitedSubject,
            }),
        ),
    ] {
        let snapshot = crlset(json!({"LimitedSubjects": {subject.clone(): allowed}}), &[]);
        let set = RevocationSet::from_snapshots(None, Some(&snapshot)).expect("index");
        assert_eq!(
            set.check_chain(&chain.as_slices(), 1).expect("chain"),
            expected
        );
    }
}

/// Chrome serial entries remove positive sign padding and use an issuer candidate SPKI.
#[test]
fn chrome_serial_uses_supplied_issuer_and_unsigned_bytes() {
    let chain = Chain::generate();
    let root = certificate(&chain.root);
    let body = serial_group(sha256(root.public_key().raw), &[&[128]]);
    let snapshot = crlset(json!({"NumParents": 1, "DeltaFrom": 0}), &body);
    let set = RevocationSet::from_snapshots(None, Some(&snapshot)).expect("index");
    assert_eq!(
        set.check_chain(&chain.as_slices(), 1).expect("chain"),
        RevocationStatus::Revoked(RevocationMatch {
            certificate_index: 0,
            reason: RevocationReason::CrlSetSerial,
        })
    );
    assert_eq!(
        set.check_chain(&[chain.leaf.as_slice()], 1)
            .expect("leaf only"),
        RevocationStatus::NotListed
    );
    let unrelated = Chain::generate();
    assert!(matches!(
        set.check_chain(
            &[
                chain.leaf.as_slice(),
                unrelated.leaf.as_slice(),
                chain.root.as_slice()
            ],
            1
        )
        .expect("interposed issuer candidate"),
        RevocationStatus::Revoked(RevocationMatch {
            certificate_index: 0,
            reason: RevocationReason::CrlSetSerial
        })
    ));
    assert!(matches!(
        set.check_chain(&[chain.root.as_slice(), chain.leaf.as_slice()], 1)
            .expect("unordered certificates"),
        RevocationStatus::Revoked(RevocationMatch {
            certificate_index: 1,
            reason: RevocationReason::CrlSetSerial
        })
    ));
    let wrong_body = serial_group(sha256(certificate(&chain.leaf).public_key().raw), &[&[128]]);
    let snapshot = crlset(json!({}), &wrong_body);
    let set = RevocationSet::from_snapshots(None, Some(&snapshot)).expect("index");
    assert_eq!(
        set.check_chain(&chain.as_slices(), 1).expect("chain"),
        RevocationStatus::NotListed
    );
}

/// A repeated issuer group conservatively retains serials from every occurrence.
#[test]
fn merges_duplicate_issuer_groups() {
    let chain = Chain::generate();
    let root_hash = sha256(certificate(&chain.root).public_key().raw);
    let mut body = serial_group(root_hash, &[&[128]]);
    body.extend_from_slice(&serial_group(root_hash, &[&[129]]));
    let snapshot = crlset(json!({"NumParents": 2}), &body);
    let set = RevocationSet::from_snapshots(None, Some(&snapshot)).expect("index");
    assert!(matches!(
        set.check_chain(&chain.as_slices(), 1).expect("chain"),
        RevocationStatus::Revoked(RevocationMatch {
            reason: RevocationReason::CrlSetSerial,
            ..
        })
    ));
}

/// Supplemental issuers fill serial lookups without checking unrelated trust anchors.
#[test]
fn supplemental_issuer_matches_omitted_issuer_without_global_root_blocks() {
    let chain = Chain::generate();
    let root = certificate(&chain.root);
    let root_hash = sha256(root.public_key().raw);
    let body = serial_group(root_hash, &[&[128]]);
    let snapshot = crlset(json!({"BlockedSPKIs": [STANDARD.encode(root_hash)]}), &body);
    let set = RevocationSet::from_snapshots(None, Some(&snapshot)).expect("index");
    let leaf_only = [chain.leaf.as_slice()];
    assert_eq!(
        set.check_chain(&leaf_only, 1).expect("leaf only"),
        RevocationStatus::NotListed
    );
    let identity = IssuerIdentity {
        subject_der: root.subject().as_raw().to_vec(),
        spki_sha256: root_hash,
    };
    assert_eq!(
        set.check_chain_with_issuers(&leaf_only, std::slice::from_ref(&identity), 1)
            .expect("supplemental issuer"),
        RevocationStatus::Revoked(RevocationMatch {
            certificate_index: 0,
            reason: RevocationReason::CrlSetSerial
        })
    );
    let results = set
        .check_chain_all_with_issuers(&leaf_only, &[identity.clone(), identity], 1)
        .expect("aggregate supplemental issuer");
    assert_eq!(
        results,
        vec![CertificateRevocations {
            certificate_index: 0,
            reasons: vec![RevocationReason::CrlSetSerial]
        }]
    );
    let unrelated = Chain::generate();
    let other_root = certificate(&unrelated.root);
    for identity in [
        IssuerIdentity {
            subject_der: root.subject().as_raw().to_vec(),
            spki_sha256: sha256(other_root.public_key().raw),
        },
        IssuerIdentity {
            subject_der: certificate(&chain.leaf).subject().as_raw().to_vec(),
            spki_sha256: root_hash,
        },
    ] {
        assert_eq!(
            set.check_chain_with_issuers(&leaf_only, &[identity], 1)
                .expect("unrelated issuer"),
            RevocationStatus::NotListed
        );
    }
}

/// Matching both feeds produces one certificate result with distinct reasons only.
#[test]
fn deduplicates_rules_certificates_and_cross_feed_results() {
    let chain = Chain::generate();
    let leaf = certificate(&chain.leaf);
    let issuer = issuer_record(&leaf);
    let subject = subject_record(&leaf);
    let onecrl = onecrl(vec![issuer.clone(), issuer, subject.clone(), subject]);
    let leaf_hash = STANDARD.encode(sha256(leaf.public_key().raw));
    let root_hash = sha256(certificate(&chain.root).public_key().raw);
    let body = serial_group(root_hash, &[&[128], &[128]]);
    let crlset = crlset(
        json!({"BlockedSPKIs": [leaf_hash.clone(), leaf_hash]}),
        &body,
    );
    let set = RevocationSet::from_snapshots(Some(&onecrl), Some(&crlset)).expect("both feeds");
    let results = set
        .check_chain_all(
            &[
                chain.leaf.as_slice(),
                chain.root.as_slice(),
                chain.leaf.as_slice(),
            ],
            1,
        )
        .expect("chain");
    assert_eq!(
        results,
        vec![CertificateRevocations {
            certificate_index: 0,
            reasons: vec![
                RevocationReason::OneCrlIssuerSerial,
                RevocationReason::OneCrlSubjectPublicKey,
                RevocationReason::CrlSetBlockedSpki,
                RevocationReason::CrlSetSerial,
            ],
        }]
    );
    assert_eq!(
        set.onecrl_issuer_serials
            .values()
            .next()
            .expect("issuer index")
            .len(),
        1
    );
    assert_eq!(
        set.onecrl_subject_keys
            .values()
            .next()
            .expect("subject index")
            .len(),
        1
    );
    let chrome = set.crlset.as_ref().expect("Chrome index");
    assert_eq!(chrome.blocked_spkis.len(), 1);
    assert_eq!(chrome.issuer_serials[&root_hash].len(), 1);
}

/// Encodings preserve feed matches, first occurrence indexes, and deduplication.
#[test]
fn mixed_certificate_encodings_preserve_matches_indexes_and_deduplication() {
    let chain = Chain::generate();
    let leaf = certificate(&chain.leaf);
    let onecrl = onecrl(vec![issuer_record(&leaf), subject_record(&leaf)]);
    let root_hash = sha256(certificate(&chain.root).public_key().raw);
    let crlset = crlset(
        json!({"BlockedSPKIs": [STANDARD.encode(sha256(leaf.public_key().raw))]}),
        &serial_group(root_hash, &[&[128]]),
    );
    let set = RevocationSet::from_snapshots(Some(&onecrl), Some(&crlset)).expect("both feeds");
    let expected = set.check_chain_all(&chain.as_slices(), 1).unwrap();
    assert_eq!(expected.len(), 1);
    assert_eq!(
        expected[0].reasons,
        vec![
            RevocationReason::OneCrlIssuerSerial,
            RevocationReason::OneCrlSubjectPublicKey,
            RevocationReason::CrlSetBlockedSpki,
            RevocationReason::CrlSetSerial,
        ]
    );
    let [leaf_pem, leaf_base64] = text_encodings(&chain.leaf);
    let [root_pem, root_base64] = text_encodings(&chain.root);
    for leaf in [&chain.leaf, &leaf_pem, &leaf_base64] {
        for root in [&chain.root, &root_pem, &root_base64] {
            let entries = [leaf.as_slice(), root.as_slice()];
            assert_eq!(set.check_chain_all(&entries, 1).unwrap(), expected);
            assert_eq!(
                set.check_chain(&entries, 1).unwrap(),
                RevocationStatus::Revoked(RevocationMatch {
                    certificate_index: 0,
                    reason: RevocationReason::OneCrlIssuerSerial,
                })
            );
        }
    }
    let entries = [
        root_base64.as_slice(),
        leaf_pem.as_slice(),
        leaf_base64.as_slice(),
        chain.leaf.as_slice(),
        root_pem.as_slice(),
    ];
    let mut expected = expected;
    expected[0].certificate_index = 1;
    assert_eq!(set.check_chain_all(&entries, 1).unwrap(), expected);
    assert_eq!(
        set.check_chain_all_with_issuers(&entries, &[], 1).unwrap(),
        expected
    );
    assert_eq!(
        set.check_chain_with_issuers(&entries, &[], 1).unwrap(),
        RevocationStatus::Revoked(RevocationMatch {
            certificate_index: 1,
            reason: RevocationReason::OneCrlIssuerSerial,
        })
    );
}

/// Issuer serial lookups use decoded issuer certificates and supplemental IDs.
#[test]
fn encoded_issuer_candidates_and_supplemental_issuers_resolve_serial_entries() {
    let chain = Chain::generate();
    let root = certificate(&chain.root);
    let root_hash = sha256(root.public_key().raw);
    let crlset = crlset(json!({}), &serial_group(root_hash, &[&[128]]));
    let set = RevocationSet::from_snapshots(None, Some(&crlset)).expect("Chrome feed");
    let expected = RevocationStatus::Revoked(RevocationMatch {
        certificate_index: 1,
        reason: RevocationReason::CrlSetSerial,
    });
    let identity = IssuerIdentity {
        subject_der: root.subject().as_raw().to_vec(),
        spki_sha256: root_hash,
    };
    let unrelated = Chain::generate();
    let [leaf_pem, leaf_base64] = text_encodings(&chain.leaf);
    for encoded_root in text_encodings(&chain.root) {
        assert_eq!(
            set.check_chain(
                &[
                    unrelated.root.as_slice(),
                    &leaf_pem,
                    &encoded_root,
                    &leaf_base64
                ],
                1,
            )
            .unwrap(),
            expected
        );
    }
    for encoded_leaf in [leaf_pem, leaf_base64] {
        assert_eq!(
            set.check_chain(&[&encoded_leaf], 1).unwrap(),
            RevocationStatus::NotListed
        );
        assert_eq!(
            set.check_chain_with_issuers(
                &[unrelated.root.as_slice(), &encoded_leaf],
                std::slice::from_ref(&identity),
                1,
            )
            .unwrap(),
            expected
        );
    }
}

/// DER stays borrowed, while text normalization leaves caller buffers intact.
#[test]
fn normalization_borrows_der_and_preserves_text_input() {
    let chain = Chain::generate();
    let normalized = normalize_certificate(&chain.leaf).unwrap();
    assert!(matches!(normalized, Cow::Borrowed(_)));
    assert_eq!(normalized.as_ptr(), chain.leaf.as_ptr());
    for text in text_encodings(&chain.leaf) {
        let original = text.clone();
        let normalized = normalize_certificate(&text).unwrap();
        assert_eq!(normalized.as_ref(), chain.leaf);
        assert_eq!(text, original);
    }
}

/// One chain entry cannot hide bundles, malformed boundaries, or extra data.
#[test]
fn rejects_ambiguous_and_malformed_certificate_encodings() {
    let chain = Chain::generate();
    let snapshot = onecrl(vec![issuer_record(&certificate(&chain.leaf))]);
    let set = RevocationSet::from_snapshots(Some(&snapshot), None).expect("Mozilla feed");
    let base64 = STANDARD.encode(&chain.leaf);
    let pem = format!("-----BEGIN CERTIFICATE-----\n{base64}\n-----END CERTIFICATE-----");
    let mut concatenated_der = chain.leaf.clone();
    concatenated_der.extend_from_slice(&chain.root);
    let mut trailing_der = chain.leaf.clone();
    trailing_der.push(0);
    let mut unicode_whitespace = base64.clone();
    unicode_whitespace.insert(4, '\u{00a0}');
    let invalid = vec![
        Vec::new(),
        b" \t\n\r\x0b\x0c".to_vec(),
        vec![0x30, 0],
        vec![0xff],
        concatenated_der.clone(),
        trailing_der.clone(),
        STANDARD.encode(concatenated_der).into_bytes(),
        STANDARD.encode(trailing_der).into_bytes(),
        STANDARD.encode(b"not a DER certificate").into_bytes(),
        b"%%%not base64%%%".to_vec(),
        unicode_whitespace.into_bytes(),
        b"-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----".to_vec(),
        b"-----BEGIN CERTIFICATE-----\n%%%%\n-----END CERTIFICATE-----".to_vec(),
        pem.replace("CERTIFICATE", "PRIVATE KEY").into_bytes(),
        pem.replacen("END CERTIFICATE", "END PUBLIC KEY", 1)
            .into_bytes(),
        format!("-----BEGIN CERTIFICATE-----\n{base64}").into_bytes(),
        format!("{base64}\n-----END CERTIFICATE-----").into_bytes(),
        format!("junk{pem}").into_bytes(),
        format!("{pem}junk").into_bytes(),
        format!("{pem}\n{pem}").into_bytes(),
        format!("-----BEGIN CERTIFICATE-----\n{pem}\n-----END CERTIFICATE-----").into_bytes(),
        format!(
            "-----BEGIN CERTIFICATE-----\n{base64}\n{}\n-----END CERTIFICATE-----",
            STANDARD.encode(&chain.root)
        )
        .into_bytes(),
    ];
    for bytes in invalid {
        for entries in [
            vec![bytes.as_slice()],
            vec![chain.leaf.as_slice(), bytes.as_slice()],
        ] {
            assert!(matches!(
                set.check_chain(&entries, 1),
                Err(Error::InvalidCertificate)
            ));
            assert!(matches!(
                set.check_chain_all(&entries, 1),
                Err(Error::InvalidCertificate)
            ));
        }
    }
}

/// Negative serial numbers cannot be normalized into positive CRLSet entries.
#[test]
fn chrome_serial_normalization_matches_unsigned_rules() {
    assert_eq!(chrome_serial(&[128]), None);
    assert_eq!(chrome_serial(&[255, 0]), None);
    assert_eq!(chrome_serial(&[0, 0, 128]), Some([128].as_slice()));
    assert_eq!(chrome_serial(&[0, 0]), Some([0].as_slice()));
    assert_eq!(chrome_serial(&[1]), Some([1].as_slice()));
}

/// Expiry rejects stale CRLSets while allowing their exact boundary second.
#[test]
fn enforces_crlset_expiry() {
    let chain = Chain::generate();
    let snapshot = crlset(json!({"NotAfter": 100}), &[]);
    let set = RevocationSet::from_snapshots(None, Some(&snapshot)).expect("index");
    assert_eq!(
        set.check_chain(&chain.as_slices(), 100).expect("boundary"),
        RevocationStatus::NotListed
    );
    assert!(matches!(
        set.check_chain(&chain.as_slices(), 101),
        Err(Error::ExpiredCrlSet)
    ));
    for extra in [json!({}), json!({"NotAfter": 0})] {
        let snapshot = crlset(extra, &[]);
        let set = RevocationSet::from_snapshots(None, Some(&snapshot)).expect("index");
        assert_eq!(
            set.check_chain(&chain.as_slices(), u64::MAX)
                .expect("no expiry"),
            RevocationStatus::NotListed
        );
    }
}

/// Malformed typed header fields and nonzero delta bases fail during indexing.
#[test]
fn rejects_invalid_crlset_headers() {
    for extra in [
        json!({"NotAfter": -1}),
        json!({"NotAfter": 1.5}),
        json!({"NotAfter": "123"}),
        json!({"DeltaFrom": 1}),
        json!({"DeltaFrom": null}),
        json!({"NumParents": 1}),
        json!({"NumParents": false}),
        json!({"BlockedSPKIs": "not an array"}),
        json!({"BlockedSPKIs": [17]}),
        json!({"BlockedSPKIs": ["bad!"]}),
        json!({"BlockedSPKIs": ["AQ=="]}),
        json!({"BlockedInterceptionSPKIs": ["AQ=="]}),
        json!({"KnownInterceptionSPKIs": ["AQ=="]}),
        json!({"LimitedSubjects": []}),
        json!({"LimitedSubjects": {STANDARD.encode([0; 32]): "bad"}}),
        json!({"LimitedSubjects": {"AQ==": []}}),
        json!({"LimitedSubjects": {STANDARD.encode([0; 32]): ["AQ=="]}}),
    ] {
        let snapshot = crlset(extra, &[]);
        assert!(RevocationSet::from_snapshots(None, Some(&snapshot)).is_err());
    }
}

/// Optional null lists/maps are empty without suppressing populated block entries.
#[test]
fn accepts_null_optional_crlset_collections() {
    let chain = Chain::generate();
    let empty = crlset(
        json!({
            "BlockedSPKIs": null,
            "BlockedInterceptionSPKIs": null,
            "KnownInterceptionSPKIs": null,
            "LimitedSubjects": null
        }),
        &[],
    );
    let set = RevocationSet::from_snapshots(None, Some(&empty)).expect("null collections");
    assert_eq!(
        set.check_chain(&chain.as_slices(), 1).expect("chain"),
        RevocationStatus::NotListed
    );
    let listed = crlset(
        json!({
            "BlockedSPKIs": [STANDARD.encode(sha256(&chain.leaf_spki))],
            "KnownInterceptionSPKIs": null
        }),
        &[],
    );
    let set = RevocationSet::from_snapshots(None, Some(&listed)).expect("populated blocklist");
    assert_eq!(
        set.check_chain(&chain.as_slices(), 1).expect("chain"),
        RevocationStatus::Revoked(RevocationMatch {
            certificate_index: 0,
            reason: RevocationReason::CrlSetBlockedSpki,
        })
    );
}

/// Every truncated position and oversized serial count is rejected without preallocation.
#[test]
fn rejects_truncated_crlset_bodies() {
    let body = serial_group([0; 32], &[&[128]]);
    for end in 0..body.len() {
        let snapshot = crlset(json!({"NumParents": 1}), &body[..end]);
        assert!(
            RevocationSet::from_snapshots(None, Some(&snapshot)).is_err(),
            "length {end}"
        );
    }
    let mut bomb = vec![0; 32];
    bomb.extend_from_slice(&u32::MAX.to_le_bytes());
    let snapshot = crlset(json!({}), &bomb);
    assert!(RevocationSet::from_snapshots(None, Some(&snapshot)).is_err());
}

/// Snapshot bytes are authoritative even if a caller changes the exposed header.
#[test]
fn reparses_original_crlset_header() {
    let chain = Chain::generate();
    let hash = STANDARD.encode(sha256(certificate(&chain.leaf).public_key().raw));
    let mut snapshot = crlset(json!({"BlockedSPKIs": [hash]}), &[]);
    snapshot.header.extra.clear();
    let set = RevocationSet::from_snapshots(None, Some(&snapshot)).expect("index");
    assert!(matches!(
        set.check_chain(&chain.as_slices(), 1).expect("chain"),
        RevocationStatus::Revoked(_)
    ));
    for bytes in [vec![], vec![0], vec![255, 255], vec![1, 0, b'{']] {
        snapshot.bytes = bytes;
        assert!(RevocationSet::from_snapshots(None, Some(&snapshot)).is_err());
    }
}

/// Bad input anywhere in a chain fails before a matching earlier certificate is reported.
#[test]
fn rejects_empty_malformed_and_trailing_certificates() {
    let chain = Chain::generate();
    let snapshot = onecrl(vec![issuer_record(&certificate(&chain.leaf))]);
    let set = RevocationSet::from_snapshots(Some(&snapshot), None).expect("index");
    let mut trailing = chain.leaf.clone();
    trailing.push(0);
    for certificates in [
        vec![],
        vec![&b"invalid"[..]],
        vec![trailing.as_slice()],
        vec![chain.leaf.as_slice(), &b"invalid"[..]],
    ] {
        assert!(matches!(
            set.check_chain(&certificates, 1),
            Err(Error::InvalidCertificate)
        ));
    }
}
