//! Signed fixtures exercise authentication independently of ZIP integrity.

use std::sync::OnceLock;

use ring::rand::SystemRandom;
use ring::signature::{KeyPair, RSA_PKCS1_SHA256, RsaKeyPair};

use super::test_support::*;
use super::*;

/// RSA fixture signer generated in memory once per test process using AWS-LC.
static RSA_SIGNER: OnceLock<RsaKeyPair> = OnceLock::new();

/// Generates a fresh RSA-2048 key using the operating system's secure RNG.
fn rsa_signer() -> &'static RsaKeyPair {
    RSA_SIGNER.get_or_init(|| {
        let key =
            rcgen::KeyPair::generate_rsa_for(&rcgen::PKCS_RSA_SHA256, rcgen::RsaKeySize::_2048)
                .expect("runtime RSA test key generation succeeds");
        RsaKeyPair::from_pkcs8(key.serialized_der()).expect("generated RSA test key is valid")
    })
}

/// Verifies test fixtures against their explicit trust anchor.
fn extract(bytes: &[u8], max_bytes: u64) -> Result<Vec<u8>> {
    extract_crl_set_with_key(bytes, max_bytes, &publisher_key_hash())
}

/// Decodes fixture parts for deliberate mutations without modifying ZIP data.
fn parts(bytes: &[u8]) -> (CrxFileHeader, Vec<u8>) {
    let offset = 12 + read_u32(bytes, 8).unwrap() as usize;
    (
        CrxFileHeader::decode(&bytes[12..offset]).unwrap(),
        bytes[offset..].to_vec(),
    )
}

/// Wraps a value with the minimal DER tag and definite-length encoding.
fn der(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut output = vec![tag];
    if value.len() < 128 {
        output.push(value.len() as u8);
    } else {
        let length = value.len().to_be_bytes();
        let first = length.iter().position(|value| *value != 0).unwrap();
        output.push(0x80 | (length.len() - first) as u8);
        output.extend_from_slice(&length[first..]);
    }
    output.extend_from_slice(value);
    output
}

/// A correctly signed P-256 component yields the bounded decompressed payload.
#[test]
fn extracts_authenticated_ecdsa_component() {
    assert_eq!(extract(&signed_crx(b"payload"), 7).unwrap(), b"payload");
}

/// A valid self-signed component never acquires Google's production identity.
#[test]
fn rejects_self_signed_component_with_production_pin() {
    assert!(matches!(
        extract_crl_set(&signed_crx(b"payload"), 100),
        Err(Error::UntrustedCrxPublisher)
    ));
    assert!(matches!(
        extract(&signed_crx_with_unrelated_key(b"payload"), 100),
        Err(Error::UntrustedCrxPublisher)
    ));
}

/// Matching Omaha hashes cannot bypass authentication in the public constructor.
#[test]
fn public_constructor_requires_authentication_after_omaha_integrity_passes() {
    let payload_header = br#"{"ContentType":"CRLSet","Version":0,"Sequence":1}"#;
    let mut payload = (payload_header.len() as u16).to_le_bytes().to_vec();
    payload.extend_from_slice(payload_header);
    assert!(crate::CrlSet::from_bytes(payload.clone()).is_ok());
    let archive = zip_entry("crl-set", &payload);
    let signed_data = SignedData {
        crx_id: Some(CRLSET_PUBLISHER_KEY_HASH[..16].to_vec()),
    }
    .encode_to_vec();
    let header = header_for(signer(), &archive, signed_data.clone());
    verify_proof(
        &header.sha256_with_ecdsa[0],
        ProofAlgorithm::Ecdsa,
        &signed_message(&signed_data, &archive),
    )
    .expect("forgery has a genuine signature from its unrelated signer");

    let mut damaged_signature = header.clone();
    damaged_signature.sha256_with_ecdsa[0]
        .signature
        .as_mut()
        .unwrap()[0] ^= 1;
    let mut damaged_archive = archive.clone();
    *damaged_archive.last_mut().unwrap() ^= 1;
    let mut damaged_header = header.clone();
    damaged_header
        .signed_header_data
        .as_mut()
        .unwrap()
        .extend([0x10, 0x01]);

    for (body, invalid_signature) in [
        (envelope(&header, &archive), false),
        (envelope(&damaged_signature, &archive), true),
        (envelope(&header, &damaged_archive), true),
        (envelope(&damaged_header, &archive), true),
    ] {
        let digest = Sha256::digest(&body)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let metadata = format!(
            r#"<gupdate><app appid="{}" status="ok"><updatecheck status="ok" codebase="https://example.test/component.crx3" hash_sha256="{digest}" size="{}"/></app></gupdate>"#,
            crate::CRLSET_COMPONENT_ID,
            body.len(),
        );
        let max_bytes = body.len() as u64;
        let component = crate::download::component_download(metadata.as_bytes(), max_bytes)
            .expect("forgery advertises valid production-component update metadata");
        crate::download::validate_download(&body, &component)
            .expect("attacker-supplied size and SHA-256 match the forged body");
        let result = crate::CrlSet::from_signed_crx(body, max_bytes);
        if invalid_signature {
            assert!(matches!(result, Err(Error::InvalidCrxSignature)));
        } else {
            assert!(matches!(result, Err(Error::UntrustedCrxPublisher)));
        }
    }
}

/// RSA proofs use PKCS#1 v1.5 SHA-256 with complete DER SPKI hashing.
#[test]
fn extracts_authenticated_rsa_component() {
    let key = rsa_signer();
    let identifier = vec![
        0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
    ];
    let mut public_bits = vec![0];
    public_bits.extend_from_slice(key.public_key().as_ref());
    let mut spki_body = identifier;
    spki_body.extend(der(0x03, &public_bits));
    let public_key = der(0x30, &spki_body);
    let signed_data = signed_data_for(&public_key);
    let archive = zip_entry("crl-set", b"rsa payload");
    let message = signed_message(&signed_data, &archive);
    let mut signature = vec![0; key.public().modulus_len()];
    key.sign(
        &RSA_PKCS1_SHA256,
        &SystemRandom::new(),
        &message,
        &mut signature,
    )
    .unwrap();
    let header = CrxFileHeader {
        sha256_with_rsa: vec![AsymmetricKeyProof {
            public_key: Some(public_key.clone()),
            signature: Some(signature),
        }],
        sha256_with_ecdsa: Vec::new(),
        signed_header_data: Some(signed_data),
    };
    let pin = Sha256::digest(public_key).into();
    assert_eq!(
        extract_crl_set_with_key(&envelope(&header, &archive), 100, &pin).unwrap(),
        b"rsa payload"
    );
}

/// Tampering is rejected before any archive parser receives the changed bytes.
#[test]
fn rejects_tampered_archive_signature_and_signed_header() {
    let mut bytes = signed_crx(b"payload");
    *bytes.last_mut().unwrap() ^= 1;
    assert!(matches!(
        extract(&bytes, 100),
        Err(Error::InvalidCrxSignature)
    ));
    assert!(matches!(
        extract(&tampered_signature_crx(b"payload"), 100),
        Err(Error::InvalidCrxSignature)
    ));
    let (mut header, archive) = parts(&signed_crx(b"payload"));
    header
        .signed_header_data
        .as_mut()
        .unwrap()
        .extend([0x10, 0x01]);
    assert!(matches!(
        extract(&envelope(&header, &archive), 100),
        Err(Error::InvalidCrxSignature)
    ));
}

/// A copied trusted public key cannot authenticate an attacker's signature.
#[test]
fn rejects_trusted_key_with_unrelated_signature() {
    let (mut header, archive) = parts(&signed_crx(b"payload"));
    header.sha256_with_ecdsa[0].signature = proof_for(
        &new_signer(),
        &signed_message(header.signed_header_data.as_deref().unwrap(), &archive),
    )
    .signature;
    assert!(matches!(
        extract(&envelope(&header, &archive), 100),
        Err(Error::InvalidCrxSignature)
    ));
}

/// All declared recognized proofs must verify, including non-pinned extras.
#[test]
fn rejects_invalid_additional_proof() {
    let (mut header, archive) = parts(&signed_crx(b"payload"));
    let mut extra = proof_for(
        &new_signer(),
        &signed_message(header.signed_header_data.as_deref().unwrap(), &archive),
    );
    extra.signature.as_mut().unwrap()[0] ^= 1;
    header.sha256_with_ecdsa.push(extra);
    assert!(matches!(
        extract(&envelope(&header, &archive), 100),
        Err(Error::InvalidCrxSignature)
    ));
}

/// Neither omitting the pinned proof nor switching developer IDs is accepted.
#[test]
fn rejects_missing_pinned_proof_and_different_component_identity() {
    let archive = zip_entry("crl-set", b"payload");
    let unrelated = new_signer();
    let unrelated_header = header_for(&unrelated, &archive, signed_data_for(&spki(signer())));
    assert!(matches!(
        extract(&envelope(&unrelated_header, &archive), 100),
        Err(Error::UntrustedCrxPublisher)
    ));

    let mut header = header_for(signer(), &archive, signed_data_for(&spki(&unrelated)));
    header.sha256_with_ecdsa.push(proof_for(
        &unrelated,
        &signed_message(header.signed_header_data.as_deref().unwrap(), &archive),
    ));
    assert!(matches!(
        extract(&envelope(&header, &archive), 100),
        Err(Error::UntrustedCrxPublisher)
    ));
}

/// Proof absence and invalid developer-ID lengths never authorize archives.
#[test]
fn rejects_missing_proofs_and_invalid_developer_ids() {
    let archive = zip_entry("crl-set", b"payload");
    let (mut header, _) = parts(&signed_crx(b"payload"));
    header.sha256_with_ecdsa.clear();
    assert!(matches!(
        extract(&envelope(&header, &archive), 100),
        Err(Error::UntrustedCrxPublisher)
    ));
    for id in [None, Some(Vec::new()), Some(vec![0; 15]), Some(vec![0; 17])] {
        header.signed_header_data = Some(SignedData { crx_id: id }.encode_to_vec());
        assert!(matches!(
            extract(&envelope(&header, &archive), 100),
            Err(Error::InvalidFormat("invalid CRX3 developer ID"))
        ));
    }
}

/// Missing proof fields and strictly malformed SPKI are rejected.
#[test]
fn rejects_malformed_spki_and_missing_signature_fields() {
    let (original, archive) = parts(&signed_crx(b"payload"));
    let mut variants = vec![None, Some(Vec::new()), Some(vec![0x30, 0x80, 0, 0])];
    let public_key = original.sha256_with_ecdsa[0].public_key.clone().unwrap();
    let mut trailing = public_key.clone();
    trailing.push(0);
    variants.push(Some(trailing));
    let mut wrong_curve = public_key.clone();
    wrong_curve[22] ^= 1;
    variants.push(Some(wrong_curve));
    let mut unused_bits = public_key;
    unused_bits[25] = 1;
    variants.push(Some(unused_bits));
    for public_key in variants {
        let mut header = original.clone();
        header.sha256_with_ecdsa[0].public_key = public_key;
        assert!(matches!(
            extract(&envelope(&header, &archive), 100),
            Err(Error::InvalidCrxSignature)
        ));
    }
    let mut header = original.clone();
    header.sha256_with_ecdsa[0].signature = None;
    assert!(matches!(
        extract(&envelope(&header, &archive), 100),
        Err(Error::InvalidCrxSignature)
    ));
    let mut header = original;
    header.sha256_with_rsa = std::mem::take(&mut header.sha256_with_ecdsa);
    assert!(matches!(
        extract(&envelope(&header, &archive), 100),
        Err(Error::InvalidCrxSignature)
    ));
}

/// Nested trailing ASN.1 values cannot be hidden inside the SPKI sequences.
#[test]
fn rejects_trailing_spki_and_algorithm_values() {
    let (original, archive) = parts(&signed_crx(b"payload"));
    for position in [23, 91] {
        let mut header = original.clone();
        let key = header.sha256_with_ecdsa[0].public_key.as_mut().unwrap();
        key.splice(position..position, [0x05, 0x00]);
        key[1] += 2;
        if position == 23 {
            key[3] += 2;
        }
        assert!(matches!(
            extract(&envelope(&header, &archive), 100),
            Err(Error::InvalidCrxSignature)
        ));
    }
}

/// ASN.1 values require their exact universal tags and minimal DER headers.
#[test]
fn rejects_mistyped_and_noncanonical_spki_fields() {
    let (original, archive) = parts(&signed_crx(b"payload"));
    let original_key = original.sha256_with_ecdsa[0].public_key.clone().unwrap();
    let mut variants = Vec::new();
    for (position, tag) in [(4, 0x04), (4, 0x46), (13, 0x04), (13, 0x46), (23, 0x83)] {
        let mut key = original_key.clone();
        key[position] = tag;
        variants.push(key);
    }
    for length_position in [1, 3, 5, 14, 24] {
        let mut key = original_key.clone();
        let length = key[length_position];
        key[length_position] = 0x81;
        key.insert(length_position + 1, length);
        if length_position > 1 {
            key[1] += 1;
        }
        if matches!(length_position, 5 | 14) {
            key[3] += 1;
        }
        variants.push(key);
    }
    for public_key in variants {
        let mut header = original.clone();
        let mut extra_proof = header.sha256_with_ecdsa[0].clone();
        extra_proof.public_key = Some(public_key);
        header.sha256_with_ecdsa.push(extra_proof);
        assert!(matches!(
            extract(&envelope(&header, &archive), 100),
            Err(Error::InvalidCrxSignature)
        ));
    }
}

/// Unknown fields and duplicate scalar fields follow normal protobuf semantics.
#[test]
fn authenticates_original_signed_protobuf_bytes() {
    let archive = zip_entry("crl-set", b"payload");
    let mut signed_data = vec![0x10, 0x07, 0x0a, 0x01, 0xff];
    signed_data.extend(signed_data_for(&spki(signer())));
    signed_data.extend([0x1a, 0x02, 0x08, 0x03]);
    let header = header_for(signer(), &archive, signed_data);
    let mut header_bytes = vec![0x08, 0x01];
    header_bytes.extend(header.encode_to_vec());
    assert_eq!(
        extract(&envelope_bytes(&header_bytes, &archive), 100).unwrap(),
        b"payload"
    );
    let mut tampered = header_bytes;
    tampered.extend(
        CrxFileHeader {
            signed_header_data: Some(signed_data_for(&spki(signer()))),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    assert!(matches!(
        extract(&envelope_bytes(&tampered, &archive), 100),
        Err(Error::InvalidCrxSignature)
    ));
}

/// The NUL domain separator and little-endian signed-header length are required.
#[test]
fn rejects_wrong_signature_domain_and_length_encoding() {
    let archive = zip_entry("crl-set", b"payload");
    let signed_data = signed_data_for(&spki(signer()));
    let message = signed_message(&signed_data, &archive);
    let mut wrong_domain = message.clone();
    wrong_domain.remove(SIGNATURE_CONTEXT.len() - 1);
    let mut wrong_length = message;
    wrong_length[SIGNATURE_CONTEXT.len()..SIGNATURE_CONTEXT.len() + 4]
        .copy_from_slice(&(signed_data.len() as u32).to_be_bytes());
    for message in [wrong_domain, wrong_length] {
        let header = CrxFileHeader {
            sha256_with_ecdsa: vec![proof_for(signer(), &message)],
            signed_header_data: Some(signed_data.clone()),
            ..Default::default()
        };
        assert!(matches!(
            extract(&envelope(&header, &archive), 100),
            Err(Error::InvalidCrxSignature)
        ));
    }
}

/// Truncated, malformed, and resource-exhausting headers fail before extraction.
#[test]
fn rejects_invalid_and_excessive_headers() {
    let bytes = signed_crx(b"payload");
    let header_end = 12 + read_u32(&bytes, 8).unwrap() as usize;
    for length in 0..header_end {
        assert!(extract(&bytes[..length], 100).is_err());
    }
    let mut excessive = bytes;
    excessive[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(extract(&excessive, 100), Err(Error::SizeLimit(_))));
    for header in [Vec::new(), vec![0xff], vec![0x12, 0x7f], vec![0]] {
        assert!(extract(&envelope_bytes(&header, b""), 100).is_err());
    }
    let repeated_proofs = [0x12, 0x00].repeat(MAX_PROOFS + 1);
    assert!(matches!(
        extract(&envelope_bytes(&repeated_proofs, b""), 100),
        Err(Error::InvalidFormat("too many CRX3 signature proofs"))
    ));
}

/// Header ZIP end tokens and CRX2/unknown-version downgrades remain forbidden.
#[test]
fn rejects_header_zip_markers_and_version_downgrades() {
    for marker in [b"PK\x05\x06", b"PK\x06\x07", b"PK\x06\x06"] {
        assert!(matches!(
            extract(&envelope_bytes(marker, b""), 100),
            Err(Error::InvalidFormat("ZIP end record in CRX header"))
        ));
    }
    for version in [0_u32, 2, 4, 99] {
        let mut bytes = signed_crx(b"payload");
        bytes[4..8].copy_from_slice(&version.to_le_bytes());
        assert!(matches!(
            extract(&bytes, 100),
            Err(Error::InvalidFormat("unsupported CRX version"))
        ));
    }
}

/// Authenticated archive contents must still provide the exact bounded entry.
#[test]
fn rejects_missing_entry_corrupt_archive_and_excessive_payload() {
    assert!(matches!(
        extract(&signed_archive(&zip_entry("manifest.json", b"{}")), 100),
        Err(Error::InvalidFormat("CRX archive has no crl-set entry"))
    ));
    assert!(matches!(
        extract(&signed_archive(b"invalid zip"), 100),
        Err(Error::Zip(_))
    ));
    assert!(matches!(
        extract(&signed_crx(b"payload"), 6),
        Err(Error::SizeLimit(6))
    ));
    let mut archive = zip_entry("crl-set", b"unique payload");
    let position = archive
        .windows(14)
        .position(|value| value == b"unique payload")
        .unwrap();
    archive[position] ^= 1;
    assert!(extract(&signed_archive(&archive), 100).is_err());
}
