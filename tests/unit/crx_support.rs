//! Locally signed CRX3 fixtures shared by downloader and cache tests.

use std::io::{Cursor, Write};
use std::sync::OnceLock;

use prost::Message;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use sha2::{Digest, Sha256};

use super::{AsymmetricKeyProof, CrxFileHeader, SIGNATURE_CONTEXT, SignedData};

/// Process-local signing key, never accepted by the production trust anchor.
static SIGNER: OnceLock<EcdsaKeyPair> = OnceLock::new();

/// Returns the stable publisher hash used for this test process's fixtures.
///
/// # Panics
///
/// Panics if the operating system cannot generate the test signing key.
pub(crate) fn publisher_key_hash() -> [u8; 32] {
    Sha256::digest(spki(signer())).into()
}

/// Builds a signed component containing the supplied `crl-set` payload.
///
/// # Panics
///
/// Panics if creating the in-memory ZIP or generating a test signature fails.
pub(crate) fn signed_crx(payload: &[u8]) -> Vec<u8> {
    signed_archive(&zip_entry("crl-set", payload))
}

/// Builds an otherwise valid component signed by an unrelated, fresh publisher.
///
/// # Panics
///
/// Panics if generating its key, in-memory ZIP, or signature fails.
pub(crate) fn signed_crx_with_unrelated_key(payload: &[u8]) -> Vec<u8> {
    let key = new_signer();
    let archive = zip_entry("crl-set", payload);
    let signed_data = signed_data_for(&spki(&key));
    envelope(&header_for(&key, &archive, signed_data), &archive)
}

/// Builds a correctly framed component whose cryptographic signature is damaged.
///
/// # Panics
///
/// Panics if creating the in-memory ZIP or generating a test signature fails.
pub(crate) fn tampered_signature_crx(payload: &[u8]) -> Vec<u8> {
    let archive = zip_entry("crl-set", payload);
    let mut header = header_for(signer(), &archive, signed_data_for(&spki(signer())));
    header.sha256_with_ecdsa[0]
        .signature
        .as_mut()
        .expect("fixture has a signature")[0] ^= 1;
    envelope(&header, &archive)
}

/// Returns the process-local fixture signer.
pub(super) fn signer() -> &'static EcdsaKeyPair {
    SIGNER.get_or_init(new_signer)
}

/// Generates an independent ECDSA P-256 fixture signer.
pub(super) fn new_signer() -> EcdsaKeyPair {
    let random = SystemRandom::new();
    let private = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &random)
        .expect("test key generation succeeds");
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, private.as_ref(), &random)
        .expect("generated test key is valid")
}

/// Wraps a ring ECDSA public point in the named-curve P-256 SPKI format.
pub(super) fn spki(key: &EcdsaKeyPair) -> Vec<u8> {
    let mut public_key = vec![
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
        0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    ];
    public_key.extend_from_slice(key.public_key().as_ref());
    public_key
}

/// Encodes the developer ID derived from a complete SPKI.
pub(super) fn signed_data_for(public_key: &[u8]) -> Vec<u8> {
    SignedData {
        crx_id: Some(Sha256::digest(public_key)[..16].to_vec()),
    }
    .encode_to_vec()
}

/// Creates exactly the bytes covered by CRX3 proofs.
pub(super) fn signed_message(signed_data: &[u8], archive: &[u8]) -> Vec<u8> {
    let mut message = SIGNATURE_CONTEXT.to_vec();
    message.extend_from_slice(&(signed_data.len() as u32).to_le_bytes());
    message.extend_from_slice(signed_data);
    message.extend_from_slice(archive);
    message
}

/// Signs one ECDSA proof using complete SPKI and ASN.1 signature encodings.
pub(super) fn proof_for(key: &EcdsaKeyPair, message: &[u8]) -> AsymmetricKeyProof {
    AsymmetricKeyProof {
        public_key: Some(spki(key)),
        signature: Some(
            key.sign(&SystemRandom::new(), message)
                .expect("test signature succeeds")
                .as_ref()
                .to_vec(),
        ),
    }
}

/// Builds a header while preserving a caller-supplied raw signed submessage.
pub(super) fn header_for(
    key: &EcdsaKeyPair,
    archive: &[u8],
    signed_data: Vec<u8>,
) -> CrxFileHeader {
    CrxFileHeader {
        sha256_with_rsa: Vec::new(),
        sha256_with_ecdsa: vec![proof_for(key, &signed_message(&signed_data, archive))],
        signed_header_data: Some(signed_data),
    }
}

/// Signs arbitrary archive bytes with the process-local key and correct ID.
pub(super) fn signed_archive(archive: &[u8]) -> Vec<u8> {
    envelope(
        &header_for(signer(), archive, signed_data_for(&spki(signer()))),
        archive,
    )
}

/// Encodes a header and archive into a complete CRX3 envelope.
pub(super) fn envelope(header: &CrxFileHeader, archive: &[u8]) -> Vec<u8> {
    envelope_bytes(&header.encode_to_vec(), archive)
}

/// Wraps possibly malformed protobuf bytes for negative parser tests.
pub(super) fn envelope_bytes(header: &[u8], archive: &[u8]) -> Vec<u8> {
    let mut bytes = b"Cr24".to_vec();
    bytes.extend_from_slice(&3_u32.to_le_bytes());
    bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
    bytes.extend_from_slice(header);
    bytes.extend_from_slice(archive);
    bytes
}

/// Builds a stored ZIP entry with a caller-selected filename and contents.
pub(super) fn zip_entry(name: &str, contents: &[u8]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file(
        name,
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )
    .expect("fixture ZIP entry opens");
    zip.write_all(contents).expect("fixture ZIP entry writes");
    zip.finish().expect("fixture ZIP finishes").into_inner()
}
