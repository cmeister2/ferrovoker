//! Authenticated, bounded extraction of Google's CRLSet CRX3 component.

use std::io::{Cursor, Read};

use prost::Message;
use ring::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use sha2::{Digest, Sha256};
use x509_parser::asn1_rs::{Any, BitString, Class, FromDer, Oid, Tag, ToDer};
use x509_parser::oid_registry::{OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_PKCS1_RSAENCRYPTION};

use crate::{Error, Result};

/// SHA-256 of the DER SPKI that Chromium pins for its CRLSet component signer.
pub(crate) const CRLSET_PUBLISHER_KEY_HASH: [u8; 32] = [
    0x75, 0xda, 0xf8, 0xcb, 0x77, 0x68, 0x40, 0x33, 0x65, 0x4c, 0x97, 0xe5, 0xc5, 0x1b, 0xcd, 0x81,
    0x7b, 0x1e, 0xeb, 0x11, 0x2c, 0xe1, 0xa4, 0x33, 0x8c, 0xf5, 0x72, 0x5e, 0xed, 0xb8, 0x43, 0x97,
];

/// Maximum encoded protobuf header accepted before allocating parsed fields.
const MAX_HEADER_BYTES: u32 = 16 * 1024 * 1024;
/// Maximum number of proofs accepted to bound signature verification work.
const MAX_PROOFS: usize = 64;
/// Domain separator, including its terminating NUL, prescribed by CRX3.
const SIGNATURE_CONTEXT: &[u8] = b"CRX3 SignedData\0";

/// CRX3's protobuf header, retaining the signed submessage as its original bytes.
#[derive(Clone, PartialEq, Message)]
struct CrxFileHeader {
    /// RSA PKCS#1 v1.5 SHA-256 proofs; the upstream schema's PSS comment is stale.
    #[prost(message, repeated, tag = "2")]
    sha256_with_rsa: Vec<AsymmetricKeyProof>,
    /// ECDSA P-256 SHA-256 proofs with ASN.1 DER signatures.
    #[prost(message, repeated, tag = "3")]
    sha256_with_ecdsa: Vec<AsymmetricKeyProof>,
    /// Original encoded `SignedData`, which must never be reserialized to verify.
    #[prost(bytes = "vec", optional, tag = "10000")]
    signed_header_data: Option<Vec<u8>>,
}

/// A public key and its signature over the CRX3 signed message.
#[derive(Clone, PartialEq, Message)]
struct AsymmetricKeyProof {
    /// Complete DER-encoded X.509 SubjectPublicKeyInfo.
    #[prost(bytes = "vec", optional, tag = "1")]
    public_key: Option<Vec<u8>>,
    /// Signature bytes, encoded according to the enclosing proof type.
    #[prost(bytes = "vec", optional, tag = "2")]
    signature: Option<Vec<u8>>,
}

/// Fields interpreted from the original signed submessage.
#[derive(Clone, PartialEq, Message)]
struct SignedData {
    /// Exactly the first 16 bytes of the developer key's SHA-256 SPKI hash.
    #[prost(bytes = "vec", optional, tag = "1")]
    crx_id: Option<Vec<u8>>,
}

/// Algorithms permitted by CRX3 proof fields.
#[derive(Clone, Copy)]
enum ProofAlgorithm {
    /// RSA PKCS#1 v1.5 with SHA-256 and a 2048–8192-bit key.
    Rsa,
    /// ECDSA with the named NIST P-256 curve and SHA-256.
    Ecdsa,
}

/// Authenticates Google's CRX3 signature, then extracts its exact `crl-set` entry.
///
/// # Errors
///
/// Returns an error for invalid framing, unsupported versions, untrusted keys,
/// invalid signatures, malformed archives, missing entries, excessive payloads,
/// or ZIP decompression and checksum failures.
pub(crate) fn extract_crl_set(bytes: &[u8], max_bytes: u64) -> Result<Vec<u8>> {
    extract_crl_set_with_key(bytes, max_bytes, &CRLSET_PUBLISHER_KEY_HASH)
}

/// Authenticates a CRX3 against an explicitly supplied internal trust anchor.
///
/// The production callers supply Google's component key. Tests supply their own
/// isolated signing key, without changing the production trust anchor.
///
/// # Errors
///
/// Returns the same authentication, archive, and size errors as `extract_crl_set`.
pub(crate) fn extract_crl_set_with_key(
    bytes: &[u8],
    max_bytes: u64,
    key_hash: &[u8; 32],
) -> Result<Vec<u8>> {
    let zip_bytes = authenticated_archive(bytes, key_hash)?;
    let mut archive = zip::ZipArchive::new(Cursor::new(zip_bytes))?;
    let mut entry = archive.by_name("crl-set").map_err(|error| match error {
        zip::result::ZipError::FileNotFound => {
            Error::InvalidFormat("CRX archive has no crl-set entry")
        }
        error => Error::Zip(error),
    })?;
    if entry.is_dir() {
        return Err(Error::InvalidFormat("CRLSet ZIP entry is a directory"));
    }
    if entry.size() > max_bytes {
        return Err(Error::SizeLimit(max_bytes));
    }

    let mut payload = Vec::new();
    (&mut entry)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut payload)?;
    if payload.len() as u64 > max_bytes {
        return Err(Error::SizeLimit(max_bytes));
    }
    Ok(payload)
}

/// Verifies every recognized proof and returns only the authenticated archive.
///
/// # Errors
///
/// Returns an error for invalid framing/protobuf, excessive headers or proofs,
/// missing developer/pinned proofs, malformed SPKI, or failed signatures.
fn authenticated_archive<'a>(bytes: &'a [u8], key_hash: &[u8; 32]) -> Result<&'a [u8]> {
    if bytes.get(..4) != Some(b"Cr24") {
        return Err(Error::InvalidFormat("missing CRX magic"));
    }
    if read_u32(bytes, 4)? != 3 {
        return Err(Error::InvalidFormat("unsupported CRX version"));
    }
    let header_size = read_u32(bytes, 8)?;
    if header_size > MAX_HEADER_BYTES {
        return Err(Error::SizeLimit(u64::from(MAX_HEADER_BYTES)));
    }
    let archive_offset = 12_usize
        .checked_add(header_size as usize)
        .ok_or(Error::InvalidFormat("CRX header length is out of range"))?;
    let header_bytes = bytes
        .get(12..archive_offset)
        .ok_or(Error::InvalidFormat("truncated CRX header"))?;
    let archive = bytes
        .get(archive_offset..)
        .ok_or(Error::InvalidFormat("truncated CRX header"))?;
    if header_bytes
        .windows(4)
        .any(|value| matches!(value, b"PK\x05\x06" | b"PK\x06\x07" | b"PK\x06\x06"))
    {
        return Err(Error::InvalidFormat("ZIP end record in CRX header"));
    }
    limit_proof_count(header_bytes)?;
    let header = CrxFileHeader::decode(header_bytes)
        .map_err(|_| Error::InvalidFormat("invalid CRX3 protobuf header"))?;
    let signed_bytes = header
        .signed_header_data
        .as_deref()
        .ok_or(Error::InvalidFormat("missing CRX3 signed header"))?;
    let signed_header = SignedData::decode(signed_bytes)
        .map_err(|_| Error::InvalidFormat("invalid CRX3 signed header"))?;
    let declared_id = signed_header
        .crx_id
        .as_deref()
        .filter(|id| id.len() == 16)
        .ok_or(Error::InvalidFormat("invalid CRX3 developer ID"))?;
    if declared_id != &key_hash[..16] {
        return Err(Error::UntrustedCrxPublisher);
    }

    let mut message = Vec::new();
    message.extend_from_slice(SIGNATURE_CONTEXT);
    message.extend_from_slice(&(signed_bytes.len() as u32).to_le_bytes());
    message.extend_from_slice(signed_bytes);
    message.extend_from_slice(archive);

    let mut found_publisher = false;
    let mut found_developer = false;
    for (proofs, algorithm) in [
        (&header.sha256_with_rsa, ProofAlgorithm::Rsa),
        (&header.sha256_with_ecdsa, ProofAlgorithm::Ecdsa),
    ] {
        for proof in proofs {
            verify_proof(proof, algorithm, &message)?;
            let public_key = proof.public_key.as_deref().unwrap_or_default();
            let hash: [u8; 32] = Sha256::digest(public_key).into();
            found_publisher |= hash == *key_hash;
            found_developer |= &hash[..16] == declared_id;
        }
    }
    if !found_publisher {
        return Err(Error::UntrustedCrxPublisher);
    }
    if !found_developer {
        return Err(Error::InvalidCrxSignature);
    }
    Ok(archive)
}

/// Counts proofs before protobuf decoding can allocate repeated message objects.
///
/// # Errors
///
/// Returns an invalid-format error for malformed protobuf or excessive proofs.
fn limit_proof_count(mut bytes: &[u8]) -> Result<()> {
    let mut count = 0;
    while !bytes.is_empty() {
        let (tag, wire_type) = prost::encoding::decode_key(&mut bytes)
            .map_err(|_| Error::InvalidFormat("invalid CRX3 protobuf header"))?;
        if matches!(tag, 2 | 3) {
            count += 1;
            if count > MAX_PROOFS {
                return Err(Error::InvalidFormat("too many CRX3 signature proofs"));
            }
        }
        prost::encoding::skip_field(wire_type, tag, &mut bytes, Default::default())
            .map_err(|_| Error::InvalidFormat("invalid CRX3 protobuf header"))?;
    }
    Ok(())
}

/// Strictly decodes one SPKI and verifies its declared CRX3 proof algorithm.
///
/// # Errors
///
/// Returns an invalid-signature error for absent or malformed fields, unsupported
/// SPKI parameters, trailing ASN.1 values, or an invalid cryptographic signature.
fn verify_proof(
    proof: &AsymmetricKeyProof,
    algorithm: ProofAlgorithm,
    message: &[u8],
) -> Result<()> {
    let public_key = proof
        .public_key
        .as_deref()
        .ok_or(Error::InvalidCrxSignature)?;
    let signature = proof
        .signature
        .as_deref()
        .ok_or(Error::InvalidCrxSignature)?;
    let (remaining, spki) = read_der(public_key, Tag::Sequence)?;
    if !remaining.is_empty() {
        return Err(Error::InvalidCrxSignature);
    }
    let (key_bytes, identifier) = read_der(spki.data, Tag::Sequence)?;
    let (parameters, oid_value) = read_der(identifier.data, Tag::Oid)?;
    let oid = Oid::try_from(oid_value).map_err(|_| Error::InvalidCrxSignature)?;
    let verification: &dyn VerificationAlgorithm = match algorithm {
        ProofAlgorithm::Rsa => {
            if oid != OID_PKCS1_RSAENCRYPTION {
                return Err(Error::InvalidCrxSignature);
            }
            if !parameters.is_empty() {
                let (remaining, value) = read_der(parameters, Tag::Null)?;
                if !remaining.is_empty() || !value.data.is_empty() {
                    return Err(Error::InvalidCrxSignature);
                }
            }
            &signature::RSA_PKCS1_2048_8192_SHA256
        }
        ProofAlgorithm::Ecdsa => {
            let (remaining, curve_value) = read_der(parameters, Tag::Oid)?;
            let curve = Oid::try_from(curve_value).map_err(|_| Error::InvalidCrxSignature)?;
            if oid != OID_KEY_TYPE_EC_PUBLIC_KEY || curve != OID_EC_P256 || !remaining.is_empty() {
                return Err(Error::InvalidCrxSignature);
            }
            &signature::ECDSA_P256_SHA256_ASN1
        }
    };
    let (remaining, key_value) = read_der(key_bytes, Tag::BitString)?;
    let key = BitString::try_from(key_value).map_err(|_| Error::InvalidCrxSignature)?;
    if !remaining.is_empty() || key.unused_bits != 0 {
        return Err(Error::InvalidCrxSignature);
    }
    UnparsedPublicKey::new(verification, key.data)
        .verify(message, signature)
        .map_err(|_| Error::InvalidCrxSignature)
}

/// Parses one ASN.1 value with an exact universal tag and canonical DER header.
///
/// The dependency's typed OID conversion does not validate its tag or class, so
/// all SPKI fields pass through these checks before their values are interpreted.
///
/// # Errors
///
/// Returns an invalid-signature error for malformed, mistyped, constructed
/// primitive, or non-minimally encoded ASN.1 values.
fn read_der(bytes: &[u8], tag: Tag) -> Result<(&[u8], Any<'_>)> {
    let (remaining, value) = Any::from_der(bytes).map_err(|_| Error::InvalidCrxSignature)?;
    let header = value
        .header
        .to_der_vec()
        .map_err(|_| Error::InvalidCrxSignature)?;
    let encoded_header_length = bytes.len() - remaining.len() - value.data.len();
    if value.class() != Class::Universal
        || value.tag() != tag
        || value.header.constructed() != (tag == Tag::Sequence)
        || bytes.get(..encoded_header_length) != Some(header.as_slice())
    {
        return Err(Error::InvalidCrxSignature);
    }
    Ok((remaining, value))
}

/// Reads a little-endian integer without indexing beyond a truncated header.
///
/// # Errors
///
/// Returns an invalid-format error if the four requested bytes are unavailable.
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or(Error::InvalidFormat("CRX header offset is out of range"))?;
    let field = bytes
        .get(offset..end)
        .ok_or(Error::InvalidFormat("truncated CRX header"))?;
    let mut value = [0_u8; 4];
    value.copy_from_slice(field);
    Ok(u32::from_le_bytes(value))
}

#[cfg(test)]
#[path = "../tests/unit/crx_support.rs"]
pub(crate) mod test_support;

#[cfg(test)]
#[path = "../tests/unit/crx.rs"]
mod tests;
