//! Runtime-generated OneCRL content-signature fixtures shared by tests.

use base64::{Engine as _, engine::general_purpose::URL_SAFE};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P384_SHA384, date_time_ymd,
};
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P384_SHA384_FIXED_SIGNING, EcdsaKeyPair};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

use super::{AuthenticatedOneCrl, OneCrlTrust};

/// DNS identity used by locally generated content-signing certificates.
pub(crate) const TEST_SIGNER_NAME: &str = "onecrl.content-signature.test";
/// Time inside the validity interval of every ordinary generated certificate.
pub(crate) const TEST_UNIX_TIME: u64 = 1_800_000_000;
/// URL used only as inert signature metadata in direct verifier tests.
const TEST_CHAIN_URL: &str = "https://onecrl.content-signature.test/chain.pem";
/// Process-static material shared by cache fixtures with one configured root pin.
static DEFAULT_SIGNER: OnceLock<SigningMaterial> = OnceLock::new();

/// A complete signed response and its independently generated trust material.
#[derive(Clone, Debug)]
pub(crate) struct SignedFixture {
    /// Raw Remote Settings changeset carrying the content signature.
    pub(crate) response: Vec<u8>,
    /// Leaf-first PEM certificate chain used to verify the signature.
    pub(crate) chain: Vec<u8>,
    /// Root pin and leaf identity expected by the verifier.
    pub(crate) trust: OneCrlTrust,
}

impl SignedFixture {
    /// Authenticate this fixture at its ordinary in-range verification time.
    ///
    /// # Panics
    ///
    /// Panics if a runtime-generated fixture is internally inconsistent.
    pub(crate) fn authenticated(&self) -> AuthenticatedOneCrl {
        AuthenticatedOneCrl::from_saved(
            self.response.clone(),
            self.chain.clone(),
            self.trust,
            TEST_UNIX_TIME,
        )
        .expect("generated OneCRL fixture authenticates")
    }
}

/// Leaf properties varied by publisher-policy regression tests.
#[derive(Clone, Copy, Debug)]
struct LeafOptions {
    /// DNS SAN encoded into the leaf certificate.
    signer_name: &'static str,
    /// Extended-key usage encoded into the leaf certificate.
    usage: ExtendedUsage,
}

impl Default for LeafOptions {
    fn default() -> Self {
        Self {
            signer_name: TEST_SIGNER_NAME,
            usage: ExtendedUsage::CodeSigning,
        }
    }
}

/// Extended-key usage selected for a generated signing leaf.
#[derive(Clone, Copy, Debug)]
enum ExtendedUsage {
    /// The code-signing purpose required by Mozilla's protocol.
    CodeSigning,
    /// A valid but unsuitable TLS server purpose.
    ServerAuth,
}

/// Generated key and chain bytes reused without checking secrets into the tree.
#[derive(Clone, Debug)]
struct SigningMaterial {
    /// PKCS#8 leaf key generated for this test process.
    leaf_key: Vec<u8>,
    /// Leaf-first certificate chain corresponding to the key.
    chain: Vec<u8>,
    /// SHA-256 pin of the generated root certificate.
    root_hash: [u8; 32],
}

/// Build a valid OneCRL snapshot with process-local, runtime-generated P-384 keys.
///
/// The records are deliberately signed after sorting by `id`, independently of
/// their order in the response, matching Mozilla's canonicalization protocol.
///
/// # Panics
///
/// Panics if certificate/key generation, canonical JSON encoding, or signing
/// fails. The private key exists only in this test process and is never stored
/// as a repository fixture.
pub(crate) fn signed_snapshot(timestamp: u64, changes: Vec<Value>) -> SignedFixture {
    signed_snapshot_with_material(timestamp, changes, default_signer())
}

/// Build a valid snapshot and return it in the library's authenticated wrapper.
///
/// # Panics
///
/// Panics under the same conditions as [`signed_snapshot`] or if the generated
/// response does not authenticate.
pub(crate) fn authenticated_snapshot(timestamp: u64, changes: Vec<Value>) -> AuthenticatedOneCrl {
    signed_snapshot(timestamp, changes).authenticated()
}

/// Build a fixture whose signing leaf uses a different DNS identity.
pub(super) fn signed_snapshot_with_name(
    timestamp: u64,
    changes: Vec<Value>,
    signer_name: &'static str,
) -> SignedFixture {
    signed_snapshot_with_options(
        timestamp,
        changes,
        LeafOptions {
            signer_name,
            ..LeafOptions::default()
        },
    )
}

/// Build a fixture whose signing leaf has the TLS-server EKU instead.
pub(super) fn signed_snapshot_with_server_eku(
    timestamp: u64,
    changes: Vec<Value>,
) -> SignedFixture {
    signed_snapshot_with_options(
        timestamp,
        changes,
        LeafOptions {
            usage: ExtendedUsage::ServerAuth,
            ..LeafOptions::default()
        },
    )
}

/// Build a fixture whose PEM bundle contains an expired, unrelated extra CA.
pub(super) fn signed_snapshot_with_unrelated_intermediate(
    timestamp: u64,
    changes: Vec<Value>,
) -> SignedFixture {
    let mut fixture = signed_snapshot(timestamp, changes);
    let mut unrelated_params = certificate_params("Unrelated expired test CA");
    unrelated_params.not_before = date_time_ymd(2000, 1, 1);
    unrelated_params.not_after = date_time_ymd(2001, 1, 1);
    unrelated_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    unrelated_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let unrelated_key = p384_key();
    let unrelated = unrelated_params
        .self_signed(&unrelated_key)
        .expect("unrelated CA self-signs")
        .pem();

    let root_start = fixture
        .chain
        .windows(b"-----BEGIN CERTIFICATE-----".len())
        .rposition(|window| window == b"-----BEGIN CERTIFICATE-----")
        .expect("generated chain contains a root certificate");
    let mut chain = Vec::with_capacity(fixture.chain.len() + unrelated.len());
    chain.extend_from_slice(&fixture.chain[..root_start]);
    chain.extend_from_slice(unrelated.as_bytes());
    chain.extend_from_slice(&fixture.chain[root_start..]);
    fixture.chain = chain;
    fixture
}

/// Generate a full chain and sign the caller's snapshot using its leaf key.
fn signed_snapshot_with_options(
    timestamp: u64,
    changes: Vec<Value>,
    options: LeafOptions,
) -> SignedFixture {
    let material = signing_material(options);
    signed_snapshot_with_material(timestamp, changes, &material)
}

/// Return the single runtime-generated signer shared by ordinary fixtures.
fn default_signer() -> &'static SigningMaterial {
    DEFAULT_SIGNER.get_or_init(|| signing_material(LeafOptions::default()))
}

/// Sign caller data with an existing chain so cache refreshes share one trust pin.
fn signed_snapshot_with_material(
    timestamp: u64,
    changes: Vec<Value>,
    material: &SigningMaterial,
) -> SignedFixture {
    let signature = sign_collection(&material.leaf_key, timestamp, &changes);
    let response = serde_json::to_vec(&json!({
        "timestamp": timestamp,
        "metadata": {
            "signatures": [{
                "x5u": TEST_CHAIN_URL,
                "mode": "p384ecdsa",
                "signature": URL_SAFE.encode(signature),
            }],
        },
        "changes": changes,
    }))
    .expect("fixture JSON serializes");
    SignedFixture {
        response,
        chain: material.chain.clone(),
        trust: OneCrlTrust {
            root_sha256: material.root_hash,
            signer_name: TEST_SIGNER_NAME,
        },
    }
}

/// Generate a leaf-first P-384 certificate chain and retain its leaf key.
fn signing_material(options: LeafOptions) -> SigningMaterial {
    let mut root_params = certificate_params("OneCRL test root");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root_key = p384_key();
    let root_certificate = root_params
        .self_signed(&root_key)
        .expect("root certificate signs");
    let root_hash = Sha256::digest(root_certificate.der().as_ref()).into();
    let root = Issuer::new(root_params, root_key);

    let mut intermediate_params = certificate_params("OneCRL test intermediate");
    intermediate_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    intermediate_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    intermediate_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::CodeSigning];
    let intermediate_key = p384_key();
    let intermediate_certificate = intermediate_params
        .signed_by(&intermediate_key, &root)
        .expect("intermediate certificate signs");
    let intermediate = Issuer::new(intermediate_params, intermediate_key);

    let mut leaf_params = CertificateParams::new(vec![options.signer_name.to_owned()])
        .expect("fixture DNS name is valid");
    leaf_params.not_before = date_time_ymd(2020, 1, 1);
    leaf_params.not_after = date_time_ymd(2100, 1, 1);
    leaf_params.distinguished_name = rcgen::DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, options.signer_name);
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![match options.usage {
        ExtendedUsage::CodeSigning => ExtendedKeyUsagePurpose::CodeSigning,
        ExtendedUsage::ServerAuth => ExtendedKeyUsagePurpose::ServerAuth,
    }];
    let leaf_key = p384_key();
    let leaf_certificate = leaf_params
        .signed_by(&leaf_key, &intermediate)
        .expect("leaf certificate signs");

    let chain = format!(
        "{}{}{}",
        leaf_certificate.pem(),
        intermediate_certificate.pem(),
        root_certificate.pem(),
    )
    .into_bytes();
    SigningMaterial {
        leaf_key: leaf_key.serialize_der(),
        chain,
        root_hash,
    }
}

/// Construct common certificate fields and a fixed validity interval.
fn certificate_params(common_name: &str) -> CertificateParams {
    let mut params = CertificateParams::default();
    params.not_before = date_time_ymd(2020, 1, 1);
    params.not_after = date_time_ymd(2100, 1, 1);
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params
}

/// Generate one ephemeral P-384 key for certificates or content signatures.
fn p384_key() -> KeyPair {
    KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384).expect("P-384 key generates")
}

/// Canonicalize and sign one snapshot independently of production parsing.
fn sign_collection(leaf_key: &[u8], timestamp: u64, changes: &[Value]) -> Vec<u8> {
    let mut records = changes.to_vec();
    for record in &mut records {
        let object = record.as_object_mut().expect("fixture record is an object");
        object.remove("deleted");
        if object.get("attachment").is_some_and(Value::is_null) {
            object.remove("attachment");
        }
    }
    records.sort_by(|left, right| {
        left["id"]
            .as_str()
            .expect("fixture record has a string ID")
            .cmp(
                right["id"]
                    .as_str()
                    .expect("fixture record has a string ID"),
            )
    });
    let canonical = canonical_json::to_string(&json!({
        "data": records,
        "last_modified": timestamp.to_string(),
    }))
    .expect("fixture canonical JSON serializes");
    let mut message = b"Content-Signature:\0".to_vec();
    message.extend_from_slice(canonical.as_bytes());

    let random = SystemRandom::new();
    let signer = EcdsaKeyPair::from_pkcs8(&ECDSA_P384_SHA384_FIXED_SIGNING, leaf_key, &random)
        .expect("rcgen P-384 key is valid PKCS#8");
    signer
        .sign(&random, &message)
        .expect("content signature succeeds")
        .as_ref()
        .to_vec()
}
