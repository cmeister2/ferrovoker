//! In-memory TLS handshakes exercise real trust, hostname, and feed checks.

use super::*;
use ::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use ::rustls::sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey};
use ::rustls::{ClientConnection, ServerConfig, ServerConnection, SignatureAlgorithm};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair, KeyUsagePurpose,
};
use serde_json::{Value, json};

use crate::{CrlSet, OneCrl, RevocationSet};

/// A replaceable provider that models published cache refreshes.
#[derive(Debug)]
struct TestProvider {
    /// Snapshot used by the next TLS verification callback.
    snapshot: std::sync::RwLock<Arc<RevocationSet>>,
}

impl RevocationProvider for TestProvider {
    /// Checks the snapshot currently published by the test cache.
    ///
    /// # Errors
    ///
    /// Returns the current snapshot's certificate or feed-expiry error.
    fn check_chain_with_issuers(
        &self,
        chain: &[&[u8]],
        issuers: &[IssuerIdentity],
        unix_time: u64,
    ) -> crate::Result<RevocationStatus> {
        self.snapshot
            .read()
            .expect("test provider lock")
            .check_chain_with_issuers(chain, issuers, unix_time)
    }
}

/// A real signing key whose selected signer emits an invalid signature.
#[derive(Debug)]
struct BadSigningKey(Arc<dyn SigningKey>);

impl SigningKey for BadSigningKey {
    /// Keeps real algorithm selection while corrupting produced signatures.
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        self.0
            .choose_scheme(offered)
            .map(|signer| Box::new(BadSigner(signer)) as Box<dyn Signer>)
    }

    /// Retains the server key's algorithm.
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
}

/// A signer that flips a byte in an otherwise correctly formed signature.
#[derive(Debug)]
struct BadSigner(Box<dyn Signer>);

impl Signer for BadSigner {
    /// Signs the handshake and corrupts the resulting proof.
    ///
    /// # Errors
    ///
    /// Returns any signing error from the underlying real private key.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let mut signature = self.0.sign(message)?;
        if let Some(byte) = signature.last_mut() {
            *byte ^= 1;
        }
        Ok(signature)
    }

    /// Retains the negotiated signature scheme.
    fn scheme(&self) -> SignatureScheme {
        self.0.scheme()
    }
}

/// A locally generated root and its localhost leaf certificate.
struct TestCertificate {
    /// Root certificate trusted by the test client.
    root: CertificateDer<'static>,
    /// Server certificate issued for localhost.
    leaf: CertificateDer<'static>,
    /// Server's private key, used for real handshake signatures.
    key: PrivateKeyDer<'static>,
}

impl TestCertificate {
    /// Generates a new root and a correctly signed localhost leaf.
    fn new() -> Self {
        Self::with_root_name("ferrovoker test issuer")
    }

    /// Generates a root with a chosen name and a correctly signed localhost leaf.
    fn with_root_name(name: &str) -> Self {
        let mut root_params = CertificateParams::default();
        root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        root_params.distinguished_name = rcgen::DistinguishedName::new();
        root_params
            .distinguished_name
            .push(DnType::CommonName, name);
        let issuer =
            CertifiedIssuer::self_signed(root_params, KeyPair::generate().expect("root key"))
                .expect("root certificate");
        let key = KeyPair::generate().expect("leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["localhost".to_owned()]).expect("leaf parameters");
        leaf_params.serial_number = Some(128_u64.into());
        let leaf = leaf_params
            .signed_by(&key, &issuer)
            .expect("leaf certificate");
        Self {
            root: issuer.der().clone(),
            leaf: leaf.der().clone(),
            key: PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        }
    }

    /// Creates a trust store containing this fixture's root.
    fn roots(&self) -> RootCertStore {
        let mut roots = RootCertStore::empty();
        roots.add(self.root.clone()).expect("valid root");
        roots
    }

    /// Creates an optional leaf revocation and CRLSet expiry restriction.
    fn revocations(&self, revoke_leaf: bool, expires_at: Option<u64>) -> Arc<RevocationSet> {
        let (_, parsed) =
            x509_parser::parse_x509_certificate(&self.leaf).expect("generated X.509 certificate");
        let changes = if revoke_leaf {
            vec![json!({
                "id": "blocked-leaf",
                "last_modified": 1,
                "enabled": true,
                "issuerName": BASE64_STANDARD.encode(parsed.issuer().as_raw()),
                "serialNumber": BASE64_STANDARD.encode(parsed.raw_serial()),
            })]
        } else {
            vec![]
        };
        let onecrl = OneCrl::from_slice(
            &serde_json::to_vec(&json!({
                "timestamp": 1,
                "metadata": {},
                "changes": changes,
            }))
            .expect("OneCRL JSON"),
        )
        .expect("OneCRL snapshot");
        let crlset = expires_at.map(|expiry| {
            let header = serde_json::to_vec(&json!({
                "ContentType": "CRLSet",
                "Version": 0,
                "Sequence": 1,
                "NotAfter": expiry,
            }))
            .expect("CRLSet JSON");
            let mut bytes = u16::try_from(header.len())
                .expect("short test header")
                .to_le_bytes()
                .to_vec();
            bytes.extend(header);
            CrlSet::from_bytes(bytes).expect("CRLSet snapshot")
        });
        Arc::new(
            RevocationSet::from_snapshots(Some(&onecrl), crlset.as_ref())
                .expect("decoded revocations"),
        )
    }

    /// Blocks serial 128 under this fixture's root, with optional header rules.
    fn chrome_revocations(&self, extra: Value) -> Arc<RevocationSet> {
        let (_, root) =
            x509_parser::parse_x509_certificate(&self.root).expect("generated root certificate");
        let mut header = json!({"ContentType": "CRLSet", "Version": 0, "Sequence": 1});
        header
            .as_object_mut()
            .expect("header object")
            .extend(extra.as_object().expect("extra header object").clone());
        let header = serde_json::to_vec(&header).expect("header JSON");
        let mut bytes = u16::try_from(header.len())
            .expect("short header")
            .to_le_bytes()
            .to_vec();
        bytes.extend(header);
        bytes.extend_from_slice(&Sha256::digest(root.public_key().raw));
        bytes.extend_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&[1, 128]);
        let crlset = CrlSet::from_bytes(bytes).expect("CRLSet fixture");
        Arc::new(RevocationSet::from_snapshots(None, Some(&crlset)).expect("CRLSet index"))
    }
}

/// Completes a real TLS handshake through memory buffers without sockets.
///
/// # Errors
///
/// Returns the certificate or TLS protocol error reported by either peer.
fn handshake(
    config: ClientConfig,
    fixture: &TestCertificate,
    name: &'static str,
) -> Result<(), Error> {
    handshake_with_signature(config, fixture, name, false)
}

/// Performs a handshake with an optionally corrupted server signature.
///
/// # Errors
///
/// Returns either peer's certificate, signature, or protocol failure.
fn handshake_with_signature(
    config: ClientConfig,
    fixture: &TestCertificate,
    name: &'static str,
    corrupt_signature: bool,
) -> Result<(), Error> {
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(
        ::rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_no_client_auth()
    .with_single_cert(vec![fixture.leaf.clone()], fixture.key.clone_key())?;
    if corrupt_signature {
        let key = ::rustls::crypto::aws_lc_rs::sign::any_supported_type(&fixture.key)?;
        let certified_key =
            CertifiedKey::new(vec![fixture.leaf.clone()], Arc::new(BadSigningKey(key)));
        server_config.cert_resolver = Arc::new(SingleCertAndKey::from(certified_key));
    }
    let mut server = ServerConnection::new(Arc::new(server_config))?;
    let mut client = ClientConnection::new(
        Arc::new(config),
        ServerName::try_from(name).expect("valid test hostname"),
    )?;
    for _ in 0..10 {
        let mut request = Vec::new();
        client.write_tls(&mut request).expect("memory write");
        server
            .read_tls(&mut request.as_slice())
            .expect("memory read");
        server.process_new_packets()?;

        let mut response = Vec::new();
        server.write_tls(&mut response).expect("memory write");
        client
            .read_tls(&mut response.as_slice())
            .expect("memory read");
        client.process_new_packets()?;
        if !client.is_handshaking() && !server.is_handshaking() {
            return Ok(());
        }
    }
    panic!("test TLS handshake did not complete");
}

#[cfg(feature = "download")]
/// Serves one TLS connection and reports complete HTTP requests received.
fn http_server(
    fixture: &TestCertificate,
) -> (std::net::SocketAddr, std::thread::JoinHandle<usize>) {
    use std::io::{Read, Write};
    use std::time::Duration;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("local TLS server");
    let address = listener.local_addr().expect("local server address");
    let config = ServerConfig::builder_with_provider(Arc::new(
        ::rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS protocols")
    .with_no_client_auth()
    .with_single_cert(vec![fixture.leaf.clone()], fixture.key.clone_key())
    .expect("server certificate and key");
    let server = std::thread::spawn(move || {
        let (socket, _) = listener.accept().expect("HTTP client connects");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("server read timeout");
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("server write timeout");
        let connection = ServerConnection::new(Arc::new(config)).expect("server connection");
        let mut stream = ::rustls::StreamOwned::new(connection, socket);
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let length = match stream.read(&mut buffer) {
                Ok(0) | Err(_) => {
                    assert!(request.is_empty(), "HTTP plaintext preceded TLS failure");
                    return 0;
                }
                Ok(length) => length,
            };
            request.extend_from_slice(&buffer[..length]);
            assert!(request.len() < 8192, "test request exceeds header limit");
        }
        assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("HTTP response");
        stream.flush().expect("TLS response flushed");
        1
    });
    (address, server)
}

#[cfg(feature = "download")]
#[test]
/// Reqwest sends HTTP only after the configured feed verifier accepts TLS.
fn reqwest_enforces_revocation_before_sending_http() {
    use std::time::Duration;

    let fixture = TestCertificate::new();
    for revoked in [false, true] {
        let (address, server) = http_server(&fixture);
        let config = client_config(fixture.roots(), fixture.revocations(revoked, None))
            .expect("client config");
        let client = reqwest::blocking::Client::builder()
            .tls_backend_preconfigured(config)
            .https_only(true)
            .timeout(Duration::from_secs(5))
            .no_proxy()
            .resolve("localhost", address)
            .build()
            .expect("Reqwest client with custom TLS");
        let response = client
            .get(format!("https://localhost:{}/", address.port()))
            .send();
        if revoked {
            assert!(response.is_err(), "revoked TLS connection was accepted");
            assert_eq!(server.join().expect("TLS server completed"), 0);
        } else {
            let response = response.expect("healthy HTTPS request");
            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert_eq!(response.text().expect("response body"), "ok");
            assert_eq!(server.join().expect("TLS server completed"), 1);
        }
    }
}

#[test]
/// The convenience configuration accepts an ordinary trusted TLS server.
fn accepts_valid_handshake() {
    let fixture = TestCertificate::new();
    let config =
        client_config(fixture.roots(), fixture.revocations(false, None)).expect("client config");
    handshake(config, &fixture, "localhost").expect("valid handshake");
}

#[test]
/// New handshakes observe provider refreshes without rebuilding TLS configuration.
fn reads_refreshed_provider_on_each_handshake() {
    let fixture = TestCertificate::new();
    let provider = Arc::new(TestProvider {
        snapshot: std::sync::RwLock::new(fixture.revocations(false, None)),
    });
    let config = client_config(fixture.roots(), provider.clone()).expect("client config");
    handshake(config.clone(), &fixture, "localhost").expect("initially valid handshake");
    *provider.snapshot.write().expect("test provider lock") = fixture.revocations(true, None);
    assert!(matches!(
        handshake(config, &fixture, "localhost"),
        Err(Error::InvalidCertificate(CertificateError::Revoked))
    ));
}

#[test]
/// Trust-anchor identities restore full subject and SPKI DER before hashing.
fn trust_anchor_identities_restore_full_der() {
    let fixture = TestCertificate::new();
    let (_, root) = x509_parser::parse_x509_certificate(&fixture.root).expect("root certificate");
    let roots = fixture.roots();
    let identities = issuer_identities(&roots).expect("issuer identities");
    assert_eq!(identities.len(), 1);
    assert_eq!(identities[0].subject_der, root.subject().as_raw());
    assert_eq!(
        identities[0].spki_sha256,
        <[u8; 32]>::from(Sha256::digest(root.public_key().raw))
    );
    assert_ne!(
        identities[0].spki_sha256,
        <[u8; 32]>::from(Sha256::digest(
            roots.roots[0].subject_public_key_info.as_ref()
        ))
    );
}

#[test]
/// DER length framing handles both short and long length forms canonically.
fn sequence_wrapper_encodes_length_boundaries() {
    for (length, prefix) in [
        (0, &[0x30, 0][..]),
        (127, &[0x30, 0x7f]),
        (128, &[0x30, 0x81, 0x80]),
        (255, &[0x30, 0x81, 0xff]),
        (256, &[0x30, 0x82, 1, 0]),
        (65_536, &[0x30, 0x83, 1, 0, 0]),
    ] {
        let contents = vec![42; length];
        let encoded = wrap_sequence(&contents).expect("DER sequence");
        assert_eq!(&encoded[..prefix.len()], prefix);
        assert_eq!(&encoded[prefix.len()..], contents);
    }
}

#[test]
/// A root-signed leaf cannot omit its root to evade CRLSet serial checks.
fn rejects_crlset_serial_when_server_omits_root() {
    let fixture = TestCertificate::new();
    let revocations = fixture.chrome_revocations(json!({}));
    assert_eq!(
        revocations
            .check_chain(&[fixture.leaf.as_ref()], 1)
            .expect("leaf without issuer"),
        RevocationStatus::NotListed
    );
    let config = client_config(fixture.roots(), revocations).expect("client config");
    assert!(matches!(
        handshake(config, &fixture, "localhost"),
        Err(Error::InvalidCertificate(CertificateError::Revoked))
    ));
}

#[test]
/// Unrelated blocked roots in the trust store do not reject healthy chains.
fn ignores_unrelated_blocked_trust_anchor() {
    let fixture = TestCertificate::new();
    let unrelated = TestCertificate::with_root_name("unrelated test issuer");
    let (_, unrelated_root) =
        x509_parser::parse_x509_certificate(&unrelated.root).expect("unrelated root");
    let revocations = unrelated.chrome_revocations(json!({
        "BlockedSPKIs": [BASE64_STANDARD.encode(Sha256::digest(unrelated_root.public_key().raw))]
    }));
    let mut roots = fixture.roots();
    roots.add(unrelated.root.clone()).expect("unrelated root");
    let config = client_config(roots, revocations).expect("client config");
    handshake(config, &fixture, "localhost").expect("healthy unrelated chain");
}

#[test]
/// Valid chains remain accepted under both supported TLS versions.
fn accepts_valid_tls12_and_tls13_handshakes() {
    let fixture = TestCertificate::new();
    for version in [&::rustls::version::TLS12, &::rustls::version::TLS13] {
        let provider = Arc::new(::rustls::crypto::aws_lc_rs::default_provider());
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(fixture.roots()),
            provider.clone(),
        )
        .build()
        .expect("WebPKI verifier");
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .expect("supported TLS version")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RevocationVerifier::new(
                verifier,
                fixture.revocations(false, None),
            )))
            .with_no_client_auth();
        handshake(config, &fixture, "localhost").expect("valid handshake");
    }
}

#[test]
/// The wrapper rejects invalid TLS 1.2 and TLS 1.3 handshake signatures.
fn rejects_invalid_handshake_signatures() {
    let fixture = TestCertificate::new();
    for version in [&::rustls::version::TLS12, &::rustls::version::TLS13] {
        let provider = Arc::new(::rustls::crypto::aws_lc_rs::default_provider());
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(fixture.roots()),
            provider.clone(),
        )
        .build()
        .expect("WebPKI verifier");
        let config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[version])
            .expect("supported TLS version")
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RevocationVerifier::new(
                verifier,
                fixture.revocations(false, None),
            )))
            .with_no_client_auth();
        assert!(matches!(
            handshake_with_signature(config, &fixture, "localhost", true),
            Err(Error::InvalidCertificate(CertificateError::BadSignature))
        ));
    }
}

#[test]
/// Adding a feed check preserves hostname validation.
fn rejects_wrong_hostname() {
    let fixture = TestCertificate::new();
    let config =
        client_config(fixture.roots(), fixture.revocations(false, None)).expect("client config");
    assert!(matches!(
        handshake(config, &fixture, "wrong.example"),
        Err(Error::InvalidCertificate(
            CertificateError::NotValidForNameContext { .. }
        ))
    ));
}

#[test]
/// Adding a feed check preserves root and chain signature validation.
fn rejects_untrusted_signing_key() {
    let fixture = TestCertificate::new();
    let unrelated = TestCertificate::new();
    let config =
        client_config(unrelated.roots(), fixture.revocations(false, None)).expect("client config");
    assert!(matches!(
        handshake(config, &fixture, "localhost"),
        Err(Error::InvalidCertificate(_))
    ));
}

#[test]
/// A feed revocation rejects an otherwise trusted and valid connection.
fn rejects_revoked_certificate_during_handshake() {
    let fixture = TestCertificate::new();
    let config =
        client_config(fixture.roots(), fixture.revocations(true, None)).expect("client config");
    assert!(matches!(
        handshake(config, &fixture, "localhost"),
        Err(Error::InvalidCertificate(CertificateError::Revoked))
    ));
}

#[test]
/// Expired CRLSets cannot silently allow a fresh connection.
fn rejects_expired_snapshot_during_handshake() {
    let fixture = TestCertificate::new();
    let config =
        client_config(fixture.roots(), fixture.revocations(false, Some(1))).expect("client config");
    assert!(matches!(
        handshake(config, &fixture, "localhost"),
        Err(Error::Other(_))
    ));
}

#[test]
/// Missing trust anchors return an error instead of panicking.
fn rejects_empty_trust_store() {
    let fixture = TestCertificate::new();
    assert!(client_config(RootCertStore::empty(), fixture.revocations(false, None)).is_err());
}
