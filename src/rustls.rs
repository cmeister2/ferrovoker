//! Add browser revocation snapshots to Rustls certificate verification.
//!
//! [`client_config`] constructs a client configuration that first performs
//! normal WebPKI certificate validation, including trust and hostname checks,
//! and then checks every certificate supplied by the server against a
//! [`RevocationProvider`]. Built-in providers check local data without network
//! requests during the TLS handshake.
//!
//! These feeds are partial blocklists: a certificate absent from them still
//! requires normal TLS verification. Managed downloads authenticate Chrome's
//! CRX3 container and Mozilla's signed OneCRL changeset against pinned production
//! publisher identities. Managed providers enforce their configured refresh and
//! cache-age policy; callers using fixed snapshots must arrange authentication
//! and freshness.

use std::sync::Arc;

use ::rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use ::rustls::client::{Resumption, WebPkiServerVerifier};
use ::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use ::rustls::{
    CertificateError, ClientConfig, DigitallySignedStruct, DistinguishedName, Error, OtherError,
    RootCertStore, SignatureScheme,
};
use sha2::{Digest, Sha256};

use crate::{IssuerIdentity, RevocationProvider, RevocationStatus};

/// A certificate verifier that adds feed checks to an existing verifier.
///
/// The inner verifier runs first and retains responsibility for certificate
/// validity, trust, hostname validation, and TLS handshake signatures. Provider
/// errors, including stale cached data or an expired CRLSet, reject the handshake.
///
/// Checks apply to the certificate list supplied by the server, rather than the
/// validation path selected by the inner verifier. An unused, revoked
/// intermediate can therefore cause conservative rejection. Certificates absent
/// from this list cannot themselves be checked. Supplemental issuer identities
/// supplied through [`Self::with_issuers`] allow CRLSet serial checks when an
/// issuing certificate is omitted; [`client_config`] supplies trust-anchor
/// identities automatically.
///
/// When installing this wrapper in a custom [`ClientConfig`], disable session
/// resumption and early data so resumed connections cannot bypass certificate
/// and snapshot expiry checks. [`client_config`] applies those settings.
#[derive(Debug)]
pub struct RevocationVerifier {
    /// Existing verifier responsible for normal TLS authentication.
    inner: Arc<dyn ServerCertVerifier>,
    /// Provider consulted for the current revocation data on every TLS handshake.
    revocations: Arc<dyn RevocationProvider>,
    /// Supplemental issuer names and key hashes for CRLSet serial matching.
    issuers: Vec<IssuerIdentity>,
}

impl RevocationVerifier {
    /// Adds snapshot checks to an existing X.509 server certificate verifier.
    ///
    /// The caller must supply an inner verifier that performs normal
    /// certificate and handshake signature validation. A fixed
    /// [`crate::RevocationSet`] or a managed provider can supply the feed checks;
    /// managed providers expose refreshed snapshots to subsequent handshakes.
    #[must_use]
    pub fn new(
        inner: Arc<dyn ServerCertVerifier>,
        revocations: Arc<dyn RevocationProvider>,
    ) -> Self {
        Self {
            inner,
            revocations,
            issuers: Vec::new(),
        }
    }

    /// Adds issuer identities for certificates omitted from the server's chain.
    ///
    /// These identities supply issuer names and SPKI hashes solely for CRLSet
    /// serial matching. They do not grant trust or cause unrelated trust anchors
    /// to be checked as certificates. The normal inner verifier still decides
    /// whether a trusted certificate path exists.
    #[must_use]
    pub fn with_issuers(mut self, issuers: Vec<IssuerIdentity>) -> Self {
        self.issuers = issuers;
        self
    }
}

impl ServerCertVerifier for RevocationVerifier {
    /// Verifies normal TLS authentication before applying feed revocations.
    ///
    /// # Errors
    ///
    /// Returns the inner verifier's error for invalid TLS credentials,
    /// [`CertificateError::Revoked`] for a listed certificate, or an
    /// [`Error::Other`] containing the provider error if certificates cannot be
    /// decoded, cached data is stale, or the CRLSet has expired.
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let verified = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        )?;
        let chain: Vec<&[u8]> = std::iter::once(end_entity.as_ref())
            .chain(intermediates.iter().map(AsRef::as_ref))
            .collect();
        match self
            .revocations
            .check_chain_with_issuers(&chain, &self.issuers, now.as_secs())
            .map_err(|error| Error::Other(OtherError(Arc::new(error))))?
        {
            RevocationStatus::NotListed => Ok(verified),
            RevocationStatus::Revoked(_) => Err(CertificateError::Revoked.into()),
        }
    }

    /// Delegates TLS 1.2 proof of private-key possession to the inner verifier.
    ///
    /// # Errors
    ///
    /// Returns the inner verifier's error if the handshake signature is invalid.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    /// Delegates TLS 1.3 proof of private-key possession to the inner verifier.
    ///
    /// # Errors
    ///
    /// Returns the inner verifier's error if the handshake signature is invalid.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    /// Preserves the inner verifier's supported signature algorithms.
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }

    /// Preserves the inner verifier's raw public key negotiation policy.
    fn requires_raw_public_keys(&self) -> bool {
        self.inner.requires_raw_public_keys()
    }

    /// Preserves certificate-authority hints from the inner verifier.
    fn root_hint_subjects(&self) -> Option<&[DistinguishedName]> {
        self.inner.root_hint_subjects()
    }
}

/// Builds a WebPKI client configuration with additional feed revocation checks.
///
/// The configuration uses Rustls' AWS-LC provider and safe default protocol
/// versions. Trust anchors come exclusively from `roots`; the helper does not
/// change global crypto-provider settings. Session resumption and early data
/// are disabled so each connection performs certificate and expiry checks.
/// ALPN is left empty for HTTP libraries to configure.
///
/// Trust-anchor subjects and SPKI hashes also supply CRLSet issuer identities,
/// allowing serial checks on the top server-supplied certificate when its root
/// is omitted. An unrelated trust anchor is never checked as a chain certificate.
///
/// The provider is consulted for every new TLS handshake. A managed provider
/// can refresh snapshots without rebuilding this configuration. Existing pooled
/// connections retain their original authentication decision; reconnect to
/// revalidate them. A fixed [`crate::RevocationSet`] keeps its original snapshots.
///
/// # Errors
///
/// Returns an [`Error::Other`] containing a
/// [`::rustls::client::VerifierBuilderError`] if `roots` is empty. Returns a
/// Rustls configuration error if the provider cannot support the safe default
/// protocol versions, or an error if a trust anchor's SPKI cannot be framed
/// within address-space and allocation limits.
pub fn client_config(
    roots: RootCertStore,
    revocations: Arc<dyn RevocationProvider>,
) -> Result<ClientConfig, Error> {
    let issuers = issuer_identities(&roots)?;
    let provider = Arc::new(::rustls::crypto::aws_lc_rs::default_provider());
    let verifier = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|error| Error::Other(OtherError(Arc::new(error))))?;
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(
            RevocationVerifier::new(verifier, revocations).with_issuers(issuers),
        ))
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    config.enable_early_data = false;
    Ok(config)
}

/// Restore full DER identifiers from Rustls trust-anchor SEQUENCE contents.
///
/// # Errors
///
/// Returns an error if an SPKI's DER framing exceeds address-space or allocation limits.
fn issuer_identities(roots: &RootCertStore) -> Result<Vec<IssuerIdentity>, Error> {
    roots
        .roots
        .iter()
        .map(|anchor| {
            let spki = wrap_sequence(anchor.subject_public_key_info.as_ref())?;
            Ok(IssuerIdentity {
                subject_der: DistinguishedName::in_sequence(anchor.subject.as_ref())
                    .as_ref()
                    .to_vec(),
                spki_sha256: Sha256::digest(&spki).into(),
            })
        })
        .collect()
}

/// Wrap DER SEQUENCE contents in a canonical tag and definite-length encoding.
///
/// # Errors
///
/// Returns an error if the encoded length exceeds address-space or allocation limits.
fn wrap_sequence(contents: &[u8]) -> Result<Vec<u8>, Error> {
    let length = contents.len().to_be_bytes();
    let significant = &length[(contents.len().leading_zeros() / 8) as usize..];
    let header_bytes = if contents.len() <= 127 {
        2
    } else {
        2 + significant.len()
    };
    let total = contents.len().checked_add(header_bytes).ok_or_else(|| {
        Error::General("trust-anchor DER length exceeds address space".to_owned())
    })?;
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(total)
        .map_err(|error| Error::Other(OtherError(Arc::new(error))))?;
    encoded.push(0x30);
    if contents.len() <= 127 {
        encoded.push(contents.len() as u8);
    } else {
        let octets = u8::try_from(significant.len())
            .map_err(|_| Error::General("trust-anchor DER length is too wide".to_owned()))?;
        encoded.push(0x80 | octets);
        encoded.extend_from_slice(significant);
    }
    encoded.extend_from_slice(contents);
    Ok(encoded)
}

#[cfg(test)]
#[path = "../tests/unit/rustls.rs"]
mod tests;
