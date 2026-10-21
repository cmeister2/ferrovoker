//! Shared async feed loading for the HTTP-client examples.

/// Errors propagated by the example's downloads, verification, and requests.
pub type ExampleError = Box<dyn std::error::Error + Send + Sync>;

/// Build a TLS configuration backed by cached, automatically refreshed feeds.
///
/// Chrome CRX3 signatures are verified against the pinned CRLSet publisher key,
/// including when loading cached data. Mozilla OneCRL is fetched over HTTPS,
/// but its content signatures are not verified.
///
/// # Errors
///
/// Returns download, feed parsing, or TLS verifier configuration errors.
pub async fn tls_config() -> Result<::rustls::ClientConfig, ExampleError> {
    let revocations = ferrovoker::fetch().await?;
    let roots = ::rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Ok(ferrovoker::rustls::client_config(roots, revocations)?)
}

/// Read the target HTTPS URL from the command line, defaulting to example.com.
pub fn target_url() -> String {
    std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.com/".to_owned())
}
