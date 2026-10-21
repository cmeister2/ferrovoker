//! Make an async Reqwest request with browser-feed certificate checks.
//!
//! Run with `cargo run --example reqwest_async --features rustls -- https://example.com/`.

mod common;

use std::time::Duration;

/// Load feeds before constructing the client, then make a verified HTTPS request.
///
/// # Errors
///
/// Returns feed, TLS configuration, or HTTP request/status failures.
#[tokio::main]
async fn main() -> Result<(), common::ExampleError> {
    let config = common::tls_config().await?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(30))
        .retry(reqwest::retry::never())
        .tls_backend_preconfigured(config)
        .build()?;
    let response = client
        .get(common::target_url())
        .send()
        .await?
        .error_for_status()?;
    println!("{}", response.status());
    Ok(())
}
