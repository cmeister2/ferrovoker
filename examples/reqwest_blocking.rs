//! Make a blocking Reqwest request with browser-feed certificate checks.
//!
//! Run with `cargo run --example reqwest_blocking --features rustls -- https://example.com/`.

mod common;

use std::time::Duration;

/// Fetch feeds asynchronously, then use a blocking HTTP client outside the runtime.
///
/// # Errors
///
/// Returns runtime creation, feed, TLS configuration, or HTTP request failures.
fn main() -> Result<(), common::ExampleError> {
    let runtime = tokio::runtime::Runtime::new()?;
    let config = runtime.block_on(common::tls_config())?;
    let client = reqwest::blocking::Client::builder()
        .https_only(true)
        .timeout(Duration::from_secs(30))
        .retry(reqwest::retry::never())
        .tls_backend_preconfigured(config)
        .build()?;
    let response = client
        .get(common::target_url())
        .send()?
        .error_for_status()?;
    println!("{}", response.status());
    Ok(())
}
