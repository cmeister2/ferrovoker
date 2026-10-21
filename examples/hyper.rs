//! Make an async Hyper request with browser-feed certificate checks.
//!
//! Run with `cargo run --example hyper --features rustls -- https://example.com/`.

mod common;

use bytes::Bytes;
use http_body_util::Empty;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};

/// Load feeds before constructing an HTTPS-only Hyper connector.
///
/// # Errors
///
/// Returns feed, TLS configuration, URL parsing, or HTTP request failures.
#[tokio::main]
async fn main() -> Result<(), common::ExampleError> {
    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(common::tls_config().await?)
        .https_only()
        .enable_http1()
        .build();
    let client = Client::builder(TokioExecutor::new()).build::<_, Empty<Bytes>>(connector);
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        client.get(common::target_url().parse()?),
    )
    .await??;
    println!("{}", response.status());
    Ok(())
}
