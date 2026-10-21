# ferrovoker

[![crates.io](https://img.shields.io/crates/v/ferrovoker.svg)](https://crates.io/crates/ferrovoker)
[![docs.rs](https://docs.rs/ferrovoker/badge.svg)](https://docs.rs/ferrovoker)
[![CI](https://github.com/cmeister2/ferrovoker/actions/workflows/ci.yml/badge.svg)](https://github.com/cmeister2/ferrovoker/actions/workflows/ci.yml)

A Rust library that checks certificates against Mozilla OneCRL and Chrome CRLSets.
It downloads and caches both feeds, refreshes them in the background, and
deduplicates matching certificates. Async Rust, rustls, and a C shared library are supported.

## Make an HTTPS request

```toml
[dependencies]
ferrovoker = { version = "1", features = ["rustls"] }
reqwest = { version = "0.13", default-features = false, features = ["rustls"] }
rustls = { version = "0.23", default-features = false, features = ["std", "aws_lc_rs", "tls12"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
webpki-roots = "1"
```

```rust,no_run
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let revocations = ferrovoker::fetch().await?;
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = ferrovoker::rustls::client_config(roots, revocations)?;
    let client = reqwest::Client::builder()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(30))
        .retry(reqwest::retry::never())
        .tls_backend_preconfigured(tls)
        .build()?;
    let response = client.get("https://example.com/").send().await?.error_for_status()?;
    println!("{}", response.status());
    Ok(())
}
```

Normal TLS verification runs before the revocation checks. The feeds have partial
coverage: an absent certificate is not proof that it is unrevoked. Chrome's CRX3
publisher signature is verified; Mozilla OneCRL content signatures remain unverified.

## C shared library

On Linux, `cargo build --release --features ffi` produces
`target/release/libferrovoker.so`. Its managed handle downloads, caches, and
refreshes both feeds. See the [C guide](docs/c-api.md),
[header](include/ferrovoker.h), and [example](examples/c/check_chain.c).

## Documentation

- [Usage, caching, certificate formats, features, and CLI](docs/usage.md)
- [C shared library](docs/c-api.md)
- [Feed verification and TLS limitations](docs/verification.md)
- [Development and releases](docs/development.md)

Runnable examples: [async Reqwest](examples/reqwest_async.rs),
[blocking Reqwest](examples/reqwest_blocking.rs), [Hyper](examples/hyper.rs),
and [C](examples/c/check_chain.c).

Rust edition **2024**. Minimum supported Rust version (MSRV): **1.88.0**.
Licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
