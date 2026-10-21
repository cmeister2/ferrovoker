# Usage

Commands in this guide run from the repository root. See the [README](../README.md)
for the main async Reqwest integration.

## Certificate checks

While the first release is unpublished, reference your local checkout:

```toml
[dependencies]
ferrovoker = { path = "../ferrovoker", features = ["rustls"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

Certificate inputs are automatically detected as DER, PEM, or base64 DER. Each
chain entry must contain exactly one complete certificate; bundles and trailing
certificate data are rejected. Supply the leaf first, followed by available
issuer certificates from the path accepted by normal TLS verification.

```rust,no_run
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let revocations = ferrovoker::fetch().await?;

    // One certificate per file; formats may be mixed in the same chain.
    let leaf = std::fs::read("server.crt")?;
    let issuer = std::fs::read("issuer.crt")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let matches = revocations.check_chain_all(&[&leaf, &issuer], now)?;
    for matched in matches {
        println!("certificate {}: {:?}", matched.certificate_index, matched.reasons);
    }
    Ok(())
}
```

`NotListed`, or an empty matches list, means only that the loaded feeds have no
matching entry. Normal certificate chain, signature, validity, and hostname
verification is still required.

`fetch()` returns a shared handle backed by both feeds. Loading, caching,
indexing, deduplication, and background refresh are handled internally. Keep the
Tokio runtime running while using the handle; dropping its final reference stops
the refresh task.

## Caching and refresh

The `directories` crate selects the OS user cache directory. A fresh cached
snapshot avoids feed requests at startup. The default refresh interval is six
hours, and snapshots older than 24 hours reject checks. CRLSet's `NotAfter`
can expire earlier. Invalid or stale cache data is replaced by a complete
successful two-feed fetch. The cache is written atomically.

Cached CRLSets retain their signed CRX3 container, and its signature and pinned
publisher key are checked again when the cache is loaded. Older unsigned cache
entries are ignored and downloaded again.

Successful background refreshes replace the shared index for subsequent checks
and TLS handshakes. Failed refreshes retain the prior snapshot and are exposed by
`last_refresh_error()`; they do not extend its maximum age. `last_updated_unix()`
reports the last successful update. Existing open TLS connections retain their
earlier authentication decision.

For an explicit cache location or different refresh policy, use `CacheConfig`
inside an async function:

```rust,no_run
let revocations = ferrovoker::CacheConfig::default()
    .with_cache_dir(std::path::PathBuf::from("/var/cache/my-app/ferrovoker"))
    .with_refresh_interval(std::time::Duration::from_secs(3600))
    .with_max_age(std::time::Duration::from_secs(12 * 3600))
    .load().await?;
```

Refresh intervals and maximum ages must be nonzero, and the maximum age must be
at least the refresh interval. Loading requires a Tokio runtime with time and
I/O enabled. Initialization fails if no fresh complete pair can be obtained.

## Features and lower-level APIs

`AsyncDownloader` and `RevocationSet::from_snapshots` remain available for custom
clients and applications managing their own persistence.
`Downloader` provides a blocking alternative. Fixed snapshots require your own
refresh policy. `Revocations::snapshot()` returns a fixed index without the
managed maximum-age checks. Custom clients must set timeouts,
transport policy, and an application/version User-Agent.

| Feature | Purpose |
| --- | --- |
| `download` (default) | Cached async loading, background refresh, and lower-level downloaders. |
| `rustls` | TLS verifier and client configuration helper. |
| `cli` | Optional command-line downloader and Clap dependency. |
| `ffi` | Managed C API with its own refresh runtime. |

Use `default-features = false` for offline parsing and matching without HTTP
dependencies. The CLI is excluded from normal library builds.

## HTTPS client examples

These examples call `ferrovoker::fetch().await?` and install its shared provider
in Rustls before making the application request:

```sh
cargo run --example reqwest_async --features rustls -- https://example.com/
cargo run --example reqwest_blocking --features rustls -- https://example.com/
cargo run --example hyper --features rustls -- https://example.com/
```

See [async Reqwest](../examples/reqwest_async.rs),
[blocking Reqwest](../examples/reqwest_blocking.rs), and [Hyper](../examples/hyper.rs),
with [shared setup](../examples/common/mod.rs). For your own client, pass a root
store and the handle to `ferrovoker::rustls::client_config`, then give
that configuration to Reqwest's `tls_backend_preconfigured` or Hyper's
`HttpsConnectorBuilder::with_tls_config`.

See [TLS behavior and limitations](verification.md#tls-behavior) for verifier details.

## Duplicate revocations

Identical rules within a feed are indexed once. `check_chain_all` returns one
result per unique certificate after normalizing its encoding to DER, with all
distinct OneCRL and CRLSet reasons.
A certificate listed by both feeds therefore produces a single result that
retains both sources. `check_chain` returns the first matching certificate.

The original snapshots retain their records. OneCRL's issuer-name/serial and
subject/key identifiers differ from CRLSet's SPKI/serial identifiers; unrelated
raw rows cannot safely be collapsed without certificate evidence. Indexing
preserves their distinct meaning and deduplicates the resulting certificate
matches.

Repeated certificates retain their first position in the supplied chain even
when their encodings differ.

## Optional CLI

```sh
cargo run --features cli -- onecrl --output onecrl.json
cargo run --features cli -- crlset --output crl-set
```

Omit `--output` to write the artifact to standard output. Progress and errors go
to standard error. Each HTTP request has a 60-second timeout; downloaded and
extracted payloads are limited to 64 MiB. Override them with `--timeout SECONDS`
and `--max-bytes BYTES`.

The CRLSet command authenticates the signed CRX3, then writes the unpacked
`crl-set` payload. This output no longer carries its publisher signature; retain
an original signed CRX container when later authentication is required.
