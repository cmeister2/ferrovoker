# Development and releases

Rust edition: **2024**. Minimum supported Rust version (MSRV): **1.88.0**.
Release tooling requires Node.js **24.15.0 or newer**.

```sh
cargo check --locked --all-targets --all-features
cargo check --locked --no-default-features --lib
cargo test --locked --no-default-features --lib
cargo test --locked --all-features
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo +1.88.0 check --locked --all-targets --all-features
cargo +1.88.0 check --locked --no-default-features --lib
cargo +1.88.0 test --locked --no-default-features --lib
cargo +1.88.0 test --locked --all-features
cargo +1.88.0 fmt --all -- --check
cargo +1.88.0 clippy --locked --all-targets --all-features -- -D warnings
cargo msrv verify -- cargo check --locked --all-targets --all-features
cargo llvm-cov --locked --all-features --workspace --lcov --output-path lcov.info
npm ci
npm test
```

CI runs stable and MSRV checks, a separate MSRV verification, coverage, and the
release-notes rendering regression. Unit tests use synthetic feeds and local
HTTP servers; ordinary tests do not depend on the public feed services.

## Releases

The repository is configured as `cmeister2/ferrovoker`; update Cargo metadata if
hosting it elsewhere. The crate is not published by the local setup process.
Before enabling publication, create the GitHub repository and set its
`CARGO_REGISTRY_TOKEN` Actions secret to a crates.io token authorized to publish
`ferrovoker`.

Pushes to `main` or `master` release through semantic-release after checks pass.
Tags are plain SemVer, such as `1.2.3`. The explicit plugin list creates GitHub
releases and publishes to crates.io; npm is private release tooling.

Keep the checked-in version at `0.0.0` in both `Cargo.toml` and `Cargo.lock`.
The preparation script injects the release version into the build checkout.
When no release is produced, CI builds an artifact using `0.0.<github.run_id>`.
There is no version commit back to the source branch.

Use Conventional Commits: `fix:` and `perf:` trigger patches, `feat:` triggers
minor releases, and a `BREAKING CHANGE:` footer triggers a major release. The
analyzer uses its default preset, so use the footer for breaking changes.
Preserve these messages when merging.

The release notes regression resolves the generator through semantic-release's
actual dependency graph. The Conventional Commits preset is intentionally
pinned to `10.4.0`, with notes generator `15.0.0-beta.3` selected by an override
for writer compatibility. Keep both pins until a replacement passes that test.

## Documentation, dependencies, and tests

Keep `package.rust-version`, the [README](../README.md), and the
[CI toolchain matrix](../.github/workflows/ci.yml) consistent. Dependency and
language changes must continue to build on the declared MSRV; changing it is an
explicit compatibility decision.

The crate denies `missing_docs`, `missing_docs_in_private_items`,
`missing_errors_doc`, and `missing_panics_doc`. Document public and private items,
including crate and module documentation. Describe actual error and panic
conditions in `# Errors` and `# Panics` sections where required; fix documentation
instead of weakening the lint policy.

Use `cargo add <crate>` for new Rust dependencies, and check current dependency
and GitHub Action versions before changing them. Renovate extends the centralized
`github>cmeister2/renovate` configuration in [renovate.json](../renovate.json).

Unit tests live under [tests/unit](../tests/unit), attached to their original
modules to preserve access to private behavior. Most feed, signature, and
certificate fixtures are generated for tests. The eMudhra regression keeps only
the public [leaf and intermediate certificates](../tests/fixtures/emudra); the
compromised CA private key used to issue the leaf is not stored in this repository.
Preserve CI's separate MSRV verification, coverage, and C ABI jobs. See the
[C smoke test](c-api.md#abi-smoke-test) for its optional live mode. Ordinary tests
do not call public feed services; explicitly ignored tests may do so.

## Release regression requirements

The release workflow fetches complete history and tags with `fetch-depth: 0`.
It installs npm dependencies and runs the rendering regression before invoking
semantic-release. Plugins in [release.config.js](../release.config.js) execute in
configured order; npm publishing is omitted. Preserve existing release tags for
release detection. Ordinary `docs:`, `test:`, `ci:`, and `chore:` commits do not
trigger releases alone; use a `BREAKING CHANGE:` footer rather than relying on
`!` alone.

[prepare-release.mjs](../scripts/prepare-release.mjs) validates the manifest and
lockfile sentinels before replacing them with a plain SemVer build or release
version. Only the crate's own `Cargo.lock` entry is updated; dependency versions
remain unchanged.

Preset 10 uses JavaScript render functions requiring
`conventional-changelog-writer` 9 or newer. The notes-generator override supplies
a compatible writer through semantic-release's actual dependency graph.
[release.config.test.mjs](../tests/release.config.test.mjs) imports the configured
notes-generator options, resolves the generator relative to semantic-release
with `createRequire`, and calls `generateNotes` with repository and release
context. Assertions cover feature and fix sections, breaking-change headings
and explanations, commit subjects, and compare, issue, and commit links. Testing
an unrelated installed writer or only checking for nonempty output is insufficient.
The same file separately verifies the analyzer's version-selection rules.

Update [package-lock.json](../package-lock.json) alongside release dependency
changes, use a Node version satisfying installed package `engines`, and run
`npm ci` followed by `npm test`. Keep that regression in CI before publication.
