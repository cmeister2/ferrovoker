# Feed verification and TLS limitations

## Mozilla OneCRL

OneCRL uses Mozilla's production v2 changeset API with `_expected=0`, relying on
the service's cache TTL. The downloaders preserve disabled records and honor
Remote Settings `Backoff` headers within each instance. Matching uses only
enabled records. Downloads are full snapshots. Managed handles cache and refresh
automatically; incremental synchronization is not used.

Authenticated downloads follow Mozilla's
[Remote Settings client specification](https://github.com/mozilla/remote-settings/blob/main/docs/client-specifications.rst).
The verifier removes fields excluded by that protocol, sorts records by string
ID, and canonicalizes an object containing the records and the collection
timestamp encoded as the JSON string `last_modified`. It verifies the
`Content-Signature:\0`-prefixed message using ECDSA P-384 with SHA-384. During
signing-key rotation, the downloader tries the supported signatures advertised
by the collection.

For each attempted signature, its certificate chain URL and every redirect must
remain on `content-signature-2.cdn.mozilla.net` over HTTPS on port 443. A separate
client downloads the chain without inheriting caller-supplied headers, cookies,
or TLS configuration; reqwest's system proxy settings still apply. The chain is
checked for current validity, code-signing usage, CA constraints, and signatures.
Its root must match Mozilla's pinned production content-signing root, and its leaf
must contain the exact DNS identity
`onecrl.content-signature.mozilla.org`. Trust is fixed by the library rather than
accepted from collection metadata.

## Chrome CRLSets

Chrome downloads require an HTTPS component URL and the advertised size and
SHA-256. Before extracting the CRLSet, the library verifies its CRX3 signature
against the pinned Google CRLSet component public-key hash and checks the signed
component ID. CRX2 containers are rejected. Extraction is bounded and checked by
ZIP CRC. The matching index handles blocked SPKIs, blocked interception SPKIs,
limited subjects, issuer/serial entries, and `NotAfter`. Known interception keys
alone do not block. CRLSet deltas are rejected. Browser-specific compiled-in policies are
outside the feed's scope.

## Offline input

For offline CRX input, `CrlSet::from_signed_crx` (with the default `download`
feature enabled) verifies the signature and publisher before parsing.
`OneCrl::from_slice`, `CrlSet::from_bytes`, and
`RevocationSet::from_snapshots` accept raw snapshots without authenticating
them. Extracting and saving just `crl-set` discards the signature; retain the
signed CRX container if later authentication is required. The public offline
OneCRL parser does not fetch or validate the certificate chain named by `x5u`.

## Publisher authentication and freshness

Signed anti-rollback protection is not implemented for either feed; local cache
timestamps enforce refresh and maximum-age policy, rather than cryptographic
freshness. Both feeds have partial coverage; their absence never establishes
that a certificate is valid.

Cached OneCRL responses and certificate chains, as well as cached CRX
containers, are reverified on every load. Invalid signatures, expired or
untrusted signing certificates, untrusted signing keys, or corrupted cached
containers trigger a complete fetch; initialization fails if no valid
replacement can be obtained. Serialized claims that a signature was previously
verified are never used as proof.

## TLS behavior

The helper performs ordinary WebPKI chain, hostname, and handshake-signature
verification before applying the feeds. It disables session resumption and early
data so new connections cannot skip snapshot checks. Applications installing the
verifier in their own configuration must disable those settings themselves.
No network I/O happens in the verifier. Expired CRLSets, stale managed snapshots,
and malformed certificates reject the handshake.
Managed providers automatically use refreshed snapshots for new handshakes.
Existing pooled connections retain their earlier authentication decision.
Offline `RevocationSet` providers stay fixed until replaced.

The wrapper checks certificates supplied by the server, rather than the exact
path selected by WebPKI. An extra revoked intermediate can cause conservative
rejection. The configuration helper uses trust-anchor identities for CRLSet
issuer/serial checks even when the server omits the root. The offline matching API accepts
additional issuer certificates or identities, and checks all candidates with a
matching issuer name regardless of their order. Roots are not globally blocked
just because an unrelated root in the store is listed.
Omitted roots supply issuer identities but are not evaluated as full certificates.
