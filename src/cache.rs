//! Persistent complete snapshots with shared background refresh.

use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::onecrl_signature::{
    AuthenticatedOneCrl, MAX_CERTIFICATE_CHAIN_BYTES, OneCrlTrust, PRODUCTION_TRUST,
};
use crate::{
    AsyncDownloader, CertificateRevocations, CrlSet, Error, IssuerIdentity, OneCrl, Result,
    RevocationProvider, RevocationSet, RevocationStatus,
};

/// Version of the complete two-feed cache envelope.
const CACHE_VERSION: u32 = 3;
/// Filename replaced atomically after a successful complete refresh.
const CACHE_FILENAME: &str = "snapshots-v3.json";
/// Bound accommodating two 64 MiB feeds, CRLSet base64 expansion, and JSON metadata.
const MAX_CACHE_BYTES: u64 = 192 * 1024 * 1024;
/// Maximum decoded CRLSet size, matching the default download bound.
const MAX_CRLSET_BYTES: usize = 64 * 1024 * 1024;
/// Maximum original signed OneCRL changeset size, matching the download bound.
const MAX_ONECRL_BYTES: usize = 64 * 1024 * 1024;
/// Maximum original signed CRX size, independent of its decompressed payload.
const MAX_CRX_BYTES: usize = 64 * 1024 * 1024;
/// Default interval between attempts to refresh a shared snapshot.
const DEFAULT_REFRESH_INTERVAL: Duration = Duration::from_secs(6 * 60 * 60);
/// Default maximum snapshot age accepted by live certificate checks.
const DEFAULT_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);

/// Future resolving to both complete feed snapshots from a single refresh.
type FeedFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(AuthenticatedOneCrl, CrlSet)>> + Send + 'a>>;

/// Internal feed source, replaceable in tests without public network requests.
trait FeedLoader: Send + Sync {
    /// Retrieve a complete pair, retaining source-specific backoff between attempts.
    fn fetch(&self) -> FeedFuture<'_>;
}

/// Production source with persistent, independent backoff for each publisher.
struct HttpLoader {
    /// Mozilla connection pooling, response limits, and publisher backoff state.
    onecrl: AsyncDownloader,
    /// Google connection pooling and backoff, unaffected by Mozilla's responses.
    crlset: AsyncDownloader,
}

impl FeedLoader for HttpLoader {
    fn fetch(&self) -> FeedFuture<'_> {
        Box::pin(async {
            let onecrl = self.onecrl.fetch_authenticated_onecrl().await?;
            let crlset = self.crlset.fetch_crlset().await?;
            Ok((onecrl, crlset))
        })
    }
}

/// Cache location and refresh/freshness policy for [`Revocations`].
///
/// The default uses the operating system's per-user cache directory, refreshes
/// every six hours, and rejects snapshots older than 24 hours. Loading requires
/// a Tokio runtime with time and I/O enabled. Chrome CRX publisher signatures
/// and Mozilla OneCRL content signatures are verified when downloading and
/// whenever cached data is loaded.
#[derive(Clone, Debug)]
pub struct CacheConfig {
    /// Platform-derived or caller-selected directory for the complete cache file.
    cache_dir: Option<PathBuf>,
    /// Delay between successful refreshes or failed refresh attempts.
    refresh_interval: Duration,
    /// Maximum time since the pair of feed snapshots was fetched successfully.
    max_age: Duration,
    /// Pinned Chrome publisher key; private to prevent caller-selected trust.
    publisher_key_hash: [u8; 32],
    /// Pinned Mozilla root and leaf identity; private to prevent caller-selected trust.
    onecrl_trust: OneCrlTrust,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            cache_dir: ProjectDirs::from("org", "ferrovoker", "ferrovoker")
                .map(|project| project.cache_dir().to_path_buf()),
            refresh_interval: DEFAULT_REFRESH_INTERVAL,
            max_age: DEFAULT_MAX_AGE,
            publisher_key_hash: crate::crx::CRLSET_PUBLISHER_KEY_HASH,
            onecrl_trust: PRODUCTION_TRUST,
        }
    }
}

impl CacheConfig {
    /// Store the complete two-feed cache in a caller-selected directory.
    #[must_use]
    pub fn with_cache_dir(mut self, directory: PathBuf) -> Self {
        self.cache_dir = Some(directory);
        self
    }

    /// Set the interval between automatic refresh attempts.
    ///
    /// The interval must be nonzero, no greater than the maximum age, and fit
    /// the platform's monotonic clock. Invalid policies are rejected by `load`.
    #[must_use]
    pub fn with_refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval;
        self
    }

    /// Set the maximum accepted age for cached data and live certificate checks.
    ///
    /// The age must be nonzero and at least the refresh interval. A refresh
    /// failure keeps the previous snapshot available only until this age limit.
    #[must_use]
    pub fn with_max_age(mut self, age: Duration) -> Self {
        self.max_age = age;
        self
    }

    /// Load fresh cached feeds or fetch both, then keep the shared index updated.
    ///
    /// Fresh, valid cached snapshots are used without network requests. Missing,
    /// corrupt, expired, stale, future-dated, or unsupported cache files trigger
    /// a complete download. Both feeds must succeed before an index is exposed.
    /// Cached Chrome CRX and Mozilla content signatures are reverified before
    /// use. Legacy caches without either feed's publisher evidence are ignored.
    /// Disk reads, signature verification, and atomic writes run on Tokio's
    /// blocking worker pool.
    ///
    /// Keep the returned handle, directly or inside a TLS verifier, alive while
    /// making requests. Dropping its last reference stops background refresh.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid policy, unavailable cache directory,
    /// missing Tokio runtime, download/format failures, expired CRLSets, cache
    /// write failures, or failed blocking tasks. No stale or partial snapshot is
    /// returned if initialization cannot obtain a complete fresh pair.
    pub async fn load(self) -> Result<Arc<Revocations>> {
        require_runtime()?;
        self.validate()?;
        let source = Arc::new(HttpLoader {
            onecrl: AsyncDownloader::new()?,
            crlset: AsyncDownloader::new()?,
        });
        self.load_with_source(source).await
    }

    /// Reject policies that could spin, expire before routine refresh, or overflow timers.
    ///
    /// # Errors
    ///
    /// Returns an error for zero intervals/ages, an interval greater than the
    /// maximum age, a timer overflow, or a missing platform cache directory.
    fn validate(&self) -> Result<()> {
        if self.cache_dir.is_none() {
            return Err(Error::CacheUnavailable);
        }
        if self.refresh_interval.is_zero()
            || self.max_age.is_zero()
            || self.refresh_interval > self.max_age
            || std::time::Instant::now()
                .checked_add(self.refresh_interval)
                .is_none()
        {
            return Err(Error::InvalidFormat(
                "invalid cache refresh or maximum-age policy",
            ));
        }
        Ok(())
    }

    /// Initialize from disk or an injectable complete feed source and spawn refresh.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid configuration, missing runtime, unsuccessful
    /// initial downloads, invalid feeds, cache writes, or failed blocking tasks.
    async fn load_with_source(self, source: Arc<dyn FeedLoader>) -> Result<Arc<Revocations>> {
        require_runtime()?;
        self.validate()?;
        let cache_dir = self.cache_dir.clone().ok_or(Error::CacheUnavailable)?;
        let cache_file = cache_dir.join(CACHE_FILENAME);
        let max_age = self.max_age;
        let publisher_key_hash = self.publisher_key_hash;
        let onecrl_trust = self.onecrl_trust;
        let read_file = cache_file.clone();
        let cached = tokio::task::spawn_blocking(move || {
            read_cache(&read_file, max_age, &publisher_key_hash, onecrl_trust)
        })
        .await
        .map_err(|_| Error::InvalidFormat("cache read task failed"))?;
        let state = match cached {
            Ok(state) => state,
            Err(_) => {
                fetch_and_persist(
                    source.as_ref(),
                    &cache_dir,
                    publisher_key_hash,
                    onecrl_trust,
                )
                .await?
            }
        };
        let delay = initial_refresh_delay(state.fetched_at, self.refresh_interval)?;
        let revocations = Arc::new(Revocations {
            current: ArcSwap::from(state),
            max_age: self.max_age,
            refresh_error: Mutex::new(None),
            refresh_task: Mutex::new(None),
        });
        let task = tokio::spawn(refresh_loop(
            Arc::downgrade(&revocations),
            source,
            cache_dir,
            self.refresh_interval,
            delay,
            publisher_key_hash,
            onecrl_trust,
        ));
        *revocations.task_guard() = Some(task);
        Ok(revocations)
    }
}

/// Load shared, cached revocation feeds and start background refresh.
///
/// This is shorthand for [`CacheConfig::default().load()`](CacheConfig::load).
/// Fresh cached feeds require no network request. The shared handle checks
/// freshness on every certificate check and receives future background updates.
///
/// # Errors
///
/// Returns the initialization, network, format, runtime, and cache errors
/// described by [`CacheConfig::load`].
pub async fn fetch() -> Result<Arc<Revocations>> {
    CacheConfig::default().load().await
}

/// Shared live revocation data, refreshed while at least one handle remains alive.
///
/// Certificate checks atomically use one complete snapshot and enforce the
/// configured maximum age. Refresh failures retain the known-good snapshot and
/// record an error; once it becomes too old, checks fail closed. Normal TLS
/// validation and the partial coverage limitations of browser feeds still apply.
#[derive(Debug)]
pub struct Revocations {
    /// Complete indexed feeds and their local fetch timestamp, swapped together.
    current: ArcSwap<SnapshotState>,
    /// Maximum snapshot age allowed by the public certificate check methods.
    max_age: Duration,
    /// Most recent refresh failure, cleared on a later successful refresh.
    refresh_error: Mutex<Option<String>>,
    /// Background task owned by this handle, without a strong reference back to it.
    refresh_task: Mutex<Option<JoinHandle<()>>>,
}

impl Revocations {
    /// Return a fixed view of the current index without its live freshness policy.
    ///
    /// The returned snapshot does not receive background updates or enforce the
    /// configured maximum age. Use this handle's check methods or its
    /// [`RevocationProvider`] implementation when live updates are required.
    #[must_use]
    pub fn snapshot(&self) -> Arc<RevocationSet> {
        Arc::clone(&self.current.load().set)
    }

    /// Return the local successful fetch timestamp, in seconds since the Unix epoch.
    #[must_use]
    pub fn last_updated_unix(&self) -> u64 {
        self.current.load().fetched_at
    }

    /// Return the last background refresh failure, or `None` after success.
    #[must_use]
    pub fn last_refresh_error(&self) -> Option<String> {
        self.error_guard().clone()
    }

    /// Check the current snapshot and reject data beyond its configured maximum age.
    ///
    /// Certificate matching and validation limitations are those of
    /// [`RevocationSet::check_chain`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleSnapshot`] for stale or future-dated snapshot data,
    /// plus the certificate and CRLSet errors from [`RevocationSet::check_chain`].
    pub fn check_chain(&self, chain: &[&[u8]], unix_time: u64) -> Result<RevocationStatus> {
        self.check_chain_with_issuers(chain, &[], unix_time)
    }

    /// Check the current snapshot with supplemental issuer identities and age enforcement.
    ///
    /// Supplemental identifiers behave as described by
    /// [`RevocationSet::check_chain_with_issuers`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleSnapshot`] for stale or future-dated snapshot data,
    /// plus errors from [`RevocationSet::check_chain_with_issuers`].
    pub fn check_chain_with_issuers(
        &self,
        chain: &[&[u8]],
        issuers: &[IssuerIdentity],
        unix_time: u64,
    ) -> Result<RevocationStatus> {
        let current = self.current.load();
        ensure_fresh(current.fetched_at, unix_time, self.max_age)?;
        current
            .set
            .check_chain_with_issuers(chain, issuers, unix_time)
    }

    /// Collect distinct matches using the current snapshot and its maximum-age policy.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleSnapshot`] for stale or future-dated snapshot data,
    /// plus errors from [`RevocationSet::check_chain_all`].
    pub fn check_chain_all(
        &self,
        chain: &[&[u8]],
        unix_time: u64,
    ) -> Result<Vec<CertificateRevocations>> {
        self.check_chain_all_with_issuers(chain, &[], unix_time)
    }

    /// Collect matches with supplemental issuers using one age-checked live snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`Error::StaleSnapshot`] for stale or future-dated snapshot data,
    /// plus errors from [`RevocationSet::check_chain_all_with_issuers`].
    pub fn check_chain_all_with_issuers(
        &self,
        chain: &[&[u8]],
        issuers: &[IssuerIdentity],
        unix_time: u64,
    ) -> Result<Vec<CertificateRevocations>> {
        let current = self.current.load();
        ensure_fresh(current.fetched_at, unix_time, self.max_age)?;
        current
            .set
            .check_chain_all_with_issuers(chain, issuers, unix_time)
    }

    /// Lock refresh diagnostics while recovering any poisoned mutex.
    fn error_guard(&self) -> MutexGuard<'_, Option<String>> {
        self.refresh_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Lock the task handle while recovering any poisoned mutex.
    fn task_guard(&self) -> MutexGuard<'_, Option<JoinHandle<()>>> {
        self.refresh_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl RevocationProvider for Revocations {
    fn check_chain_with_issuers(
        &self,
        chain: &[&[u8]],
        issuers: &[IssuerIdentity],
        unix_time: u64,
    ) -> Result<RevocationStatus> {
        self.check_chain_with_issuers(chain, issuers, unix_time)
    }
}

impl Drop for Revocations {
    fn drop(&mut self) {
        if let Some(task) = self
            .refresh_task
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
        {
            task.abort();
        }
    }
}

/// One atomic live state, keeping the timestamp and identifiers from the same refresh.
#[derive(Debug)]
struct SnapshotState {
    /// Indexed identifiers from both complete feed snapshots.
    set: Arc<RevocationSet>,
    /// Local Unix time after both feeds were fetched successfully.
    fetched_at: u64,
}

/// Single versioned file ensuring the two feed snapshots cannot be mixed by a crash.
#[derive(Deserialize, Serialize)]
struct CacheEnvelope {
    /// Supported cache format version.
    version: u32,
    /// Local Unix time of the complete successful download.
    fetched_at: u64,
    /// Base64-encoded original changeset containing canonical signed values.
    onecrl_response: String,
    /// Base64-encoded PEM chain selected during Mozilla signing-key rotation.
    onecrl_certificate_chain: String,
    /// Base64-encoded original CRX, retaining publisher signatures for verification.
    crlset_crx: String,
}

/// Require a Tokio runtime before constructing clients or blocking worker tasks.
///
/// # Errors
///
/// Returns [`Error::RuntimeRequired`] outside a Tokio runtime.
fn require_runtime() -> Result<()> {
    tokio::runtime::Handle::try_current()
        .map(|_| ())
        .map_err(|_| Error::RuntimeRequired)
}

/// Read the current wall clock as a duration without silently accepting pre-epoch time.
///
/// # Errors
///
/// Returns an error when the system clock is before the Unix epoch.
fn unix_now() -> Result<Duration> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::InvalidFormat("system clock is before the Unix epoch"))
}

/// Reject snapshots that are too old or timestamped after the supplied check time.
///
/// # Errors
///
/// Returns [`Error::StaleSnapshot`] for a future timestamp or an age above `max_age`.
fn ensure_fresh(fetched_at: u64, unix_time: u64, max_age: Duration) -> Result<()> {
    let age = unix_time
        .checked_sub(fetched_at)
        .ok_or(Error::StaleSnapshot)?;
    if Duration::from_secs(age) > max_age {
        return Err(Error::StaleSnapshot);
    }
    Ok(())
}

/// Schedule the first refresh from the original fetch time, not this cache load.
///
/// # Errors
///
/// Returns an error for a pre-epoch clock or overflowing refresh deadline.
fn initial_refresh_delay(fetched_at: u64, interval: Duration) -> Result<Duration> {
    let due = Duration::from_secs(fetched_at)
        .checked_add(interval)
        .ok_or(Error::InvalidFormat("cache refresh deadline overflow"))?;
    Ok(due.saturating_sub(unix_now()?))
}

/// Validate, index, and reject an expired CRLSet using the authoritative byte header.
///
/// # Errors
///
/// Returns feed-format errors or [`Error::ExpiredCrlSet`] for an expired snapshot.
fn index_pair(onecrl: &OneCrl, crlset: &CrlSet, fetched_at: u64) -> Result<Arc<SnapshotState>> {
    let set = RevocationSet::from_snapshots(Some(onecrl), Some(crlset))?;
    if crlset
        .header
        .extra
        .get("NotAfter")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|expiry| expiry != 0 && fetched_at > expiry)
    {
        return Err(Error::ExpiredCrlSet);
    }
    Ok(Arc::new(SnapshotState {
        set: Arc::new(set),
        fetched_at,
    }))
}

/// Read one bounded envelope and require fresh complete feed data.
///
/// # Errors
///
/// Returns I/O, JSON, size, version, timestamp, base64, publisher-signature, or
/// feed validation errors.
fn read_cache(
    path: &Path,
    max_age: Duration,
    publisher_key_hash: &[u8; 32],
    onecrl_trust: OneCrlTrust,
) -> Result<Arc<SnapshotState>> {
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > MAX_CACHE_BYTES {
        return Err(Error::SizeLimit(MAX_CACHE_BYTES));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CACHE_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_CACHE_BYTES {
        return Err(Error::SizeLimit(MAX_CACHE_BYTES));
    }
    let envelope: CacheEnvelope = serde_json::from_slice(&bytes)?;
    if envelope.version != CACHE_VERSION {
        return Err(Error::InvalidFormat("unsupported revocation cache version"));
    }
    let now = unix_now()?.as_secs();
    ensure_fresh(envelope.fetched_at, now, max_age)?;
    let onecrl_response = decode_cache_field(
        &envelope.onecrl_response,
        MAX_ONECRL_BYTES,
        "invalid OneCRL response base64 in cache",
    )?;
    let onecrl_certificate_chain = decode_cache_field(
        &envelope.onecrl_certificate_chain,
        MAX_CERTIFICATE_CHAIN_BYTES,
        "invalid OneCRL certificate-chain base64 in cache",
    )?;
    let onecrl = AuthenticatedOneCrl::from_saved(
        onecrl_response,
        onecrl_certificate_chain,
        onecrl_trust,
        now,
    )?;
    if envelope.crlset_crx.len() > MAX_CRX_BYTES.div_ceil(3) * 4 {
        return Err(Error::SizeLimit(MAX_CRX_BYTES as u64));
    }
    let bytes = STANDARD
        .decode(&envelope.crlset_crx)
        .map_err(|_| Error::InvalidFormat("invalid CRX base64 in cache"))?;
    if bytes.len() > MAX_CRX_BYTES {
        return Err(Error::SizeLimit(MAX_CRX_BYTES as u64));
    }
    let crlset =
        CrlSet::from_signed_crx_with_key(bytes, MAX_CRLSET_BYTES as u64, publisher_key_hash)?;
    let state = index_pair(&onecrl.snapshot, &crlset, envelope.fetched_at)?;
    // Expiration is evaluated at load time, rather than only at the cached fetch time.
    if crlset
        .header
        .extra
        .get("NotAfter")
        .and_then(serde_json::Value::as_u64)
        .is_some_and(|expiry| expiry != 0 && now > expiry)
    {
        return Err(Error::ExpiredCrlSet);
    }
    Ok(state)
}

/// Decode one bounded base64 field without permitting encoded-size amplification.
///
/// # Errors
///
/// Returns a size error for an excessive encoded or decoded value, and an
/// invalid-format error for malformed base64.
fn decode_cache_field(encoded: &str, maximum: usize, malformed: &'static str) -> Result<Vec<u8>> {
    if encoded.len() > maximum.div_ceil(3) * 4 {
        return Err(Error::SizeLimit(maximum as u64));
    }
    let decoded = STANDARD
        .decode(encoded)
        .map_err(|_| Error::InvalidFormat(malformed))?;
    if decoded.len() > maximum {
        return Err(Error::SizeLimit(maximum as u64));
    }
    Ok(decoded)
}

/// Persist one complete pair through a same-directory atomic rename and file sync.
///
/// # Errors
///
/// Returns directory, serialization, size, flush, sync, or atomic replacement errors.
fn write_cache(directory: &Path, envelope: &CacheEnvelope) -> Result<()> {
    std::fs::create_dir_all(directory)?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer(temporary.as_file_mut(), envelope)?;
    if temporary.as_file().metadata()?.len() > MAX_CACHE_BYTES {
        return Err(Error::SizeLimit(MAX_CACHE_BYTES));
    }
    temporary.as_file_mut().flush()?;
    temporary.as_file().sync_all()?;
    temporary
        .persist(directory.join(CACHE_FILENAME))
        .map_err(|error| error.error)?;
    // Unix directory synchronization makes the replacement durable across a crash.
    #[cfg(unix)]
    std::fs::File::open(directory)?.sync_all()?;
    Ok(())
}

/// Download a complete pair, validate it, and persist before publishing its state.
///
/// # Errors
///
/// Returns source, clock, feed-format, expired CRLSet, cache, or blocking task errors.
async fn fetch_and_persist(
    source: &dyn FeedLoader,
    directory: &Path,
    publisher_key_hash: [u8; 32],
    onecrl_trust: OneCrlTrust,
) -> Result<Arc<SnapshotState>> {
    let (onecrl, crlset) = source.fetch().await?;
    let fetched_at = unix_now()?.as_secs();
    let directory = directory.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let signed_crx = crlset
            .signed_crx
            .ok_or(Error::InvalidFormat("CRLSet is missing its signed CRX"))?;
        if signed_crx.len() > MAX_CRX_BYTES {
            return Err(Error::SizeLimit(MAX_CRX_BYTES as u64));
        }
        // Reconstruct from authenticated bytes, ignoring mutable public payload/header fields.
        let crlset = CrlSet::from_signed_crx_with_key(
            signed_crx.clone(),
            MAX_CRLSET_BYTES as u64,
            &publisher_key_hash,
        )?;
        if onecrl.response.len() > MAX_ONECRL_BYTES {
            return Err(Error::SizeLimit(MAX_ONECRL_BYTES as u64));
        }
        if onecrl.certificate_chain.len() > MAX_CERTIFICATE_CHAIN_BYTES {
            return Err(Error::SizeLimit(MAX_CERTIFICATE_CHAIN_BYTES as u64));
        }
        // Reconstruct from authenticated bytes, ignoring mutable public snapshot fields.
        let onecrl = AuthenticatedOneCrl::from_saved(
            onecrl.response,
            onecrl.certificate_chain,
            onecrl_trust,
            fetched_at,
        )?;
        let state = index_pair(&onecrl.snapshot, &crlset, fetched_at)?;
        let envelope = CacheEnvelope {
            version: CACHE_VERSION,
            fetched_at,
            onecrl_response: STANDARD.encode(&onecrl.response),
            onecrl_certificate_chain: STANDARD.encode(&onecrl.certificate_chain),
            crlset_crx: STANDARD.encode(signed_crx),
        };
        write_cache(&directory, &envelope)?;
        Ok(state)
    })
    .await
    .map_err(|_| Error::InvalidFormat("cache write task failed"))?
}

/// Refresh without holding a strong live-handle reference across sleeps or downloads.
async fn refresh_loop(
    live: Weak<Revocations>,
    source: Arc<dyn FeedLoader>,
    cache_dir: PathBuf,
    interval: Duration,
    mut delay: Duration,
    publisher_key_hash: [u8; 32],
    onecrl_trust: OneCrlTrust,
) {
    loop {
        tokio::time::sleep(delay).await;
        if live.strong_count() == 0 {
            return;
        }
        let refreshed = fetch_and_persist(
            source.as_ref(),
            &cache_dir,
            publisher_key_hash,
            onecrl_trust,
        )
        .await;
        let Some(handle) = live.upgrade() else {
            return;
        };
        match refreshed {
            Ok(state) => {
                handle.current.store(state);
                *handle.error_guard() = None;
            }
            Err(error) => *handle.error_guard() = Some(error.to_string()),
        }
        drop(handle);
        delay = interval;
    }
}

#[cfg(test)]
#[path = "../tests/unit/cache.rs"]
mod tests;
