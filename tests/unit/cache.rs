//! Offline cache, atomic publication, lifetime, and refresh policy regressions.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::Notify;

use super::*;

/// Deterministic response to one complete-pair loading attempt.
enum Outcome {
    /// A successful complete pair of feed snapshots.
    Feeds(OneCrl, CrlSet),
    /// A failure that must not replace the current snapshot.
    Failure,
    /// A failure held until the test has inspected the preceding successful state.
    GatedFailure(Arc<Notify>),
    /// A complete pair held until the test has inspected failure retention.
    GatedFeeds(Arc<Notify>, OneCrl, CrlSet),
    /// An in-flight request that remains pending until its task is aborted.
    Pending,
}

/// Injected feed source tracking attempts without opening network sockets.
struct MockLoader {
    /// Scripted outcomes in request order, followed by failures indefinitely.
    outcomes: Mutex<VecDeque<Outcome>>,
    /// Number of complete-pair attempts started.
    calls: AtomicUsize,
    /// Notification emitted when a scripted pending request starts.
    pending_started: Notify,
}

impl MockLoader {
    /// Build a source with deterministic outcomes and no real HTTP client.
    fn new(outcomes: Vec<Outcome>) -> Arc<Self> {
        Arc::new(Self {
            outcomes: Mutex::new(outcomes.into()),
            calls: AtomicUsize::new(0),
            pending_started: Notify::new(),
        })
    }
}

impl FeedLoader for MockLoader {
    fn fetch(&self) -> FeedFuture<'_> {
        Box::pin(async {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let outcome = self
                .outcomes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .pop_front()
                .unwrap_or(Outcome::Failure);
            match outcome {
                Outcome::Feeds(onecrl, crlset) => Ok((onecrl, crlset)),
                Outcome::Failure => Err(Error::InvalidFormat("scripted refresh failure")),
                Outcome::GatedFailure(gate) => {
                    gate.notified().await;
                    Err(Error::InvalidFormat("scripted refresh failure"))
                }
                Outcome::GatedFeeds(gate, onecrl, crlset) => {
                    gate.notified().await;
                    Ok((onecrl, crlset))
                }
                Outcome::Pending => {
                    self.pending_started.notify_one();
                    std::future::pending().await
                }
            }
        })
    }
}

/// Current Unix second for fresh, portable cache fixtures.
///
/// # Panics
///
/// Panics if the test system's clock is before the Unix epoch.
fn now() -> u64 {
    unix_now().expect("test clock").as_secs()
}

/// Create a complete small CRLSet around additional header metadata.
///
/// # Panics
///
/// Panics if the test header cannot be framed as a supported small CRLSet.
fn crlset(sequence: u64, extra: Value) -> CrlSet {
    let mut header = json!({"ContentType": "CRLSet", "Version": 0, "Sequence": sequence});
    header
        .as_object_mut()
        .expect("header object")
        .extend(extra.as_object().expect("extra object").clone());
    let header = header.to_string();
    let mut bytes = u16::try_from(header.len())
        .expect("small header")
        .to_le_bytes()
        .to_vec();
    bytes.extend_from_slice(header.as_bytes());
    parse_crx(crate::crx::test_support::signed_crx(&bytes))
}

/// Verify a synthetic signed envelope with the fixed test publisher key.
///
/// # Panics
///
/// Panics when the test envelope is not a correctly signed, supported CRLSet.
fn parse_crx(bytes: Vec<u8>) -> CrlSet {
    CrlSet::from_signed_crx_with_key(
        bytes,
        MAX_CRLSET_BYTES as u64,
        &crate::crx::test_support::publisher_key_hash(),
    )
    .expect("authenticated test CRLSet")
}

/// Construct a pair with matching visible sequence identifiers and optional leaf block.
///
/// # Panics
///
/// Panics if a supplied generated certificate cannot be parsed.
fn feeds(sequence: u64, blocked: Option<&[u8]>) -> (OneCrl, CrlSet) {
    let onecrl = OneCrl {
        timestamp: sequence,
        metadata: json!({}),
        changes: vec![],
    };
    let extra = blocked.map_or_else(
        || json!({}),
        |der| {
            let (_, certificate) =
                x509_parser::parse_x509_certificate(der).expect("generated leaf");
            json!({"BlockedSPKIs": [STANDARD.encode(Sha256::digest(certificate.public_key().raw))]})
        },
    );
    (onecrl, crlset(sequence, extra))
}

/// Create one versioned complete envelope at a caller-selected fetch time.
///
/// # Panics
///
/// Panics if the generated test CRLSet lacks its signed container.
fn envelope(sequence: u64, fetched_at: u64) -> CacheEnvelope {
    let (onecrl, crlset) = feeds(sequence, None);
    CacheEnvelope {
        version: CACHE_VERSION,
        fetched_at,
        onecrl,
        crlset_crx: STANDARD.encode(crlset.signed_crx.expect("signed test CRLSet")),
    }
}

/// Use an isolated temporary cache directory and a slow background interval.
fn config(directory: &Path) -> CacheConfig {
    CacheConfig {
        publisher_key_hash: crate::crx::test_support::publisher_key_hash(),
        ..CacheConfig::default()
    }
    .with_cache_dir(directory.to_path_buf())
    .with_refresh_interval(Duration::from_secs(60))
    .with_max_age(Duration::from_secs(300))
}

/// Wait briefly for an asynchronous state transition with a bounded test timeout.
///
/// # Panics
///
/// Panics if the expected transition is not observed within three seconds.
async fn wait_until(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("background transition completes");
}

/// Calls outside a Tokio runtime return a typed error without constructing HTTP transport.
#[test]
fn missing_runtime_is_reported_without_panicking() {
    let mut future = std::pin::pin!(fetch());
    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        future.as_mut().poll(&mut context),
        Poll::Ready(Err(Error::RuntimeRequired))
    ));
}

/// Invalid timing policy and absent platform directory fail before work is spawned.
#[test]
fn invalid_configurations_fail_validation() {
    let base = config(Path::new("unused"));
    for invalid in [
        base.clone().with_refresh_interval(Duration::ZERO),
        base.clone().with_max_age(Duration::ZERO),
        base.clone().with_refresh_interval(Duration::from_secs(301)),
        base.with_refresh_interval(Duration::MAX)
            .with_max_age(Duration::MAX),
    ] {
        assert!(matches!(invalid.validate(), Err(Error::InvalidFormat(_))));
    }
    let unavailable = CacheConfig {
        cache_dir: None,
        ..CacheConfig::default()
    };
    assert!(matches!(
        unavailable.validate(),
        Err(Error::CacheUnavailable)
    ));
}

/// A valid fresh cache causes no source calls and preserves its original fetch time.
#[tokio::test]
async fn fresh_cache_hit_uses_no_network_and_preserves_age() {
    let directory = tempfile::tempdir().expect("cache directory");
    let fetched_at = now().saturating_sub(10);
    let original = envelope(7, fetched_at);
    let signed_crx = STANDARD.decode(&original.crlset_crx).expect("signed CRX");
    write_cache(directory.path(), &original).expect("initial cache");
    let source = MockLoader::new(vec![Outcome::Failure]);
    let live = config(directory.path())
        .load_with_source(source.clone())
        .await
        .expect("cached feeds");
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(live.last_updated_unix(), fetched_at);
    assert!(live.last_refresh_error().is_none());
    let saved: CacheEnvelope = serde_json::from_slice(
        &std::fs::read(directory.path().join(CACHE_FILENAME)).expect("saved cache"),
    )
    .expect("cache envelope");
    assert_eq!(
        STANDARD.decode(saved.crlset_crx).expect("CRX bytes"),
        signed_crx
    );
    assert_eq!(parse_crx(signed_crx.clone()).signed_crx, Some(signed_crx));
    assert!(
        initial_refresh_delay(fetched_at, Duration::from_secs(60)).expect("deadline")
            <= Duration::from_secs(50)
    );
    drop(live);
}

/// Legacy unpacked snapshots never initialize managed state or replace a failed download.
#[tokio::test]
async fn legacy_unsigned_cache_is_ignored_and_replacement_must_succeed() {
    for replacement_succeeds in [false, true] {
        let directory = tempfile::tempdir().expect("cache directory");
        let legacy_path = directory.path().join("snapshots-v1.json");
        let (legacy_onecrl, legacy_crlset) = feeds(1, None);
        let legacy_bytes = serde_json::to_vec(&json!({
            "version": 1,
            "fetched_at": now(),
            "onecrl": legacy_onecrl,
            "crlset": STANDARD.encode(legacy_crlset.bytes),
            "authenticated": true,
        }))
        .expect("legacy cache");
        std::fs::write(&legacy_path, &legacy_bytes).expect("legacy fixture");
        let (onecrl, crlset) = feeds(2, None);
        let outcome = if replacement_succeeds {
            Outcome::Feeds(onecrl, crlset)
        } else {
            Outcome::Failure
        };
        let source = MockLoader::new(vec![outcome]);
        let result = config(directory.path())
            .load_with_source(source.clone())
            .await;
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
        assert_eq!(result.is_ok(), replacement_succeeds);
        assert_eq!(
            std::fs::read(&legacy_path).expect("unchanged legacy cache"),
            legacy_bytes
        );
        assert_eq!(
            directory.path().join(CACHE_FILENAME).exists(),
            replacement_succeeds
        );
    }
}

/// Signature and publisher failures force a fresh pair and fail closed without one.
#[tokio::test]
async fn unauthenticated_cache_never_supplies_managed_state() {
    for case in 0..4 {
        for replacement_succeeds in [false, true] {
            let directory = tempfile::tempdir().expect("cache directory");
            let mut cached = envelope(1, now());
            let payload = crlset(1, json!({})).bytes;
            let invalid_crx = match case {
                0 => {
                    let mut crx = crate::crx::test_support::signed_crx(&payload);
                    *crx.last_mut().expect("nonempty ZIP") ^= 1;
                    crx
                }
                1 => crate::crx::test_support::tampered_signature_crx(&payload),
                2 => crate::crx::test_support::signed_crx_with_unrelated_key(&payload),
                3 => payload,
                _ => unreachable!("bounded cache case"),
            };
            cached.crlset_crx = STANDARD.encode(invalid_crx);
            let mut forged_cache = serde_json::to_value(&cached).expect("cache JSON");
            forged_cache["authenticated"] = json!(true);
            forged_cache["publisher_verified"] = json!(true);
            let path = directory.path().join(CACHE_FILENAME);
            std::fs::write(
                &path,
                serde_json::to_vec(&forged_cache).expect("forged cache"),
            )
            .expect("invalid fixture");
            assert!(
                read_cache(
                    &path,
                    Duration::from_secs(300),
                    &crate::crx::test_support::publisher_key_hash(),
                )
                .is_err()
            );
            let (onecrl, crlset) = feeds(2, None);
            let outcome = if replacement_succeeds {
                Outcome::Feeds(onecrl, crlset)
            } else {
                Outcome::Failure
            };
            let source = MockLoader::new(vec![outcome]);
            let result = config(directory.path())
                .load_with_source(source.clone())
                .await;
            assert_eq!(source.calls.load(Ordering::SeqCst), 1, "cache case {case}");
            assert_eq!(result.is_ok(), replacement_succeeds, "cache case {case}");
            if replacement_succeeds {
                let saved: CacheEnvelope =
                    serde_json::from_slice(&std::fs::read(path).expect("replacement cache"))
                        .expect("complete replacement");
                assert_eq!(saved.onecrl.timestamp, 2);
                assert_eq!(
                    parse_crx(STANDARD.decode(saved.crlset_crx).expect("replacement CRX"))
                        .header
                        .sequence,
                    2,
                );
            }
        }
    }
}

/// Default cache policy pins Google's publisher instead of trusting a signed cache claim.
#[tokio::test]
async fn default_policy_rejects_an_unrelated_publisher() {
    let directory = tempfile::tempdir().expect("cache directory");
    write_cache(directory.path(), &envelope(1, now())).expect("unrelated signer fixture");
    let config = CacheConfig::default().with_cache_dir(directory.path().to_path_buf());
    assert_eq!(
        config.publisher_key_hash,
        crate::crx::CRLSET_PUBLISHER_KEY_HASH
    );
    assert_ne!(
        config.publisher_key_hash,
        crate::crx::test_support::publisher_key_hash()
    );
    assert!(
        read_cache(
            &directory.path().join(CACHE_FILENAME),
            config.max_age,
            &config.publisher_key_hash,
        )
        .is_err()
    );
    let source = MockLoader::new(vec![Outcome::Failure]);
    assert!(config.load_with_source(source.clone()).await.is_err());
    assert_eq!(source.calls.load(Ordering::SeqCst), 1);
}

/// Cache publication reconstructs the authenticated payload instead of trusting mutable fields.
#[tokio::test]
async fn publication_uses_signed_payload_and_rejects_unsigned_snapshots() {
    let directory = tempfile::tempdir().expect("cache directory");
    let (onecrl, mut downloaded) = feeds(7, None);
    let authentic_crx = downloaded.signed_crx.clone().expect("signed fixture");
    downloaded.bytes.clear();
    downloaded.header.sequence = 999;
    let source = MockLoader::new(vec![Outcome::Feeds(onecrl, downloaded)]);
    let live = config(directory.path())
        .load_with_source(source)
        .await
        .expect("authenticate original container");
    let saved: CacheEnvelope = serde_json::from_slice(
        &std::fs::read(directory.path().join(CACHE_FILENAME)).expect("published cache"),
    )
    .expect("published envelope");
    assert_eq!(
        STANDARD.decode(saved.crlset_crx).expect("original CRX"),
        authentic_crx
    );
    assert_eq!(parse_crx(authentic_crx).header.sequence, 7);
    drop(live);

    let unsigned_directory = tempfile::tempdir().expect("unsigned cache directory");
    let (onecrl, signed) = feeds(8, None);
    let unsigned = CrlSet::from_bytes(signed.bytes).expect("raw unsigned snapshot");
    let source = MockLoader::new(vec![Outcome::Feeds(onecrl, unsigned)]);
    assert!(
        config(unsigned_directory.path())
            .load_with_source(source)
            .await
            .is_err()
    );
    assert!(!unsigned_directory.path().join(CACHE_FILENAME).exists());
}

/// Missing, corrupt, stale, future, unsupported, and expired caches refresh completely.
#[tokio::test]
async fn invalid_caches_are_replaced_with_complete_pairs() {
    for case in 0..9 {
        let directory = tempfile::tempdir().expect("cache directory");
        let path = directory.path().join(CACHE_FILENAME);
        let mut cached = envelope(1, now());
        match case {
            0 => {}
            1 => std::fs::write(&path, b"truncated{").expect("corrupt fixture"),
            2 => {
                cached.fetched_at = now().saturating_sub(301);
                write_cache(directory.path(), &cached).expect("stale fixture");
            }
            3 => {
                cached.fetched_at = now() + 60;
                write_cache(directory.path(), &cached).expect("future fixture");
            }
            4 => {
                cached.version += 1;
                write_cache(directory.path(), &cached).expect("version fixture");
            }
            5 => {
                cached.crlset_crx = "bad!".into();
                write_cache(directory.path(), &cached).expect("bad base64 fixture");
            }
            6 => {
                cached.crlset_crx = STANDARD.encode(
                    crlset(1, json!({"NotAfter": now().saturating_sub(1)}))
                        .signed_crx
                        .expect("signed expired CRLSet"),
                );
                write_cache(directory.path(), &cached).expect("expired fixture");
            }
            7 => {
                let file = std::fs::File::create(&path).expect("large fixture");
                file.set_len(MAX_CACHE_BYTES + 1).expect("sparse fixture");
            }
            8 => {
                cached.version = 1;
                write_cache(directory.path(), &cached).expect("legacy version fixture");
            }
            _ => unreachable!("bounded test case"),
        }
        let (onecrl, crlset) = feeds(2, None);
        let source = MockLoader::new(vec![Outcome::Feeds(onecrl, crlset)]);
        let live = config(directory.path())
            .load_with_source(source.clone())
            .await
            .expect("replacement feeds");
        assert_eq!(source.calls.load(Ordering::SeqCst), 1, "cache case {case}");
        let saved: CacheEnvelope =
            serde_json::from_slice(&std::fs::read(&path).expect("saved pair"))
                .expect("saved envelope");
        assert_eq!(saved.version, CACHE_VERSION);
        assert_eq!(saved.onecrl.timestamp, 2);
        assert_eq!(
            parse_crx(STANDARD.decode(saved.crlset_crx).expect("saved base64"))
                .header
                .sequence,
            2
        );
        drop(live);
    }
}

/// Initialization fails without publishing or caching a partial/expired download.
#[tokio::test]
async fn initial_failure_and_expired_download_do_not_create_cache() {
    for outcome in [
        Outcome::Failure,
        Outcome::Feeds(feeds(1, None).0, crlset(1, json!({"NotAfter": 1}))),
    ] {
        let directory = tempfile::tempdir().expect("cache directory");
        let source = MockLoader::new(vec![outcome]);
        assert!(
            config(directory.path())
                .load_with_source(source.clone())
                .await
                .is_err()
        );
        assert_eq!(source.calls.load(Ordering::SeqCst), 1);
        assert!(!directory.path().join(CACHE_FILENAME).exists());
    }
}

/// Atomic replacements keep readers on a complete matching pair and leave no temporary files.
#[test]
fn atomic_cache_replacements_keep_complete_pairs() {
    let directory = tempfile::tempdir().expect("cache directory");
    let fetched_at = now();
    write_cache(directory.path(), &envelope(0, fetched_at)).expect("initial cache");
    let path = directory.path().join(CACHE_FILENAME);
    let reader = std::thread::spawn(move || {
        for _ in 0..100 {
            let saved: CacheEnvelope =
                serde_json::from_slice(&std::fs::read(&path).expect("read atomic file"))
                    .expect("complete JSON");
            let crlset = parse_crx(STANDARD.decode(saved.crlset_crx).expect("base64"));
            assert_eq!(saved.onecrl.timestamp, crlset.header.sequence);
        }
    });
    for sequence in 1..20 {
        write_cache(directory.path(), &envelope(sequence, fetched_at)).expect("atomic replacement");
    }
    reader.join().expect("atomic reader");
    assert_eq!(
        std::fs::read_dir(directory.path())
            .expect("directory entries")
            .count(),
        1
    );
    assert!(
        read_cache(
            &directory.path().join(CACHE_FILENAME),
            Duration::from_secs(60),
            &crate::crx::test_support::publisher_key_hash(),
        )
        .is_ok()
    );
}

/// Managed checks reject stale and future-dated snapshots at the exact age boundary.
#[tokio::test]
async fn live_checks_enforce_maximum_age_without_mutating_static_snapshots() {
    let directory = tempfile::tempdir().expect("cache directory");
    let (onecrl, crlset) = feeds(1, None);
    let source = MockLoader::new(vec![Outcome::Feeds(onecrl, crlset)]);
    let live = config(directory.path())
        .load_with_source(source)
        .await
        .expect("live snapshot");
    let generated = rcgen::generate_simple_self_signed(vec!["example.test".into()]).expect("leaf");
    let chain = [generated.cert.der().as_ref()];
    let fetched_at = live.last_updated_unix();
    assert_eq!(
        live.check_chain(&chain, fetched_at + 300)
            .expect("maximum age boundary"),
        RevocationStatus::NotListed
    );
    assert!(matches!(
        live.check_chain(&chain, fetched_at + 301),
        Err(Error::StaleSnapshot)
    ));
    assert!(matches!(
        live.check_chain_all(&chain, fetched_at + 301),
        Err(Error::StaleSnapshot)
    ));
    assert!(matches!(
        live.check_chain(&chain, fetched_at - 1),
        Err(Error::StaleSnapshot)
    ));
    assert_eq!(
        live.snapshot()
            .check_chain(&chain, fetched_at + 301)
            .expect("explicit static view"),
        RevocationStatus::NotListed
    );
}

/// Managed checks normalize mixed encodings before matching and deduplicating certificates.
#[tokio::test]
async fn managed_checks_accept_mixed_certificate_encodings_and_deduplicate() {
    let directory = tempfile::tempdir().expect("cache directory");
    let blocked = rcgen::generate_simple_self_signed(vec!["blocked.test".into()])
        .expect("blocked certificate");
    let unblocked = rcgen::generate_simple_self_signed(vec!["unblocked.test".into()])
        .expect("unblocked certificate");
    let (onecrl, crlset) = feeds(1, Some(blocked.cert.der().as_ref()));
    let source = MockLoader::new(vec![Outcome::Feeds(onecrl, crlset)]);
    let live = config(directory.path())
        .load_with_source(source)
        .await
        .expect("managed snapshot");
    let pem = blocked.cert.pem();
    let base64 = STANDARD.encode(blocked.cert.der().as_ref());
    let mixed = [
        unblocked.cert.der().as_ref(),
        pem.as_bytes(),
        base64.as_bytes(),
        blocked.cert.der().as_ref(),
    ];
    let unix_time = live.last_updated_unix();
    assert_eq!(
        live.check_chain(&mixed, unix_time)
            .expect("mixed certificate encodings"),
        RevocationStatus::Revoked(crate::RevocationMatch {
            certificate_index: 1,
            reason: crate::RevocationReason::CrlSetBlockedSpki,
        }),
    );
    assert_eq!(
        live.check_chain_all(&mixed, unix_time)
            .expect("distinct normalized matches"),
        vec![CertificateRevocations {
            certificate_index: 1,
            reasons: vec![crate::RevocationReason::CrlSetBlockedSpki],
        }],
    );
}

/// Scheduled refresh updates the shared index, retains failed data, and clears diagnostics.
#[tokio::test]
async fn background_refresh_updates_and_retains_last_good_snapshot_after_failure() {
    let directory = tempfile::tempdir().expect("cache directory");
    write_cache(directory.path(), &envelope(1, now().saturating_sub(1))).expect("due cache");
    let generated = rcgen::generate_simple_self_signed(vec!["example.test".into()]).expect("leaf");
    let chain = [generated.cert.der().as_ref()];
    let (onecrl, crlset) = feeds(2, Some(chain[0]));
    let (clear_onecrl, clear_crlset) = feeds(3, None);
    let failure_gate = Arc::new(Notify::new());
    let recovery_gate = Arc::new(Notify::new());
    let source = MockLoader::new(vec![
        Outcome::Feeds(onecrl, crlset),
        Outcome::GatedFailure(Arc::clone(&failure_gate)),
        Outcome::GatedFeeds(Arc::clone(&recovery_gate), clear_onecrl, clear_crlset),
    ]);
    let live = config(directory.path())
        .with_refresh_interval(Duration::from_millis(40))
        .load_with_source(source.clone())
        .await
        .expect("cached live handle");
    wait_until(|| {
        matches!(
            live.check_chain(&chain, now()),
            Ok(RevocationStatus::Revoked(_))
        )
    })
    .await;
    let blocked_snapshot = live.snapshot();
    failure_gate.notify_one();
    wait_until(|| live.last_refresh_error().is_some()).await;
    assert!(Arc::ptr_eq(&blocked_snapshot, &live.snapshot()));
    assert!(matches!(
        live.check_chain(&chain, now()),
        Ok(RevocationStatus::Revoked(_))
    ));
    recovery_gate.notify_one();
    wait_until(|| source.calls.load(Ordering::SeqCst) >= 3 && live.last_refresh_error().is_none())
        .await;
    assert_eq!(
        live.check_chain(&chain, now()).expect("new clear snapshot"),
        RevocationStatus::NotListed
    );
    assert!(matches!(
        blocked_snapshot.check_chain(&chain, now()),
        Ok(RevocationStatus::Revoked(_))
    ));
    let saved = read_cache(
        &directory.path().join(CACHE_FILENAME),
        Duration::from_secs(300),
        &crate::crx::test_support::publisher_key_hash(),
    )
    .expect("refreshed cache");
    assert_eq!(
        saved
            .set
            .check_chain(&chain, now())
            .expect("persisted clear index"),
        RevocationStatus::NotListed
    );
}

/// Dropping the last live handle cancels an in-flight refresh without retaining a cycle.
#[tokio::test]
async fn dropping_last_handle_aborts_pending_refresh_without_reference_cycle() {
    let directory = tempfile::tempdir().expect("cache directory");
    write_cache(directory.path(), &envelope(1, now().saturating_sub(1))).expect("due cache");
    let source = MockLoader::new(vec![Outcome::Pending]);
    let live = config(directory.path())
        .with_refresh_interval(Duration::from_millis(40))
        .load_with_source(source.clone())
        .await
        .expect("cached handle");
    tokio::time::timeout(Duration::from_secs(3), source.pending_started.notified())
        .await
        .expect("refresh starts");
    let weak_live = Arc::downgrade(&live);
    let weak_source = Arc::downgrade(&source);
    drop(source);
    drop(live);
    assert!(weak_live.upgrade().is_none());
    wait_until(|| weak_source.upgrade().is_none()).await;
}
