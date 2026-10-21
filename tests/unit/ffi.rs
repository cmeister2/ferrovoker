//! ABI contract tests requiring no network service or C compiler.

use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::ffi::CStr;

use crate::{OneCrl, RevocationSet};

/// Complete, empty OneCRL snapshot for exercising handle ownership.
const EMPTY_ONECRL: &[u8] = br#"{"timestamp":0,"metadata":{},"changes":[]}"#;

/// Read the current diagnostic into an owned string for assertions.
fn error() -> String {
    // SAFETY: The ABI returns a live, nonnull thread-local C string.
    unsafe { CStr::from_ptr(ferrovoker_last_error()) }
        .to_string_lossy()
        .into_owned()
}

/// Construct a managed-runtime handle using a local OneCRL fixture.
///
/// # Panics
///
/// Panics if the valid fixture cannot be parsed or its runtime cannot be created.
fn snapshot_handle(snapshot: &[u8]) -> *mut Ferrovoker {
    let onecrl = OneCrl::from_slice(snapshot).expect("valid OneCRL fixture");
    let revocations = Arc::new(
        RevocationSet::from_snapshots(Some(&onecrl), None).expect("valid revocation fixture"),
    );
    let mut handle = ptr::null_mut();
    // SAFETY: The exclusive output slot remains valid during construction.
    let status = unsafe { new_with_loader(&mut handle, |_| Ok(revocations)) };
    assert_eq!(status, 0, "{}", error());
    assert!(!handle.is_null());
    handle
}

/// Construct a handle backed by an empty local OneCRL fixture.
///
/// # Panics
///
/// Panics if creating the fixture handle fails.
fn empty_handle() -> *mut Ferrovoker {
    snapshot_handle(EMPTY_ONECRL)
}

/// Notify the test when an executor-owned background future is destroyed.
struct DropSignal(std::sync::mpsc::Sender<()>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        let _ = self.0.send(());
    }
}

/// Install a pending background task and wait until the executor has started it.
///
/// # Errors
///
/// Returns an error if the background task stops before signaling readiness.
fn start_background_task(
    runtime: &Runtime,
    stopped: std::sync::mpsc::Sender<()>,
) -> Result<(), String> {
    let (started, ready) = tokio::sync::oneshot::channel();
    runtime.spawn(async move {
        let _lifetime = DropSignal(stopped);
        let _ = started.send(());
        std::future::pending::<()>().await;
    });
    runtime.block_on(ready).map_err(|error| error.to_string())
}

/// Initial load failures clear output, preserve diagnostics, and stop their runtime.
#[test]
fn constructor_reports_load_errors_and_cleans_up_runtime() {
    let mut handle = ptr::dangling_mut();
    let (stopped, stopped_rx) = std::sync::mpsc::channel();
    // SAFETY: The exclusive output slot remains valid during construction.
    let status = unsafe {
        new_with_loader(&mut handle, |runtime| {
            start_background_task(runtime, stopped)?;
            Err("initial managed load failed".to_owned())
        })
    };
    assert_eq!(status, -1);
    assert!(handle.is_null());
    assert_eq!(error(), "initial managed load failed");
    stopped_rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .expect("failed construction stops the background executor");
}

/// Null output slots are rejected before constructing clients or invoking a loader.
#[test]
fn constructor_rejects_null_output() {
    // SAFETY: Null output pointers are explicitly accepted as error inputs.
    assert_eq!(unsafe { ferrovoker_new(ptr::null_mut()) }, -1);
    assert!(error().contains("output"));
    // SAFETY: The null output is rejected before the closure can be invoked.
    assert_eq!(
        unsafe { new_with_loader(ptr::null_mut(), |_| panic!("loader must not run")) },
        -1
    );
    assert!(error().contains("output"));
}

/// The handle retains its provider and executor until the caller releases it.
#[test]
fn managed_constructor_retains_background_runtime_until_free() {
    let onecrl = OneCrl::from_slice(EMPTY_ONECRL).expect("valid empty fixture");
    let revocations = Arc::new(
        RevocationSet::from_snapshots(Some(&onecrl), None).expect("valid empty revocations"),
    );
    let provider = Arc::downgrade(&revocations);
    let mut handle = ptr::null_mut();
    let (stopped, stopped_rx) = std::sync::mpsc::channel();
    // SAFETY: The exclusive output slot remains valid during construction.
    let status = unsafe {
        new_with_loader(&mut handle, |runtime| {
            start_background_task(runtime, stopped)?;
            Ok(revocations)
        })
    };
    assert_eq!(status, 0, "{}", error());
    assert!(!handle.is_null());
    assert!(provider.upgrade().is_some());
    assert!(matches!(
        stopped_rx.try_recv(),
        Err(std::sync::mpsc::TryRecvError::Empty)
    ));
    // SAFETY: The test transfers its sole handle ownership to the destructor.
    unsafe { ferrovoker_free(handle) };
    assert!(provider.upgrade().is_none());
    stopped_rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .expect("freeing the handle stops its background executor");
    assert_eq!(error(), "");
}

/// Successful ownership operations clear errors and tolerate null frees.
#[test]
fn success_clears_diagnostic_and_free_accepts_null() {
    set_error("earlier failure");
    let handle = empty_handle();
    assert_eq!(error(), "");
    // SAFETY: This test owns the handle and does not reuse it after freeing.
    unsafe { ferrovoker_free(handle) };
    // SAFETY: Null handles are accepted by the destructor.
    unsafe { ferrovoker_free(ptr::null_mut()) };
    assert_eq!(error(), "");
}

/// Releasing a handle's refresh executor is safe inside another Tokio runtime.
#[tokio::test]
async fn managed_runtime_can_be_freed_inside_async_context() {
    let handle = empty_handle();
    // SAFETY: The test transfers its sole handle ownership to the destructor.
    unsafe { ferrovoker_free(handle) };
    assert_eq!(error(), "");
}

/// Nested runtime failures remain catchable while cleaning up the new executor.
#[tokio::test]
async fn failed_load_cleans_up_runtime_without_a_second_panic() {
    let mut handle = ptr::dangling_mut();
    // SAFETY: The exclusive output remains valid while a loader panic is contained.
    let status = unsafe {
        new_with_loader(&mut handle, |runtime| {
            runtime.block_on(std::future::ready(()));
            unreachable!("nested runtime loading must panic")
        })
    };
    assert_eq!(status, -1);
    assert!(handle.is_null());
    assert!(error().contains("panic"));
}

/// Malformed certificates return errors and leave a predictable match output.
#[test]
fn chain_failure_initializes_output() {
    let handle = empty_handle();
    let certificate = FerrovokerCertificate {
        data: b"bad DER".as_ptr(),
        len: 7,
    };
    let mut found = FerrovokerMatch {
        certificate_index: 7,
        reason: 5,
    };
    // SAFETY: Handle, descriptor, bytes, and exclusive output remain valid.
    let status = unsafe { ferrovoker_check_chain(handle, &certificate, 1, 0, &mut found) };
    assert_eq!(status, -1);
    assert_eq!(found, FerrovokerMatch::EMPTY);
    assert!(!error().is_empty());
    // SAFETY: This test owns the handle and has finished checking it.
    unsafe { ferrovoker_free(handle) };
}

/// DER, PEM, and base64 DER cross the ABI with identical matches and stable indices.
#[test]
fn certificate_formats_preserve_matches_indices_and_borrowed_inputs() {
    let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .expect("create test certificate");
    let der = certificate.cert.der();
    let encoded = STANDARD.encode(der);
    let formats = vec![
        der.to_vec(),
        format!(" \n{}\t\r\n", certificate.cert.pem()).into_bytes(),
        format!(" \n{}\n\t{}\r\n", &encoded[..20], &encoded[20..]).into_bytes(),
    ];
    let originals = formats.clone();
    let descriptors: Vec<_> = formats
        .iter()
        .map(|bytes| FerrovokerCertificate {
            data: bytes.as_ptr(),
            len: bytes.len(),
        })
        .collect();
    let mut found = FerrovokerMatch::EMPTY;
    let empty = empty_handle();
    for descriptor in &descriptors {
        // SAFETY: The handle, descriptor, certificate bytes, and output are valid.
        assert_eq!(
            unsafe { ferrovoker_check_chain(empty, descriptor, 1, 0, &mut found) },
            0,
            "{}",
            error()
        );
        assert_eq!(found, FerrovokerMatch::EMPTY);
    }
    // SAFETY: This test owns the handle and has finished using it.
    unsafe { ferrovoker_free(empty) };

    let (_, parsed) =
        x509_parser::parse_x509_certificate(der).expect("parse generated certificate");
    let snapshot = serde_json::json!({
        "timestamp": 0,
        "metadata": {},
        "changes": [{
            "id": "ffi-test",
            "last_modified": 0,
            "enabled": true,
            "issuerName": STANDARD.encode(parsed.issuer().as_raw()),
            "serialNumber": STANDARD.encode(parsed.raw_serial()),
        }]
    })
    .to_string();
    let revoked = snapshot_handle(snapshot.as_bytes());
    drop(snapshot);
    for descriptor in &descriptors {
        // SAFETY: The handle owns its feed data; descriptor and bytes remain valid.
        assert_eq!(
            unsafe { ferrovoker_check_chain(revoked, descriptor, 1, 0, &mut found) },
            1,
            "{}",
            error()
        );
        assert_eq!(
            found,
            FerrovokerMatch {
                certificate_index: 0,
                reason: 1,
            }
        );
    }

    let unlisted = rcgen::generate_simple_self_signed(vec!["other.example".to_owned()])
        .expect("create unrelated certificate");
    let unlisted_pem = unlisted.cert.pem();
    let mixed_chain = [
        FerrovokerCertificate {
            data: unlisted_pem.as_ptr(),
            len: unlisted_pem.len(),
        },
        descriptors[2],
        descriptors[0],
        descriptors[1],
    ];
    // SAFETY: All descriptors and backing buffers live unchanged through the call.
    assert_eq!(
        unsafe {
            ferrovoker_check_chain(
                revoked,
                mixed_chain.as_ptr(),
                mixed_chain.len(),
                0,
                &mut found,
            )
        },
        1,
        "{}",
        error()
    );
    assert_eq!(
        found,
        FerrovokerMatch {
            certificate_index: 1,
            reason: 1,
        }
    );
    assert_eq!(formats, originals);
    assert_eq!(error(), "");
    // SAFETY: This test owns the handle and has finished using it.
    unsafe { ferrovoker_free(revoked) };
}

/// Null handles, chains, outputs, and certificate bytes are rejected safely.
#[test]
fn check_rejects_null_arguments() {
    let handle = empty_handle();
    let certificate = FerrovokerCertificate {
        data: ptr::null(),
        len: 0,
    };
    let mut found = FerrovokerMatch::EMPTY;
    // SAFETY: The null handle is explicitly rejected before access.
    assert_eq!(
        unsafe { ferrovoker_check_chain(ptr::null(), &certificate, 1, 0, &mut found) },
        -1
    );
    // SAFETY: The null descriptor pointer is explicitly rejected before access.
    assert_eq!(
        unsafe { ferrovoker_check_chain(handle, ptr::null(), 1, 0, &mut found) },
        -1
    );
    // SAFETY: The null output is explicitly rejected before reading inputs.
    assert_eq!(
        unsafe { ferrovoker_check_chain(handle, &certificate, 1, 0, ptr::null_mut()) },
        -1
    );
    // SAFETY: The valid descriptor's null bytes are rejected before access.
    assert_eq!(
        unsafe { ferrovoker_check_chain(handle, &certificate, 1, 0, &mut found) },
        -1
    );
    assert_eq!(found, FerrovokerMatch::EMPTY);
    // SAFETY: This test owns the handle and has finished using it.
    unsafe { ferrovoker_free(handle) };
}

/// The ABI contains unwinding panics and sanitizes embedded NUL diagnostics.
#[test]
fn operation_contains_panics_and_preserves_c_strings() {
    assert_eq!(operation(|| panic!("simulated panic")), -1);
    assert!(error().contains("panic"));
    assert_eq!(operation(|| Err("with\0nul".into())), -1);
    assert_eq!(error(), "with\\0nul");
}

/// A caught panic's destructor must not trigger an unwind across the ABI.
#[test]
fn operation_does_not_drop_arbitrary_panic_payloads() {
    /// Panic payload that would fail if a handler tried to drop it.
    struct PanicOnDrop;

    impl Drop for PanicOnDrop {
        fn drop(&mut self) {
            panic!("panic payload destructor must not run");
        }
    }

    assert_eq!(operation(|| std::panic::panic_any(PanicOnDrop)), -1);
    assert!(error().contains("panic"));
}

/// Diagnostics are independent for concurrent C callers.
#[test]
fn diagnostics_are_thread_local() {
    set_error("parent thread");
    let diagnostic = std::thread::spawn(|| {
        assert_eq!(error(), "");
        set_error("child thread");
        error()
    })
    .join()
    .expect("diagnostic test thread completes");
    assert_eq!(diagnostic, "child thread");
    assert_eq!(error(), "parent thread");
}
