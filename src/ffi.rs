//! Optional C ABI for managed certificate revocation checks.
//!
//! Build with `--features ffi` and include `include/ferrovoker.h` from C. Handles
//! own cached revocation data and a background runtime for periodic refresh.
//! Handles support concurrent checks. A successful
//! check means only that the supplied certificates were not listed; callers must
//! also perform normal TLS chain, hostname, validity, and policy verification.

use crate::{RevocationProvider, RevocationReason, RevocationStatus};
use std::cell::RefCell;
use std::ffi::{CString, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::slice;
use std::sync::Arc;
use tokio::runtime::Runtime;

thread_local! {
    /// Last diagnostic for the calling thread, retained until its next operation.
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

/// Opaque managed revocation provider and refresh runtime owned by the C caller.
pub struct Ferrovoker {
    /// Automatically refreshed revocation identifiers.
    revocations: Arc<dyn RevocationProvider>,
    /// Retained executor for managed downloads and their periodic refresh task.
    runtime: Option<Runtime>,
}

impl Drop for Ferrovoker {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            // Releasing a C handle may itself happen within an async executor.
            // Tokio's ordinary runtime destructor would panic in that context.
            runtime.shutdown_background();
        }
    }
}

/// Temporary runtime owner that also permits safe cleanup if construction fails.
struct PendingRuntime {
    /// Executor awaiting transfer to a successfully constructed C handle.
    runtime: Option<Runtime>,
}

impl Drop for PendingRuntime {
    fn drop(&mut self) {
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_background();
        }
    }
}

/// One borrowed certificate, matching `FerrovokerCertificate` in the C header.
///
/// Accepts complete DER, one PEM `CERTIFICATE` block, or base64-encoded DER.
/// Text input may contain ASCII whitespace. Each descriptor holds exactly one
/// certificate, and checking leaves its borrowed bytes unchanged.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct FerrovokerCertificate {
    /// Pointer to one complete certificate in DER, PEM, or base64 DER format.
    pub data: *const u8,
    /// Number of certificate bytes at `data`.
    pub len: usize,
}

/// Details of a revocation match, matching `FerrovokerMatch` in the C header.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FerrovokerMatch {
    /// Zero-based position in the supplied leaf-first chain, or `SIZE_MAX`.
    pub certificate_index: usize,
    /// Matching identifier kind (1 through 5), or zero when there is no match.
    pub reason: u32,
}

impl FerrovokerMatch {
    /// Output value used before checking a chain and when no match is found.
    const EMPTY: Self = Self {
        certificate_index: usize::MAX,
        reason: 0,
    };
}

/// Save a diagnostic without allowing embedded NUL bytes into the C string.
fn set_error(message: &str) {
    let message = CString::new(message.replace('\0', "\\0")).unwrap_or_default();
    let _ = LAST_ERROR.try_with(|slot| {
        if let Ok(mut error) = slot.try_borrow_mut() {
            *error = message;
        }
    });
}

/// Execute one ABI operation, translating errors and unwind panics to status -1.
fn operation(action: impl FnOnce() -> Result<i32, String>) -> i32 {
    match catch_unwind(AssertUnwindSafe(|| {
        set_error("");
        action()
    })) {
        Ok(Ok(status)) => status,
        Ok(Err(message)) => {
            set_error(&message);
            -1
        }
        Err(payload) => {
            // Arbitrary panic payloads may panic in Drop. Retain this payload so
            // its destructor cannot start another unwind across the C boundary.
            std::mem::forget(payload);
            set_error("Rust panic while performing a ferrovoker operation");
            -1
        }
    }
}

/// Borrow an optional input after checking null and representable slice length.
///
/// # Errors
///
/// Returns an error for a nonzero length with a null pointer, or a length larger
/// than `isize::MAX`.
///
/// # Safety
///
/// For a nonnull pointer and representable length, `data` must identify that many
/// initialized bytes in one allocation and remain readable for the return lifetime.
unsafe fn input_bytes<'a>(data: *const u8, len: usize) -> Result<Option<&'a [u8]>, String> {
    if len > isize::MAX as usize {
        return Err("input length exceeds isize::MAX".into());
    }
    if data.is_null() {
        return if len == 0 {
            Ok(None)
        } else {
            Err("a nonempty input has a null data pointer".into())
        };
    }
    // SAFETY: The caller guarantees the allocation, initialized bytes, and lifetime.
    Ok(Some(unsafe { slice::from_raw_parts(data, len) }))
}

/// Initialize a constructor output before attempting parsing or downloading.
///
/// # Errors
///
/// Returns an error if the output pointer is null.
///
/// # Safety
///
/// A nonnull `out` must be aligned, writable, and exclusively accessible.
unsafe fn initialize_handle(out: *mut *mut Ferrovoker) -> Result<(), String> {
    if out.is_null() {
        return Err("handle output pointer is null".into());
    }
    // SAFETY: The caller guarantees a valid, exclusive output slot.
    unsafe { out.write(ptr::null_mut()) };
    Ok(())
}

/// Load or download both feeds and retain automatic background refresh.
///
/// The initial load blocks and uses the managed cache and defaults from
/// [`crate::fetch`]. The handle owns one executor thread for periodic refresh
/// until freed. Certificate checks use the current in-memory snapshot without
/// network I/O, and fail when that snapshot becomes too old. Returns 0 on success,
/// or -1 on invalid arguments, cache, download, integrity, or parsing errors.
/// Errors leave `*out` null. Chrome CRX3 signatures are verified against the
/// pinned CRLSet publisher key, including when loading cached data. Mozilla
/// OneCRL content signatures are not verified.
///
/// # Safety
///
/// A nonnull `out` must be aligned, writable, and exclusively accessible for this
/// call. A null output pointer is rejected.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ferrovoker_new(out: *mut *mut Ferrovoker) -> i32 {
    // SAFETY: The output slot has the same caller contract as this constructor.
    unsafe {
        new_with_loader(out, |runtime| {
            runtime
                .block_on(crate::fetch())
                .map(|revocations| revocations as Arc<dyn RevocationProvider>)
                .map_err(|error| error.to_string())
        })
    }
}

/// Build a managed handle with a private injectable initial loading operation.
///
/// Production loads the shared cache while tests use local providers. The runtime
/// is retained on success and safely shut down on any failure or caught panic.
///
/// # Safety
///
/// A nonnull `out` must be aligned, writable, and exclusively accessible for this
/// call. A null output pointer is rejected before invoking the loader.
unsafe fn new_with_loader(
    out: *mut *mut Ferrovoker,
    load: impl FnOnce(&Runtime) -> Result<Arc<dyn RevocationProvider>, String>,
) -> i32 {
    operation(|| {
        // SAFETY: The caller supplies a valid output slot or null.
        unsafe { initialize_handle(out)? };
        let mut runtime = PendingRuntime {
            runtime: Some(
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(1)
                    .enable_all()
                    .build()
                    .map_err(|error| error.to_string())?,
            ),
        };
        let revocations = load(
            runtime
                .runtime
                .as_ref()
                .ok_or_else(|| "managed runtime is unavailable".to_owned())?,
        )?;
        let handle = Box::into_raw(Box::new(Ferrovoker {
            revocations,
            runtime: runtime.runtime.take(),
        }));
        // SAFETY: The output slot was validated above and remains exclusive.
        unsafe { out.write(handle) };
        Ok(0)
    })
}

/// Translate a Rust reason into the stable identifiers from the C header.
fn reason_code(reason: RevocationReason) -> u32 {
    match reason {
        RevocationReason::OneCrlIssuerSerial => 1,
        RevocationReason::OneCrlSubjectPublicKey => 2,
        RevocationReason::CrlSetBlockedSpki => 3,
        RevocationReason::CrlSetLimitedSubject => 4,
        RevocationReason::CrlSetSerial => 5,
    }
}

/// Check certificates against the feeds and return the first match.
///
/// Each descriptor accepts complete DER, one PEM `CERTIFICATE` block, or base64
/// DER, detected automatically. ASCII whitespace is tolerated in text input.
/// Inputs remain borrowed and unchanged. Equivalent encodings identify the same
/// certificate; a match retains its original descriptor index.
///
/// Call after normal TLS certificate, chain, and hostname verification, with the
/// leaf first and available issuer candidates in any order, including the trust
/// anchor when available. Chrome serial entries use every candidate with matching
/// subject/issuer DER names. An unrelated or unverified candidate can cause a
/// conservative rejection; the actual verified path is preferred. `unix_time` is
/// seconds since the Unix epoch and is used to reject expired CRLSets.
/// Returns 0 for not listed, 1 for revoked, or -1 for errors (including malformed
/// certificates, an expired CRLSet, or a stale managed snapshot). A result of 0
/// does not establish trust or
/// complete revocation coverage. The output uses `SIZE_MAX` and reason 0 unless
/// a revocation match is returned.
///
/// # Safety
///
/// `handle` must be null or a live handle from this library. A live handle must
/// not be freed during this call. A nonnull `chain` must identify `chain_len`
/// initialized, aligned certificate descriptors in one allocation; their total
/// size must not exceed `isize::MAX`. Each nonnull certificate buffer must identify
/// its stated number of readable bytes in one allocation, with its length at
/// most `isize::MAX`. A nonnull `out` must be aligned, writable, exclusively
/// accessible, and must not overlap the handle, descriptors, or certificates.
/// All inputs must remain unchanged for this call. Null pointers are rejected.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ferrovoker_check_chain(
    handle: *const Ferrovoker,
    chain: *const FerrovokerCertificate,
    chain_len: usize,
    unix_time: u64,
    out: *mut FerrovokerMatch,
) -> i32 {
    operation(|| {
        if out.is_null() {
            return Err("match output pointer is null".into());
        }
        // SAFETY: The caller guarantees a valid, exclusive match output slot.
        unsafe { out.write(FerrovokerMatch::EMPTY) };
        if handle.is_null() {
            return Err("revocation handle is null".into());
        }
        if chain.is_null() || chain_len == 0 {
            return Err("certificate chain must contain at least one certificate".into());
        }
        if chain_len
            .checked_mul(size_of::<FerrovokerCertificate>())
            .is_none_or(|size| size > isize::MAX as usize)
        {
            return Err("certificate descriptor array exceeds isize::MAX".into());
        }
        // SAFETY: The caller guarantees initialized descriptors with this length.
        let certificates = unsafe { slice::from_raw_parts(chain, chain_len) };
        let chain = certificates
            .iter()
            .map(|certificate| {
                // SAFETY: The caller guarantees readable certificate buffers.
                unsafe { input_bytes(certificate.data, certificate.len)? }
                    .ok_or_else(|| "certificate data pointer is null".to_owned())
            })
            .collect::<Result<Vec<_>, String>>()?;
        // SAFETY: The caller guarantees a live handle throughout this call.
        let status = unsafe { &*handle }
            .revocations
            .check_chain_with_issuers(&chain, &[], unix_time)
            .map_err(|error| error.to_string())?;
        match status {
            RevocationStatus::NotListed => Ok(0),
            RevocationStatus::Revoked(found) => {
                // SAFETY: The output slot remains valid and exclusive.
                unsafe {
                    out.write(FerrovokerMatch {
                        certificate_index: found.certificate_index,
                        reason: reason_code(found.reason),
                    })
                };
                Ok(1)
            }
        }
    })
}

/// Release a handle; a null pointer is accepted and has no effect.
///
/// # Safety
///
/// A nonnull pointer must be a live handle returned by this library, must not have
/// been freed, and must not be used by another thread or operation during or after
/// this call. Each handle must be freed at most once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ferrovoker_free(handle: *mut Ferrovoker) {
    operation(|| {
        if !handle.is_null() {
            // SAFETY: The caller transfers exclusive ownership of a live handle.
            drop(unsafe { Box::from_raw(handle) });
        }
        Ok(0)
    });
}

/// Return the calling thread's most recent error as a borrowed UTF-8 C string.
///
/// The pointer is nonnull and valid until the next ferrovoker operation on this
/// thread or thread exit. Do not modify or free it. Calling this function does not
/// clear the diagnostic; successful operations clear it to an empty string.
#[unsafe(no_mangle)]
pub extern "C" fn ferrovoker_last_error() -> *const c_char {
    LAST_ERROR
        .try_with(|slot| {
            slot.try_borrow()
                .map_or(c"error details unavailable".as_ptr(), |error| {
                    error.as_ptr()
                })
        })
        .unwrap_or(c"error details unavailable".as_ptr())
}

#[cfg(test)]
#[path = "../tests/unit/ffi.rs"]
mod tests;
