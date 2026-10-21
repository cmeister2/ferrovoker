#ifndef FERROVOKER_H
#define FERROVOKER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Revocation handle; multiple threads may check it concurrently. Never free a
 * handle while a check is running. All lengths and offsets use the platform's
 * size_t. Nonnull pointers must identify allocated, initialized storage of the
 * stated size; descriptor and output pointers must be appropriately aligned.
 * Buffer lengths and descriptor arrays in bytes must not exceed PTRDIFF_MAX.
 * Outputs must be writable and exclusively accessible during the call. */
typedef struct Ferrovoker Ferrovoker;

/* One complete X.509 certificate per descriptor. The library detects binary
 * DER, PEM CERTIFICATE, or base64-encoded DER and decodes text internally.
 * ASCII whitespace is accepted in text encodings. Bundles and concatenated
 * certificates are rejected; use separate descriptors for a chain. */
typedef struct FerrovokerCertificate {
    const uint8_t *data; /* Borrowed certificate bytes; no NUL terminator needed. */
    size_t len;          /* Exact byte length, excluding any NUL terminator. */
} FerrovokerCertificate;

typedef struct FerrovokerMatch {
    size_t certificate_index; /* Leaf-first index, or SIZE_MAX when not revoked. */
    uint32_t reason;          /* FerrovokerReason, or 0 when not revoked. */
} FerrovokerMatch;

enum FerrovokerStatus {
    FERROVOKER_ERROR = -1,
    FERROVOKER_NOT_LISTED = 0,
    FERROVOKER_REVOKED = 1
};

enum FerrovokerReason {
    FERROVOKER_ONECRL_ISSUER_SERIAL = 1,
    FERROVOKER_ONECRL_SUBJECT_PUBLIC_KEY = 2,
    FERROVOKER_CRLSET_BLOCKED_SPKI = 3,
    FERROVOKER_CRLSET_LIMITED_SUBJECT = 4,
    FERROVOKER_CRLSET_SERIAL = 5
};

/* Create a managed revocation handle, blocking for the initial load from the
 * platform cache or HTTPS. A nonnull output slot must be aligned, writable,
 * and exclusively accessible during this call.
 * The handle owns an executor thread that refreshes the feeds periodically until
 * freed. The default refresh interval is 6 hours and maximum snapshot age is
 * 24 hours. Checks use in-memory data and fail if the snapshot becomes too old.
 * Returns 0 on success, -1 on cache, download, integrity, or parsing errors.
 * Errors set *out to NULL. Chrome CRX3 signatures are verified against the pinned
 * CRLSet publisher key, including when loading cached data. Mozilla OneCRL
 * content signatures are not verified. */
int32_t ferrovoker_new(Ferrovoker **out);

/* Check chain_len certificates in DER, PEM, or base64 DER format. Formats may
 * be mixed; each descriptor must contain exactly one complete certificate.
 * Match indexes refer to the original descriptor array. Use only after normal
 * TLS chain, signature, validity, hostname, and policy verification.
 * Supply the leaf first and available issuer candidates in any
 * order, including the trust anchor when available. Chrome serial entries use
 * every candidate with matching subject/issuer DER names. An unrelated or
 * unverified candidate can cause conservative rejection; prefer the actual
 * verified path. unix_time is current Unix time in seconds; expired CRLSets
 * cause an error. Managed handles also reject snapshots past their maximum age.
 *
 * Returns 0 for NOT LISTED, 1 for REVOKED, -1 for ERROR. NOT LISTED does not mean
 * trusted: both feeds have partial coverage and this is an additional check.
 * out is required. It contains the match on REVOKED, otherwise SIZE_MAX and 0.
 * Descriptors and certificate bytes are borrowed and must remain unchanged for
 * the call. The library does not modify input buffers while decoding them.
 * Output must not overlap the handle, descriptors, or certificate data. */
int32_t ferrovoker_check_chain(const Ferrovoker *handle,
                              const FerrovokerCertificate *chain,
                              size_t chain_len, uint64_t unix_time,
                              FerrovokerMatch *out);

/* Free exactly once; NULL is accepted. No other operation may use this handle
 * during or after the call. */
void ferrovoker_free(Ferrovoker *handle);

/* Borrowed, nonnull UTF-8 diagnostic for this thread. Do not free or modify.
 * Valid until the next ferrovoker operation on this thread or thread exit.
 * Calling last_error does not clear the message. Successful operations clear it.
 * Copy this text before freeing a handle if its error must be retained. */
const char *ferrovoker_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* FERROVOKER_H */
