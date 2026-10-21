# C shared library

Run build commands from the repository root.

Build a Linux shared library and link a C program against the supplied header:

```sh
cargo build --release --features ffi
cc -std=c11 -Wall -Wextra -Werror -Iinclude examples/c/check_chain.c \
  -Ltarget/release -lferrovoker -o target/check_chain
LD_LIBRARY_PATH=target/release target/check_chain server.crt issuer.crt
```

This produces `target/release/libferrovoker.so`. See
[ferrovoker.h](../include/ferrovoker.h) and the [C example](../examples/c/check_chain.c).
`ferrovoker_new(&handle)` loads the platform cache or downloads the feeds, then
keeps its own runtime for caching and background refresh until the handle is freed;
`ferrovoker_check_chain` checks borrowed certificates without network I/O;
`ferrovoker_free` releases the handle. C callers only supply certificates;
feed downloads, formats, caching, and refresh remain inside the library. The
initial load blocks. Chrome's signed CRX3 container is verified, including when
loading the cache. Mozilla's OneCRL content signature, pinned production signing
root, and OneCRL leaf identity are also verified on downloads and cache loads.
The constructor returns `0` on success or `-1` on error.

The C API returns `NOT_LISTED`, `REVOKED`, or `ERROR`, with thread-local diagnostic
text. Use it after your TLS library's normal verification. `NOT_LISTED` does not
mean trusted. The header defines ownership, threading, and pointer contracts.

## Certificate formats and ownership

Each `FerrovokerCertificate` supplies one readable buffer and its byte length.
The library automatically detects DER, PEM, or base64 DER, and formats may be
mixed in a chain. Each descriptor must contain exactly one complete certificate;
certificate bundles are rejected. Input bytes are never modified. Matching indexes
refer to the first original descriptor for each normalized certificate.

A handle supports concurrent checks. Free it exactly once after all operations
using it finish. Descriptors and certificate buffers are borrowed for each call
and must remain unchanged until it returns. Output pointers must be writable,
aligned, and separate from inputs; the header specifies allocation and length
requirements. Supply current Unix time in seconds when checking certificates.

Diagnostics are thread-local and borrowed until the next ferrovoker operation
on that thread or thread exit. Do not free or modify them. Successful operations,
including `ferrovoker_free`, clear diagnostics; copy an error before freeing a
handle if it must be retained. The constructor clears its output on failure,
and `ferrovoker_free(NULL)` is accepted.

## ABI smoke test

```sh
cargo build --features ffi
cc -std=c11 -Wall -Wextra -Werror -Iinclude tests/c_abi.c \
  -Ltarget/debug -lferrovoker -o target/c_abi
LD_LIBRARY_PATH=target/debug target/c_abi
LD_LIBRARY_PATH=target/debug target/c_abi --live
```

The default test checks error contracts without network requests. `--live` also
loads managed feeds and exercises certificate errors with a real handle.
