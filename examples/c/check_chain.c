/* Build libferrovoker with `cargo build --release --features ffi`, then:
 * cc -std=c11 -Wall -Wextra -Werror -Iinclude examples/c/check_chain.c \
 *    -Ltarget/release -lferrovoker -o target/check_chain
 * LD_LIBRARY_PATH=target/release target/check_chain leaf.crt issuer.crt root.crt
 *
 * The library downloads, caches, and refreshes its feeds. Certificates must come
 * from the path selected by normal TLS verification; this example itself does
 * no trust verification. Each file must contain one certificate encoded as DER,
 * PEM, or base64 DER. Certificate bundles are not accepted.
 * No feed match is not proof that a certificate is valid or unrevoked.
 */
#include "ferrovoker.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

/* Owned file buffer, released after the library finishes borrowing its bytes. */
struct file_bytes {
    uint8_t *data;
    size_t len;
};

/* Read an entire nonempty certificate file; the library detects its encoding. */
static int read_file(const char *path, struct file_bytes *out) {
    FILE *file;
    long length;

    out->data = NULL;
    out->len = 0;
    file = fopen(path, "rb");
    if (file == NULL) {
        perror(path);
        return -1;
    }
    if (fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) <= 0 ||
        (uintmax_t)length > SIZE_MAX || fseek(file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "Cannot determine a valid file size: %s\n", path);
        fclose(file);
        return -1;
    }
    out->data = malloc((size_t)length);
    if (out->data == NULL) {
        fprintf(stderr, "Cannot allocate file buffer: %s\n", path);
        fclose(file);
        return -1;
    }
    out->len = (size_t)length;
    if (fread(out->data, 1, out->len, file) != out->len) {
        fprintf(stderr, "Cannot read complete file: %s\n", path);
        free(out->data);
        out->data = NULL;
        out->len = 0;
        fclose(file);
        return -1;
    }
    if (fclose(file) != 0) {
        perror(path);
        free(out->data);
        out->data = NULL;
        out->len = 0;
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    struct file_bytes *certificates = NULL;
    FerrovokerCertificate *chain = NULL;
    Ferrovoker *handle = NULL;
    FerrovokerMatch found;
    size_t chain_len = 0;
    time_t now;
    int result = EXIT_FAILURE;
    int32_t status;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s leaf.crt [issuer.crt ...]\n", argv[0]);
        return EXIT_FAILURE;
    }
    chain_len = (size_t)(argc - 1);
    certificates = calloc(chain_len, sizeof(*certificates));
    chain = calloc(chain_len, sizeof(*chain));
    if (certificates == NULL || chain == NULL) {
        fprintf(stderr, "Cannot allocate certificate chain\n");
        goto cleanup;
    }
    for (size_t i = 0; i < chain_len; ++i) {
        if (read_file(argv[i + 1], &certificates[i]) != 0) {
            fprintf(stderr, "Expected a certificate file: %s\n", argv[i + 1]);
            goto cleanup;
        }
        chain[i].data = certificates[i].data;
        chain[i].len = certificates[i].len;
    }
    status = ferrovoker_new(&handle);
    if (status == FERROVOKER_ERROR) {
        fprintf(stderr, "Feed initialization error: %s\n", ferrovoker_last_error());
        goto cleanup;
    }
    now = time(NULL);
    if (now == (time_t)-1 || now < 0) {
        fprintf(stderr, "Cannot read current Unix time\n");
        goto cleanup;
    }
    status = ferrovoker_check_chain(handle, chain, chain_len, (uint64_t)now, &found);
    if (status == FERROVOKER_ERROR) {
        fprintf(stderr, "Check error: %s\n", ferrovoker_last_error());
        goto cleanup;
    }
    if (status == FERROVOKER_REVOKED) {
        printf("Revoked: certificate %zu, reason %u\n",
               found.certificate_index, (unsigned)found.reason);
        result = 2;
    } else {
        puts("Not listed in the loaded feeds; this does not establish certificate trust.");
        result = EXIT_SUCCESS;
    }

cleanup:
    ferrovoker_free(handle);
    if (certificates != NULL) {
        for (size_t i = 0; i < chain_len; ++i) {
            free(certificates[i].data);
        }
    }
    free(certificates);
    free(chain);
    return result;
}
