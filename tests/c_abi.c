/* Compile and link against the built shared library to check the public C ABI:
 * cc -std=c11 -Wall -Wextra -Werror -Iinclude tests/c_abi.c \
 *    -Ltarget/debug -lferrovoker -o target/c_abi
 * LD_LIBRARY_PATH=target/debug target/c_abi
 *
 * The default checks require no network. Add --live to initialize the managed
 * feeds and exercise certificate errors with a real handle.
 */
#include "ferrovoker.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv) {
    static const uint8_t invalid_der[] = "invalid DER";
    const FerrovokerCertificate certificate = {
        invalid_der, sizeof(invalid_der) - 1
    };
    Ferrovoker *handle = NULL;
    FerrovokerMatch found = {7, FERROVOKER_CRLSET_SERIAL};
    int live;
    time_t now;

    if (argc > 2 || (argc == 2 && strcmp(argv[1], "--live") != 0)) {
        fprintf(stderr, "Usage: %s [--live]\n", argv[0]);
        return EXIT_FAILURE;
    }
    live = argc == 2;

    assert(ferrovoker_last_error() != NULL);
    assert(ferrovoker_new(NULL) == FERROVOKER_ERROR);
    assert(strlen(ferrovoker_last_error()) > 0);
    assert(ferrovoker_check_chain(NULL, &certificate, 1, 0, &found) ==
           FERROVOKER_ERROR);
    assert(found.certificate_index == SIZE_MAX);
    assert(found.reason == 0);
    assert(strlen(ferrovoker_last_error()) > 0);
    assert(ferrovoker_check_chain(NULL, &certificate, 1, 0, NULL) ==
           FERROVOKER_ERROR);
    assert(strlen(ferrovoker_last_error()) > 0);
    ferrovoker_free(NULL);
    assert(strlen(ferrovoker_last_error()) == 0);

    if (live) {
        if (ferrovoker_new(&handle) == FERROVOKER_ERROR) {
            fprintf(stderr, "Managed constructor error: %s\n",
                    ferrovoker_last_error());
            return EXIT_FAILURE;
        }
        assert(handle != NULL);
        assert(strlen(ferrovoker_last_error()) == 0);
        now = time(NULL);
        assert(now != (time_t)-1 && now >= 0);
        assert(ferrovoker_check_chain(handle, &certificate, 1, (uint64_t)now,
                                      &found) == FERROVOKER_ERROR);
        assert(found.certificate_index == SIZE_MAX);
        assert(found.reason == 0);
        assert(strlen(ferrovoker_last_error()) > 0);
        assert(ferrovoker_check_chain(handle, NULL, 0, (uint64_t)now, &found) ==
               FERROVOKER_ERROR);
        assert(found.certificate_index == SIZE_MAX);
        assert(found.reason == 0);
        assert(strlen(ferrovoker_last_error()) > 0);
        ferrovoker_free(handle);
        assert(strlen(ferrovoker_last_error()) == 0);
    }
    ferrovoker_free(NULL);
    assert(strlen(ferrovoker_last_error()) == 0);
    return EXIT_SUCCESS;
}
