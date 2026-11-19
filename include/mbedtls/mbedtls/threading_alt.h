#ifndef MBEDTLS_THREADING_ALT_H
#define MBEDTLS_THREADING_ALT_H

/* Mutex type for MBEDTLS_THREADING_ALT on Windows (ApkSpy).
 *
 * The storage is an opaque buffer so this header, which mbedTLS pulls into
 * every compiled source file, does not drag <windows.h> (and its macros) in.
 * Tls.cpp casts `cs` to a CRITICAL_SECTION and provides the init/free/lock/
 * unlock callbacks through mbedtls_threading_set_alt().
 *
 * A CRITICAL_SECTION is 24 bytes on x86 and 40 on x64; 128 bytes is ample. */

typedef struct mbedtls_threading_mutex_t {
    unsigned char cs[128];
    int is_valid; /* 0 until initialised */
} mbedtls_threading_mutex_t;

#endif /* MBEDTLS_THREADING_ALT_H */
