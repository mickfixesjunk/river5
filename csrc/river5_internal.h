/*
 * Internal interface shared between the public dispatcher (river5.c)
 * and the per-implementation backends (river5_aesni.c, river5_stub.c).
 *
 * Each backend defines `struct river5_ctx` PRIVATELY in its own TU
 * with whatever layout it needs. The public header only forward-
 * declares it, and the dispatcher passes the pointer through without
 * dereferencing — so the type doesn't have to escape its translation
 * unit.
 */
#ifndef RIVER5_INTERNAL_H
#define RIVER5_INTERNAL_H

#include "river5.h"

/*
 * Portable 16-byte alignment for static SECRET tables. GCC/Clang
 * accept `__attribute__((aligned(16)))` post-declaration; MSVC
 * needs `__declspec(align(16))` pre-declaration. Define a macro
 * that works pre-declaration on both compilers so the source code
 * reads identically.
 *
 *   static const RIVER5_ALIGN16 uint8_t TABLE[N] = { ... };
 */
#if defined(_MSC_VER)
#  define RIVER5_ALIGN16 __declspec(align(16))
#else
#  define RIVER5_ALIGN16 __attribute__((aligned(16)))
#endif

typedef struct {
    void          (*one_shot)(const void *input, size_t len,
                              const uint8_t *seed, uint8_t *out);
    river5_ctx_t *(*new_state)(const uint8_t *seed);
    void          (*update)(river5_ctx_t *ctx, const void *data, size_t len);
    void          (*finalize)(river5_ctx_t *ctx, uint8_t *out);
    void          (*free_state)(river5_ctx_t *ctx);
    const char     *name;
} river5_vtable;

extern const river5_vtable RIVER5_VTABLE_AESNI;     /* v1: 8 lanes, 128 B blocks (legacy) */
extern const river5_vtable RIVER5_VTABLE_AESNI_V2;  /* v2: 16 lanes, no per-block diffusion (FAILS SMHasher3) */
extern const river5_vtable RIVER5_VTABLE_AESNI_V3;  /* v3: 16 lanes + per-block butterfly + pre-diffusion finalize (default) */
extern const river5_vtable RIVER5_VTABLE_AESNI_V6;  /* v6: v3 + per-lane PSHUFB byte-permutation of input */
extern const river5_vtable RIVER5_VTABLE_STUB;      /* xxhash3 fallback */

#endif
