/*
 * river5 — 128-bit hash for the superdeduper file deduper.
 *
 * Stable C ABI. The current implementation is a STUB that delegates to
 * xxhash3-128 so outputs are real, stable, and deterministic; the AES-NI
 * design described in the project notes will replace it without changing
 * this header.
 */
#ifndef RIVER5_H
#define RIVER5_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIVER5_HASH_BYTES 16
#define RIVER5_SEED_BYTES 32

typedef struct river5_ctx river5_ctx_t;

/* One-shot. `seed` may be NULL for the default key. */
void river5_hash(const void *input,
                 size_t len,
                 const uint8_t seed[RIVER5_SEED_BYTES],
                 uint8_t out[RIVER5_HASH_BYTES]);

/* Streaming. Caller owns the context and must river5_free it.
 * river5_finalize may be called once; after it, the context is consumed
 * but still must be freed. */
river5_ctx_t *river5_new(void);
river5_ctx_t *river5_new_seeded(const uint8_t seed[RIVER5_SEED_BYTES]);
void          river5_update(river5_ctx_t *ctx, const void *data, size_t len);
void          river5_finalize(river5_ctx_t *ctx, uint8_t out[RIVER5_HASH_BYTES]);
void          river5_free(river5_ctx_t *ctx);

/*
 * Stack-allocatable streaming variant — avoids the per-call heap
 * allocation that river5_new() does. The caller provides a buffer
 * of at least RIVER5_CTX_BYTES bytes, aligned to RIVER5_CTX_ALIGN.
 *
 * Returns the same ctx pointer (cast from the storage) on success,
 * NULL on size/alignment error.
 *
 * Usage pattern (C):
 *     _Alignas(RIVER5_CTX_ALIGN) uint8_t storage[RIVER5_CTX_BYTES];
 *     river5_ctx_t *ctx = river5_init_in(storage, sizeof storage, NULL);
 *     river5_update(ctx, data, len);
 *     river5_finalize(ctx, out);
 *     // No river5_free() — storage is caller-owned.
 *
 * The Rust `StackHasher` type wraps this; consumers who specifically
 * want to avoid the per-call allocation use it for hot paths.
 *
 * RIVER5_CTX_BYTES is sized generously (1024) to cover all current
 * and reasonably-future variants; the actual ctx for v15 is ~528 B.
 * Static asserts in each variant's TU guarantee its sizeof fits.
 */
#define RIVER5_CTX_BYTES 1024
#define RIVER5_CTX_ALIGN 16
river5_ctx_t *river5_init_in(void *storage,
                              size_t storage_size,
                              const uint8_t seed[RIVER5_SEED_BYTES]);

/* Implementation tag, useful for benchmark output. Returns e.g.
 * "river5-stub-xxh3" today, "river5-aesni-v1" once the real impl lands. */
const char *river5_impl_name(void);

#ifdef __cplusplus
}
#endif

#endif /* RIVER5_H */
