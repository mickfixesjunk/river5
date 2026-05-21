#ifndef RIVER5_BENCH_HASHES_H
#define RIVER5_BENCH_HASHES_H

#include <stddef.h>
#include <stdint.h>

/* Bench plugin interface.
 *
 * Each hash exposes a one-shot AND a streaming API. The streaming
 * pieces use opaque void* contexts so the harness can hold many
 * implementations behind one type.
 */
typedef struct hash_impl {
    const char *name;
    int         output_bits;

    /* One-shot: hash `input[0..len]` into `out` (`output_bits/8` bytes). */
    void (*one_shot)(const void *input, size_t len, uint8_t *out);

    /* Streaming. `new_state` returns an opaque heap-allocated ctx;
     * `free_state` releases it. `digest` writes `output_bits/8` bytes
     * into `out` and does NOT free the state (caller frees). */
    void *(*new_state)(void);
    void  (*update)(void *state, const void *data, size_t len);
    void  (*digest)(void *state, uint8_t *out);
    void  (*free_state)(void *state);
} hash_impl;

extern const hash_impl *const g_hashes[];
extern const size_t           g_hashes_count;

/* Returns NULL if no hash matches. */
const hash_impl *hash_find(const char *name);

#endif
