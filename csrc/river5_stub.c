/*
 * Stub backend — wraps xxhash3-128 behind the river5 vtable.
 * Used as the fallback on CPUs without AES-NI (and as a sanity
 * comparison baseline for the AES-NI backend during development).
 */
#include "river5.h"
#include "river5_internal.h"

#include <stdlib.h>
#include <string.h>

#define XXH_STATIC_LINKING_ONLY
#define XXH_INLINE_ALL
#include "xxhash.h"

/* This TU's private definition of the opaque context type. */
struct river5_ctx {
    XXH3_state_t *xxh;
};

static uint64_t seed_to_u64(const uint8_t *seed)
{
    if (!seed) return 0;
    uint64_t s;
    memcpy(&s, seed, sizeof(s));
    return s;
}

static void write_hash(XXH128_hash_t h, uint8_t out[RIVER5_HASH_BYTES])
{
    for (int i = 0; i < 8; ++i) {
        out[i]     = (uint8_t)(h.low64  >> (i * 8));
        out[i + 8] = (uint8_t)(h.high64 >> (i * 8));
    }
}

static void stub_one_shot(const void *input, size_t len,
                          const uint8_t *seed, uint8_t *out)
{
    XXH128_hash_t h = XXH3_128bits_withSeed(input, len, seed_to_u64(seed));
    write_hash(h, out);
}

static river5_ctx_t *stub_new(const uint8_t *seed)
{
    river5_ctx_t *c = (river5_ctx_t *)malloc(sizeof(*c));
    if (!c) return NULL;
    c->xxh = XXH3_createState();
    if (!c->xxh) { free(c); return NULL; }
    XXH3_128bits_reset_withSeed(c->xxh, seed_to_u64(seed));
    return c;
}

static void stub_update(river5_ctx_t *c, const void *data, size_t len)
{
    XXH3_128bits_update(c->xxh, data, len);
}

static void stub_finalize(river5_ctx_t *c, uint8_t *out)
{
    XXH128_hash_t h = XXH3_128bits_digest(c->xxh);
    write_hash(h, out);
}

static void stub_free(river5_ctx_t *c)
{
    if (!c) return;
    XXH3_freeState(c->xxh);
    free(c);
}

/* xxhash3's state needs heap alloc + 64-byte alignment, neither of
 * which fits the river5_init_in storage contract. Return NULL to
 * signal "not supported" — the Rust StackHasher wrapper falls back
 * to heap-allocated Hasher on non-AES-NI hosts. */
static river5_ctx_t *stub_init_in(void *storage, const uint8_t *seed)
{
    (void)storage;
    (void)seed;
    return NULL;
}

const river5_vtable RIVER5_VTABLE_STUB = {
    .one_shot           = stub_one_shot,
    .new_state          = stub_new,
    .update             = stub_update,
    .finalize           = stub_finalize,
    .free_state         = stub_free,
    .init_in            = stub_init_in,
    .ctx_bytes_required = 0,                /* signals "init_in unsupported" */
    .name               = "river5-stub-xxh3",
};
