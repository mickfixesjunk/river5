#include "hashes.h"

#include <stdlib.h>
#include <string.h>

#include "river5.h"
#include "river5_internal.h"   /* RIVER5_VTABLE_AESNI for v1 A/B comparison */

#define XXH_INLINE_ALL
#include "xxhash.h"

/* ---------- xxhash3-128 (canonical big-endian output) ---------- */

static void xxh3_128_one(const void *in, size_t len, uint8_t *out)
{
    XXH128_hash_t h = XXH3_128bits(in, len);
    XXH128_canonical_t c;
    XXH128_canonicalFromHash(&c, h);
    memcpy(out, c.digest, 16);
}

static void xxh3_128_free(void *s) { XXH3_freeState((XXH3_state_t *)s); }

static void *xxh3_128_new_reset(void)
{
    XXH3_state_t *s = XXH3_createState();
    XXH3_128bits_reset(s);
    return s;
}

static void xxh3_128_update(void *s, const void *d, size_t n)
{
    XXH3_128bits_update((XXH3_state_t *)s, d, n);
}

static void xxh3_128_digest(void *s, uint8_t *out)
{
    XXH128_hash_t h = XXH3_128bits_digest((XXH3_state_t *)s);
    XXH128_canonical_t c;
    XXH128_canonicalFromHash(&c, h);
    memcpy(out, c.digest, 16);
}

static const hash_impl xxh3_128 = {
    .name        = "xxh3-128",
    .output_bits = 128,
    .one_shot    = xxh3_128_one,
    .new_state   = xxh3_128_new_reset,
    .update      = xxh3_128_update,
    .digest      = xxh3_128_digest,
    .free_state  = xxh3_128_free,
};

/* ---------- river5 (public API → routes to v6 on AES-NI CPUs) ---------- */

static void river5_one(const void *in, size_t len, uint8_t *out)
{
    river5_hash(in, len, NULL, out);
}

static void *river5_new_state(void)         { return river5_new(); }
static void  river5_update_(void *s, const void *d, size_t n)
                                            { river5_update((river5_ctx_t *)s, d, n); }
static void  river5_digest_(void *s, uint8_t *out)
                                            { river5_finalize((river5_ctx_t *)s, out); }
static void  river5_free_(void *s)          { river5_free((river5_ctx_t *)s); }

static const hash_impl river5_impl = {
    .name        = "river5",
    .output_bits = 128,
    .one_shot    = river5_one,
    .new_state   = river5_new_state,
    .update      = river5_update_,
    .digest      = river5_digest_,
    .free_state  = river5_free_,
};

/* ---------- river5 v12 (direct vtable, HighwayHash-inspired) ---------- */

static void river5_v12_one(const void *in, size_t len, uint8_t *out)
{
    RIVER5_VTABLE_AESNI_V12.one_shot(in, len, NULL, out);
}
static void *river5_v12_new(void)
{
    return RIVER5_VTABLE_AESNI_V12.new_state(NULL);
}
static void  river5_v12_update(void *s, const void *d, size_t n)
{
    RIVER5_VTABLE_AESNI_V12.update((river5_ctx_t *)s, d, n);
}
static void  river5_v12_digest(void *s, uint8_t *out)
{
    RIVER5_VTABLE_AESNI_V12.finalize((river5_ctx_t *)s, out);
}
static void  river5_v12_free(void *s)
{
    RIVER5_VTABLE_AESNI_V12.free_state((river5_ctx_t *)s);
}

static const hash_impl river5_v12_impl = {
    .name        = "river5-v12",
    .output_bits = 128,
    .one_shot    = river5_v12_one,
    .new_state   = river5_v12_new,
    .update      = river5_v12_update,
    .digest      = river5_v12_digest,
    .free_state  = river5_v12_free,
};

/* ---------- river5 v3 (direct vtable, for A/B vs the new v6 default) ---------- */

static void river5_v3_one(const void *in, size_t len, uint8_t *out)
{
    RIVER5_VTABLE_AESNI_V3.one_shot(in, len, NULL, out);
}
static void *river5_v3_new(void)
{
    return RIVER5_VTABLE_AESNI_V3.new_state(NULL);
}
static void  river5_v3_update(void *s, const void *d, size_t n)
{
    RIVER5_VTABLE_AESNI_V3.update((river5_ctx_t *)s, d, n);
}
static void  river5_v3_digest(void *s, uint8_t *out)
{
    RIVER5_VTABLE_AESNI_V3.finalize((river5_ctx_t *)s, out);
}
static void  river5_v3_free(void *s)
{
    RIVER5_VTABLE_AESNI_V3.free_state((river5_ctx_t *)s);
}

static const hash_impl river5_v3_impl = {
    .name        = "river5-v3",
    .output_bits = 128,
    .one_shot    = river5_v3_one,
    .new_state   = river5_v3_new,
    .update      = river5_v3_update,
    .digest      = river5_v3_digest,
    .free_state  = river5_v3_free,
};

/* ---------- river5 v1 (direct vtable call, for A/B comparison) ---------- */

static void river5_v1_one(const void *in, size_t len, uint8_t *out)
{
    RIVER5_VTABLE_AESNI.one_shot(in, len, NULL, out);
}
static void *river5_v1_new(void)
{
    return RIVER5_VTABLE_AESNI.new_state(NULL);
}
static void  river5_v1_update(void *s, const void *d, size_t n)
{
    RIVER5_VTABLE_AESNI.update((river5_ctx_t *)s, d, n);
}
static void  river5_v1_digest(void *s, uint8_t *out)
{
    RIVER5_VTABLE_AESNI.finalize((river5_ctx_t *)s, out);
}
static void  river5_v1_free(void *s)
{
    RIVER5_VTABLE_AESNI.free_state((river5_ctx_t *)s);
}

static const hash_impl river5_v1_impl = {
    .name        = "river5-v1",
    .output_bits = 128,
    .one_shot    = river5_v1_one,
    .new_state   = river5_v1_new,
    .update      = river5_v1_update,
    .digest      = river5_v1_digest,
    .free_state  = river5_v1_free,
};

/* ---------- river5 v2 (direct vtable, FAILS SMHasher3, for A/B perf) ---------- */

static void river5_v2_one(const void *in, size_t len, uint8_t *out)
{
    RIVER5_VTABLE_AESNI_V2.one_shot(in, len, NULL, out);
}
static void *river5_v2_new(void)
{
    return RIVER5_VTABLE_AESNI_V2.new_state(NULL);
}
static void  river5_v2_update(void *s, const void *d, size_t n)
{
    RIVER5_VTABLE_AESNI_V2.update((river5_ctx_t *)s, d, n);
}
static void  river5_v2_digest(void *s, uint8_t *out)
{
    RIVER5_VTABLE_AESNI_V2.finalize((river5_ctx_t *)s, out);
}
static void  river5_v2_free(void *s)
{
    RIVER5_VTABLE_AESNI_V2.free_state((river5_ctx_t *)s);
}

static const hash_impl river5_v2_impl = {
    .name        = "river5-v2",
    .output_bits = 128,
    .one_shot    = river5_v2_one,
    .new_state   = river5_v2_new,
    .update      = river5_v2_update,
    .digest      = river5_v2_digest,
    .free_state  = river5_v2_free,
};

/* ---------- BLAKE3 (256-bit output) ---------- */

extern void  blake3_wrap_one_shot(const void *in, size_t len, uint8_t out[32]);
extern void *blake3_wrap_new_state(void);
extern void  blake3_wrap_update(void *state, const void *data, size_t len);
extern void  blake3_wrap_digest(void *state, uint8_t *out);
extern void  blake3_wrap_free(void *state);

static const hash_impl blake3_impl = {
    .name        = "blake3",
    .output_bits = 256,
    .one_shot    = blake3_wrap_one_shot,
    .new_state   = blake3_wrap_new_state,
    .update      = blake3_wrap_update,
    .digest      = blake3_wrap_digest,
    .free_state  = blake3_wrap_free,
};

/* ---------- MetroHash128 (128-bit output) ---------- */

extern void  metrohash128_one_shot(const void *in, size_t len, uint8_t out[16]);
extern void *metrohash128_new_state(void);
extern void  metrohash128_update(void *state, const void *data, size_t len);
extern void  metrohash128_digest(void *state, uint8_t *out);
extern void  metrohash128_free(void *state);

static const hash_impl metrohash_impl = {
    .name        = "metrohash-128",
    .output_bits = 128,
    .one_shot    = metrohash128_one_shot,
    .new_state   = metrohash128_new_state,
    .update      = metrohash128_update,
    .digest      = metrohash128_digest,
    .free_state  = metrohash128_free,
};

/* ---------- Meow Hash (128-bit output, requires AES-NI) ----------
 *
 * Meow REQUIRES AES-NI on x86_64; on hosts without AES-NI the wrapper's
 * SIMD intrinsics will fault. We register it unconditionally — the
 * Makefile is responsible for only building this on x86_64 with -maes.
 */

extern void  meow_wrap_one_shot(const void *in, size_t len, uint8_t out[16]);
extern void *meow_wrap_new_state(void);
extern void  meow_wrap_update(void *state, const void *data, size_t len);
extern void  meow_wrap_digest(void *state, uint8_t *out);
extern void  meow_wrap_free(void *state);

static const hash_impl meow_impl = {
    .name        = "meow-128",
    .output_bits = 128,
    .one_shot    = meow_wrap_one_shot,
    .new_state   = meow_wrap_new_state,
    .update      = meow_wrap_update,
    .digest      = meow_wrap_digest,
    .free_state  = meow_wrap_free,
};

/* ---------- registry ---------- */

const hash_impl *const g_hashes[] = {
    &xxh3_128,
    &river5_impl,
    &river5_v12_impl,
    &river5_v3_impl,
    &river5_v2_impl,
    &river5_v1_impl,
    &blake3_impl,
    &metrohash_impl,
    &meow_impl,
};
const size_t g_hashes_count = sizeof(g_hashes) / sizeof(g_hashes[0]);

const hash_impl *hash_find(const char *name)
{
    for (size_t i = 0; i < g_hashes_count; ++i) {
        if (strcmp(g_hashes[i]->name, name) == 0) {
            return g_hashes[i];
        }
    }
    return NULL;
}
