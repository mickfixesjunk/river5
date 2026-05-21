/*
 * river5 v5 — v3 + non-linear pre-finalize round (the differential fix).
 *
 * Goal: close v3's residual SMHasher3 Permutation failure on 32-bit
 * truncated DIFFERENTIAL collision tests, without giving back the
 * throughput headroom v3 has over v4.
 *
 * Why v4's salt fix didn't work for the differential half:
 *   v4 XOR'd a per-lane salt into the input before each AESENC. XOR
 *   is linear, so HASH_v4(A) XOR HASH_v4(B) = HASH_v3(A^s) XOR
 *   HASH_v3(B^s) — the differential structure between (A, B) shifts
 *   by the salt but is otherwise preserved. v4 fixed *direct*
 *   position symmetry but added zero new non-linear defense against
 *   an attacker tracking δ = A XOR B through the pipeline.
 *
 * What v5 changes:
 *   Adds ONE round of per-lane AESENC at the *start* of finalize,
 *   with each lane's round key = (π-derived per-lane constant) XOR
 *   (length encoded as 64-bit halves). This is non-linear (AES's
 *   S-box destroys linear differential trails) AND length-dependent
 *   AND lane-position-dependent — three independent variables an
 *   attacker would need to navigate. After this round, the existing
 *   v3 butterfly + tree-reduce + length-fold runs unchanged.
 *
 * Cost model:
 *   - 16 AESENCs added to finalize (mutually independent → ~4 cycles
 *     critical-path latency on a 1-AES-unit CPU like i7-7700K)
 *   - The 16 lane-key precomputations are 16 LOADs from a static
 *     const array + 16 XORs with a length-derived value, all
 *     independent and pipelinable
 *   - For a 1 MiB hash: ~16,000 main-loop cycles + 4 added finalize
 *     cycles = +0.025% overhead, in the noise
 *   - For a 128-byte hash (single block): ~32 main-loop cycles + 4
 *     added = +12% per-call overhead. Acceptable since tiny inputs
 *     are not the use case.
 *
 * Output is NOT byte-compatible with v3 (a different round of mixing
 * is performed). Consumers caching v3-tagged rows need to re-hash.
 */
#include "river5.h"
#include "river5_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
#  include <intrin.h>
#  define RIVER5_AESNI_FN
#else
#  include <wmmintrin.h>
#  include <emmintrin.h>
#  if defined(__GNUC__) || defined(__clang__)
#    define RIVER5_AESNI_FN __attribute__((target("aes,sse4.1")))
#  else
#    define RIVER5_AESNI_FN
#  endif
#endif

#define LANES_V5   16
#define LANE_BYTES 16
#define BLOCK_V5   (LANES_V5 * LANE_BYTES)   /* 256 */

/*
 * Same 256-byte π-derived secret v3 uses. Used as:
 *   - initial lane values:   SECRET[i * 16 ..]
 *   - pre-finalize round key: SECRET[(15 - i) * 16 ..]  (reverse-lane
 *     order so finalize-keys differ from init values for every lane)
 *   - tail padding (when partial trailing block padded with secret)
 */
static const uint8_t RIVER5_V5_SECRET[256] __attribute__((aligned(16))) = {
    0x24,0x3F,0x6A,0x88,0x85,0xA3,0x08,0xD3,
    0x13,0x19,0x8A,0x2E,0x03,0x70,0x73,0x44,
    0xA4,0x09,0x38,0x22,0x29,0x9F,0x31,0xD0,
    0x08,0x2E,0xFA,0x98,0xEC,0x4E,0x6C,0x89,
    0x45,0x28,0x21,0xE6,0x38,0xD0,0x13,0x77,
    0xBE,0x54,0x66,0xCF,0x34,0xE9,0x0C,0x6C,
    0xC0,0xAC,0x29,0xB7,0xC9,0x7C,0x50,0xDD,
    0x3F,0x84,0xD5,0xB5,0xB5,0x47,0x09,0x17,
    0x92,0x16,0xD5,0xD9,0x89,0x79,0xFB,0x1B,
    0xD1,0x31,0x0B,0xA6,0x98,0xDF,0xB5,0xAC,
    0x2F,0xFD,0x72,0xDB,0xD0,0x1A,0xDF,0xB7,
    0xB8,0xE1,0xAF,0xED,0x6A,0x26,0x7E,0x96,
    0xBA,0x7C,0x90,0x45,0xF1,0x2C,0x7F,0x99,
    0x24,0xA1,0x99,0x47,0xB3,0x91,0x6C,0xF7,
    0x08,0x01,0xF2,0xE2,0x85,0x8E,0xFC,0x16,
    0x63,0x69,0x20,0xD8,0x71,0x57,0x4E,0x69,
    0xA4,0x58,0xFE,0xA3,0xF4,0x93,0x3D,0x7E,
    0x0D,0x95,0x74,0x8F,0x72,0x8E,0xB6,0x58,
    0x71,0x8B,0xCD,0x58,0x82,0x15,0x4A,0xEE,
    0x7B,0x54,0xA4,0x1D,0xC2,0x5A,0x59,0xB5,
    0x9C,0x30,0xD5,0x39,0x2A,0xF2,0x60,0x13,
    0xC5,0xD1,0xB0,0x23,0x28,0x60,0x85,0xF0,
    0xCA,0x41,0x79,0x18,0xB8,0xDB,0x38,0xEF,
    0x8E,0x79,0xDC,0xB0,0x60,0x3A,0x18,0x0E,
    0x6C,0x9E,0x0E,0x8B,0xB0,0x1E,0x8A,0x3E,
    0xD7,0x15,0x77,0xC1,0xBD,0x31,0x4B,0x27,
    0x78,0xAF,0x2F,0xDA,0x55,0x60,0x5C,0x60,
    0xE6,0x55,0x25,0xF3,0xAA,0x55,0xAB,0x94,
    0x57,0x48,0x98,0x62,0x63,0xE8,0x14,0x40,
    0x55,0xCA,0x39,0x6A,0x2A,0xAB,0x10,0xB6,
    0xB4,0xCC,0x5C,0x34,0x11,0x41,0xE8,0xCE,
    0xA1,0x54,0x86,0xAF,0x7C,0x72,0xE9,0x93,
};

struct river5_ctx {
    __m128i  lane[LANES_V5];
    uint64_t total_bytes;
    size_t   buf_len;
    uint8_t  buf[BLOCK_V5];
};

RIVER5_AESNI_FN
static inline __m128i load128(const void *p)
{
    return _mm_loadu_si128((const __m128i *)p);
}

RIVER5_AESNI_FN
static void init_lanes(__m128i lane[LANES_V5], const uint8_t *seed)
{
    for (int i = 0; i < LANES_V5; ++i) {
        lane[i] = load128(&RIVER5_V5_SECRET[i * LANE_BYTES]);
    }
    if (seed) {
        __m128i s0 = load128(seed);
        __m128i s1 = load128(seed + 16);
        for (int i = 0; i < LANES_V5; ++i) {
            uint64_t k    = (uint64_t)i * 0x9E3779B97F4A7C15ULL;
            __m128i  diff = _mm_set_epi64x((int64_t)k, (int64_t)~k);
            __m128i  tmp  = _mm_xor_si128(_mm_xor_si128(lane[i], s0), diff);
            lane[i]       = _mm_aesenc_si128(tmp, s1);
        }
    }
}

/* Symmetric butterfly — identical to v3's. */
RIVER5_AESNI_FN
static inline void butterfly_mix(__m128i lane[LANES_V5])
{
    __m128i t0 = lane[0], t1 = lane[1], t2 = lane[2], t3 = lane[3];
    __m128i t4 = lane[4], t5 = lane[5], t6 = lane[6], t7 = lane[7];

    lane[0]  = _mm_aesenc_si128(lane[0],  lane[ 8]);
    lane[1]  = _mm_aesenc_si128(lane[1],  lane[ 9]);
    lane[2]  = _mm_aesenc_si128(lane[2],  lane[10]);
    lane[3]  = _mm_aesenc_si128(lane[3],  lane[11]);
    lane[4]  = _mm_aesenc_si128(lane[4],  lane[12]);
    lane[5]  = _mm_aesenc_si128(lane[5],  lane[13]);
    lane[6]  = _mm_aesenc_si128(lane[6],  lane[14]);
    lane[7]  = _mm_aesenc_si128(lane[7],  lane[15]);
    lane[8]  = _mm_aesenc_si128(lane[ 8], t0);
    lane[9]  = _mm_aesenc_si128(lane[ 9], t1);
    lane[10] = _mm_aesenc_si128(lane[10], t2);
    lane[11] = _mm_aesenc_si128(lane[11], t3);
    lane[12] = _mm_aesenc_si128(lane[12], t4);
    lane[13] = _mm_aesenc_si128(lane[13], t5);
    lane[14] = _mm_aesenc_si128(lane[14], t6);
    lane[15] = _mm_aesenc_si128(lane[15], t7);
}

/* Main loop — identical to v3. 16 input-mixing AESENCs + butterfly. */
RIVER5_AESNI_FN
static inline void process_block(__m128i lane[LANES_V5], const uint8_t *block)
{
    lane[0]  = _mm_aesenc_si128(lane[0],  load128(block +  0 * 16));
    lane[1]  = _mm_aesenc_si128(lane[1],  load128(block +  1 * 16));
    lane[2]  = _mm_aesenc_si128(lane[2],  load128(block +  2 * 16));
    lane[3]  = _mm_aesenc_si128(lane[3],  load128(block +  3 * 16));
    lane[4]  = _mm_aesenc_si128(lane[4],  load128(block +  4 * 16));
    lane[5]  = _mm_aesenc_si128(lane[5],  load128(block +  5 * 16));
    lane[6]  = _mm_aesenc_si128(lane[6],  load128(block +  6 * 16));
    lane[7]  = _mm_aesenc_si128(lane[7],  load128(block +  7 * 16));
    lane[8]  = _mm_aesenc_si128(lane[8],  load128(block +  8 * 16));
    lane[9]  = _mm_aesenc_si128(lane[9],  load128(block +  9 * 16));
    lane[10] = _mm_aesenc_si128(lane[10], load128(block + 10 * 16));
    lane[11] = _mm_aesenc_si128(lane[11], load128(block + 11 * 16));
    lane[12] = _mm_aesenc_si128(lane[12], load128(block + 12 * 16));
    lane[13] = _mm_aesenc_si128(lane[13], load128(block + 13 * 16));
    lane[14] = _mm_aesenc_si128(lane[14], load128(block + 14 * 16));
    lane[15] = _mm_aesenc_si128(lane[15], load128(block + 15 * 16));

    butterfly_mix(lane);
}

/*
 * v5b finalize: TWO rounds of per-lane non-linear AESENC at the start,
 * each round keyed by a different (π-derived per-lane constant XOR
 * length-encoding) — gives every output bit ~2 rounds of AES's
 * non-linear S-box between any input differential and the output.
 *
 * Round 1 keys: SECRET in REVERSE-lane order  XOR (total_bytes:  ~total_bytes)
 * Round 2 keys: SECRET in SHIFTED  order (i^8) XOR (~total_bytes:  total_bytes)
 *
 * The keys differ in both source bytes AND length-half ordering so
 * the two rounds are genuinely independent transforms (not just
 * "the same round twice"). Then v3's pre-diffusion butterfly + tree
 * reduce + length-fold run unchanged.
 */
RIVER5_AESNI_FN
static __m128i finalize_state(__m128i lane[LANES_V5], uint64_t total_bytes)
{
    /* === v5 ROUND 1: per-lane non-linear pre-mix === */
    __m128i len_fold  = _mm_set_epi64x((int64_t)~total_bytes,
                                        (int64_t)total_bytes);

    lane[ 0] = _mm_aesenc_si128(lane[ 0], _mm_xor_si128(load128(&RIVER5_V5_SECRET[15 * 16]), len_fold));
    lane[ 1] = _mm_aesenc_si128(lane[ 1], _mm_xor_si128(load128(&RIVER5_V5_SECRET[14 * 16]), len_fold));
    lane[ 2] = _mm_aesenc_si128(lane[ 2], _mm_xor_si128(load128(&RIVER5_V5_SECRET[13 * 16]), len_fold));
    lane[ 3] = _mm_aesenc_si128(lane[ 3], _mm_xor_si128(load128(&RIVER5_V5_SECRET[12 * 16]), len_fold));
    lane[ 4] = _mm_aesenc_si128(lane[ 4], _mm_xor_si128(load128(&RIVER5_V5_SECRET[11 * 16]), len_fold));
    lane[ 5] = _mm_aesenc_si128(lane[ 5], _mm_xor_si128(load128(&RIVER5_V5_SECRET[10 * 16]), len_fold));
    lane[ 6] = _mm_aesenc_si128(lane[ 6], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 9 * 16]), len_fold));
    lane[ 7] = _mm_aesenc_si128(lane[ 7], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 8 * 16]), len_fold));
    lane[ 8] = _mm_aesenc_si128(lane[ 8], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 7 * 16]), len_fold));
    lane[ 9] = _mm_aesenc_si128(lane[ 9], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 6 * 16]), len_fold));
    lane[10] = _mm_aesenc_si128(lane[10], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 5 * 16]), len_fold));
    lane[11] = _mm_aesenc_si128(lane[11], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 4 * 16]), len_fold));
    lane[12] = _mm_aesenc_si128(lane[12], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 3 * 16]), len_fold));
    lane[13] = _mm_aesenc_si128(lane[13], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 2 * 16]), len_fold));
    lane[14] = _mm_aesenc_si128(lane[14], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 1 * 16]), len_fold));
    lane[15] = _mm_aesenc_si128(lane[15], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 0 * 16]), len_fold));

    /* === v5b ROUND 2: second per-lane non-linear pre-mix === */
    /* Lane i now reads SECRET at index (i ^ 8) to pull a different
     * 16-byte slice than round 1, and uses the SWAPPED length encoding
     * (~total_bytes in low half, total_bytes in high half). */
    __m128i len_swap  = _mm_set_epi64x((int64_t)total_bytes,
                                        (int64_t)~total_bytes);

    lane[ 0] = _mm_aesenc_si128(lane[ 0], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 8 * 16]), len_swap));
    lane[ 1] = _mm_aesenc_si128(lane[ 1], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 9 * 16]), len_swap));
    lane[ 2] = _mm_aesenc_si128(lane[ 2], _mm_xor_si128(load128(&RIVER5_V5_SECRET[10 * 16]), len_swap));
    lane[ 3] = _mm_aesenc_si128(lane[ 3], _mm_xor_si128(load128(&RIVER5_V5_SECRET[11 * 16]), len_swap));
    lane[ 4] = _mm_aesenc_si128(lane[ 4], _mm_xor_si128(load128(&RIVER5_V5_SECRET[12 * 16]), len_swap));
    lane[ 5] = _mm_aesenc_si128(lane[ 5], _mm_xor_si128(load128(&RIVER5_V5_SECRET[13 * 16]), len_swap));
    lane[ 6] = _mm_aesenc_si128(lane[ 6], _mm_xor_si128(load128(&RIVER5_V5_SECRET[14 * 16]), len_swap));
    lane[ 7] = _mm_aesenc_si128(lane[ 7], _mm_xor_si128(load128(&RIVER5_V5_SECRET[15 * 16]), len_swap));
    lane[ 8] = _mm_aesenc_si128(lane[ 8], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 0 * 16]), len_swap));
    lane[ 9] = _mm_aesenc_si128(lane[ 9], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 1 * 16]), len_swap));
    lane[10] = _mm_aesenc_si128(lane[10], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 2 * 16]), len_swap));
    lane[11] = _mm_aesenc_si128(lane[11], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 3 * 16]), len_swap));
    lane[12] = _mm_aesenc_si128(lane[12], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 4 * 16]), len_swap));
    lane[13] = _mm_aesenc_si128(lane[13], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 5 * 16]), len_swap));
    lane[14] = _mm_aesenc_si128(lane[14], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 6 * 16]), len_swap));
    lane[15] = _mm_aesenc_si128(lane[15], _mm_xor_si128(load128(&RIVER5_V5_SECRET[ 7 * 16]), len_swap));

    /* === v3 unchanged from here: pre-diffusion butterfly + tree reduce === */
    butterfly_mix(lane);

    __m128i a0 = _mm_aesenc_si128(lane[0], lane[8]);
    __m128i a1 = _mm_aesenc_si128(lane[1], lane[9]);
    __m128i a2 = _mm_aesenc_si128(lane[2], lane[10]);
    __m128i a3 = _mm_aesenc_si128(lane[3], lane[11]);
    __m128i a4 = _mm_aesenc_si128(lane[4], lane[12]);
    __m128i a5 = _mm_aesenc_si128(lane[5], lane[13]);
    __m128i a6 = _mm_aesenc_si128(lane[6], lane[14]);
    __m128i a7 = _mm_aesenc_si128(lane[7], lane[15]);

    __m128i b0 = _mm_aesenc_si128(a0, a4);
    __m128i b1 = _mm_aesenc_si128(a1, a5);
    __m128i b2 = _mm_aesenc_si128(a2, a6);
    __m128i b3 = _mm_aesenc_si128(a3, a7);

    __m128i c0 = _mm_aesenc_si128(b0, b2);
    __m128i c1 = _mm_aesenc_si128(b1, b3);

    __m128i d        = _mm_aesenc_si128(c0, c1);
    __m128i len_blk  = _mm_set_epi64x((int64_t)total_bytes,
                                       (int64_t)~total_bytes);
    return _mm_aesenc_si128(d, len_blk);
}

/* ---- vtable backends (structurally identical to v3) ---- */

RIVER5_AESNI_FN
static void v5_one_shot(const void *input, size_t len,
                         const uint8_t *seed, uint8_t *out)
{
    __m128i lane[LANES_V5];
    init_lanes(lane, seed);

    const uint8_t *p         = (const uint8_t *)input;
    size_t         remaining = len;

    while (remaining >= BLOCK_V5 * 2) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(p + BLOCK_V5, 0, 0);
#endif
        process_block(lane, p);
        p         += BLOCK_V5;
        remaining -= BLOCK_V5;
    }
    while (remaining >= BLOCK_V5) {
        process_block(lane, p);
        p         += BLOCK_V5;
        remaining -= BLOCK_V5;
    }

    if (remaining > 0) {
        uint8_t tail[BLOCK_V5];
        memcpy(tail, p, remaining);
        memcpy(tail + remaining,
               RIVER5_V5_SECRET + remaining,
               BLOCK_V5 - remaining);
        process_block(lane, tail);
    }

    __m128i r = finalize_state(lane, (uint64_t)len);
    _mm_storeu_si128((__m128i *)out, r);
}

RIVER5_AESNI_FN
static river5_ctx_t *v5_new(const uint8_t *seed)
{
    size_t sz = (sizeof(struct river5_ctx) + 15u) & ~(size_t)15u;
#if defined(_MSC_VER)
    river5_ctx_t *c = (river5_ctx_t *)_aligned_malloc(sz, 16);
#else
    river5_ctx_t *c = (river5_ctx_t *)aligned_alloc(16, sz);
#endif
    if (!c) return NULL;
    init_lanes(c->lane, seed);
    c->total_bytes = 0;
    c->buf_len     = 0;
    return c;
}

RIVER5_AESNI_FN
static void v5_update(river5_ctx_t *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->total_bytes += (uint64_t)len;

    __m128i lane[LANES_V5];
    memcpy(lane, c->lane, sizeof(lane));

    if (c->buf_len > 0) {
        size_t need = BLOCK_V5 - c->buf_len;
        size_t take = (len < need) ? len : need;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take;
        p          += take;
        len        -= take;
        if (c->buf_len == BLOCK_V5) {
            process_block(lane, c->buf);
            c->buf_len = 0;
        }
    }

    while (len >= BLOCK_V5 * 2) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(p + BLOCK_V5, 0, 0);
#endif
        process_block(lane, p);
        p   += BLOCK_V5;
        len -= BLOCK_V5;
    }
    while (len >= BLOCK_V5) {
        process_block(lane, p);
        p   += BLOCK_V5;
        len -= BLOCK_V5;
    }

    if (len > 0) {
        memcpy(c->buf, p, len);
        c->buf_len = len;
    }

    memcpy(c->lane, lane, sizeof(lane));
}

RIVER5_AESNI_FN
static void v5_finalize(river5_ctx_t *c, uint8_t *out)
{
    if (c->buf_len > 0) {
        memcpy(c->buf + c->buf_len,
               RIVER5_V5_SECRET + c->buf_len,
               BLOCK_V5 - c->buf_len);
        process_block(c->lane, c->buf);
        c->buf_len = 0;
    }
    __m128i r = finalize_state(c->lane, c->total_bytes);
    _mm_storeu_si128((__m128i *)out, r);
}

static void v5_free(river5_ctx_t *c)
{
    if (!c) return;
#if defined(_MSC_VER)
    _aligned_free(c);
#else
    free(c);
#endif
}

const river5_vtable RIVER5_VTABLE_AESNI_V5 = {
    .one_shot   = v5_one_shot,
    .new_state  = v5_new,
    .update     = v5_update,
    .finalize   = v5_finalize,
    .free_state = v5_free,
    .name       = "river5-aesni-v5b",
};
