/*
 * river5 v10 = v6 + dual butterfly per block (d8 then d4) in the main loop.
 *
 * The "heavy fix" after v4/v5/v7/v8/v9 confirmed that finalize-only
 * tweaks can't pass v6's ~1.5× Permutation ceiling. Five cheap-fix
 * attempts either regressed (interference / repeated-pattern attacks)
 * or distributed the residual without clearing it.
 *
 * v10 changes the main loop: every process_block now does TWO
 * cross-lane butterfly rounds instead of one, using disjoint pair
 * structures so each round provides genuinely new differential
 * resistance (not the v8 repeated-pattern trap):
 *
 *   Step 1 — v6 input mix:      16 AESENCs (PSHUFB + AESENC per lane)
 *   Step 2 — butterfly_mix_d8:  16 AESENCs pair (i, i^8)
 *   Step 3 — butterfly_mix_d4:  16 AESENCs pair (i, i^4)
 *                               TOTAL: 48 AESENCs per 256-byte block
 *                                      (v6 was 32 AESENCs)
 *
 * Per-byte cost: 50% more main-loop AES work than v6. On the i7-7700K's
 * single AES execution unit, that means roughly 33% slowdown vs v6 in
 * the cache-resident regime. Expected: v6's ~20 GB/s → v10's ~13-15
 * GB/s in cache. Still beats BLAKE3 (~3 GB/s) by 4-5×.
 *
 * Theory: each AES round provides ~6 bits of differential resistance.
 * v6 main loop: 2 AES layers ≈ 12 bits per block.
 * v10 main loop: 3 AES layers ≈ 18 bits per block.
 * For single-block keys (the SMHasher3 Permutation killers), the
 * extra 6 bits should drop the 1.5× residual by ~factor 64 → ~1.02×
 * which clears the score-99 (~1.05×) threshold. That's the bet.
 *
 * Status: experimental. v6 is the current main default. v10 only
 * promotes to main if SMHasher3 Permutation actually clears (the test
 * everything else has been ruled out for).
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
#  include <tmmintrin.h>   /* PSHUFB / _mm_shuffle_epi8 */
#  if defined(__GNUC__) || defined(__clang__)
#    define RIVER5_AESNI_FN __attribute__((target("aes,ssse3,sse4.1")))
#  else
#    define RIVER5_AESNI_FN
#  endif
#endif

#define LANES_V10   16
#define LANE_BYTES 16
#define BLOCK_V10   (LANES_V10 * LANE_BYTES)   /* 256 */

/* π-derived secret, same as v3. */
static const RIVER5_ALIGN16 uint8_t RIVER5_V10_SECRET[256] = {
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

/*
 * Per-lane PSHUFB patterns: 16 distinct byte permutations of {0..15},
 * chosen to NOT be simple rotations (which alone wouldn't defeat
 * 8-byte cyclic input). Each pattern is a full permutation so every
 * input byte contributes to the lane's AESENC input.
 *
 * The patterns combine: pair swaps, half swaps, and full byte
 * reversal. Adjacent lanes (i, i+1) get visibly different patterns
 * so a single byte change in one input position lands at a different
 * AES position per lane.
 */
static const RIVER5_ALIGN16 uint8_t RIVER5_V10_SHUFFLE[16][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15},   /* identity */
    { 1, 0, 3, 2, 5, 4, 7, 6, 9, 8,11,10,13,12,15,14},   /* pair swap */
    { 2, 3, 0, 1, 6, 7, 4, 5,10,11, 8, 9,14,15,12,13},   /* 4-group swap */
    { 3, 2, 1, 0, 7, 6, 5, 4,11,10, 9, 8,15,14,13,12},   /* 4-reverse */
    { 4, 5, 6, 7, 0, 1, 2, 3,12,13,14,15, 8, 9,10,11},   /* 8-half swap */
    { 5, 4, 7, 6, 1, 0, 3, 2,13,12,15,14, 9, 8,11,10},   /* 8-half + pair */
    { 6, 7, 4, 5, 2, 3, 0, 1,14,15,12,13,10,11, 8, 9},
    { 7, 6, 5, 4, 3, 2, 1, 0,15,14,13,12,11,10, 9, 8},   /* 8-half reverse */
    { 8, 9,10,11,12,13,14,15, 0, 1, 2, 3, 4, 5, 6, 7},   /* top-bot swap */
    { 9, 8,11,10,13,12,15,14, 1, 0, 3, 2, 5, 4, 7, 6},
    {10,11, 8, 9,14,15,12,13, 2, 3, 0, 1, 6, 7, 4, 5},
    {11,10, 9, 8,15,14,13,12, 3, 2, 1, 0, 7, 6, 5, 4},
    {12,13,14,15, 8, 9,10,11, 4, 5, 6, 7, 0, 1, 2, 3},
    {13,12,15,14, 9, 8,11,10, 5, 4, 7, 6, 1, 0, 3, 2},
    {14,15,12,13,10,11, 8, 9, 6, 7, 4, 5, 2, 3, 0, 1},
    {15,14,13,12,11,10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},   /* full reverse */
};

struct river5_ctx {
    __m128i  lane[LANES_V10];
    uint64_t total_bytes;
    size_t   buf_len;
    uint8_t  buf[BLOCK_V10];
};

RIVER5_AESNI_FN
static inline __m128i load128(const void *p)
{
    return _mm_loadu_si128((const __m128i *)p);
}

RIVER5_AESNI_FN
static void init_lanes(__m128i lane[LANES_V10], const uint8_t *seed)
{
    for (int i = 0; i < LANES_V10; ++i) {
        lane[i] = load128(&RIVER5_V10_SECRET[i * LANE_BYTES]);
    }
    if (seed) {
        __m128i s0 = load128(seed);
        __m128i s1 = load128(seed + 16);
        for (int i = 0; i < LANES_V10; ++i) {
            uint64_t k    = (uint64_t)i * 0x9E3779B97F4A7C15ULL;
            __m128i  diff = _mm_set_epi64x((int64_t)k, (int64_t)~k);
            __m128i  tmp  = _mm_xor_si128(_mm_xor_si128(lane[i], s0), diff);
            lane[i]       = _mm_aesenc_si128(tmp, s1);
        }
    }
}

/* d8 butterfly — pair (i, i^8). Same as v3/v6. */
RIVER5_AESNI_FN
static inline void butterfly_mix_d8(__m128i lane[LANES_V10])
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

/* d4 butterfly — pair (i, i^4). Disjoint pair structure from d8.
 * Pairs: (0,4) (1,5) (2,6) (3,7) (8,12) (9,13) (10,14) (11,15). */
RIVER5_AESNI_FN
static inline void butterfly_mix_d4(__m128i lane[LANES_V10])
{
    __m128i t0 = lane[0], t1 = lane[1], t2  = lane[2],  t3  = lane[3];
    __m128i t8 = lane[8], t9 = lane[9], t10 = lane[10], t11 = lane[11];

    lane[0]  = _mm_aesenc_si128(lane[0],  lane[4]);
    lane[1]  = _mm_aesenc_si128(lane[1],  lane[5]);
    lane[2]  = _mm_aesenc_si128(lane[2],  lane[6]);
    lane[3]  = _mm_aesenc_si128(lane[3],  lane[7]);
    lane[4]  = _mm_aesenc_si128(lane[4],  t0);
    lane[5]  = _mm_aesenc_si128(lane[5],  t1);
    lane[6]  = _mm_aesenc_si128(lane[6],  t2);
    lane[7]  = _mm_aesenc_si128(lane[7],  t3);
    lane[8]  = _mm_aesenc_si128(lane[8],  lane[12]);
    lane[9]  = _mm_aesenc_si128(lane[9],  lane[13]);
    lane[10] = _mm_aesenc_si128(lane[10], lane[14]);
    lane[11] = _mm_aesenc_si128(lane[11], lane[15]);
    lane[12] = _mm_aesenc_si128(lane[12], t8);
    lane[13] = _mm_aesenc_si128(lane[13], t9);
    lane[14] = _mm_aesenc_si128(lane[14], t10);
    lane[15] = _mm_aesenc_si128(lane[15], t11);
}

/* Alias for existing call sites — v6 only had one butterfly. */
#define butterfly_mix butterfly_mix_d8

/*
 * v10 process_block: input goes through per-lane PSHUFB before AESENC.
 * Same number of AESENCs as v3 (16 input + 16 butterfly = 32 per block);
 * adds 16 PSHUFB + 16 shuffle-pattern loads.
 */
#define SHUF(i) load128(&RIVER5_V10_SHUFFLE[(i)][0])

RIVER5_AESNI_FN
static inline void process_block(__m128i lane[LANES_V10], const uint8_t *block)
{
    lane[ 0] = _mm_aesenc_si128(lane[ 0], _mm_shuffle_epi8(load128(block +  0 * 16), SHUF( 0)));
    lane[ 1] = _mm_aesenc_si128(lane[ 1], _mm_shuffle_epi8(load128(block +  1 * 16), SHUF( 1)));
    lane[ 2] = _mm_aesenc_si128(lane[ 2], _mm_shuffle_epi8(load128(block +  2 * 16), SHUF( 2)));
    lane[ 3] = _mm_aesenc_si128(lane[ 3], _mm_shuffle_epi8(load128(block +  3 * 16), SHUF( 3)));
    lane[ 4] = _mm_aesenc_si128(lane[ 4], _mm_shuffle_epi8(load128(block +  4 * 16), SHUF( 4)));
    lane[ 5] = _mm_aesenc_si128(lane[ 5], _mm_shuffle_epi8(load128(block +  5 * 16), SHUF( 5)));
    lane[ 6] = _mm_aesenc_si128(lane[ 6], _mm_shuffle_epi8(load128(block +  6 * 16), SHUF( 6)));
    lane[ 7] = _mm_aesenc_si128(lane[ 7], _mm_shuffle_epi8(load128(block +  7 * 16), SHUF( 7)));
    lane[ 8] = _mm_aesenc_si128(lane[ 8], _mm_shuffle_epi8(load128(block +  8 * 16), SHUF( 8)));
    lane[ 9] = _mm_aesenc_si128(lane[ 9], _mm_shuffle_epi8(load128(block +  9 * 16), SHUF( 9)));
    lane[10] = _mm_aesenc_si128(lane[10], _mm_shuffle_epi8(load128(block + 10 * 16), SHUF(10)));
    lane[11] = _mm_aesenc_si128(lane[11], _mm_shuffle_epi8(load128(block + 11 * 16), SHUF(11)));
    lane[12] = _mm_aesenc_si128(lane[12], _mm_shuffle_epi8(load128(block + 12 * 16), SHUF(12)));
    lane[13] = _mm_aesenc_si128(lane[13], _mm_shuffle_epi8(load128(block + 13 * 16), SHUF(13)));
    lane[14] = _mm_aesenc_si128(lane[14], _mm_shuffle_epi8(load128(block + 14 * 16), SHUF(14)));
    lane[15] = _mm_aesenc_si128(lane[15], _mm_shuffle_epi8(load128(block + 15 * 16), SHUF(15)));

    butterfly_mix_d8(lane);   /* v6 baseline */
    butterfly_mix_d4(lane);   /* v10 NEW: second cross-lane round with disjoint pair pattern */
}

/* Identical to v3 finalize: pre-diffusion butterfly + 4-round tree. */
RIVER5_AESNI_FN
static __m128i finalize_state(__m128i lane[LANES_V10], uint64_t total_bytes)
{
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

    __m128i d       = _mm_aesenc_si128(c0, c1);
    __m128i len_blk = _mm_set_epi64x((int64_t)total_bytes,
                                      (int64_t)~total_bytes);
    return _mm_aesenc_si128(d, len_blk);
}

/* ---- vtable backends (structurally identical to v3) ---- */

RIVER5_AESNI_FN
static void v10_one_shot(const void *input, size_t len,
                         const uint8_t *seed, uint8_t *out)
{
    __m128i lane[LANES_V10];
    init_lanes(lane, seed);

    const uint8_t *p         = (const uint8_t *)input;
    size_t         remaining = len;

    while (remaining >= BLOCK_V10 * 2) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(p + BLOCK_V10, 0, 0);
#endif
        process_block(lane, p);
        p         += BLOCK_V10;
        remaining -= BLOCK_V10;
    }
    while (remaining >= BLOCK_V10) {
        process_block(lane, p);
        p         += BLOCK_V10;
        remaining -= BLOCK_V10;
    }

    if (remaining > 0) {
        uint8_t tail[BLOCK_V10];
        memcpy(tail, p, remaining);
        memcpy(tail + remaining,
               RIVER5_V10_SECRET + remaining,
               BLOCK_V10 - remaining);
        process_block(lane, tail);
    }

    __m128i r = finalize_state(lane, (uint64_t)len);
    _mm_storeu_si128((__m128i *)out, r);
}

RIVER5_AESNI_FN
static river5_ctx_t *v10_new(const uint8_t *seed)
{
    size_t sz = (sizeof(struct river5_ctx) + 15u) & ~(size_t)15u;
    /* Gate on _WIN32 (platform) so both MSVC and mingw-via-zig
     * use _aligned_malloc; mingw's <stdlib.h> doesn't declare
     * aligned_alloc and would error out otherwise. */
#if defined(_WIN32)
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
static void v10_update(river5_ctx_t *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->total_bytes += (uint64_t)len;

    __m128i lane[LANES_V10];
    memcpy(lane, c->lane, sizeof(lane));

    if (c->buf_len > 0) {
        size_t need = BLOCK_V10 - c->buf_len;
        size_t take = (len < need) ? len : need;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take;
        p          += take;
        len        -= take;
        if (c->buf_len == BLOCK_V10) {
            process_block(lane, c->buf);
            c->buf_len = 0;
        }
    }

    while (len >= BLOCK_V10 * 2) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(p + BLOCK_V10, 0, 0);
#endif
        process_block(lane, p);
        p   += BLOCK_V10;
        len -= BLOCK_V10;
    }
    while (len >= BLOCK_V10) {
        process_block(lane, p);
        p   += BLOCK_V10;
        len -= BLOCK_V10;
    }

    if (len > 0) {
        memcpy(c->buf, p, len);
        c->buf_len = len;
    }

    memcpy(c->lane, lane, sizeof(lane));
}

RIVER5_AESNI_FN
static void v10_finalize(river5_ctx_t *c, uint8_t *out)
{
    if (c->buf_len > 0) {
        memcpy(c->buf + c->buf_len,
               RIVER5_V10_SECRET + c->buf_len,
               BLOCK_V10 - c->buf_len);
        process_block(c->lane, c->buf);
        c->buf_len = 0;
    }
    __m128i r = finalize_state(c->lane, c->total_bytes);
    _mm_storeu_si128((__m128i *)out, r);
}

static void v10_free(river5_ctx_t *c)
{
    if (!c) return;
    /* Matches the _WIN32 alloc-side guard above. */
#if defined(_WIN32)
    _aligned_free(c);
#else
    free(c);
#endif
}

const river5_vtable RIVER5_VTABLE_AESNI_V10 = {
    .one_shot   = v10_one_shot,
    .new_state  = v10_new,
    .update     = v10_update,
    .finalize   = v10_finalize,
    .free_state = v10_free,
    .name       = "river5-aesni-v10",
};
