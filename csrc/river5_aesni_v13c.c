/*
 * river5 v13c — v3 + per-lane PSHUFB byte rotation of input.
 *
 * Targets the structural failure on Permutation keysets that v5/v5b
 * couldn't reach. The hypothesis: those failures (9× excess on
 * 'Combination 8-bytes [0, low bit; LE]') stem from every lane seeing
 * the SAME 16-byte slice of input when the input is 8-byte cyclic —
 * lane[i]'s AESENC effectively has a fixed input-byte mapping.
 *
 * v13c makes each lane see a DIFFERENT byte ordering of its 16-byte
 * input slice via PSHUFB, with rotation amount = lane index. Even
 * for cyclic input, lane[1] sees its input shifted by 1 byte vs
 * lane[0], lane[2] shifted by 2 vs lane[0], etc.
 *
 * Known limitation: byte rotation by N over an N-cyclic pattern is
 * identity. So for 8-byte cyclic input, lane[0] and lane[8] still
 * see the same effective bytes. This may not fully clear the killer
 * keyset, but should help every other failing keyset (where the
 * cyclic period isn't aligned with a single rotation amount).
 *
 * Cost: 16 PSHUFB + 16 shuffle-pattern LOADs per 256-byte block.
 * PSHUFB lives on port 5; AESENC on port 0. They pipeline well, so
 * predicted throughput cost is ~5-10% vs v3.
 *
 * Status: experimental. NOT the dispatcher default — v3 still ships.
 * Promote v13c only if SMHasher3 Permutation clears or substantially
 * improves on every keyset.
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

#define LANES_V13C   16
#define LANE_BYTES 16
#define BLOCK_V13C   (LANES_V13C * LANE_BYTES)   /* 256 */

/* π-derived secret, same as v3. */
static const RIVER5_ALIGN16 uint8_t RIVER5_V13C_SECRET[256] = {
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
static const RIVER5_ALIGN16 uint8_t RIVER5_V13C_SHUFFLE[16][16] = {
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
    __m128i  lane[LANES_V13C];
    uint64_t total_bytes;
    size_t   buf_len;
    uint8_t  buf[BLOCK_V13C];
};

RIVER5_AESNI_FN
static inline __m128i load128(const void *p)
{
    return _mm_loadu_si128((const __m128i *)p);
}

RIVER5_AESNI_FN
static void init_lanes(__m128i lane[LANES_V13C], const uint8_t *seed)
{
    for (int i = 0; i < LANES_V13C; ++i) {
        lane[i] = load128(&RIVER5_V13C_SECRET[i * LANE_BYTES]);
    }
    if (seed) {
        __m128i s0 = load128(seed);
        __m128i s1 = load128(seed + 16);
        for (int i = 0; i < LANES_V13C; ++i) {
            uint64_t k    = (uint64_t)i * 0x9E3779B97F4A7C15ULL;
            __m128i  diff = _mm_set_epi64x((int64_t)k, (int64_t)~k);
            __m128i  tmp  = _mm_xor_si128(_mm_xor_si128(lane[i], s0), diff);
            lane[i]       = _mm_aesenc_si128(tmp, s1);
        }
    }
}

/* Symmetric butterfly — identical to v3's. */
RIVER5_AESNI_FN
static inline void butterfly_mix(__m128i lane[LANES_V13C])
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

/*
 * v13c process_block: HYBRID v6 fixed PSHUFB + v13 content-dependent XOR mix.
 *
 *   shuf_v6[i]    = PSHUFB(in_self, FIXED_SHUFFLE[i])           ← v6
 *   shuf_partner  = PSHUFB(in_partner, in_partner & 0x0F)        ← v13
 *   mixed[i]      = shuf_v6[i] XOR shuf_partner
 *   lane[i]       = AESENC(lane[i], mixed[i])
 *
 * v6's distinct fixed PSHUFB patterns make each lane see a different
 * byte ordering of self's input — defeats the 8-byte cyclic killer
 * because even when self inputs are identical across lanes, the
 * SHUFFLED versions differ.
 *
 * The XOR'd content-dependent partner shuffle adds the v13-style
 * data-driven mixing on top, which is what produced v13's 1.14-1.33×
 * improvement on the bulk of Permutation keysets.
 *
 * Goal: combine both defenses in one stream at v6 speed.
 *
 * Cost vs v6: one extra PSHUFB per lane + one extra AND per lane + one
 * extra XOR per lane = ~3 extra ops per lane. PSHUFB on port 5, AND/XOR
 * on any ALU port. Pipelines freely with AESENC's port 0 bottleneck.
 * Predicted: 5-15% slowdown vs v6.
 */
#define SHUF(i) load128(&RIVER5_V13C_SHUFFLE[(i)][0])

RIVER5_AESNI_FN
static inline void process_block(__m128i lane[LANES_V13C], const uint8_t *block)
{
    const __m128i nibble_mask = _mm_set1_epi8(0x0F);

    /* Pre-load all 16 input slices — each lane reads self + partner. */
    __m128i in0  = load128(block +  0 * 16);
    __m128i in1  = load128(block +  1 * 16);
    __m128i in2  = load128(block +  2 * 16);
    __m128i in3  = load128(block +  3 * 16);
    __m128i in4  = load128(block +  4 * 16);
    __m128i in5  = load128(block +  5 * 16);
    __m128i in6  = load128(block +  6 * 16);
    __m128i in7  = load128(block +  7 * 16);
    __m128i in8  = load128(block +  8 * 16);
    __m128i in9  = load128(block +  9 * 16);
    __m128i in10 = load128(block + 10 * 16);
    __m128i in11 = load128(block + 11 * 16);
    __m128i in12 = load128(block + 12 * 16);
    __m128i in13 = load128(block + 13 * 16);
    __m128i in14 = load128(block + 14 * 16);
    __m128i in15 = load128(block + 15 * 16);

    /* v13c mix: v6's fixed-shuffle of self XOR partner-content-dep shuffle of partner. */
#define V13C_MIX(self, partner, fixed_idx) \
    _mm_xor_si128(_mm_shuffle_epi8(self, SHUF(fixed_idx)),                        \
                  _mm_shuffle_epi8(partner, _mm_and_si128(partner, nibble_mask)))

    lane[ 0] = _mm_aesenc_si128(lane[ 0], V13C_MIX(in0,  in8,   0));
    lane[ 1] = _mm_aesenc_si128(lane[ 1], V13C_MIX(in1,  in9,   1));
    lane[ 2] = _mm_aesenc_si128(lane[ 2], V13C_MIX(in2,  in10,  2));
    lane[ 3] = _mm_aesenc_si128(lane[ 3], V13C_MIX(in3,  in11,  3));
    lane[ 4] = _mm_aesenc_si128(lane[ 4], V13C_MIX(in4,  in12,  4));
    lane[ 5] = _mm_aesenc_si128(lane[ 5], V13C_MIX(in5,  in13,  5));
    lane[ 6] = _mm_aesenc_si128(lane[ 6], V13C_MIX(in6,  in14,  6));
    lane[ 7] = _mm_aesenc_si128(lane[ 7], V13C_MIX(in7,  in15,  7));
    lane[ 8] = _mm_aesenc_si128(lane[ 8], V13C_MIX(in8,  in0,   8));
    lane[ 9] = _mm_aesenc_si128(lane[ 9], V13C_MIX(in9,  in1,   9));
    lane[10] = _mm_aesenc_si128(lane[10], V13C_MIX(in10, in2,  10));
    lane[11] = _mm_aesenc_si128(lane[11], V13C_MIX(in11, in3,  11));
    lane[12] = _mm_aesenc_si128(lane[12], V13C_MIX(in12, in4,  12));
    lane[13] = _mm_aesenc_si128(lane[13], V13C_MIX(in13, in5,  13));
    lane[14] = _mm_aesenc_si128(lane[14], V13C_MIX(in14, in6,  14));
    lane[15] = _mm_aesenc_si128(lane[15], V13C_MIX(in15, in7,  15));

#undef V13C_MIX

    butterfly_mix(lane);
}

/* Identical to v3 finalize: pre-diffusion butterfly + 4-round tree. */
RIVER5_AESNI_FN
static __m128i finalize_state(__m128i lane[LANES_V13C], uint64_t total_bytes)
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
static void v13c_one_shot(const void *input, size_t len,
                         const uint8_t *seed, uint8_t *out)
{
    __m128i lane[LANES_V13C];
    init_lanes(lane, seed);

    const uint8_t *p         = (const uint8_t *)input;
    size_t         remaining = len;

    while (remaining >= BLOCK_V13C * 2) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(p + BLOCK_V13C, 0, 0);
#endif
        process_block(lane, p);
        p         += BLOCK_V13C;
        remaining -= BLOCK_V13C;
    }
    while (remaining >= BLOCK_V13C) {
        process_block(lane, p);
        p         += BLOCK_V13C;
        remaining -= BLOCK_V13C;
    }

    if (remaining > 0) {
        uint8_t tail[BLOCK_V13C];
        memcpy(tail, p, remaining);
        memcpy(tail + remaining,
               RIVER5_V13C_SECRET + remaining,
               BLOCK_V13C - remaining);
        process_block(lane, tail);
    }

    __m128i r = finalize_state(lane, (uint64_t)len);
    _mm_storeu_si128((__m128i *)out, r);
}

RIVER5_AESNI_FN
static river5_ctx_t *v13c_new(const uint8_t *seed)
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
static void v13c_update(river5_ctx_t *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->total_bytes += (uint64_t)len;

    __m128i lane[LANES_V13C];
    memcpy(lane, c->lane, sizeof(lane));

    if (c->buf_len > 0) {
        size_t need = BLOCK_V13C - c->buf_len;
        size_t take = (len < need) ? len : need;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take;
        p          += take;
        len        -= take;
        if (c->buf_len == BLOCK_V13C) {
            process_block(lane, c->buf);
            c->buf_len = 0;
        }
    }

    while (len >= BLOCK_V13C * 2) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(p + BLOCK_V13C, 0, 0);
#endif
        process_block(lane, p);
        p   += BLOCK_V13C;
        len -= BLOCK_V13C;
    }
    while (len >= BLOCK_V13C) {
        process_block(lane, p);
        p   += BLOCK_V13C;
        len -= BLOCK_V13C;
    }

    if (len > 0) {
        memcpy(c->buf, p, len);
        c->buf_len = len;
    }

    memcpy(c->lane, lane, sizeof(lane));
}

RIVER5_AESNI_FN
static void v13c_finalize(river5_ctx_t *c, uint8_t *out)
{
    if (c->buf_len > 0) {
        memcpy(c->buf + c->buf_len,
               RIVER5_V13C_SECRET + c->buf_len,
               BLOCK_V13C - c->buf_len);
        process_block(c->lane, c->buf);
        c->buf_len = 0;
    }
    __m128i r = finalize_state(c->lane, c->total_bytes);
    _mm_storeu_si128((__m128i *)out, r);
}

static void v13c_free(river5_ctx_t *c)
{
    if (!c) return;
    /* Matches the _WIN32 alloc-side guard above. */
#if defined(_WIN32)
    _aligned_free(c);
#else
    free(c);
#endif
}

const river5_vtable RIVER5_VTABLE_AESNI_V13C = {
    .one_shot   = v13c_one_shot,
    .new_state  = v13c_new,
    .update     = v13c_update,
    .finalize   = v13c_finalize,
    .free_state = v13c_free,
    .name       = "river5-aesni-v13c",
};
