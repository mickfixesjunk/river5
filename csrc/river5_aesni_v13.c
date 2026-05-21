/*
 * river5 v13 — CONTENT-DEPENDENT PSHUFB shuffles.
 *
 * v6's structural ceiling on SMHasher3 Permutation comes from FIXED
 * shuffle patterns: every input goes through the same 16 PSHUFB
 * masks. A differential attacker constructing a trail can predict
 * exactly which input byte ends up at which AES position because
 * the shuffle masks are static.
 *
 * v13 makes the shuffle masks DATA-DEPENDENT — each lane's PSHUFB
 * control is derived from the PARTNER lane's input bytes:
 *
 *   shuffle_mask[i] = input[i ^ 8] & 0x0F  (low nibble of each byte)
 *   shuffled[i]     = PSHUFB(input[i], shuffle_mask[i])
 *   lane[i]         = AESENC(lane[i], shuffled[i])
 *
 * For SMHasher3 Permutation tests where keys differ by byte position,
 * the shuffle mask changes per input. An attacker can no longer
 * predict "input byte at position p_a maps to AES position p_b" —
 * the mapping itself depends on which bytes are present.
 *
 * This is the most genuinely-novel direction in the night's run: I've
 * not seen content-dependent shuffles used in any published SMHasher-
 * passing hash. Has timing-channel implications for cryptographic use
 * (mask depends on data), irrelevant for our non-adversarial dedup
 * positioning.
 *
 * Cost vs v6: one extra _mm_and_si128 per lane (16 ANDs/block). AND
 * pipelines freely with AESENC. Predicted: ~5% slowdown vs v6.
 *
 * Status: experimental. Public dispatcher unchanged (v6).
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

#define LANES_V13   16
#define LANE_BYTES 16
#define BLOCK_V13   (LANES_V13 * LANE_BYTES)   /* 256 */

/* π-derived secret, same as v3. */
static const RIVER5_ALIGN16 uint8_t RIVER5_V13_SECRET[256] = {
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
static const RIVER5_ALIGN16 uint8_t RIVER5_V13_SHUFFLE[16][16] = {
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
    __m128i  lane[LANES_V13];
    uint64_t total_bytes;
    size_t   buf_len;
    uint8_t  buf[BLOCK_V13];
};

RIVER5_AESNI_FN
static inline __m128i load128(const void *p)
{
    return _mm_loadu_si128((const __m128i *)p);
}

RIVER5_AESNI_FN
static void init_lanes(__m128i lane[LANES_V13], const uint8_t *seed)
{
    for (int i = 0; i < LANES_V13; ++i) {
        lane[i] = load128(&RIVER5_V13_SECRET[i * LANE_BYTES]);
    }
    if (seed) {
        __m128i s0 = load128(seed);
        __m128i s1 = load128(seed + 16);
        for (int i = 0; i < LANES_V13; ++i) {
            uint64_t k    = (uint64_t)i * 0x9E3779B97F4A7C15ULL;
            __m128i  diff = _mm_set_epi64x((int64_t)k, (int64_t)~k);
            __m128i  tmp  = _mm_xor_si128(_mm_xor_si128(lane[i], s0), diff);
            lane[i]       = _mm_aesenc_si128(tmp, s1);
        }
    }
}

/* Symmetric butterfly — identical to v3's. */
RIVER5_AESNI_FN
static inline void butterfly_mix(__m128i lane[LANES_V13])
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
 * v13 process_block: CONTENT-DEPENDENT PSHUFB shuffles.
 *
 * v6 uses 16 FIXED PSHUFB patterns. The fixed structure is what gives
 * differential attackers something to align with.
 *
 * v13 derives lane[i]'s PSHUFB control from the PARTNER lane's input
 * (lane i^8). Since the partner-lane input is what the butterfly will
 * mix in anyway, we're using the same data — just earlier and to
 * different effect.
 *
 * For Permutation tests where keys differ by byte position, the
 * PSHUFB mask changes per-input — an attacker can't predict the shuffle
 * pattern from just one input lane's bytes.
 *
 * Cost vs v6: one extra AND per lane (16 ANDs per block), and replace
 * the fixed-pattern LOAD with a partner-input LOAD (same load count).
 * Predicted: ~5% slower than v6.
 */
RIVER5_AESNI_FN
static inline void process_block(__m128i lane[LANES_V13], const uint8_t *block)
{
    const __m128i shuf_mask_filter = _mm_set1_epi8(0x0F);

    /* Pre-load all 16 input slices: each lane needs its own input AND
     * its partner's input. Loading once means GCC can keep them
     * register-resident; on i7-7700K we have 16 XMM regs and need
     * temps for AESENC results too, so some spill is expected but
     * load-port traffic is cheap. */
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

    /* Content-dependent shuffle (v13b):
     *   shuffled = PSHUFB(partner_input, partner_input & 0x0F)
     *   mixed    = in_self XOR shuffled
     * in_self is XOR'd directly so EVERY self-input bit contributes
     * unconditionally (fixes the v13a sanity-check-2 failure where
     * single-bit flips at certain positions cancelled in PSHUFB).
     * The PSHUFB output adds content-dependent mixing from the partner.
     */
#define V13_MIX(self, partner) \
    _mm_xor_si128(self, _mm_shuffle_epi8(partner, _mm_and_si128(partner, shuf_mask_filter)))

    lane[ 0] = _mm_aesenc_si128(lane[ 0], V13_MIX(in0,  in8 ));
    lane[ 1] = _mm_aesenc_si128(lane[ 1], V13_MIX(in1,  in9 ));
    lane[ 2] = _mm_aesenc_si128(lane[ 2], V13_MIX(in2,  in10));
    lane[ 3] = _mm_aesenc_si128(lane[ 3], V13_MIX(in3,  in11));
    lane[ 4] = _mm_aesenc_si128(lane[ 4], V13_MIX(in4,  in12));
    lane[ 5] = _mm_aesenc_si128(lane[ 5], V13_MIX(in5,  in13));
    lane[ 6] = _mm_aesenc_si128(lane[ 6], V13_MIX(in6,  in14));
    lane[ 7] = _mm_aesenc_si128(lane[ 7], V13_MIX(in7,  in15));
    lane[ 8] = _mm_aesenc_si128(lane[ 8], V13_MIX(in8,  in0 ));
    lane[ 9] = _mm_aesenc_si128(lane[ 9], V13_MIX(in9,  in1 ));
    lane[10] = _mm_aesenc_si128(lane[10], V13_MIX(in10, in2 ));
    lane[11] = _mm_aesenc_si128(lane[11], V13_MIX(in11, in3 ));
    lane[12] = _mm_aesenc_si128(lane[12], V13_MIX(in12, in4 ));
    lane[13] = _mm_aesenc_si128(lane[13], V13_MIX(in13, in5 ));
    lane[14] = _mm_aesenc_si128(lane[14], V13_MIX(in14, in6 ));
    lane[15] = _mm_aesenc_si128(lane[15], V13_MIX(in15, in7 ));

#undef V13_MIX

    butterfly_mix(lane);
}

/* Identical to v3 finalize: pre-diffusion butterfly + 4-round tree. */
RIVER5_AESNI_FN
static __m128i finalize_state(__m128i lane[LANES_V13], uint64_t total_bytes)
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
static void v13_one_shot(const void *input, size_t len,
                         const uint8_t *seed, uint8_t *out)
{
    __m128i lane[LANES_V13];
    init_lanes(lane, seed);

    const uint8_t *p         = (const uint8_t *)input;
    size_t         remaining = len;

    while (remaining >= BLOCK_V13 * 2) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(p + BLOCK_V13, 0, 0);
#endif
        process_block(lane, p);
        p         += BLOCK_V13;
        remaining -= BLOCK_V13;
    }
    while (remaining >= BLOCK_V13) {
        process_block(lane, p);
        p         += BLOCK_V13;
        remaining -= BLOCK_V13;
    }

    if (remaining > 0) {
        uint8_t tail[BLOCK_V13];
        memcpy(tail, p, remaining);
        memcpy(tail + remaining,
               RIVER5_V13_SECRET + remaining,
               BLOCK_V13 - remaining);
        process_block(lane, tail);
    }

    __m128i r = finalize_state(lane, (uint64_t)len);
    _mm_storeu_si128((__m128i *)out, r);
}

RIVER5_AESNI_FN
static river5_ctx_t *v13_new(const uint8_t *seed)
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
static void v13_update(river5_ctx_t *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->total_bytes += (uint64_t)len;

    __m128i lane[LANES_V13];
    memcpy(lane, c->lane, sizeof(lane));

    if (c->buf_len > 0) {
        size_t need = BLOCK_V13 - c->buf_len;
        size_t take = (len < need) ? len : need;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take;
        p          += take;
        len        -= take;
        if (c->buf_len == BLOCK_V13) {
            process_block(lane, c->buf);
            c->buf_len = 0;
        }
    }

    while (len >= BLOCK_V13 * 2) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(p + BLOCK_V13, 0, 0);
#endif
        process_block(lane, p);
        p   += BLOCK_V13;
        len -= BLOCK_V13;
    }
    while (len >= BLOCK_V13) {
        process_block(lane, p);
        p   += BLOCK_V13;
        len -= BLOCK_V13;
    }

    if (len > 0) {
        memcpy(c->buf, p, len);
        c->buf_len = len;
    }

    memcpy(c->lane, lane, sizeof(lane));
}

RIVER5_AESNI_FN
static void v13_finalize(river5_ctx_t *c, uint8_t *out)
{
    if (c->buf_len > 0) {
        memcpy(c->buf + c->buf_len,
               RIVER5_V13_SECRET + c->buf_len,
               BLOCK_V13 - c->buf_len);
        process_block(c->lane, c->buf);
        c->buf_len = 0;
    }
    __m128i r = finalize_state(c->lane, c->total_bytes);
    _mm_storeu_si128((__m128i *)out, r);
}

static void v13_free(river5_ctx_t *c)
{
    if (!c) return;
    /* Matches the _WIN32 alloc-side guard above. */
#if defined(_WIN32)
    _aligned_free(c);
#else
    free(c);
#endif
}

const river5_vtable RIVER5_VTABLE_AESNI_V13 = {
    .one_shot   = v13_one_shot,
    .new_state  = v13_new,
    .update     = v13_update,
    .finalize   = v13_finalize,
    .free_state = v13_free,
    .name       = "river5-aesni-v13",
};
