/*
 * river5 v11 — PCLMULQDQ input mixing + AESENC butterfly.
 *
 * Fresh primitive direction after v4-v10 confirmed that v6's PSHUFB
 * structure has a structural Permutation floor. v11 abandons PSHUFB
 * entirely and uses CARRY-LESS MULTIPLICATION (PCLMULQDQ in GF(2^64))
 * as the input-mixing primitive — completely different algebra from
 * AESENC, so the differential trails that aligned with v6's PSHUFB
 * have nothing to align with here.
 *
 * Per-block pipeline:
 *   1. PCLMULQDQ input mix — for each lane, multiply input by a
 *      per-lane secret key in GF(2^64). Linear in GF(2) but provides
 *      universal-hashing diffusion bounds (Lemire's CLHash family).
 *   2. AESENC non-linearity — per-lane AESENC pass with a second
 *      secret key. AES's S-box destroys linear differential trails
 *      that pure PCLMULQDQ would leak.
 *   3. butterfly_mix — same as v6's d8 pair-AESENC cross-lane mix.
 *
 * Cost on i7-7700K: PCLMULQDQ and AESENC both go through port 0
 * (single AES/CLMUL execution unit), so they SERIALIZE. Predicted
 * throughput: ~12-15 GB/s in cache (about half of v6's ~22). Still
 * 4-5x BLAKE3.
 *
 * Status: experimental. Public dispatcher unchanged (v6). Promote
 * only if SMHasher3 Permutation clears AND throughput stays in the
 * "river5 is meaningfully fast" zone (~10+ GB/s vs BLAKE3's ~3).
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
#  include <wmmintrin.h>   /* AES intrinsics */
#  include <emmintrin.h>   /* SSE2 */
#  include <smmintrin.h>   /* SSE4.1 */
#  /* PCLMULQDQ intrinsics live in wmmintrin.h alongside AES */
#  if defined(__GNUC__) || defined(__clang__)
#    define RIVER5_AESNI_FN __attribute__((target("aes,pclmul,sse4.1")))
#  else
#    define RIVER5_AESNI_FN
#  endif
#endif

#define LANES_V11   16
#define LANE_BYTES 16
#define BLOCK_V11   (LANES_V11 * LANE_BYTES)   /* 256 */

/* π-derived secret, same as v3. */
static const RIVER5_ALIGN16 uint8_t RIVER5_V11_SECRET[256] = {
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
 * Per-lane PCLMULQDQ keys.
 *
 * Each lane multiplies its input by a unique 128-bit key in GF(2^64).
 * The keys are SECRET in REVERSE-lane order so they differ from the
 * lane's init value (init = SECRET[i*16..], key = SECRET[(15-i)*16..]).
 *
 * For universal hashing the keys should have non-zero high bits;
 * pi-derived bytes satisfy this trivially.
 */
#define CLMUL_KEY(i) load128(&RIVER5_V11_SECRET[(15 - (i)) * 16])

/* Per-lane AES round key for the non-linearity step. Use SECRET at
 * offset (i+8) mod 16 — distinct from both init values and clmul keys. */
#define AES_KEY(i)   load128(&RIVER5_V11_SECRET[(((i) + 8) & 15) * 16])

struct river5_ctx {
    __m128i  lane[LANES_V11];
    uint64_t total_bytes;
    size_t   buf_len;
    uint8_t  buf[BLOCK_V11];
};

RIVER5_AESNI_FN
static inline __m128i load128(const void *p)
{
    return _mm_loadu_si128((const __m128i *)p);
}

RIVER5_AESNI_FN
static void init_lanes(__m128i lane[LANES_V11], const uint8_t *seed)
{
    for (int i = 0; i < LANES_V11; ++i) {
        lane[i] = load128(&RIVER5_V11_SECRET[i * LANE_BYTES]);
    }
    if (seed) {
        __m128i s0 = load128(seed);
        __m128i s1 = load128(seed + 16);
        for (int i = 0; i < LANES_V11; ++i) {
            uint64_t k    = (uint64_t)i * 0x9E3779B97F4A7C15ULL;
            __m128i  diff = _mm_set_epi64x((int64_t)k, (int64_t)~k);
            __m128i  tmp  = _mm_xor_si128(_mm_xor_si128(lane[i], s0), diff);
            lane[i]       = _mm_aesenc_si128(tmp, s1);
        }
    }
}

/* Symmetric butterfly — identical to v3's. */
RIVER5_AESNI_FN
static inline void butterfly_mix(__m128i lane[LANES_V11])
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
 * v11 process_block: PCLMULQDQ input mix → per-lane AESENC → butterfly.
 *
 * For each lane i:
 *   1. Load 16-byte input slice.
 *   2. Compute clmul_combined = (in_lo * key_lo) XOR (in_hi * key_hi),
 *      where each * is a carry-less 64x64→128 multiplication in GF(2).
 *      This gives a 128-bit "universally hashed" value that mixes
 *      both halves of the input with the per-lane secret key.
 *   3. XOR the clmul product into the lane.
 *   4. AESENC the lane with a per-lane AES round key for non-linearity.
 *
 * Total per block: 32 PCLMULQDQ + 16 XOR + 16 AESENC + 16 butterfly AESENC.
 *                  = 48 AES/CLMUL ops through port 0 + 16 cycles butterfly latency.
 *                  Predicted: ~12-15 GB/s on i7-7700K.
 */
RIVER5_AESNI_FN
static inline void process_block(__m128i lane[LANES_V11], const uint8_t *block)
{
    /* Step 1: PCLMULQDQ input mix — XOR (lo*lo) ^ (hi*hi) per lane. */
#define CLMUL_MIX(i)                                                         \
    do {                                                                     \
        __m128i in = load128(block + (i) * 16);                              \
        __m128i k  = CLMUL_KEY(i);                                           \
        __m128i p  = _mm_xor_si128(_mm_clmulepi64_si128(in, k, 0x00),        \
                                    _mm_clmulepi64_si128(in, k, 0x11));      \
        lane[i]    = _mm_xor_si128(lane[i], p);                              \
    } while (0)

    CLMUL_MIX( 0); CLMUL_MIX( 1); CLMUL_MIX( 2); CLMUL_MIX( 3);
    CLMUL_MIX( 4); CLMUL_MIX( 5); CLMUL_MIX( 6); CLMUL_MIX( 7);
    CLMUL_MIX( 8); CLMUL_MIX( 9); CLMUL_MIX(10); CLMUL_MIX(11);
    CLMUL_MIX(12); CLMUL_MIX(13); CLMUL_MIX(14); CLMUL_MIX(15);
#undef CLMUL_MIX

    /* Step 2: AESENC each lane with per-lane round key for non-linearity. */
    lane[ 0] = _mm_aesenc_si128(lane[ 0], AES_KEY( 0));
    lane[ 1] = _mm_aesenc_si128(lane[ 1], AES_KEY( 1));
    lane[ 2] = _mm_aesenc_si128(lane[ 2], AES_KEY( 2));
    lane[ 3] = _mm_aesenc_si128(lane[ 3], AES_KEY( 3));
    lane[ 4] = _mm_aesenc_si128(lane[ 4], AES_KEY( 4));
    lane[ 5] = _mm_aesenc_si128(lane[ 5], AES_KEY( 5));
    lane[ 6] = _mm_aesenc_si128(lane[ 6], AES_KEY( 6));
    lane[ 7] = _mm_aesenc_si128(lane[ 7], AES_KEY( 7));
    lane[ 8] = _mm_aesenc_si128(lane[ 8], AES_KEY( 8));
    lane[ 9] = _mm_aesenc_si128(lane[ 9], AES_KEY( 9));
    lane[10] = _mm_aesenc_si128(lane[10], AES_KEY(10));
    lane[11] = _mm_aesenc_si128(lane[11], AES_KEY(11));
    lane[12] = _mm_aesenc_si128(lane[12], AES_KEY(12));
    lane[13] = _mm_aesenc_si128(lane[13], AES_KEY(13));
    lane[14] = _mm_aesenc_si128(lane[14], AES_KEY(14));
    lane[15] = _mm_aesenc_si128(lane[15], AES_KEY(15));

    /* Step 3: cross-lane butterfly. */
    butterfly_mix(lane);
}

/* Identical to v3 finalize: pre-diffusion butterfly + 4-round tree. */
RIVER5_AESNI_FN
static __m128i finalize_state(__m128i lane[LANES_V11], uint64_t total_bytes)
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
static void v11_one_shot(const void *input, size_t len,
                         const uint8_t *seed, uint8_t *out)
{
    __m128i lane[LANES_V11];
    init_lanes(lane, seed);

    const uint8_t *p         = (const uint8_t *)input;
    size_t         remaining = len;

    while (remaining >= BLOCK_V11 * 2) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(p + BLOCK_V11, 0, 0);
#endif
        process_block(lane, p);
        p         += BLOCK_V11;
        remaining -= BLOCK_V11;
    }
    while (remaining >= BLOCK_V11) {
        process_block(lane, p);
        p         += BLOCK_V11;
        remaining -= BLOCK_V11;
    }

    if (remaining > 0) {
        uint8_t tail[BLOCK_V11];
        memcpy(tail, p, remaining);
        memcpy(tail + remaining,
               RIVER5_V11_SECRET + remaining,
               BLOCK_V11 - remaining);
        process_block(lane, tail);
    }

    __m128i r = finalize_state(lane, (uint64_t)len);
    _mm_storeu_si128((__m128i *)out, r);
}

RIVER5_AESNI_FN
static river5_ctx_t *v11_new(const uint8_t *seed)
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
static void v11_update(river5_ctx_t *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->total_bytes += (uint64_t)len;

    __m128i lane[LANES_V11];
    memcpy(lane, c->lane, sizeof(lane));

    if (c->buf_len > 0) {
        size_t need = BLOCK_V11 - c->buf_len;
        size_t take = (len < need) ? len : need;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take;
        p          += take;
        len        -= take;
        if (c->buf_len == BLOCK_V11) {
            process_block(lane, c->buf);
            c->buf_len = 0;
        }
    }

    while (len >= BLOCK_V11 * 2) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(p + BLOCK_V11, 0, 0);
#endif
        process_block(lane, p);
        p   += BLOCK_V11;
        len -= BLOCK_V11;
    }
    while (len >= BLOCK_V11) {
        process_block(lane, p);
        p   += BLOCK_V11;
        len -= BLOCK_V11;
    }

    if (len > 0) {
        memcpy(c->buf, p, len);
        c->buf_len = len;
    }

    memcpy(c->lane, lane, sizeof(lane));
}

RIVER5_AESNI_FN
static void v11_finalize(river5_ctx_t *c, uint8_t *out)
{
    if (c->buf_len > 0) {
        memcpy(c->buf + c->buf_len,
               RIVER5_V11_SECRET + c->buf_len,
               BLOCK_V11 - c->buf_len);
        process_block(c->lane, c->buf);
        c->buf_len = 0;
    }
    __m128i r = finalize_state(c->lane, c->total_bytes);
    _mm_storeu_si128((__m128i *)out, r);
}

static void v11_free(river5_ctx_t *c)
{
    if (!c) return;
    /* Matches the _WIN32 alloc-side guard above. */
#if defined(_WIN32)
    _aligned_free(c);
#else
    free(c);
#endif
}

const river5_vtable RIVER5_VTABLE_AESNI_V11 = {
    .one_shot   = v11_one_shot,
    .new_state  = v11_new,
    .update     = v11_update,
    .finalize   = v11_finalize,
    .free_state = v11_free,
    .name       = "river5-aesni-v11",
};
