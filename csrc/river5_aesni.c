/*
 * river5 — AES-NI implementation.
 *
 * Design:
 *   - 8 parallel 128-bit lanes, each consuming 16 B/step via
 *     lane[i] = AESENC(lane[i] XOR input[i], round_key[i])
 *   - 128 B consumed per "block" step.
 *   - On a CPU that retires one AESENC per cycle, 8 independent
 *     chains keeps the AES unit saturated; theoretical 16 B/cycle.
 *   - Finalization cross-mixes the 8 lanes down to one 128-bit lane
 *     through 3 rounds of paired AESENC, then folds in the byte
 *     length to defeat trivial length-collision attacks.
 *
 * Honest caveats:
 *   - Each input lane only sees 1/8 of the input bytes during the
 *     main loop, so river5 is a "tree-mixed" hash, not a strong
 *     cryptographic primitive. The finalization compensates well
 *     enough for dedup but adversarial collisions are findable.
 *   - Tail bytes are padded with the same pi-derived secret used
 *     for initial state; this avoids the zero-pad bias of naive
 *     designs but doesn't use xxhash3's "overlap-read" trick.
 *
 * Build:
 *   - GCC/Clang: every function carries
 *     __attribute__((target("aes,ssse3,sse4.1"))) so this TU compiles
 *     without -maes at the project level. CPUs without AES-NI never
 *     enter this TU — the dispatcher routes them to the stub.
 *   - MSVC: AES intrinsics are always available; the target macro
 *     expands to nothing.
 */
#include "river5.h"
#include "river5_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Intrinsic-availability split: MSVC has every SSE/AES intrinsic
 * unconditionally via <intrin.h>; Clang and GCC need the per-function
 * target attribute to unlock them. mingw-via-zig presents as Clang
 * but predefines _WIN32, so gating purely on _WIN32 would
 * incorrectly drop the attribute and the build would fail with
 * "always_inline … requires target feature 'aes'". Use the compiler
 * macro (_MSC_VER) instead of the platform macro (_WIN32). */
#if defined(_MSC_VER)
#  include <intrin.h>
#  define RIVER5_AESNI_FN
#else
#  include <wmmintrin.h>   /* AES intrinsics */
#  include <emmintrin.h>   /* SSE2 */
#  include <tmmintrin.h>   /* SSSE3 */
#  if defined(__GNUC__) || defined(__clang__)
#    define RIVER5_AESNI_FN __attribute__((target("aes,ssse3,sse4.1")))
#  else
#    define RIVER5_AESNI_FN
#  endif
#endif

#define LANES       8
#define LANE_BYTES  16
#define BLOCK_BYTES (LANES * LANE_BYTES)   /* 128 */

/*
 * 256 bytes of "nothing-up-my-sleeve" constants — the fractional
 * part of pi (after the leading 3.) in hex. The first ~136 bytes
 * are the same values Blowfish uses for its P-array and S-box init.
 * We use [0..128) as initial lane values and [128..256) as the
 * per-lane round keys for the main mixing loop.
 */
static const uint8_t RIVER5_SECRET[256] = {
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

/* Private context layout for this TU. */
struct river5_ctx {
    __m128i  lane     [LANES];
    __m128i  round_key[LANES];
    __m128i  cross_key[LANES];
    uint64_t total_bytes;
    size_t   buf_len;
    uint8_t  buf      [BLOCK_BYTES];
};

RIVER5_AESNI_FN
static inline __m128i load128(const void *p)
{
    return _mm_loadu_si128((const __m128i *)p);
}

RIVER5_AESNI_FN
static void init_keys(__m128i lane[LANES],
                      __m128i round_key[LANES],
                      __m128i cross_key[LANES],
                      const uint8_t *seed /* 32 bytes or NULL */)
{
    for (int i = 0; i < LANES; ++i) {
        lane[i]      = load128(&RIVER5_SECRET[i * LANE_BYTES]);
        round_key[i] = load128(&RIVER5_SECRET[128 + i * LANE_BYTES]);
    }

    if (seed) {
        __m128i s0 = load128(seed);
        __m128i s1 = load128(seed + 16);
        /* Mix the two seed halves into every lane with a per-lane
         * differential so identical lanes don't end up XORed with
         * identical seed masks. */
        for (int i = 0; i < LANES; ++i) {
            uint64_t k = (uint64_t)i * 0x9E3779B97F4A7C15ULL;
            __m128i diff = _mm_set_epi64x((int64_t)k, (int64_t)~k);
            lane[i]      = _mm_xor_si128(lane[i],
                                          _mm_xor_si128(s0, diff));
            round_key[i] = _mm_xor_si128(round_key[i],
                                          _mm_xor_si128(s1, diff));
        }
    }

    /* Derive cross-mixing keys deterministically from the (possibly
     * seeded) lane + round_key pairs. AESENC keeps them well-mixed
     * even when the inputs are similar. */
    for (int i = 0; i < LANES; ++i) {
        cross_key[i] = _mm_aesenc_si128(
            _mm_xor_si128(round_key[i], lane[i]),
            round_key[(i + 1) % LANES]);
    }
}

RIVER5_AESNI_FN
static inline void process_block(__m128i lane[LANES],
                                  const __m128i round_key[LANES],
                                  const uint8_t *block)
{
    __m128i b0 = load128(block + 0 * 16);
    __m128i b1 = load128(block + 1 * 16);
    __m128i b2 = load128(block + 2 * 16);
    __m128i b3 = load128(block + 3 * 16);
    __m128i b4 = load128(block + 4 * 16);
    __m128i b5 = load128(block + 5 * 16);
    __m128i b6 = load128(block + 6 * 16);
    __m128i b7 = load128(block + 7 * 16);

    lane[0] = _mm_aesenc_si128(_mm_xor_si128(lane[0], b0), round_key[0]);
    lane[1] = _mm_aesenc_si128(_mm_xor_si128(lane[1], b1), round_key[1]);
    lane[2] = _mm_aesenc_si128(_mm_xor_si128(lane[2], b2), round_key[2]);
    lane[3] = _mm_aesenc_si128(_mm_xor_si128(lane[3], b3), round_key[3]);
    lane[4] = _mm_aesenc_si128(_mm_xor_si128(lane[4], b4), round_key[4]);
    lane[5] = _mm_aesenc_si128(_mm_xor_si128(lane[5], b5), round_key[5]);
    lane[6] = _mm_aesenc_si128(_mm_xor_si128(lane[6], b6), round_key[6]);
    lane[7] = _mm_aesenc_si128(_mm_xor_si128(lane[7], b7), round_key[7]);
}

RIVER5_AESNI_FN
static __m128i finalize_state(__m128i lane[LANES],
                               const __m128i cross_key[LANES],
                               uint64_t total_bytes)
{
    /* Round 1: pair lanes (0,4) (1,5) (2,6) (3,7) — every output
     * mixes two originally independent chains. */
    __m128i m0 = _mm_aesenc_si128(_mm_xor_si128(lane[0], lane[4]), cross_key[0]);
    __m128i m1 = _mm_aesenc_si128(_mm_xor_si128(lane[1], lane[5]), cross_key[1]);
    __m128i m2 = _mm_aesenc_si128(_mm_xor_si128(lane[2], lane[6]), cross_key[2]);
    __m128i m3 = _mm_aesenc_si128(_mm_xor_si128(lane[3], lane[7]), cross_key[3]);

    /* Round 2: pair (0,2) (1,3) — every output now depends on all
     * eight original lanes. */
    __m128i n0 = _mm_aesenc_si128(_mm_xor_si128(m0, m2), cross_key[4]);
    __m128i n1 = _mm_aesenc_si128(_mm_xor_si128(m1, m3), cross_key[5]);

    /* Round 3: combine the last two halves, then fold in the byte
     * length. The length block uses the value and its bitwise NOT
     * so it can't be zeroed by a same-length collision. */
    __m128i len_blk = _mm_set_epi64x((int64_t)total_bytes,
                                      (int64_t)~total_bytes);
    __m128i r = _mm_aesenc_si128(_mm_xor_si128(n0, n1), cross_key[6]);
    r = _mm_aesenc_si128(_mm_xor_si128(r, len_blk), cross_key[7]);
    return r;
}

/* ---- vtable backends ---- */

RIVER5_AESNI_FN
static void aesni_one_shot(const void *input, size_t len,
                            const uint8_t *seed, uint8_t *out)
{
    __m128i lane[LANES], round_key[LANES], cross_key[LANES];
    init_keys(lane, round_key, cross_key, seed);

    const uint8_t *p = (const uint8_t *)input;
    size_t remaining = len;

    while (remaining >= BLOCK_BYTES) {
        process_block(lane, round_key, p);
        p         += BLOCK_BYTES;
        remaining -= BLOCK_BYTES;
    }

    if (remaining > 0) {
        uint8_t tail[BLOCK_BYTES];
        memcpy(tail, p, remaining);
        /* Pad with secret material indexed by `remaining` so that
         * "ABCD" padded with secret[4..] differs from "ABCDE"
         * padded with secret[5..]. */
        memcpy(tail + remaining,
               RIVER5_SECRET + remaining,
               BLOCK_BYTES - remaining);
        process_block(lane, round_key, tail);
    }

    __m128i r = finalize_state(lane, cross_key, (uint64_t)len);
    _mm_storeu_si128((__m128i *)out, r);
}

RIVER5_AESNI_FN
static river5_ctx_t *aesni_new(const uint8_t *seed)
{
    /* Round size up to a multiple of alignment so aligned_alloc is
     * happy; the __m128i fields require 16-byte alignment. */
    size_t sz = (sizeof(struct river5_ctx) + 15u) & ~(size_t)15u;
#if defined(_WIN32)
    river5_ctx_t *c = (river5_ctx_t *)_aligned_malloc(sz, 16);
#else
    river5_ctx_t *c = (river5_ctx_t *)aligned_alloc(16, sz);
#endif
    if (!c) return NULL;
    init_keys(c->lane, c->round_key, c->cross_key, seed);
    c->total_bytes = 0;
    c->buf_len     = 0;
    return c;
}

RIVER5_AESNI_FN
static river5_ctx_t *aesni_init_in(void *storage, const uint8_t *seed)
{
    river5_ctx_t *c = (river5_ctx_t *)storage;
    init_keys(c->lane, c->round_key, c->cross_key, seed);
    c->total_bytes = 0;
    c->buf_len     = 0;
    return c;
}

RIVER5_AESNI_FN
static void aesni_update(river5_ctx_t *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->total_bytes += (uint64_t)len;

    /* Stack-local lane copy so GCC can keep them in registers across
     * the hot loop. If we passed c->lane directly, the alias-analyzer
     * forces a memory store after every AESENC (lane could alias p).
     * Round keys are read-only so they don't have this problem. */
    __m128i lane[LANES];
    memcpy(lane, c->lane, sizeof(lane));

    /* Fill an in-flight partial buffer first if there is one. */
    if (c->buf_len > 0) {
        size_t need = BLOCK_BYTES - c->buf_len;
        size_t take = (len < need) ? len : need;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take;
        p          += take;
        len        -= take;
        if (c->buf_len == BLOCK_BYTES) {
            process_block(lane, c->round_key, c->buf);
            c->buf_len = 0;
        }
    }

    while (len >= BLOCK_BYTES) {
        process_block(lane, c->round_key, p);
        p   += BLOCK_BYTES;
        len -= BLOCK_BYTES;
    }

    if (len > 0) {
        memcpy(c->buf, p, len);
        c->buf_len = len;
    }

    memcpy(c->lane, lane, sizeof(lane));
}

RIVER5_AESNI_FN
static void aesni_finalize(river5_ctx_t *c, uint8_t *out)
{
    if (c->buf_len > 0) {
        memcpy(c->buf + c->buf_len,
               RIVER5_SECRET + c->buf_len,
               BLOCK_BYTES - c->buf_len);
        process_block(c->lane, c->round_key, c->buf);
        c->buf_len = 0;
    }

    __m128i r = finalize_state(c->lane, c->cross_key, c->total_bytes);
    _mm_storeu_si128((__m128i *)out, r);
}

static void aesni_free(river5_ctx_t *c)
{
    if (!c) return;
#if defined(_WIN32)
    _aligned_free(c);
#else
    free(c);
#endif
}

_Static_assert(sizeof(struct river5_ctx) <= RIVER5_CTX_BYTES,
               "v1 ctx exceeds RIVER5_CTX_BYTES");

const river5_vtable RIVER5_VTABLE_AESNI = {
    .one_shot           = aesni_one_shot,
    .new_state          = aesni_new,
    .update             = aesni_update,
    .finalize           = aesni_finalize,
    .free_state         = aesni_free,
    .init_in            = aesni_init_in,
    .ctx_bytes_required = sizeof(struct river5_ctx),
    .name               = "river5-aesni-v1",
};
