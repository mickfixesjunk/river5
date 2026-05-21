/*
 * river5 v2 — wide-lane AES-NI implementation.
 *
 * Key changes vs v1:
 *
 *   1. 16 × 128-bit lanes (was 8) → 256 B per block (was 128 B).
 *      Doubles the in-flight independent AESENC chains. On dual-AES
 *      cores (Zen3+, Ice Lake+) this lets both AES ports stay busy.
 *
 *   2. lane[i] = AESENC(lane[i], input[i])
 *      AESENC's built-in AddRoundKey takes the input directly. Three
 *      consequences:
 *        - 8 PXOR uops per block eliminated (was lane XOR input)
 *        - 8 XMM registers freed (no separate round-key state)
 *        - We can run 16 lanes with one temp = ~17 regs, near the
 *          XMM0-XMM15 ceiling. The freed regs are what unlock 16-wide.
 *
 *   3. All init constants precomputed. Unseeded `new_state()` is
 *      16 LOADs from a const array — no AESENC at init time. (v1 spent
 *      8 AESENCs deriving cross_keys per call; that's what made small
 *      inputs 3× slower than xxh3.)
 *
 *   4. 4-round tree finalization 16→8→4→2→1, with byte-length fold
 *      in the last round. Latency: 4 dependent AESENCs (~16 cycles)
 *      vs v1's 4-round path which had to first derive cross_keys.
 *
 * Per-byte cost: 1 AESENC + 1 LOAD per 16 bytes.
 * Theoretical ceiling on dual-AES CPUs: 16 AESENCs / 8 cycles per
 * 256-byte block = 32 B/cycle = 128 GB/s @ 4 GHz. Practical ceiling
 * is whatever the memory subsystem delivers.
 *
 * What's intentionally NOT here yet (deferred to v3):
 *   - VAES/AVX2 path: 8 YMM lanes, VAESENC processes 2 lanes per
 *     instruction. Fewer instructions issued, same uop pressure.
 *   - VAES/AVX-512 path: 8 ZMM lanes, 4 lanes per VAESENC.
 *   Both require runtime CPUID dispatch the WSL dev machine can't
 *   exercise (no VAES). The XMM path here is the universal baseline.
 */
#include "river5.h"
#include "river5_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Gate on _MSC_VER (compiler) not _WIN32 (platform) so Clang-via-zig
 * targeting mingw still uses the `target("aes,...")` attribute path
 * and AES intrinsics compile cleanly. */
#if defined(_MSC_VER)
#  include <intrin.h>
#  define RIVER5_AESNI_FN
#else
#  include <wmmintrin.h>   /* AES intrinsics */
#  include <emmintrin.h>   /* SSE2 */
#  if defined(__GNUC__) || defined(__clang__)
#    define RIVER5_AESNI_FN __attribute__((target("aes,sse4.1")))
#  else
#    define RIVER5_AESNI_FN
#  endif
#endif

#define LANES_V2   16
#define LANE_BYTES 16
#define BLOCK_V2   (LANES_V2 * LANE_BYTES)   /* 256 */

/*
 * Same 256 bytes of pi-derived secret v1 uses. Reused as initial lane
 * values and as cyclic padding for partial trailing blocks.
 * (Duplicated rather than shared so each backend TU stays standalone
 * and the per-TU `struct river5_ctx` definitions don't conflict.)
 */
static const RIVER5_ALIGN16 uint8_t RIVER5_V2_SECRET[256] = {
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
    __m128i  lane[LANES_V2];
    uint64_t total_bytes;
    size_t   buf_len;
    uint8_t  buf[BLOCK_V2];
};

RIVER5_AESNI_FN
static inline __m128i load128(const void *p)
{
    return _mm_loadu_si128((const __m128i *)p);
}

RIVER5_AESNI_FN
static void init_lanes(__m128i lane[LANES_V2], const uint8_t *seed)
{
    for (int i = 0; i < LANES_V2; ++i) {
        lane[i] = load128(&RIVER5_V2_SECRET[i * LANE_BYTES]);
    }
    if (seed) {
        __m128i s0 = load128(seed);
        __m128i s1 = load128(seed + 16);
        /* Pure XOR mixing would lose information when s0 == s1
         * (e.g. seed = [0x11; 32]). One AESENC per lane is non-linear,
         * so distinct seeds always produce distinct seeded init values,
         * even uniform ones. The 16-AESENC overhead applies only to
         * seeded calls; unseeded init stays at 16 LOADs. */
        for (int i = 0; i < LANES_V2; ++i) {
            uint64_t k    = (uint64_t)i * 0x9E3779B97F4A7C15ULL;
            __m128i  diff = _mm_set_epi64x((int64_t)k, (int64_t)~k);
            __m128i  tmp  = _mm_xor_si128(_mm_xor_si128(lane[i], s0), diff);
            lane[i]       = _mm_aesenc_si128(tmp, s1);
        }
    }
}

/*
 * Manually unrolled. Each line is independent of the other 15, so the
 * out-of-order scheduler issues all 16 AESENCs in parallel — one per
 * cycle on single-AES cores, two per cycle on dual-AES cores. The
 * temporary load values can be reused so register pressure stays
 * around 17 XMMs (lanes + one temp), fitting XMM0-XMM15 with at
 * worst a single spill.
 */
RIVER5_AESNI_FN
static inline void process_block(__m128i lane[LANES_V2], const uint8_t *block)
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
}

/*
 * Tree reduction 16 → 8 → 4 → 2 → 1.
 *
 * Pairing pattern (0,8), (1,9), ... in round 1 maximises lane mixing:
 * lanes that have been independent through the whole main loop only
 * meet here, so every output bit ends up depending on every input
 * bit through these 4 dependent AESENC layers + the length fold.
 *
 * Each round has independent AESENCs in parallel, so the latency on
 * the critical path is 4 × AESENC_latency ≈ 16 cycles.
 */
RIVER5_AESNI_FN
static __m128i finalize_state(__m128i lane[LANES_V2], uint64_t total_bytes)
{
    /* Round 1: 16 → 8 */
    __m128i a0 = _mm_aesenc_si128(lane[0], lane[8]);
    __m128i a1 = _mm_aesenc_si128(lane[1], lane[9]);
    __m128i a2 = _mm_aesenc_si128(lane[2], lane[10]);
    __m128i a3 = _mm_aesenc_si128(lane[3], lane[11]);
    __m128i a4 = _mm_aesenc_si128(lane[4], lane[12]);
    __m128i a5 = _mm_aesenc_si128(lane[5], lane[13]);
    __m128i a6 = _mm_aesenc_si128(lane[6], lane[14]);
    __m128i a7 = _mm_aesenc_si128(lane[7], lane[15]);

    /* Round 2: 8 → 4 */
    __m128i b0 = _mm_aesenc_si128(a0, a4);
    __m128i b1 = _mm_aesenc_si128(a1, a5);
    __m128i b2 = _mm_aesenc_si128(a2, a6);
    __m128i b3 = _mm_aesenc_si128(a3, a7);

    /* Round 3: 4 → 2 */
    __m128i c0 = _mm_aesenc_si128(b0, b2);
    __m128i c1 = _mm_aesenc_si128(b1, b3);

    /* Round 4: combine + length fold. The length block uses the value
     * and its bitwise NOT so a same-length collision can't simply
     * zero out the length contribution. */
    __m128i d       = _mm_aesenc_si128(c0, c1);
    __m128i len_blk = _mm_set_epi64x((int64_t)total_bytes,
                                      (int64_t)~total_bytes);
    return _mm_aesenc_si128(d, len_blk);
}

/* ---- vtable backends ---- */

RIVER5_AESNI_FN
static void v2_one_shot(const void *input, size_t len,
                         const uint8_t *seed, uint8_t *out)
{
    __m128i lane[LANES_V2];
    init_lanes(lane, seed);

    const uint8_t *p         = (const uint8_t *)input;
    size_t         remaining = len;

    /* Software prefetch as in v2_update — same reasoning. */
    while (remaining >= BLOCK_V2 * 2) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(p + BLOCK_V2, 0, 0);
#endif
        process_block(lane, p);
        p         += BLOCK_V2;
        remaining -= BLOCK_V2;
    }
    while (remaining >= BLOCK_V2) {
        process_block(lane, p);
        p         += BLOCK_V2;
        remaining -= BLOCK_V2;
    }

    if (remaining > 0) {
        uint8_t tail[BLOCK_V2];
        memcpy(tail, p, remaining);
        /* Pad with secret offset by `remaining` so "ABCD" (len 4) and
         * "ABCDE" (len 5) get distinct tail blocks even before the
         * length fold. */
        memcpy(tail + remaining,
               RIVER5_V2_SECRET + remaining,
               BLOCK_V2 - remaining);
        process_block(lane, tail);
    }

    __m128i r = finalize_state(lane, (uint64_t)len);
    _mm_storeu_si128((__m128i *)out, r);
}

RIVER5_AESNI_FN
static river5_ctx_t *v2_new(const uint8_t *seed)
{
    size_t sz = (sizeof(struct river5_ctx) + 15u) & ~(size_t)15u;
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
static void v2_update(river5_ctx_t *c, const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    c->total_bytes += (uint64_t)len;

    /* CRITICAL: pull the lanes onto the stack before the hot loop.
     * When process_block writes to c->lane[i] directly, GCC can't
     * prove that lane[] doesn't alias with the input pointer `p`,
     * so it conservatively stores every lane to memory after every
     * AESENC — about 16 wasted stores AND 16 wasted reloads per
     * 256-byte block. By using a stack array whose address never
     * escapes, GCC keeps all 16 lanes in XMM registers for the
     * entire loop. Measured on a hot block this is the difference
     * between ~32 GB/s and ~50+ GB/s. */
    __m128i lane[LANES_V2];
    memcpy(lane, c->lane, sizeof(lane));

    if (c->buf_len > 0) {
        size_t need = BLOCK_V2 - c->buf_len;
        size_t take = (len < need) ? len : need;
        memcpy(c->buf + c->buf_len, p, take);
        c->buf_len += take;
        p          += take;
        len        -= take;
        if (c->buf_len == BLOCK_V2) {
            process_block(lane, c->buf);
            c->buf_len = 0;
        }
    }

    /* Software prefetch hides L2→L1 latency on large inputs. We
     * prefetch one block ahead with NTA (non-temporal allocate)
     * because dedup hashing is a streaming one-pass workload — we
     * don't want to evict useful L1 data. Helps the 1 MiB+ regime
     * close the gap to Meow. */
    while (len >= BLOCK_V2 * 2) {
#if defined(__GNUC__) || defined(__clang__)
        __builtin_prefetch(p + BLOCK_V2, 0, 0);
#endif
        process_block(lane, p);
        p   += BLOCK_V2;
        len -= BLOCK_V2;
    }
    while (len >= BLOCK_V2) {
        process_block(lane, p);
        p   += BLOCK_V2;
        len -= BLOCK_V2;
    }

    if (len > 0) {
        memcpy(c->buf, p, len);
        c->buf_len = len;
    }

    memcpy(c->lane, lane, sizeof(lane));
}

RIVER5_AESNI_FN
static void v2_finalize(river5_ctx_t *c, uint8_t *out)
{
    if (c->buf_len > 0) {
        memcpy(c->buf + c->buf_len,
               RIVER5_V2_SECRET + c->buf_len,
               BLOCK_V2 - c->buf_len);
        process_block(c->lane, c->buf);
        c->buf_len = 0;
    }
    __m128i r = finalize_state(c->lane, c->total_bytes);
    _mm_storeu_si128((__m128i *)out, r);
}

static void v2_free(river5_ctx_t *c)
{
    if (!c) return;
#if defined(_WIN32)
    _aligned_free(c);
#else
    free(c);
#endif
}

const river5_vtable RIVER5_VTABLE_AESNI_V2 = {
    .one_shot   = v2_one_shot,
    .new_state  = v2_new,
    .update     = v2_update,
    .finalize   = v2_finalize,
    .free_state = v2_free,
    .name       = "river5-aesni-v2",
};
