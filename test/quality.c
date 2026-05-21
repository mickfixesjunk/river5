/*
 * Mini quality gate for river5.
 *
 * Not a substitute for SMHasher3 (see scripts/run_smhasher.sh for
 * that). These are the four fast checks every iteration of the hash
 * should pass before it's worth spending 30 minutes on the full
 * SMHasher3 battery:
 *
 *   1. Avalanche             — flipping each input bit flips ~50% of
 *                              output bits, with low variance per
 *                              bit position.
 *   2. Length sensitivity    — hashes of 0..1023-byte all-zero inputs
 *                              must all be distinct.
 *   3. Sparse-key collisions — hashing 1M consecutive little-endian
 *                              integers as 4-byte keys must produce
 *                              zero collisions in the output set.
 *   4. Output-bit balance    — on random inputs, each of the 128 output
 *                              bits should be set ~50% of the time.
 *
 * Any failure here is disqualifying: don't even bother with
 * SMHasher3, the hash is broken.
 *
 * Exit code: 0 on all-pass, nonzero on any failure.
 */
#include "river5.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HASH_BITS  128
#define HASH_BYTES (HASH_BITS / 8)

static int hamming128(const uint8_t a[HASH_BYTES], const uint8_t b[HASH_BYTES])
{
    int c = 0;
    for (int i = 0; i < HASH_BYTES; ++i) c += __builtin_popcount(a[i] ^ b[i]);
    return c;
}

/* Splitmix64 — deterministic noise. */
static uint64_t splitmix(uint64_t *state)
{
    *state += 0x9E3779B97F4A7C15ULL;
    uint64_t z = *state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* ---- Test 1: Avalanche on 64-byte random keys ---- */
#define AVAL_KEY_BYTES 64
#define AVAL_N_KEYS    1024

static int test_avalanche(int *out_fail_bits, double *out_mean,
                           double *out_min, double *out_max)
{
    uint64_t rng = 0xC0FFEE;
    uint8_t  key[AVAL_KEY_BYTES];
    uint8_t  h_base[HASH_BYTES], h_flip[HASH_BYTES];

    int    per_bit_flips[AVAL_KEY_BYTES * 8] = {0};
    double sum = 0.0;
    double min = HASH_BITS, max = 0;
    long   total_samples = 0;

    for (int k = 0; k < AVAL_N_KEYS; ++k) {
        for (int i = 0; i < AVAL_KEY_BYTES; ++i) {
            key[i] = (uint8_t)splitmix(&rng);
        }
        river5_hash(key, AVAL_KEY_BYTES, NULL, h_base);

        for (int bit = 0; bit < AVAL_KEY_BYTES * 8; ++bit) {
            key[bit / 8] ^= (uint8_t)(1u << (bit % 8));
            river5_hash(key, AVAL_KEY_BYTES, NULL, h_flip);
            key[bit / 8] ^= (uint8_t)(1u << (bit % 8));

            int d = hamming128(h_base, h_flip);
            per_bit_flips[bit] += d;
            sum += d;
            total_samples++;
            if (d < min) min = d;
            if (d > max) max = d;
        }
    }

    *out_mean = sum / (double)total_samples;
    *out_min  = min;
    *out_max  = max;

    /* Count input bit positions where the mean differs from 64 by
     * more than ~8 (very loose; an ideal hash should be tight). */
    int weak = 0;
    for (int bit = 0; bit < AVAL_KEY_BYTES * 8; ++bit) {
        double m = (double)per_bit_flips[bit] / (double)AVAL_N_KEYS;
        if (m < 56.0 || m > 72.0) ++weak;
    }
    *out_fail_bits = weak;

    return (weak == 0 && *out_mean > 60.0 && *out_mean < 68.0) ? 0 : 1;
}

/* ---- Test 2: length sensitivity (zeros, 0..1023 bytes) ---- */
static int test_length_sensitivity(int *out_collisions)
{
    const int N = 1024;
    uint8_t  zeros[1024] = {0};
    uint8_t *hashes = (uint8_t *)malloc((size_t)N * HASH_BYTES);
    if (!hashes) { perror("malloc"); return 1; }

    for (int i = 0; i < N; ++i) {
        river5_hash(zeros, (size_t)i, NULL, hashes + (size_t)i * HASH_BYTES);
    }

    /* O(N^2) collision check, fine at N=1024. */
    int coll = 0;
    for (int i = 0; i < N; ++i) {
        for (int j = i + 1; j < N; ++j) {
            if (memcmp(hashes + (size_t)i * HASH_BYTES,
                       hashes + (size_t)j * HASH_BYTES,
                       HASH_BYTES) == 0) {
                coll++;
                if (coll <= 5) {
                    fprintf(stderr, "  collision: len=%d == len=%d\n", i, j);
                }
            }
        }
    }
    free(hashes);
    *out_collisions = coll;
    return coll == 0 ? 0 : 1;
}

/* ---- Test 3: sparse-key collisions (1M consecutive integers) ----
 * For a 128-bit hash on 1M keys the birthday probability of any
 * collision is ~10^-26 — observing one means something is very
 * wrong. We use a sorted-then-compare approach because a hash table
 * would itself become the bottleneck. */
static int u8cmp_16(const void *a, const void *b)
{
    return memcmp(a, b, HASH_BYTES);
}

static int test_sparse_keys(int *out_collisions, uint32_t n_keys)
{
    uint8_t *hashes = (uint8_t *)malloc((size_t)n_keys * HASH_BYTES);
    if (!hashes) { perror("malloc"); return 1; }

    for (uint32_t i = 0; i < n_keys; ++i) {
        uint8_t key[4] = {
            (uint8_t)(i      ), (uint8_t)(i >>  8),
            (uint8_t)(i >> 16), (uint8_t)(i >> 24),
        };
        river5_hash(key, sizeof key, NULL, hashes + (size_t)i * HASH_BYTES);
    }

    qsort(hashes, n_keys, HASH_BYTES, u8cmp_16);

    int coll = 0;
    for (uint32_t i = 1; i < n_keys; ++i) {
        if (memcmp(hashes + (size_t)(i - 1) * HASH_BYTES,
                   hashes + (size_t) i      * HASH_BYTES,
                   HASH_BYTES) == 0) {
            coll++;
        }
    }
    free(hashes);
    *out_collisions = coll;
    return coll == 0 ? 0 : 1;
}

/* ---- Test 4: output-bit balance on random inputs ---- */
static int test_bit_balance(int *out_skewed_bits, double *out_min_p,
                             double *out_max_p)
{
    enum { N = 10000, BAL_KEY_BYTES = 32 };
    uint64_t       rng = 0xBA1A;
    uint8_t        key[BAL_KEY_BYTES];
    uint8_t        h[HASH_BYTES];
    int            counts[HASH_BITS] = {0};

    for (int n = 0; n < N; ++n) {
        for (int i = 0; i < BAL_KEY_BYTES; ++i) key[i] = (uint8_t)splitmix(&rng);
        river5_hash(key, BAL_KEY_BYTES, NULL, h);
        for (int b = 0; b < HASH_BITS; ++b) {
            if (h[b / 8] & (1u << (b % 8))) counts[b]++;
        }
    }

    /* Each bit's probability should be near 0.5. With N=10000 and
     * binomial std-dev ~50, a 3-sigma tolerance is ~15. */
    double min_p = 1.0, max_p = 0.0;
    int    skewed = 0;
    for (int b = 0; b < HASH_BITS; ++b) {
        double p = (double)counts[b] / (double)N;
        if (p < min_p) min_p = p;
        if (p > max_p) max_p = p;
        if (p < 0.47 || p > 0.53) ++skewed;
    }
    *out_skewed_bits = skewed;
    *out_min_p       = min_p;
    *out_max_p       = max_p;
    return skewed == 0 ? 0 : 1;
}

/* ---- driver ---- */

static const char *PASS = "\x1b[32mPASS\x1b[0m";
static const char *FAIL = "\x1b[31mFAIL\x1b[0m";

int main(void)
{
    extern const char *river5_impl_name(void);
    printf("river5 mini quality gate — implementation: %s\n\n",
           river5_impl_name());

    int failures = 0;

    /* Test 1 */
    {
        int weak; double mean, mn, mx;
        int rc = test_avalanche(&weak, &mean, &mn, &mx);
        printf("[%s] avalanche  mean=%.2f  range=[%.0f, %.0f]  weak_bits=%d/512\n",
               rc ? FAIL : PASS, mean, mn, mx, weak);
        if (rc) failures++;
    }

    /* Test 2 */
    {
        int coll;
        int rc = test_length_sensitivity(&coll);
        printf("[%s] lengths    0..1023 byte zeros: %d collisions\n",
               rc ? FAIL : PASS, coll);
        if (rc) failures++;
    }

    /* Test 3 */
    {
        int coll;
        const uint32_t N = 1000000;
        int rc = test_sparse_keys(&coll, N);
        printf("[%s] sparse     %u consecutive 4-byte keys: %d collisions\n",
               rc ? FAIL : PASS, N, coll);
        if (rc) failures++;
    }

    /* Test 4 */
    {
        int skewed; double mn, mx;
        int rc = test_bit_balance(&skewed, &mn, &mx);
        printf("[%s] balance    min_p=%.4f  max_p=%.4f  skewed_bits=%d/128\n",
               rc ? FAIL : PASS, mn, mx, skewed);
        if (rc) failures++;
    }

    putchar('\n');
    if (failures) {
        printf("\x1b[31m%d test(s) failed.\x1b[0m\n", failures);
        return 1;
    }
    printf("\x1b[32mAll quality gates passed.\x1b[0m\n");
    return 0;
}
