/*
 * Microbench: in-cache throughput at fixed sizes.
 *
 * Buffer is allocated once, filled with deterministic noise, and
 * hashed in a tight loop until at least `min_seconds` of wall time
 * elapses. Sizes are chosen to fit in L1/L2/L3 caches so the result
 * isolates hash CPU cost from memory bandwidth.
 *
 * Honest caveats:
 *   - We don't pin the thread or disable turbo here. For more rigorous
 *     numbers, run with taskset/affinity and a performance governor.
 *   - We use wall clock (CLOCK_MONOTONIC) plus rdtsc only as a sanity
 *     check; we don't trust rdtsc for cycle accounting across
 *     frequency-scaling transitions.
 */
#include "hashes.h"
#include "timing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const size_t kSizes[] = {
    64, 256, 1024, 4096, 16384, 65536, 262144, 1048576,
};
static const size_t kNumSizes = sizeof(kSizes) / sizeof(kSizes[0]);

static void fill_random(uint8_t *buf, size_t n, uint64_t seed)
{
    /* Splitmix64 — deterministic, no allocation, fast. */
    for (size_t i = 0; i < n; ++i) {
        seed += 0x9E3779B97F4A7C15ULL;
        uint64_t z = seed;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        z ^=  z >> 31;
        buf[i] = (uint8_t)z;
    }
}

static double bench_one_size(const hash_impl *h, uint8_t *buf, size_t n, double min_sec)
{
    uint8_t out[64];
    /* Calibration: 1 iter, then size up until we exceed min_sec / 10. */
    uint64_t iters = 1;
    double t = 0.0;
    for (;;) {
        double t0 = now_seconds();
        for (uint64_t i = 0; i < iters; ++i) {
            h->one_shot(buf, n, out);
        }
        t = now_seconds() - t0;
        if (t >= min_sec / 10.0) break;
        iters *= 4;
        if (iters > (1ULL << 40)) break;
    }

    /* Scale to hit min_sec, then run for real. */
    uint64_t scaled = (uint64_t)((double)iters * (min_sec / (t > 0 ? t : 1e-9)));
    if (scaled < iters) scaled = iters;

    double t0 = now_seconds();
    for (uint64_t i = 0; i < scaled; ++i) {
        h->one_shot(buf, n, out);
    }
    double dt = now_seconds() - t0;

    /* Black-hole the output so the compiler can't eliminate the loop. */
    static volatile uint8_t sink;
    sink ^= out[0];

    double bytes = (double)scaled * (double)n;
    return bytes / dt; /* B/s */
}

/*
 * Cold-buffer variant: rotates through `n_buffers` distinct input
 * regions packed into `pool` of size `pool_bytes`. Each call hashes
 * a different region than the previous call, so the input is unlikely
 * to be hot in L1/L2 from the immediately-preceding call.
 *
 * Caller is responsible for sizing the pool relative to cache levels:
 *   pool_bytes >  L1 (32 KiB on KbL) → input cold to L1 across calls
 *   pool_bytes >  L2 (256 KiB)       → input cold to L2 across calls
 *   pool_bytes >  L3 (8 MiB on i7-7700K) → input forces RAM traffic
 *
 * For input size > pool_bytes the loop just hashes one buffer
 * (effectively hot) — caller should pick pool_bytes >= input * 2.
 */
static double bench_one_size_cold(const hash_impl *h, uint8_t *pool,
                                   size_t pool_bytes, size_t n, double min_sec)
{
    uint8_t out[64];
    size_t n_buffers = (n > 0) ? (pool_bytes / n) : 1;
    if (n_buffers < 1) n_buffers = 1;

    /* Calibration. */
    uint64_t iters = 1;
    double t = 0.0;
    for (;;) {
        size_t bi = 0;
        double t0 = now_seconds();
        for (uint64_t i = 0; i < iters; ++i) {
            h->one_shot(pool + (bi * n), n, out);
            bi = bi + 1;
            if (bi >= n_buffers) bi = 0;
        }
        t = now_seconds() - t0;
        if (t >= min_sec / 10.0) break;
        iters *= 4;
        if (iters > (1ULL << 40)) break;
    }

    uint64_t scaled = (uint64_t)((double)iters * (min_sec / (t > 0 ? t : 1e-9)));
    if (scaled < iters) scaled = iters;

    size_t bi = 0;
    double t0 = now_seconds();
    for (uint64_t i = 0; i < scaled; ++i) {
        h->one_shot(pool + (bi * n), n, out);
        bi = bi + 1;
        if (bi >= n_buffers) bi = 0;
    }
    double dt = now_seconds() - t0;

    static volatile uint8_t sink;
    sink ^= out[0];

    double bytes = (double)scaled * (double)n;
    return bytes / dt;
}

int run_micro(int argc, char **argv)
{
    double min_sec = 1.0;
    const char *only = NULL;
    int csv = 0;
    size_t cold_pool_bytes = 0;   /* 0 means hot (current default) */
    size_t only_size = 0;         /* 0 means sweep all sizes (default) */

    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--csv") == 0) csv = 1;
        else if (strcmp(argv[i], "--seconds") == 0 && i + 1 < argc) {
            min_sec = atof(argv[++i]);
        } else if (strcmp(argv[i], "--hash") == 0 && i + 1 < argc) {
            only = argv[++i];
        } else if (strcmp(argv[i], "--size") == 0 && i + 1 < argc) {
            /* Restrict to a single input size — useful for MT aggregate
             * driving via shell so each worker doesn't run the full sweep. */
            char *endp = NULL;
            unsigned long long v = strtoull(argv[++i], &endp, 0);
            if (endp && *endp) {
                if (*endp == 'k' || *endp == 'K') v *= 1024ULL;
                else if (*endp == 'm' || *endp == 'M') v *= 1024ULL * 1024;
            }
            only_size = (size_t)v;
        } else if (strcmp(argv[i], "--cold") == 0 && i + 1 < argc) {
            /* Accept either raw bytes (e.g. 524288) or human suffix
             * (e.g. 512K, 16M). Defaults to bytes if no suffix. */
            char *endp = NULL;
            unsigned long long v = strtoull(argv[++i], &endp, 0);
            if (endp && *endp) {
                if (*endp == 'k' || *endp == 'K') v *= 1024ULL;
                else if (*endp == 'm' || *endp == 'M') v *= 1024ULL * 1024;
                else if (*endp == 'g' || *endp == 'G') v *= 1024ULL * 1024 * 1024;
            }
            cold_pool_bytes = (size_t)v;
        }
    }

    /* Allocate either the cold pool (if --cold given) or the existing
     * single hot buffer. Cold pool needs to be at least one max-size
     * input; we round up so the largest sweep size still fits. */
    size_t max_size = kSizes[kNumSizes - 1];
    size_t alloc_size = cold_pool_bytes > 0 ? cold_pool_bytes : max_size;
    if (alloc_size < max_size) alloc_size = max_size;
    uint8_t *buf = (uint8_t *)aligned_alloc(64, alloc_size);
    if (!buf) {
        fprintf(stderr, "alloc failed (%zu bytes)\n", alloc_size);
        return 1;
    }
    fill_random(buf, alloc_size, 0xDDD128CAFEULL);

    if (csv) {
        printf("hash,size_bytes,mode,pool_bytes,throughput_bytes_per_sec,throughput_gb_per_sec,ns_per_byte\n");
    } else {
        if (cold_pool_bytes > 0) {
            printf("=== Microbench (COLD-buffer, pool=%zu bytes, ~%.1fs per cell) ===\n",
                   cold_pool_bytes, min_sec);
        } else {
            printf("=== Microbench (in-cache, hot buffer, ~%.1fs per cell) ===\n", min_sec);
        }
        printf("%-14s %10s %14s %12s\n", "hash", "size", "throughput", "ns/byte");
        printf("%-14s %10s %14s %12s\n", "----", "----", "----------", "-------");
    }

    for (size_t hi = 0; hi < g_hashes_count; ++hi) {
        const hash_impl *h = g_hashes[hi];
        if (only && strcmp(only, h->name) != 0) continue;

        for (size_t si = 0; si < kNumSizes; ++si) {
            size_t n = kSizes[si];
            if (only_size > 0 && n != only_size) continue;
            double bps;
            if (cold_pool_bytes > 0) {
                bps = bench_one_size_cold(h, buf, alloc_size, n, min_sec);
            } else {
                bps = bench_one_size(h, buf, n, min_sec);
            }
            double gbps = bps / 1e9;
            double ns_per_byte = 1e9 / bps;

            if (csv) {
                printf("%s,%zu,%s,%zu,%.0f,%.3f,%.4f\n",
                       h->name, n,
                       cold_pool_bytes > 0 ? "cold" : "hot",
                       cold_pool_bytes > 0 ? alloc_size : n,
                       bps, gbps, ns_per_byte);
            } else {
                char size_str[32];
                if (n >= 1024 * 1024) snprintf(size_str, sizeof size_str, "%zuM", n / (1024 * 1024));
                else if (n >= 1024)    snprintf(size_str, sizeof size_str, "%zuK", n / 1024);
                else                   snprintf(size_str, sizeof size_str, "%zuB", n);

                char tput_str[32];
                snprintf(tput_str, sizeof tput_str, "%.2f GB/s", gbps);

                printf("%-14s %10s %14s %12.4f\n",
                       h->name, size_str, tput_str, ns_per_byte);
            }
        }
        if (!csv) puts("");
    }

    free(buf);
    return 0;
}
