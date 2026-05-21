/*
 * File-walk bench: walks a directory, reads each regular file once,
 * feeds the same chunks to every registered hash, optionally across
 * multiple worker threads.
 *
 * Two phases:
 *   1. WALK — single-threaded traversal collects all file paths into a
 *      vector. Stat happens here too so workers don't re-stat.
 *   2. HASH — N pthread workers atomically claim paths from the vector
 *      via an atomic counter, hash each file with every selected hash,
 *      and accumulate per-worker per-hash CPU time and byte counters.
 *      At the end the main thread sums them.
 *
 * Each worker XORs every file's digest into a per-hash accumulator;
 * the final corpus fingerprint is the XOR of all worker accumulators.
 * XOR is commutative, so the fingerprint is invariant to thread
 * ordering and useful as a corpus-level correctness check across runs.
 *
 * Notes:
 *   - POSIX walk (opendir/readdir). Windows port deferred.
 *   - "Cold cache" requires the user to drop OS caches first
 *     (`sudo sysctl -w vm.drop_caches=3` on Linux, EmptyStandbyList
 *     on Windows). The bench just measures what it's given.
 *   - With --threads N, both the disk and the AES execution units
 *     become contention points. That's the *point* of the test —
 *     measuring how each hash scales under file-level parallelism.
 */
#include "hashes.h"
#include "timing.h"

#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define READ_CHUNK   (1 << 20) /* 1 MiB */
#define MAX_HASHES   16
#define MAX_THREADS  256

/* ---- path collection ---- */

typedef struct {
    char  **items;
    size_t  len;
    size_t  cap;
} path_vec;

static void pv_push(path_vec *v, const char *p)
{
    if (v->len == v->cap) {
        v->cap = v->cap ? v->cap * 2 : 256;
        v->items = (char **)realloc(v->items, v->cap * sizeof(*v->items));
    }
    v->items[v->len++] = strdup(p);
}

static void pv_free(path_vec *v)
{
    for (size_t i = 0; i < v->len; ++i) free(v->items[i]);
    free(v->items);
    v->items = NULL; v->len = 0; v->cap = 0;
}

static int walk_collect(const char *root, path_vec *out, uint64_t *out_bytes)
{
    DIR *d = opendir(root);
    if (!d) {
        fprintf(stderr, "opendir %s: %s\n", root, strerror(errno));
        return -1;
    }
    struct dirent *de;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;

        char path[4096];
        snprintf(path, sizeof path, "%s/%s", root, de->d_name);

        struct stat st;
        if (lstat(path, &st) != 0) continue;
        if (S_ISLNK(st.st_mode))  continue;

        if (S_ISDIR(st.st_mode)) {
            walk_collect(path, out, out_bytes);
            continue;
        }
        if (!S_ISREG(st.st_mode)) continue;

        pv_push(out, path);
        *out_bytes += (uint64_t)st.st_size;
    }
    closedir(d);
    return 0;
}

/* ---- shared work state ---- */

typedef struct {
    const hash_impl *const *active;
    size_t                   n_hashes;

    path_vec                *paths;
    _Atomic size_t           next;       /* atomic file index */
    _Atomic uint64_t         files_done; /* successfully-opened counter */
} job_t;

typedef struct {
    int       thread_id;
    pthread_t thread;
    job_t    *job;

    /* Per-hash counters, indexed parallel to job->active[]. */
    double    cpu_seconds[MAX_HASHES];
    uint64_t  bytes_hashed;
    uint64_t  files_hashed;
    uint8_t   fingerprint[MAX_HASHES][64]; /* XOR of every file's digest */
} worker_t;

static void *worker_main(void *arg)
{
    worker_t *w = (worker_t *)arg;
    job_t    *j = w->job;

    /* Per-worker hash contexts (heap-allocated, reused across files). */
    void *hstate[MAX_HASHES] = {0};
    for (size_t hi = 0; hi < j->n_hashes; ++hi) {
        hstate[hi] = j->active[hi]->new_state();
    }

    /* Per-worker read buffer. Heap so it's not on a tiny stack. */
    uint8_t *buf = (uint8_t *)malloc(READ_CHUNK);
    if (!buf) goto done;

    uint8_t digest[64];

    for (;;) {
        size_t idx = atomic_fetch_add_explicit(&j->next, 1,
                                                memory_order_relaxed);
        if (idx >= j->paths->len) break;

        FILE *f = fopen(j->paths->items[idx], "rb");
        if (!f) continue;

        /* Reset each hash for this file. The hash plugins don't expose
         * a "reset" primitive, so we free+new. Cheap relative to file
         * I/O. */
        for (size_t hi = 0; hi < j->n_hashes; ++hi) {
            j->active[hi]->free_state(hstate[hi]);
            hstate[hi] = j->active[hi]->new_state();
        }

        uint64_t fbytes = 0;
        size_t   got;
        while ((got = fread(buf, 1, READ_CHUNK, f)) > 0) {
            fbytes += got;
            for (size_t hi = 0; hi < j->n_hashes; ++hi) {
                double t0 = now_seconds();
                j->active[hi]->update(hstate[hi], buf, got);
                w->cpu_seconds[hi] += now_seconds() - t0;
            }
        }
        fclose(f);

        for (size_t hi = 0; hi < j->n_hashes; ++hi) {
            int outbytes = j->active[hi]->output_bits / 8;
            double t0 = now_seconds();
            j->active[hi]->digest(hstate[hi], digest);
            w->cpu_seconds[hi] += now_seconds() - t0;
            for (int b = 0; b < outbytes; ++b) {
                w->fingerprint[hi][b] ^= digest[b];
            }
        }

        w->bytes_hashed += fbytes;
        w->files_hashed += 1;
        atomic_fetch_add_explicit(&j->files_done, 1, memory_order_relaxed);
    }

    free(buf);

done:
    for (size_t hi = 0; hi < j->n_hashes; ++hi) {
        if (hstate[hi]) j->active[hi]->free_state(hstate[hi]);
    }
    return NULL;
}

static void print_hex(const uint8_t *p, int n)
{
    for (int i = 0; i < n; ++i) printf("%02x", p[i]);
}

static void human_bytes(uint64_t n, char *out, size_t outlen)
{
    const char *u[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    int  ui = 0;
    double v = (double)n;
    while (v >= 1024.0 && ui < 4) { v /= 1024.0; ui++; }
    snprintf(out, outlen, "%.2f %s", v, u[ui]);
}

int run_file(int argc, char **argv)
{
    const char *root = NULL;
    int   csv     = 0;
    int   threads = 1;
    const char *only = NULL;

    for (int i = 0; i < argc; ++i) {
        if (strcmp(argv[i], "--csv") == 0) csv = 1;
        else if (strcmp(argv[i], "--hash") == 0 && i + 1 < argc) {
            only = argv[++i];
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < argc) {
            threads = atoi(argv[++i]);
            if (threads < 1) threads = 1;
            if (threads > MAX_THREADS) threads = MAX_THREADS;
        } else if (argv[i][0] != '-') {
            root = argv[i];
        }
    }

    if (!root) {
        fprintf(stderr,
            "usage: river5-bench file [--csv] [--hash NAME] [--threads N] <path>\n");
        return 1;
    }

    /* Build the active-hash list. */
    size_t n_hashes = 0;
    const hash_impl *active[MAX_HASHES];
    for (size_t i = 0; i < g_hashes_count && n_hashes < MAX_HASHES; ++i) {
        if (only && strcmp(only, g_hashes[i]->name) != 0) continue;
        active[n_hashes++] = g_hashes[i];
    }
    if (n_hashes == 0) {
        fprintf(stderr, "no hashes matched --hash %s\n", only ? only : "");
        return 1;
    }

    /* Phase 1: walk. */
    path_vec paths = {0};
    uint64_t expected_bytes = 0;
    if (walk_collect(root, &paths, &expected_bytes) != 0) {
        pv_free(&paths);
        return 1;
    }
    if (paths.len == 0) {
        fprintf(stderr, "no regular files under %s\n", root);
        pv_free(&paths);
        return 1;
    }

    /* Phase 2: spawn workers. */
    job_t job = {
        .active     = active,
        .n_hashes   = n_hashes,
        .paths      = &paths,
        .next       = 0,
        .files_done = 0,
    };

    worker_t *workers = (worker_t *)calloc((size_t)threads, sizeof(*workers));
    for (int t = 0; t < threads; ++t) {
        workers[t].thread_id = t;
        workers[t].job       = &job;
    }

    double t0 = now_seconds();
    for (int t = 0; t < threads; ++t) {
        pthread_create(&workers[t].thread, NULL, worker_main, &workers[t]);
    }
    for (int t = 0; t < threads; ++t) {
        pthread_join(workers[t].thread, NULL);
    }
    double wall = now_seconds() - t0;

    /* Aggregate. */
    double   agg_cpu[MAX_HASHES] = {0};
    uint8_t  agg_fp[MAX_HASHES][64] = {{0}};
    uint64_t total_bytes = 0;
    uint64_t total_files = 0;
    for (int t = 0; t < threads; ++t) {
        total_bytes += workers[t].bytes_hashed;
        total_files += workers[t].files_hashed;
        for (size_t hi = 0; hi < n_hashes; ++hi) {
            agg_cpu[hi] += workers[t].cpu_seconds[hi];
            int outbytes = active[hi]->output_bits / 8;
            for (int b = 0; b < outbytes; ++b) {
                agg_fp[hi][b] ^= workers[t].fingerprint[hi][b];
            }
        }
    }

    /* Report. */
    if (csv) {
        printf("hash,threads,files,bytes,wall_seconds,cpu_seconds,throughput_gb_per_sec,fingerprint\n");
        for (size_t hi = 0; hi < n_hashes; ++hi) {
            double gbps = (double)total_bytes / agg_cpu[hi] / 1e9;
            printf("%s,%d,%lu,%lu,%.4f,%.4f,%.3f,",
                   active[hi]->name, threads,
                   (unsigned long)total_files, (unsigned long)total_bytes,
                   wall, agg_cpu[hi], gbps);
            print_hex(agg_fp[hi], active[hi]->output_bits / 8);
            printf("\n");
        }
    } else {
        char bytes_str[32];
        human_bytes(total_bytes, bytes_str, sizeof bytes_str);
        double job_gbps = (double)total_bytes / wall / 1e9;
        printf("=== File walk: %s ===\n", root);
        printf("Files: %lu   Bytes: %s   Wall: %.3fs   Threads: %d   Job rate: %.2f GB/s\n",
               (unsigned long)total_files, bytes_str, wall, threads, job_gbps);
        printf("\n%-14s %12s %14s   %s\n",
               "hash", "agg cpu", "cpu rate", "corpus fingerprint");
        printf("%-14s %12s %14s   %s\n",
               "----", "-------", "--------", "------------------");
        for (size_t hi = 0; hi < n_hashes; ++hi) {
            /* Effective per-stream CPU rate. With threads=1 this is the
             * familiar single-stream throughput. With threads>1 the
             * agg_cpu sums across workers and bytes also sums across
             * workers, so the per-thread factors cancel and you see the
             * average rate each individual worker was running at — a
             * lower number than 1-thread when SMT / AES-unit contention
             * slows each worker down. */
            double cpu_rate = (double)total_bytes / agg_cpu[hi] / 1e9;
            char tput[32];
            snprintf(tput, sizeof tput, "%.2f GB/s", cpu_rate);
            printf("%-14s %11.3fs %14s   ", active[hi]->name, agg_cpu[hi], tput);
            print_hex(agg_fp[hi], active[hi]->output_bits / 8);
            printf("\n");
        }
    }

    free(workers);
    pv_free(&paths);
    return 0;
}
