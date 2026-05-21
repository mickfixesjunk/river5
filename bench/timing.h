#ifndef RIVER5_BENCH_TIMING_H
#define RIVER5_BENCH_TIMING_H

#include <stdint.h>
#include <time.h>

static inline double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

#if defined(__x86_64__) || defined(_M_X64)
#  if defined(_MSC_VER)
#    include <intrin.h>
static inline uint64_t rdtsc(void) { return __rdtsc(); }
#  else
static inline uint64_t rdtsc(void)
{
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}
#  endif
#else
static inline uint64_t rdtsc(void) { return 0; }
#endif

#endif
