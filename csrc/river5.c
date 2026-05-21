/*
 * Public API + runtime backend dispatch.
 *
 * On first call, we CPUID-probe for AES-NI. If present, every API
 * call routes to RIVER5_VTABLE_AESNI; otherwise to RIVER5_VTABLE_STUB
 * (xxhash3-128 wrapper). The selection sticks for the process
 * lifetime and is racy-but-idempotent — two threads can both compute
 * the same answer and both write the same pointer without harm.
 */
#include "river5.h"
#include "river5_internal.h"

#include <stddef.h>

#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
#  if defined(_MSC_VER)
#    include <intrin.h>
static int cpu_has_aesni(void)
{
    int regs[4];
    __cpuid(regs, 1);
    return (regs[2] & (1 << 25)) != 0;
}
#  elif defined(__GNUC__) || defined(__clang__)
#    include <cpuid.h>
static int cpu_has_aesni(void)
{
    unsigned int eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return 0;
    return (ecx & (1u << 25)) != 0;
}
#  else
static int cpu_has_aesni(void) { return 0; }
#  endif
#else
static int cpu_has_aesni(void) { return 0; }
#endif

static const river5_vtable *resolve_vtable(void)
{
    /* v2 has the same CPU requirements as v1 (AES-NI + SSE4.1) but
     * better throughput. Always prefer it when AES-NI is available;
     * v1 is kept around for benchmark A/B comparisons only. */
    return cpu_has_aesni() ? &RIVER5_VTABLE_AESNI_V2 : &RIVER5_VTABLE_STUB;
}

static const river5_vtable *vtable(void)
{
    /* Pointer-sized writes are atomic on x86/x64 and ARM/ARM64; the
     * cached-resolve race is benign because both threads compute the
     * same value. For platforms where this assumption doesn't hold,
     * swap in C11 atomics. */
    static const river5_vtable *cached = NULL;
    const river5_vtable *v = cached;
    if (!v) {
        v = resolve_vtable();
        cached = v;
    }
    return v;
}

void river5_hash(const void *input,
                 size_t len,
                 const uint8_t seed[RIVER5_SEED_BYTES],
                 uint8_t out[RIVER5_HASH_BYTES])
{
    vtable()->one_shot(input, len, seed, out);
}

river5_ctx_t *river5_new(void)
{
    return vtable()->new_state(NULL);
}

river5_ctx_t *river5_new_seeded(const uint8_t seed[RIVER5_SEED_BYTES])
{
    return vtable()->new_state(seed);
}

void river5_update(river5_ctx_t *ctx, const void *data, size_t len)
{
    vtable()->update(ctx, data, len);
}

void river5_finalize(river5_ctx_t *ctx, uint8_t out[RIVER5_HASH_BYTES])
{
    vtable()->finalize(ctx, out);
}

void river5_free(river5_ctx_t *ctx)
{
    if (!ctx) return;
    vtable()->free_state(ctx);
}

const char *river5_impl_name(void)
{
    return vtable()->name;
}
