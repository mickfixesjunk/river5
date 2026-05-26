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
#include <stdint.h>

#ifdef RIVER5_HAS_AESNI
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
#endif

static const river5_vtable *resolve_vtable(void)
{
    /* v15 is the current default — same lane structure and per-lane
     * PSHUFB input scramble as v6, but WITHOUT v6's per-block
     * butterfly_mix. Halves per-byte AES work for ~2x throughput.
     *
     * Quality: Avalanche passes cleanly (max bias 0.94%, score ≤4)
     * because PSHUFB is preserved. Verified zero full-128-bit
     * collisions across ~150M test keys (Dict, TextNum, Text patterns,
     * Cyclic, Sparse keysets). Deliberately fails SMHasher3
     * Permutation/Cyclic at narrow truncations — those theoretical
     * biases don't manifest in actual 128-bit comparison and the
     * cost of defending against them was 50% throughput.
     *
     * v6 and the other historical variants remain available in the
     * bench (river5-v6, river5-v3, river5-v2, river5-v1) and as
     * git tags for consumers who need byte-for-byte stability with
     * a prior version. See docs/TAGS.md for the full inventory.
     *
     * Public callers (river5_hash(), Rust crate) always get v15. */
#ifdef RIVER5_HAS_AESNI
    return cpu_has_aesni() ? &RIVER5_VTABLE_AESNI_V15 : &RIVER5_VTABLE_STUB;
#else
    /* Built for a target without AES-NI sources (e.g. aarch64). The
     * AES-NI vtable symbols don't exist in this build; cpu_has_aesni()
     * already returns 0 on these archs, so we'd pick the stub anyway. */
    return &RIVER5_VTABLE_STUB;
#endif
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

river5_ctx_t *river5_init_in(void *storage,
                              size_t storage_size,
                              const uint8_t seed[RIVER5_SEED_BYTES])
{
    if (!storage) return NULL;
    if (((uintptr_t)storage & (RIVER5_CTX_ALIGN - 1)) != 0) return NULL;
    const river5_vtable *v = vtable();
    if (storage_size < v->ctx_bytes_required) return NULL;
    return v->init_in(storage, seed);
}

const char *river5_impl_name(void)
{
    return vtable()->name;
}
