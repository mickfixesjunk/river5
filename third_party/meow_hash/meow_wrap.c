/* Thin wrapper around Meow Hash for the bench harness.
 *
 * IMPORTANT: Meow Hash requires AES-NI (x86_64). On systems without
 * AES-NI this translation unit will not link/run correctly. The bench
 * is only registered with Meow on x86_64 + AES-NI builds (see the
 * Makefile -maes -msse4 flags applied to this file).
 *
 * Output is 128 bits (16 bytes) — Meow actually produces 128 bits of
 * mixed hash in the low xmm0 lane after MeowEnd; we extract via
 * _mm_storeu_si128 into a 16-byte buffer.
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "meow_hash_x64_aesni.h"

void meow_wrap_one_shot(const void *in, size_t len, uint8_t out[16])
{
    meow_u128 h = MeowHash(MeowDefaultSeed, (meow_umm)len, (void *)in);
    _mm_storeu_si128((__m128i *)out, h);
}

void *meow_wrap_new_state(void)
{
    /* MeowAbsorbBlocks can over-read the residual Buffer (Pad[2] in the
     * struct exists for exactly that), so any heap allocation that
     * returns the full struct size is fine. */
    meow_state *s = (meow_state *)malloc(sizeof(meow_state));
    if (s) MeowBegin(s, MeowDefaultSeed);
    return s;
}

void meow_wrap_update(void *state, const void *data, size_t len)
{
    MeowAbsorb((meow_state *)state, (meow_umm)len, (void *)data);
}

void meow_wrap_digest(void *state, uint8_t *out)
{
    meow_u128 h = MeowEnd((meow_state *)state, NULL);
    _mm_storeu_si128((__m128i *)out, h);
}

void meow_wrap_free(void *state)
{
    free(state);
}
