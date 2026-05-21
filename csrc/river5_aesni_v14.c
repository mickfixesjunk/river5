/*
 * river5 v14 — two-stream interleaved hash, XOR-combined.
 *
 * Runs TWO independent hash streams on every input, XORs their
 * 128-bit outputs:
 *
 *   Stream A: v6 (16-lane AES + fixed PSHUFB + butterfly + tree)
 *   Stream B: v11 (PCLMULQDQ input mix + per-lane AES + butterfly + tree)
 *
 *   river5_v14(x) = river5_v6(x) XOR river5_v11(x)
 *
 * Theoretical motivation: if the two streams have INDEPENDENT bias
 * structures on SMHasher Permutation (different algebra → different
 * differential trail patterns), then XOR-combining their outputs
 * cancels both biases. For a collision in v14: H_v6(A) XOR H_v11(A)
 * = H_v6(B) XOR H_v11(B), which requires H_v6(A) XOR H_v6(B) =
 * H_v11(A) XOR H_v11(B). If the two streams' output differences for
 * each input pair are independent random 32-bit values, the
 * combined collision rate is exactly 2^-32 (random baseline, no bias).
 *
 * Realistic expectation: streams aren't perfectly independent — both
 * use AES somewhere, both have 16-lane structure. But the input
 * mixing primitives (PSHUFB vs PCLMULQDQ) ARE algebraically distinct,
 * so the bias patterns should be at least partly uncorrelated.
 *
 * Cost: ~2× v6 throughput (running both streams). Predicted: ~10-12
 * GB/s on i7-7700K. Still 3-4× BLAKE3.
 *
 * Status: experimental, expensive. Promote only if combined excess
 * meaningfully drops below v6's 1.5× residual.
 */
#include "river5.h"
#include "river5_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#if defined(_MSC_VER)
#  include <intrin.h>
#endif

/* Forward declarations of the two stream vtables we'll wrap. */
extern const river5_vtable RIVER5_VTABLE_AESNI_V6;
extern const river5_vtable RIVER5_VTABLE_AESNI_V11;

/* v14 context holds BOTH stream states. We use the vtables'
 * new_state/update/finalize/free to manage each stream so we don't
 * have to know their internal layouts. */
struct river5_ctx {
    river5_ctx_t *stream_v6;
    river5_ctx_t *stream_v11;
};

static void v14_one_shot(const void *input, size_t len,
                          const uint8_t *seed, uint8_t *out)
{
    uint8_t out_v6[16];
    uint8_t out_v11[16];
    RIVER5_VTABLE_AESNI_V6.one_shot(input, len, seed, out_v6);
    RIVER5_VTABLE_AESNI_V11.one_shot(input, len, seed, out_v11);

    /* XOR-combine the two 128-bit outputs byte-by-byte. */
    for (int i = 0; i < 16; ++i) {
        out[i] = out_v6[i] ^ out_v11[i];
    }
}

static river5_ctx_t *v14_new(const uint8_t *seed)
{
    struct river5_ctx *c = (struct river5_ctx *)malloc(sizeof(struct river5_ctx));
    if (!c) return NULL;
    c->stream_v6  = RIVER5_VTABLE_AESNI_V6.new_state(seed);
    c->stream_v11 = RIVER5_VTABLE_AESNI_V11.new_state(seed);
    if (!c->stream_v6 || !c->stream_v11) {
        if (c->stream_v6)  RIVER5_VTABLE_AESNI_V6.free_state(c->stream_v6);
        if (c->stream_v11) RIVER5_VTABLE_AESNI_V11.free_state(c->stream_v11);
        free(c);
        return NULL;
    }
    return (river5_ctx_t *)c;
}

static void v14_update(river5_ctx_t *ctx, const void *data, size_t len)
{
    struct river5_ctx *c = (struct river5_ctx *)ctx;
    RIVER5_VTABLE_AESNI_V6.update(c->stream_v6, data, len);
    RIVER5_VTABLE_AESNI_V11.update(c->stream_v11, data, len);
}

static void v14_finalize(river5_ctx_t *ctx, uint8_t *out)
{
    struct river5_ctx *c = (struct river5_ctx *)ctx;
    uint8_t out_v6[16];
    uint8_t out_v11[16];
    RIVER5_VTABLE_AESNI_V6.finalize(c->stream_v6, out_v6);
    RIVER5_VTABLE_AESNI_V11.finalize(c->stream_v11, out_v11);
    for (int i = 0; i < 16; ++i) {
        out[i] = out_v6[i] ^ out_v11[i];
    }
}

static void v14_free(river5_ctx_t *ctx)
{
    struct river5_ctx *c = (struct river5_ctx *)ctx;
    if (!c) return;
    RIVER5_VTABLE_AESNI_V6.free_state(c->stream_v6);
    RIVER5_VTABLE_AESNI_V11.free_state(c->stream_v11);
    free(c);
}

const river5_vtable RIVER5_VTABLE_AESNI_V14 = {
    .one_shot   = v14_one_shot,
    .new_state  = v14_new,
    .update     = v14_update,
    .finalize   = v14_finalize,
    .free_state = v14_free,
    .name       = "river5-aesni-v14",
};
