/* Thin wrapper exposing a simple one-shot and streaming API for the
 * bench harness. Returns 32 bytes (BLAKE3_OUT_LEN). */

#include "blake3.h"

#include <stdlib.h>
#include <string.h>

void blake3_wrap_one_shot(const void *in, size_t len, uint8_t out[32])
{
    blake3_hasher h;
    blake3_hasher_init(&h);
    blake3_hasher_update(&h, in, len);
    blake3_hasher_finalize(&h, out, 32);
}

void *blake3_wrap_new_state(void)
{
    blake3_hasher *h = (blake3_hasher *)malloc(sizeof(blake3_hasher));
    if (h) blake3_hasher_init(h);
    return h;
}

void blake3_wrap_update(void *state, const void *data, size_t len)
{
    blake3_hasher_update((blake3_hasher *)state, data, len);
}

void blake3_wrap_digest(void *state, uint8_t *out)
{
    blake3_hasher_finalize((const blake3_hasher *)state, out, 32);
}

void blake3_wrap_free(void *state)
{
    free(state);
}
