/* Thin C-callable wrapper around MetroHash128 (C++).
 * Output is 16 bytes (128-bit). */

#include "metrohash128.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

extern "C" {

void metrohash128_one_shot(const void *in, size_t len, uint8_t out[16])
{
    MetroHash128::Hash((const uint8_t *)in, (uint64_t)len, out, 0);
}

void *metrohash128_new_state(void)
{
    MetroHash128 *h = new MetroHash128(0);
    return (void *)h;
}

void metrohash128_update(void *state, const void *data, size_t len)
{
    ((MetroHash128 *)state)->Update((const uint8_t *)data, (uint64_t)len);
}

void metrohash128_digest(void *state, uint8_t *out)
{
    ((MetroHash128 *)state)->Finalize(out);
}

void metrohash128_free(void *state)
{
    delete (MetroHash128 *)state;
}

} /* extern "C" */
