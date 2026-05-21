# v4-position-mix — branch notes

**Status:** abandoned dead-end. **DO NOT merge to main.**

Kept on GitHub so the next person tempted to try this exact approach can
see the result without redoing the work.

## What v4 tried

v3 (the production default on `main`) passes SMHasher3 Avalanche / BIC /
Cyclic outright, but Permutation still fails on the **32-bit-truncated**
collision counts. The full 128-bit output has zero unexpected collisions;
the failure is only visible at narrow output windows.

The hypothesis behind v4: the residual Permutation failure is caused by
**lane-symmetry** — when an input like "16 cycles of 8 bytes" is fed in,
every one of v3's 16 lanes sees the same 16-byte window of input bytes.
The lanes only diverge based on their initial state, which is a weak
position-symmetry breaker.

The v4 fix: before each AESENC, XOR a per-lane unique salt into the
input. `lane[i] = AESENC(lane[i], input[i] XOR salt[i])` instead of
v3's `lane[i] = AESENC(lane[i], input[i])`. The salts are 16 distinct
16-byte values pulled from the π-derived secret in reverse-lane order.
Cost prediction: ~5% throughput (just 16 PXORs per block, supposedly
issued in parallel with AESENC on different ports).

## What actually happened

**Direct Permutation collisions — dramatically improved:**

| metric | v3 | v4 |
|---|---|---|
| Direct 40-bit | 1.555× (score 27 ⚠️) | **1.008× (score 1) ✓** |
| Direct 32-bit | 1.502× (score 99 ⚠️) | **1.046× (score 54)** still flagged but much smaller bias |
| Direct 22..43 bit | 1.123× (score 99 ⚠️) | **1.046× (score 49)** smaller bias |

**Differential Permutation collisions — unchanged:**

| metric | v3 | v4 |
|---|---|---|
| Differential 40-bit | 1.555× (score 27) | 1.625× (score 33) |
| Differential 32-bit | 1.502× (score 99) | 1.494× (score 99) |
| Differential 22..43 bit | 1.123× (score 99) | 1.120× (score 99) |

The Permutation test still hits the `*********FAIL*********` marker because
the differential section's score-99 entries trip the strict threshold.

**Throughput cost — much bigger than predicted:**

Measured on i7-7700K (the predicted ~5% overhead was wrong):

| size | v3 | v4 | v4 vs v3 |
|---|---|---|---|
| 4 KiB | 14.6 GB/s | 8.4 GB/s | 57% |
| 16 KiB | 14.7 GB/s | 11.2 GB/s | 76% |
| 64 KiB | 15.0 GB/s | 10.7 GB/s | 71% |
| 256 KiB | 15.2 GB/s | 9.4 GB/s | 62% |
| 1 MiB | 5.0 GB/s | 4.1 GB/s | 82% |

(Numbers are depressed across the board because they were taken while a
background SMHasher3 was competing for CPU; relative comparison is still
valid.)

The 20-25% slowdown turned out to be real even though the salt XORs *should*
have been free at the port-allocation level. Hypothesis: the 16 extra
loads of `SECRET[(15-i)*16]` per block — even though L1-resident — eat
into load-port throughput, since the main loop already has 16 input loads
plus heavy AES register pressure.

## Why we stopped

Two reasons combined:

1. **Wrong fix for the remaining failure.** The salt fix addresses
   *direct* position-symmetry (same bytes in different positions →
   different hashes). It does NOT address *differential* correlation
   (does `HASH(A) XOR HASH(B)` show structure when `A XOR B = δ`?).
   XOR is linear, so adding a fixed per-lane XOR doesn't add any
   non-linearity that differential cryptanalysis would have to
   navigate. The differential half of Permutation is unchanged.

2. **Cost / benefit ratio doesn't justify it.** v4 buys us "direct
   Permutation looks much cleaner" at 20-25% throughput cost. The
   FAIL marker still fires due to the unchanged differential section,
   so we'd ship "still fails Permutation" *and* "noticeably slower
   than v3" — strictly worse story than "ships v3 with a documented
   narrow caveat on differential truncation."

## What WOULD work (and what we chose not to do)

To clear the differential failure, you need *non-linear* per-block
diffusion. The candidate that would probably work:

```c
// In addition to v4's salt + v3's butterfly, add one more AESENC
// per lane per block, with the lane's index as a position constant:
lane[i] = AESENC(lane[i], _mm_set1_epi32(i));
```

Cost: another 16 AESENCs per block = another ~50% slowdown on top
of v4's existing 20-25%. v4b at maybe 6-8 GB/s peak on i7-7700K —
below xxhash3 in cache, and well below BLAKE3-with-AVX2 on newer
CPUs. At that point we'd be no faster than the alternatives and
still wouldn't be SMHasher3-clean (the residual would shrink but
not disappear without a full Meow-style SHUFFLE chain).

The conclusion this leaves us with: **river5 is what it is**.
A fast non-adversarial AES-NI dedup hash that PASSES Avalanche /
BIC / Cyclic / Sanity on SMHasher3 and has a known, narrow,
documented residual on Permutation differential truncation. Trying
to make it general-purpose-grade by adding diffusion eats most of
the speed advantage that made the project worth doing in the first
place.

## What's preserved on this branch

- `csrc/river5_aesni_v4.c` — the salt-XOR implementation, intact
- `bench/hashes.c` — `river5-v4` registered for direct A/B
- `Makefile`, `build.rs` — v4 compiled into the library
- `csrc/river5_internal.h` — `RIVER5_VTABLE_AESNI_V4` declaration

The public dispatcher in `csrc/river5.c` was NOT changed on this
branch — the public `river5_hash()` still routes to v3. v4 is
reachable only via the bench's `river5-v4` entry.

If you want to revisit: branch from this branch (don't re-implement
v4 from scratch) and add the non-linear-per-lane AESENC step above
on top.
