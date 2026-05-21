# v12-highwayhash — branch notes

**Status:** abandoned (first attempt). **DO NOT merge.**

## What v12 tried

HighwayHash-inspired three-primitive mix per block, each with disjoint
algebra (no single differential trail can align with all three):

1. **ADD** (`_mm_add_epi64(lane, input)`) — integer 64-bit addition,
   non-linear over GF(2) via carries.
2. **MUL** (cross-lane `_mm_mul_epu32(lo32(lane[i]), hi32(lane[i^8]))`)
   — integer multiplication, non-linear in both standard arithmetic
   and GF(2). Inspired by HighwayHash's ZipperMerge cross-32-bit-chunk
   pollination.
3. **AES** butterfly_mix — same as v6's d8 pair cross-mix.

## What actually happened

**v12 max excess 10.02×** with 7 distinct ratios above 2× (10.02, 9.88,
8.50, 8.39, 5.54, 5.16, 5.02). Worse than v6, similar magnitude to v11
and v8/v7 regressions.

## Why it failed

Likely several compounding issues:

1. **`_mm_mul_epu32` only multiplies the LOW 32 bits of each 64-bit half**
   of each operand. Half the lane state never goes through MUL —
   asymmetric mixing.
2. **No post-MUL diffusion**: HighwayHash uses ZipperMerge (a specific
   PSHUFB pattern) immediately after MUL to remix the bit positions and
   spread the multiplication result across the state. v12 skipped this
   step, so the MUL contributions stay localized.
3. **ADD's carry chain is structured for structured input**: the integer
   ADD provides carry-based non-linearity only when the input is "noisy"
   enough. For Permutation keysets with controlled differences, the
   carry chain output is itself structured.
4. **All three primitives compose ADDITIVELY** in a sense: the output
   is `AES(ADD(input) ^ MUL(ADD(input)))`. A differential δ propagates:
   `δ → δ (mod carry effects) → MUL × δ → still structured`. Not enough
   layers of dissimilar non-linearity.

## What WOULD work (variants if v13/v14 also fail)

- **v12b**: add a PSHUFB post-MUL remix (proper ZipperMerge port). Should
  spread MUL contributions across all 128 bits of each lane.
- **v12c**: use 4× `_mm_mul_epu32` per lane (covering all 4 lo32 chunks
  of the 128-bit lane), not just 2.
- **v12d**: more rounds of MUL+ADD before butterfly — depth instead of
  primitive variety.

Per overnight plan: not iterating on v12 yet. Moving to v13.

## What's preserved on this branch

- `csrc/river5_aesni_v12.c` — HighwayHash-inspired ADD+MUL+AES implementation
- `bench/hashes.c` — `river5-v12` registered for A/B
- `Makefile`, `build.rs` — v12 compiled
- `csrc/river5_internal.h` — `RIVER5_VTABLE_AESNI_V12` declaration
- `diagnostics/v12-permutation-full.log` — raw SMHasher3 output

Public dispatcher unchanged; main routes to v6.

## Performance on i7-7700K (v12 vs v6, 0.3s/cell)

| size | v6 | v12 | v12 vs v6 |
|---|---|---|---|
| 4 KiB | 26.2 GB/s | 17.8 | 68% |
| 16 KiB | 29.5 | 15.7 | 53% |
| 64 KiB | 27.6 | 16.5 | 60% |
| 256 KiB | 27.5 | 17.3 | 63% |
| 1 MiB | 23.7 | 15.2 | 64% |

v12 is ~55-65% of v6's throughput — acceptable speed but the algorithm
is dramatically worse on SMHasher3.
