# v11-pclmulqdq — branch notes

**Status:** abandoned (first attempt). **DO NOT merge.**

## What v11 tried

Different algebraic primitive than every previous attempt: replace
v6's `AESENC(lane, PSHUFB(input))` input mix with PCLMULQDQ (carry-less
multiplication in GF(2^64)). Hypothesis: PCLMULQDQ has completely
different algebra than AES, so the differential trails that aligned
with v6's PSHUFB structure have no analogous structure to align with
in v11's polynomial multiplication.

Per-block pipeline:
1. PCLMULQDQ input mix — `lane[i] ^= (in_lo * key_lo) ^ (in_hi * key_hi)` where * is GF(2) multiplication.
2. AESENC with fixed per-lane key for non-linearity.
3. butterfly_mix (cross-lane AESENC, same as v6).

## What actually happened

**v11 regressed catastrophically: max excess 22.61×** with 7 distinct
ratios above 2× (22.61, 9.80, 8.47, 7.02, 4.84, 3.72, 2.33). Worst
result of any river5 attempt to date — even worse than v3's original
9.37× spike.

## Why it failed

PCLMULQDQ is **linear in GF(2)**. For input differential δ:

  HASH(A) ^ HASH(B) (after step 1) = clmul(A^B, key) = clmul(δ, key)

This is a HIGHLY STRUCTURED differential output — not random. Then
step 2's AESENC with a FIXED per-lane key is a single AES round
applied to a known-structure input. One AES round provides ~2^-6
differential probability per S-box, but with structured input, an
attacker can construct trails that target specific S-box pairs.

By the time the butterfly runs in step 3, the structural bias is
already too strong for the cross-lane mixing to fully break.

The lesson: pure-linear primitive (PCLMULQDQ) followed by a single
fixed-key AESENC isn't equivalent to v6's two-AESENC structure. The
data dependence of v6's AES key (input bytes serve as the round key
via the PSHUFB+AESENC pattern) is what was actually doing the work.

## What WOULD work (variants to consider if time allows after v12/v13/v14)

- **v11b**: skip the fixed-key AESENC, go straight to butterfly_mix
  (which uses partner-lane state as AES key — data-dependent). Lets
  the data-dependence handle non-linearity.
- **v11c**: 2 rounds of PCLMULQDQ with different per-round keys before
  any AES. Deeper polynomial evaluation → more diffusion before the
  non-linear barrier.
- **v11d**: PCLMULQDQ + AESENC chain where the AES round key is the
  partner lane's current state (not a fixed secret). Combines the
  algebraic novelty of clmul with data-dependent AES keys.

Per the overnight plan: not iterating on v11 yet. Moving to v12
(HighwayHash topology) and v13 (content-dependent shuffles) first.
If none of v12/v13/v14 work AND v11 looked most promising at this
level, will come back and try v11b-d.

## What's preserved on this branch

- `csrc/river5_aesni_v11.c` — the PCLMULQDQ + fixed-key AESENC + butterfly impl
- `bench/hashes.c` — `river5-v11` registered for A/B
- `Makefile`, `build.rs` — v11 compiled into libriver5
- `csrc/river5_internal.h` — `RIVER5_VTABLE_AESNI_V11` declaration
- `diagnostics/v11-permutation-full.log` — raw SMHasher3 output

Public dispatcher unchanged; main routes to v6.

## Performance on i7-7700K (v11 vs v6)

| size | v6 | v11 | v11 vs v6 |
|---|---|---|---|
| 4 KiB | 26.4 GB/s | 16.1 | 61% |
| 16 KiB | 30.0 | 16.6 | 55% |
| 64 KiB | 31.2 | 16.4 | 53% |
| 256 KiB | 29.2 | 16.2 | 55% |
| 1 MiB | 22.5 | 14.8 | 66% |

v11 is ~50-65% of v6's throughput — still ~5× BLAKE3. The cost is
acceptable per the "stay meaningfully fast" constraint, but moot
because the algorithm is dramatically worse on SMHasher3.
