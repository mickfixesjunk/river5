# v10-double-aesni — branch notes

**Status:** abandoned dead-end. **DO NOT merge.** The final confirmation
that **v6's ~1.5× SMHasher3 Permutation residual is a STRUCTURAL FLOOR
that cheap fixes cannot pass at any cost level.**

## What v10 tried — the "heavy fix"

After v4 (linear salt), v5/v5b (non-linear pre-finalize), v7 (combined),
v8 (repeated butterfly), and v9 (per-block rotation + dual butterfly)
all either regressed or distributed the residual without clearing it,
v10 was the explicit "accept the throughput cost" attempt.

The hypothesis: v6's main loop has only 2 AES layers per block
(input mix + butterfly_d8 = ~12 bits of differential resistance per
block). Adding a third layer (butterfly_d4 with disjoint pair
structure) should bring it to 3 layers ≈ 18 bits per block. For
single-block keys this extra 6 bits should drop v6's 1.5× residual
by factor 64 → ~1.02× (passing the score-99 threshold).

Cost: 48 AESENCs per block vs v6's 32 = 50% more main-loop work.
Measured ~30-35% throughput hit vs v6 (~16 GB/s in cache vs v6's ~22).
Still 5× BLAKE3.

## What actually happened

**v10 regressed to 2.73× max excess** (worse than v6's 1.53×), with
5 distinct ratios above 2× across the keysets.

The d4 butterfly's `(i, i^4)` pair structure interacts with v6's
PSHUFB byte-permutation pattern in the same way v7/v8/v9's additions
did — creates *new* differential alignment trails specific to certain
keyset families. Not as catastrophic as v7/v8's 9× spikes, but
strictly worse than v6's clean 1.53× ceiling.

## The full picture across all 6 cheap-fix attempts

| version | mechanism | cost vs v6 | max excess | spikes > 2× |
|---|---|---|---|---|
| v3 (prior main) | tree finalize only | ~0% | **9.37×** | 1 |
| v4 | linear per-lane salt XOR | +20-25% | similar | yes |
| v5/v5b | non-linear pre-finalize | ~+0% | 9.37/9.7× | yes |
| **v6 (current main)** | per-lane PSHUFB input | baseline | **1.53×** | **0** |
| v7 | v6 + structured non-linear finalize | +0% | 9.82× | many |
| v8 | v6 + 3× same butterfly | +0% | 9.73× | many |
| v9 | v6 + per-block rotation + dual finalize butterfly | +5-10% | 1.67× | 0 |
| v10 | v6 + dual butterfly in MAIN LOOP | +30-35% | 2.73× | 5 |

**Six different angles of attack at every cost level — from
essentially free (v5, v7, v8) through moderate (v4, v9) up to heavy
(v10) — and not one of them passes v6's 1.53× residual.**

This is the ironclad case for v6 being a *local minimum* in the
design space, not a "we just haven't tried hard enough" situation.
Every structural addition we've tested creates new differential
alignment with v6's PSHUFB pattern. The 16-lane fixed-mapping
design has this floor baked in.

## Why this happens — the structural intuition

v6's PSHUFB input scramble fixes the catastrophic 9× failure that
v3 had on cyclic 8-byte keys, but it does so by introducing a
*specific byte-permutation structure* into the main loop. Any
additional mixing layer — whether structured per-lane keys (v7),
repeated identical patterns (v8), per-block rotation (v9), or
different pair-structures in extra rounds (v10) — has its own
specific algebraic relationship to v6's permutation structure.

In differential cryptanalysis terms: the differential trail an
attacker is trying to push through the hash gets blocked by v6's
non-linearity, but when you add a SECOND non-linearity with a
*structured* relationship to v6's, you can open up a NEW
differential trail that aligns through the gap between them.

The fix that would actually work: replace v6's PSHUFB structure
entirely with something that has no specific algebraic structure
(e.g., content-dependent shuffles, or full reimplementation in
Meow's style). At that point you're no longer evolving river5;
you're writing a different hash.

## What's preserved on this branch

- `csrc/river5_aesni_v10.c` — the double-butterfly main-loop
  implementation. `process_block` does input mix + butterfly_d8 +
  butterfly_d4 = 48 AESENCs per block.
- `bench/hashes.c` — `river5-v10` registered for A/B comparison.
- `Makefile`, `build.rs` — v10 compiled into libriver5.
- `csrc/river5_internal.h` — `RIVER5_VTABLE_AESNI_V10` declaration.
- `diagnostics/v10-permutation-full.log` — raw SMHasher3 output.

Public dispatcher unchanged; main still routes to v6.

## The exhaustive negative result

The branches `v4-position-mix`, `v5-nonlinear-finalize`,
`v8-deeper-finalize`, `v9-rotated-mainloop`, and now
`v10-double-aesni` together establish that **the 16-lane fixed-mapping
design of river5 has a ~1.5× SMHasher3 Permutation residual at
32-bit truncation that cannot be reduced by any combination of
finalize tweaks, per-block rotation, or main-loop additions tested
to date.**

To push past it, the design itself has to change in a way that
removes v6's PSHUFB structure. That's no longer iterating on
river5; that's writing a different hash. Accept v6 as the floor,
ship it as the final answer, and document the limitation honestly.

(The README's "version-by-version journey" section captures this
publicly.)
