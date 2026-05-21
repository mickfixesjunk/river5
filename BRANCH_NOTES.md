# v6-input-rotation — branch notes

**Status:** v6 is being promoted to `main` as the new default. v7 is
preserved on this branch as a documented negative result. **DO NOT
merge this branch directly** — `main` will get a clean v6-only commit.

## What v6 tried (and won)

After v4 (linear per-lane salt — failed) and v5/v5b (non-linear
pre-finalize 1-2 rounds — couldn't reach structural failures), v6
attacked the SMHasher3 Permutation residual at its root cause: the
fact that v3's main loop has every lane processing a fixed 16-byte
slice of input through the same AES round, which lets 8-byte-cyclic
inputs produce structurally correlated lane outputs (the 9.37× excess
on the 'Combination 8-bytes [0, low bit; LE]' keyset).

v6 inserts a per-lane PSHUFB byte-permutation BEFORE each lane's
AESENC. Each lane sees a different byte ordering of its 16-byte input
slice, breaking the lane-symmetry that caused the structural spikes.

**Result on i7-7700K vs v3:**

| keyset | v3 worst | v6 worst |
|---|---|---|
| 4-bytes [3 high bits; BE] | (high; v5 measured 1.86×) | 1.120× |
| 4-bytes [0, low bit; LE] | 1.08× | 1.040× |
| **8-bytes [0, low bit; LE] ← v3 killer** | **9.37×** | **1.525×** |
| 8-bytes [0, high bit; LE] | 1.25× | 1.510× |
| **max excess across all keysets** | **9.37×** | **1.53×** |

v6 doesn't fully PASS SMHasher3 (the 1.5× residual still trips the
score-99 threshold), but it eliminates the catastrophic 9× outliers
and produces a UNIFORM 1.5× ceiling across every keyset. All
keysets pass the full 128-bit and 64-bit collision tests with 0
unexpected collisions; failures are only at 32-40-bit truncations.

**Throughput cost on i7-7700K:** ~15-25% slower than v3. PSHUFB shares
port 5 with butterfly's other shuffles, and the 16 shuffle-pattern
loads per block add load-port pressure. Still 5-10× BLAKE3, still
faster than xxhash3 at most sizes from 256 B to 256 KiB.

**Why we're promoting it:** v6 is strictly better-behaved than v3 on
the worst case (no more 9× spikes) at a real but acceptable cost. For
a hash that aims to be "more honest than v3" rather than "fully
SMHasher3-clean," this is the right trade.

## What v7 tried (and lost)

v7 stacked v6's PSHUFB input scramble with v5's non-linear pre-finalize
round, on the hypothesis that the two attacks address different failure
modes and would compose additively.

They didn't. v7 INTERFERED with itself:

| ratio range | v6 count | v7 count |
|---|---|---|
| 1.0–2.0× | many | many |
| 2.0–5.0× | 2 (distribution biases) | 2 (distribution biases) |
| 5.0–10.0× | 0 | **5 catastrophic spikes (8.22×, 8.22×, 8.24×, 9.67×, 9.82×)** |

v7's direct collision tests on the failing keyset actually PASS
cleanly (e.g., 0.97× on 8-bytes [0, low bit; BE]). It's the
DIFFERENTIAL analysis that explodes to 9.67×. The most likely
explanation: v5's structured per-lane non-linear round key creates a
new differential trail that aligns with the structure v6's PSHUFB
left in place. AES's non-linearity normally breaks linear differential
trails, but it can also REVEAL new trails when its keys have specific
algebraic structure relative to the upstream transformations.

This is a known cryptanalysis pitfall: stacking "good" rounds with
"different mechanisms" doesn't always strictly improve resistance —
sometimes the rounds align in ways that create new attacks.

**v7 confirms the cheap-fix design space is exhausted.** No
combination of finalize-tweaks + cheap main-loop additions clears
SMHasher3 Permutation on this 16-lane fixed-mapping structure. The
genuine fixes from here require:
- True per-block diffusion (Meow's MEOW_SHUFFLE-style heavy mixing,
  ~50% throughput cost)
- Different lane assignment (overlapping windows, content-dependent
  rotation, etc. — schedule-hostile)
- Major redesign

## What's preserved on this branch

- `csrc/river5_aesni_v6.c` — the v6 PSHUFB implementation (promoted
  to `main` as the new default in a separate commit there)
- `csrc/river5_aesni_v7.c` — the v7 failed combined attempt, kept
  for the historical record so future revisitors know that
  "PSHUFB + non-linear finalize" doesn't compose
- `bench/hashes.c` — both registered as `river5-v6` and `river5-v7`
- `diagnostics/v6-permutation-full.log`, `v7-permutation-full.log` —
  raw SMHasher3 output for both

## The full v3 → v7 journey

| version | mechanism | max excess | cost | shipped? |
|---|---|---|---|---|
| v3 | tree finalize only | 9× outlier, 1.5× others | baseline | currently on `main` |
| v4 | linear per-lane XOR salt | similar to v3 | +20-25% | branch only |
| v5 | non-linear finalize ×1 | 9× outlier, 1.05-1.28× others | +0% | branch only |
| v5b | non-linear finalize ×2 | 9.7× outlier, regressed some others | +0% | branch only |
| **v6** | per-lane PSHUFB input | **1.53× uniform** | **+15-25%** | **promoted to main** |
| v7 | v6 + v5 combined | 9.82× regression | +20-25% | branch only |

This branch contains v6 (kept) and v7 (failed). `main` after promotion
contains only v6 + the README update explaining the new default.

If you want to try the next layer (v8 main-loop redesign), branch from
`main` (which will have v6 as the baseline), not from this branch.
