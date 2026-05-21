# v8-deeper-finalize — branch notes

**Status:** abandoned dead-end (same pattern as v7). **DO NOT merge.**

Kept on GitHub so future revisitors don't repeat the experiment.

## What v8 tried

v6 (current main default) brought v3's worst-case Permutation excess
down from 9.4× to a uniform 1.5× ceiling, but the 1.5× still trips
SMHasher3's score-99 threshold. v7 already tried stacking v6 with v5's
non-linear per-lane keys and REGRESSED to 9.7× (interference between
v6's PSHUFB and v5's structured per-lane keys revealed a new
differential trail).

v8's hypothesis: instead of adding a NEW round structure (which is
what made v7 interfere), just repeat v6's existing `butterfly_mix`
THREE times in finalize. The butterfly uses data-dependent keys
(lane[i] mixed with lane[i+8]) so there's no static structure for
new differential trails to align with — that was supposed to make
it interference-safe.

Cost: identical to v6 in the main loop. +32 AESENCs in finalize,
running in parallel batches of 16 → ~8 extra cycles of latency.
Predicted overhead: 0.05% for 1 MiB inputs, ~25% per-call for 256-byte
inputs.

Theory: each AES round provides ~6 bits of differential resistance.
v6's 1 butterfly + 4 tree rounds ≈ 30 bits. v8's 3 butterflies +
4 tree rounds ≈ 42 bits. Should drop v6's 1.5× residual below the
score-99 (~1.05×) threshold.

## What actually happened

**v8 regressed to 9.73× / 8.47×** on the 'Combination 8-bytes
[0, high bit; BE]' keyset (differential analysis at 40-bit / 32-bit
truncation). v6 had this same keyset at only ~1.5×.

The theory about "repeated identical patterns don't add resistance"
turned out to be the real story. Three butterflies in series with the
SAME (i, i+8) pair-mixing pattern is effectively *one* operation
repeated three times — and an attacker constructing a differential
through the (lane 0, lane 8) pair has the same pair to attack three
times. The differentials compose through repeated identical structure
rather than getting blocked by it.

This confirms a known cryptanalysis principle: differential resistance
doesn't compose by simple repetition. To get N times the resistance
you need N rounds with DIFFERENT structure, not the same round done
N times.

## The pattern across all attempts

| version | mechanism | worst case | shipped? |
|---|---|---|---|
| v3 | tree finalize only | 9.37× | prior main default |
| v4 | linear per-lane salt XOR | similar to v3 | branch only |
| v5 / v5b | non-linear pre-finalize ×1/×2 (structured keys) | 9.37× / 9.7× | branch only |
| **v6** | per-lane PSHUFB input | **1.53× uniform** | **current main** |
| v7 | v6 + v5 combined | 9.82× (interference) | branch only |
| v8 | v6 + 3× butterfly | 9.73× (repeated-pattern alignment) | branch only |

Three different "stack more cheap stuff on top of v6" attempts have
all REGRESSED, each in a slightly different way:
- v7: interference with v5's structured per-lane keys
- v8: repeated-pattern attack on identical butterfly structure
- (and we know v4-style linear salt doesn't help anyway)

**The 1.5× v6 residual is structurally final at this design level.**
Cheap finalize-only fixes can't reach it; cheap main-loop fixes
(per-block rotation by block_count) don't apply to the failing
keysets (which are all single-river5-block, so block_count = 0).

## What WOULD work (and what we chose not to do)

To reduce the 1.5× residual below SMHasher3's threshold on this
16-lane fixed-mapping structure, you need a main-loop change with
significant cost:

- **Double AESENC per lane per block** — Meow-style. ~50% extra AES
  work. Probably actually clears SMHasher3. Cost makes river5 no
  faster than its competitors.

- **Content-dependent butterfly pairing** — derive the (i, partner)
  pair-pattern from input bytes so different keys mix differently.
  Hard to schedule efficiently on SIMD because variable-index XMM
  access forces stack spills.

- **Overlapping lane input windows** — lane[i] reads bytes [i..i+16)
  instead of [i*16..(i+1)*16). Defeats fixed-position alignments
  but only consumes 31 bytes per "block" rather than 256, so we'd
  need 8× as many iterations.

None of these are tried on this branch. The conclusion this branch
contributes: **finalize-level fixes have reached their ceiling**.

## What's preserved on this branch

- `csrc/river5_aesni_v8.c` — the triple-butterfly v8 implementation
- `bench/hashes.c` — `river5-v8` registered for A/B comparison
- `Makefile`, `build.rs` — v8 compiled into libriver5
- `csrc/river5_internal.h` — `RIVER5_VTABLE_AESNI_V8` declaration
- `diagnostics/v8-permutation-full.log` — raw SMHasher3 output

The public dispatcher in `csrc/river5.c` was NOT changed; public
`river5_hash()` still routes to v6.

If you want to try v9 (next layer), branch from `main` and target
the *main-loop* changes listed in "What WOULD work" — finalize
tricks won't get you there.
