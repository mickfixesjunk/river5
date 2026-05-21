# v9-rotated-mainloop — branch notes

**Status:** abandoned. **DO NOT merge.** Fifth confirmation that cheap
finalize/rotation fixes can't pass v6's 1.5× Permutation ceiling.

## What v9 tried

After v7 and v8 both regressed when adding new structures on top of
v6, v9 tried a more careful combination:

  1. **Per-block input rotation** in the main loop — lane[i] reads
     input slice at `((i + block_count) & 15) * 16` instead of `i*16`.
     For multi-block keys this means the same input bytes land in
     different lanes each block, attacking the cyclic-pattern lane-
     symmetry from a different angle than v6's PSHUFB.

  2. **TWO DIFFERENT butterfly patterns in finalize** — `butterfly_mix_d8`
     pairs (i, i^8) like v6/v3 do; `butterfly_mix_d4` pairs (i, i^4),
     a completely disjoint pair structure. The two patterns share NO
     (a, b) lane-pair so a differential trail through d8 can't simply
     re-enter d4 on the same pair.

  Per-block input rotation requires tracking a block counter in the
  streaming context struct. The streaming-equivalence Rust tests
  (`streaming_matches_one_shot`, `_one_byte_at_a_time_`, `_random_chunking_`)
  all pass with v9, so the state-bumping is correct.

## What actually happened

| version | max excess | catastrophic spikes (>2×) |
|---|---|---|
| v6 (current main) | 1.53× | 0 |
| v7 | 9.82× | many (regression) |
| v8 | 9.73× | many (regression) |
| **v9** | **1.67×** | **0** |

v9 didn't regress like v7/v8 did — no catastrophic spikes. But the
worst case (1.67×) is slightly *higher* than v6's (1.53×). The
distribution is different: many keysets now cluster in the 1.10-1.20×
range (closer to passing than v6's typical 1.5×), but the worst case
moved up. v9 traded "narrow tall peak" for "wider shorter ridge."

Net: not strictly better than v6, and slightly slower (per-block
rotation address calc + extra butterfly in finalize). No reason to
ship.

## The picture across all 5 cheap-fix attempts

| approach | result | lesson |
|---|---|---|
| v4 (linear salt) | failed | XOR is linear → can't break differential trails |
| v5/v5b (non-linear pre-finalize) | failed | structured per-lane keys can't reach 9× structural failures |
| v7 (v6 + v5 combined) | regressed | interference: structured keys aligned with PSHUFB |
| v8 (v6 + 3× same butterfly) | regressed | repeated identical pattern: differentials compose through it |
| **v9 (v6 + per-block rotation + dual butterfly)** | **1.67× residual, no regression** | **the 1.5× floor is structural** |

Five attempts at the cheap-fix level. All either regress (v7, v8)
or distribute the residual differently without clearing it (v9).
**v6's 1.5× ceiling is the cheap-fix floor for this 16-lane fixed-
mapping design.** To get past it, the fix has to be in the main loop
with significant throughput cost (double-AESENC per lane, ~50%
slowdown — that's v10's territory on the `v10-double-aesni`
branch).

## What's preserved on this branch

- `csrc/river5_aesni_v9.c` — the per-block rotation + dual butterfly
  implementation, including the `block_count` field in struct and
  the `butterfly_mix_d4` second pattern.
- `bench/hashes.c` — `river5-v9` registered for A/B comparison.
- `Makefile`, `build.rs` — v9 compiled into libriver5.
- `csrc/river5_internal.h` — `RIVER5_VTABLE_AESNI_V9` declaration.
- `diagnostics/v9-permutation-full.log` — raw SMHasher3 output.

Public dispatcher in `csrc/river5.c` unchanged on this branch;
main still routes to v6.
