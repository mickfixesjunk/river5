# river5 tags — inventory and when to pin

The default `river5_hash()` on `main` always routes to the current
production default (today: **v15**). Most consumers should not pin —
just track `main` or a release tag.

You only need to pin to a specific algorithm-version tag if:
- You have a persistent hash-value cache that must stay byte-stable
  across river5 updates (a `cargo update` could otherwise invalidate it)
- You need a specific tradeoff (max throughput, max statistical quality,
  reproducing historical behavior)

For Rust consumers, pin via Cargo:

```toml
river5 = { git = "https://github.com/mickfixesjunk/river5", tag = "v15" }
```

For C/CMake consumers: `git checkout v15` then build normally.

---

## Recommended (most promising at top)

### `v15` — current default ✅

Speed (i7-7700K, in-cache, 16 KiB): **~50-55 GB/s** — in-cache CPU
microbench only; on real (IO-bound) dedup, river5 is competitive/tied
with BLAKE3 and hash choice is below the noise floor. No fastest/
superiority claim — see the README Performance section.

- ~2× v6 in-cache CPU throughput (internal A/B; not a real-workload claim)
- Avalanche passes cleanly (max bias 0.94%, score ≤4)
- Verified zero full-128-bit collisions across ~150M test keys
  (Dict, TextNum, Text patterns, Cyclic, Sparse keysets at 128-bit)
- Deliberately fails SMHasher3 Permutation/Cyclic at narrow truncations
  (those theoretical biases don't manifest in actual 128-bit comparison)

**Pin to v15 if**: you want byte-stable v15 hashes (cache stability)
or want to make the variant choice explicit. Otherwise just use the
default — you already get v15.

### `v6` — prior default (balanced)

Speed (i7-7700K, in-cache, 16 KiB): **~30 GB/s**

- Passes Avalanche, BIC, Cyclic, Sanity cleanly
- Partial Permutation pass — 1.5× residual at 32-bit truncation,
  zero full-128-bit collisions
- Slower than v15 by ~half

**Pin to v6 if**: you have a v6-format hash cache you don't want to
invalidate, or you specifically want SMHasher Permutation closer to
clean (1.5× residual vs v15's deliberate failure). For most consumers,
v15 is the better choice.

### `v3` — older default (faster than v6, with a Permutation spike)

Speed (i7-7700K, in-cache, 16 KiB): **~33 GB/s**

- Same passes as v6 but has a 9.4× catastrophic Permutation spike on
  one specific keyset (8-byte cyclic input)
- Slightly faster than v6, much faster than v15 on... wait, no, v3 is
  slower than v15 (33 vs 50+ GB/s). v3 is interesting historically
  but v15 dominates it on speed AND v6 dominates it on Permutation quality

**Pin to v3 if**: you have a v3-format hash cache from before the v6
promotion. Otherwise no good reason.

---

## Available but not generally recommended

### `v2` — fastest river5 variant in-cache, Avalanche-weak (no git tag, bench-only)

Speed (i7-7700K, in-cache, 16 KiB): **~65 GB/s** (fastest *river5 variant*
in the in-cache microbench — not a real-workload or cross-hash claim;
see the README Performance section: dedup is IO-bound).

- Fastest river5 variant in-cache — ~14% over v15 (in-cache microbench only)
- **Avalanche FAILS** (1.83% bias, score 59σ in SMHasher3)
- Verified zero full-128-bit collisions across ~150M test keys
  (same keysets as v15)

**Why no git tag**: v2 was never a production default. To use v2,
call `RIVER5_VTABLE_AESNI_V2` directly through `river5_internal.h`
(C) or via the `river5-v2` bench entry. There's no `river5 = { tag = "v2" }`
pin path because the public `river5_hash()` API has never routed to v2.

**Use v2 if**: you specifically need the fastest river5 variant for the
narrow in-memory / already-decompressed-data + idle-cores case (where
hash CPU cost actually shows), and you don't care that someone running
SMHasher will see the Avalanche fail.
For 99% of dedup workloads, v15 is fast enough and looks cleaner.

### `v9` — abandoned partial experiment

Speed: similar to v6

Tagged as `v9` because it was an interesting partial-improvement
experiment (per-block input rotation + dual-pattern finalize butterfly).
Didn't actually improve on v6, just distributed the bias differently.
Kept tagged for reproducibility of the journey, not for use.

### `v10` — abandoned

Tagged as `v10`. Triple butterfly experiment, regressed to 2.7×.
Documented negative result.

---

## ⚠️ DO NOT USE

### `v14` ⚠️ — STRUCTURAL 128-BIT COLLISIONS

Tagged but **unsafe**. v14 was a two-stream XOR variant
(`v6 ⊕ v11`) that initially looked like the SMHasher3 breakthrough.
**Full SMHasher3 battery surfaced actual 128-bit collisions** on
short-text keysets:

| Keyset | Keys tested | v14 collisions |
|---|---|---|
| Dict (dictionary words) | 528,194 | **1,515 actual 128-bit collisions** |
| Words (1-4 alnum chars) | 1,000,000 | **3,969** |
| Words (1-16 alnum chars) | 1,000,000 | **1,149** |

These are real duplicate hashes for distinct strings. The tag is kept
on the repo for reproducibility of the failure as a documented
negative result — anyone tempted by "two-stream XOR cancellation"
should read `v14-two-stream` branch's `BRANCH_NOTES.md` to understand
why naive XOR-combination of two hashes with shared finalize structure
correlates rather than cancels biases.

**Anyone who pinned to `v14`: migrate to `v15` immediately.**

---

## Experimental branches (no tags)

Several earlier attempts to clear SMHasher3 are kept as branches with
detailed `BRANCH_NOTES.md` but were not tagged because they didn't
ship anything:

- `v4-position-mix` — linear per-lane salt, no improvement
- `v5-nonlinear-finalize` — non-linear pre-finalize, couldn't reach
  structural failures
- `v8-deeper-finalize` — 3× same butterfly, regressed via repeated-pattern attack
- `v11-pclmulqdq` — PCLMULQDQ input mix, regressed to 22×
- `v12-highwayhash` — ADD+MUL+AES three-primitive mix, regressed to 10×
- `v13-content-shuffle` — content-dependent shuffles, 152× spike on cyclic killer
- `v13c-hybrid-shuffle` — hybrid v6+v13, matched v6 with no improvement

Each branch has its own `BRANCH_NOTES.md` documenting the hypothesis,
implementation, and measured failure for future researchers.

---

## Summary cheat-sheet

| variant | tag | speed @ 16K | use for |
|---|---|---|---|
| **v15** | `v15` (and default) | **~50-55 GB/s** | **default — fast consumer dedup** |
| v6 | `v6` | ~30 GB/s | cache stability with prior default |
| v3 | `v3` | ~33 GB/s | very old cache compatibility |
| v2 | (none, bench-only) | ~65 GB/s | absolute max speed, niche |
| v9 / v10 | `v9`, `v10` | reference only | journey reproducibility |
| **v14** | `v14` | ⚠️ **DO NOT USE** | — |

If you just want "river5 in your project," don't pin. Track `main`.
You get v15.
