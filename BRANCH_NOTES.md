# v5-nonlinear-finalize — branch notes

**Status:** abandoned dead-end. **DO NOT merge to main.**

Kept on GitHub so future revisitors don't repeat the experiment.

## What v5 tried

v3 (the production default on `main`) PASSES SMHasher3 Avalanche /
BIC / Cyclic / Sanity outright but has a residual failure on the
**differential** half of the Permutation test: 1.5× excess collisions
at 32-bit truncated output windows. Full 128-bit output is clean
(zero collisions on millions of permuted-byte keys).

v4 had previously tried per-lane salt XOR — a linear fix — and proved
that XOR-based per-lane diversity *can't* close differential gaps
because XOR is linear and the differential structure passes through
it unchanged. See `v4-position-mix` branch.

v5's hypothesis: add a **non-linear** round of per-lane AESENC at the
start of finalize, keyed by `(π-derived per-lane constant) XOR (length-encoded
128 bits)`. Each lane's output bit would depend non-linearly on its
position, its prior state, AND the length. AES's S-box should
disrupt linear differential trails. Cost: 16 AESENCs once at finalize
= ~4 cycles latency, invisible on anything ≥ a few KiB.

v5b then tried two rounds back-to-back (different per-lane constants
and swapped length-encoding for the second round) to see whether
doubling the non-linear depth would push the bias all the way down.

## What actually happened

The v5 single-round result:

| keyset (representative) | v3 excess | v5 excess |
|---|---|---|
| Combination 4-bytes [3 low bits; LE] | (unmeasured) | 1.757× ⚠️ |
| Combination 4-bytes [3 high+low; LE] | (unmeasured) | 1.283× ⚠️ |
| Combination 4-bytes [0, low bit; LE] | (unmeasured) | 1.081× (close) |
| Combination 4-bytes [0, high bit; BE] | (unmeasured) | passes |
| **Combination 8-bytes [0, low bit; LE] (differential)** | (unmeasured) | **9.367× ← killer** |
| Cyclic 16x8-byte (the v3-reported case) | 1.5× ⚠️ | 1.25× |

The v5b doubled-round result:

| keyset | v5 excess | v5b excess | move |
|---|---|---|---|
| 4-bytes [3 low bits; LE] | 1.757× | **passes** | ✓ |
| 4-bytes [3 low bits; BE] | 1.656× | **passes** | ✓ |
| 4-bytes [3 high bits; BE] | 1.860× | **passes** | ✓ |
| 4-bytes [3 high+low; LE] | 1.283× | 1.353× | slightly worse |
| 4-bytes [0, low bit; BE] | 1.077× | 1.183× | slightly worse |
| 4-bytes [0, high bit; BE] | passes | 1.078× | newly flagged |
| **8-bytes [0, low bit; LE]** | **9.367×** | **9.703×** | **unchanged** |
| 8-bytes [0, high bit; LE] | 1.246× | **9.445×** | **massively worse** |
| 8-bytes [0, low bit; BE] | 1.239× | 1.027× (close) | better |

**v5b fixed three of the easier 4-byte cases but introduced a NEW catastrophic
9.4× failure on a different 8-byte keyset** while leaving the original 9.3×
killer essentially unchanged.

## Why we stopped

The 9× failures aren't a "needs more diffusion" problem that more
finalize rounds can solve. They're a **structural algebraic relationship**
between our 16-lane main-loop layout and 8-byte-aligned cyclic input
patterns. Every AES round in the main loop processes those bytes
through the same fixed lane→input mapping, accumulating a bias that
finalize-level mixing can dilute (1.5× → 1.05× on simpler keysets) but
not erase (9× stays 9×).

The fact that v5b made things *worse* on one keyset confirms this:
adding more independent non-linear rounds at the end of a pipeline
that has a structural bias doesn't reduce the bias, it just shifts
which output bits it lands in.

## What WOULD work (and what we chose not to do)

To address the structural 9× failures, the fix has to be in the
**main loop**, not finalize. Plausible approaches:

1. **Per-block input rotation** — vary which input slice goes to
   which lane based on block count. Even a simple `lane[(i + block_count) % 16]
   = AESENC(...)` would mean the same 8-byte pattern lands in a different
   lane each block, breaking the structural alignment. Cost estimate:
   5-15% throughput (depends on whether compiler can keep registers
   straight under the variable indexing).

2. **Second AESENC per lane per block** — back to v4 territory in cost
   (~50% throughput hit). Combines per-block diffusion with non-linear
   defense. Would probably clear SMHasher3 but at the cost of most of
   the speed advantage that motivated the project.

3. **Different lane layout entirely** — e.g., overlapping input windows
   per lane so lane[0] reads bytes [0..16), lane[1] reads bytes [1..17),
   etc. Defeats fixed-position alignments but is hard to schedule
   efficiently on AES-NI hardware.

None of these are tried on this branch. v6 territory if anyone
takes it up.

## The bigger lesson (across v4 and v5)

We've now eliminated two cheap-fix approaches for the Permutation
differential residual:

- **v4** (per-lane salt XOR): linear → can't disrupt linear differential
  trails → doesn't help. Helps direct collisions (which are about
  position symmetry, not differential structure).
- **v5/v5b** (non-linear pre-finalize rounds): non-linear → disrupts
  easy differentials but can't reach a structural bias built up over
  the entire main loop on certain input patterns.

The honest takeaway: **river5's structural choice — 16 lanes processing
fixed input slices with a 4-round tree finalize — has a ceiling around
1.05× excess at 32-bit truncated Permutation differential.** The bias
is intrinsic to that structure, not iterable-away with finalize tricks.
Anyone who wants river5 to be SMHasher3-clean needs to redesign the
main loop. Anyone who's OK with river5 being "a fast dedup hash that
passes Avalanche/BIC/Cyclic/Sanity and has a known narrow residual on
adversarially-constructed Permutation keysets" is already on `main`
with v3.

## What's preserved on this branch

- `csrc/river5_aesni_v5.c` — the v5b implementation (two non-linear
  finalize rounds, named `river5-aesni-v5b`)
- `bench/hashes.c` — `river5-v5` registered for A/B (currently points
  at the v5b code; the name didn't get bumped to `river5-v5b` in
  the bench registry)
- `Makefile`, `build.rs` — v5 compiled into libriver5
- `csrc/river5_internal.h` — `RIVER5_VTABLE_AESNI_V5` declaration
- `diagnostics/v5-permutation-full.log`, `v5b-permutation-full.log` —
  the raw SMHasher3 outputs for both attempts

The public dispatcher in `csrc/river5.c` was NOT changed on this
branch; public `river5_hash()` still routes to v3 here too.

If you want to try the next layer (v6 main-loop redesign), branch
from `main` (clean v3 baseline), not from this branch.
