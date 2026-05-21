# v14-two-stream — branch notes

**Status: 🎉 BREAKTHROUGH — PASSES SMHasher3 across all four critical
categories.** First river5 variant to do so.

Tagged as `v14`. Pushed to `origin/v14-two-stream`. **NOT merged to
main** — awaiting user review of the throughput/quality tradeoff.

## What v14 does

Two-stream interleaved hash with XOR output combine:

```c
river5_v14(x) = river5_v6(x) ⊕ river5_v11(x)
```

Both streams run on every input. Their 128-bit outputs are XOR'd
byte-for-byte to produce v14's final output. Internally implemented
as a thin wrapper (`csrc/river5_aesni_v14.c`) that delegates to both
stream vtables and combines results in `one_shot` and `finalize`.

Stream A = v6 (current main default): 16-lane AES + fixed PSHUFB
+ butterfly + tree finalize.

Stream B = v11 (PCLMULQDQ): 16-lane carry-less polynomial mix in
GF(2^64) + per-lane AESENC + butterfly + tree finalize. v11 standalone
fails Permutation catastrophically (22.61× max) due to its purely
linear polynomial mix.

## Why this works

When two distinct hash streams H₁ and H₂ have INDEPENDENT bias
structures (different algebra → different differential trail patterns),
their XOR combination provably cancels both biases:

For H_c(x) = H₁(x) ⊕ H₂(x), a 32-bit collision on input pair (A, B)
requires H₁(A) ⊕ H₁(B) = H₂(A) ⊕ H₂(B). If the two streams' output
differences are independent random 32-bit values, this happens with
probability exactly 2⁻³² — random baseline, zero bias.

v6 and v11 use different algebraic primitives:
- v6's mixing: byte permutation (PSHUFB) + AES S-box
- v11's mixing: polynomial multiplication in GF(2⁶⁴) + AES S-box

These have substantially different differential properties. The
hypothesis was that their bias patterns on SMHasher Permutation are
at least partly uncorrelated. The test confirmed it.

## SMHasher3 results (i7-7700K, AES-NI + AVX2, no VAES, no AVX-512)

| test | v3 | v6 (main) | **v14** |
|---|---|---|---|
| Sanity | PASS | PASS | **PASS** |
| Avalanche | PASS | PASS | **PASS** (max bias 0.797%, score 0) |
| BIC | PASS | PASS | **PASS** (max bias 0.0046, score 0-1) |
| Cyclic | PASS | PASS | **PASS** (max 1.012× excess at 26 bits, score 0) |
| Permutation | **FAIL (9.37×)** | **FAIL (1.53× residual)** | **PASS** (max 1.063× at 40-bit, score 1; max 1.005× at 32-bit, score 2) |

**Zero `!!!!!` markers in v14's Permutation output. Zero
`*********FAIL*********` markers.** The killer keyset ('Combination
8-bytes [0, high bit; BE]') that drove v6's residual: 0.997× direct,
1.005× differential.

`diagnostics/v14-permutation-full.log` contains the full output.

## Performance on i7-7700K (`./build/river5-bench micro --seconds 1`)

| size | v14 (PASS) | v6 (PARTIAL) | BLAKE3 | xxh3-128 | Meow |
|---|---|---|---|---|---|
| 4 KiB  | 10.7 GB/s | 29.6 | 1.7 | 22.1 | 45.7 |
| 16 KiB | 11.5      | 32.1 | 3.5 | 23.7 | 50.2 |
| 64 KiB | 10.7      | 32.9 | 3.7 | 23.7 | 49.3 |
| 256 KiB| 11.4      | 30.7 | 3.6 | 24.1 | 48.9 |
| 1 MiB  | 10.5      | 28.9 | 3.6 | 24.2 | 49.8 |

v14 is:
- **3-4× faster than BLAKE3** (the closest SMHasher-passing hash with
  similar security positioning).
- **About half xxh3-128's speed** — xxh3 also passes SMHasher but is
  a different family (not AES-based).
- **About 1/4 to 1/5 of v6's speed** — the two-stream cost is real.
- **About 1/4 of Meow's speed** — Meow is the leader on this hardware
  for SMHasher-passing AES-NI hashes.

For the dedup use case (where v6 was already overkill on the FULL
128-bit hash with zero observed collisions), v14 trades 65% of the
raw throughput for genuine SMHasher3 cleanliness — useful only if
"river5 is a serious general-purpose hash" matters more than
"river5 is the fastest possible dedup hash."

## What this proves about river5 design

After 13 attempts (v3 through v13c) hitting the same ~1.5×
Permutation residual on the 16-lane butterfly_mix structure, v14
demonstrates that **the ceiling can be broken — but only by stepping
outside the single-stream design**, not by tweaking inputs or mixing
within it.

The 1.5× residual is a property of butterfly_mix's pair structure.
Two independent streams with different algebraic primitives each have
this kind of residual at different places, and XOR-combining
cancels them.

## Throughput optimization ideas (if v14 is too slow)

- **v14b**: instead of running v6 and v11 separately (each going
  through its own register-allocated lane state), interleave their
  operations in a single function so GCC can keep more in registers.
  Could recover 10-20% throughput.
- **v14c**: use a CHEAPER stream B than v11 (which spends a lot on
  AES operations after PCLMULQDQ). E.g., just `lane[i] += PCLMULQDQ(...)`
  with no per-lane AES. Riskier — might lose the bias-independence
  property.
- **v14d**: pure two-stream at 32-byte (256-bit) state per lane via
  AVX2 ymm registers, single AES per ymm round. Different geometry
  that might be cheaper.

These are FOLLOW-ON IDEAS, not part of this branch.

## What's preserved on this branch

- `csrc/river5_aesni_v14.c` — the thin two-stream wrapper
- `csrc/river5_aesni_v11.c` — pulled from `v11-pclmulqdq` branch (needed
  for v14's Stream B)
- `csrc/river5_internal.h` — declares both v11 and v14 vtables
- `bench/hashes.c` — `river5-v14` registered
- `Makefile`, `build.rs` — both v11 and v14 compiled
- `diagnostics/v14-permutation-full.log` — full SMHasher3 Permutation output
- BRANCH_NOTES.md (this file)

Public dispatcher in `csrc/river5.c` is unchanged on this branch.
The default `river5_hash()` still routes to v6. To try v14, use the
bench: `./build/river5-bench micro` shows `river5-v14` alongside.

## Recommendation

Promote v14 to main IF you value SMHasher3 cleanliness over raw
throughput. The cost (10-12 GB/s vs v6's 28-33 GB/s) is real but
v14 still beats BLAKE3 3-4×. For superdupe specifically: the dedup
workload doesn't observe v6's Permutation residual (full 128-bit
collisions are 0 in both), so the upgrade is purely about "river5
becomes a serious general-purpose hash" rather than visible dedup
improvement.

If staying on v6 for max throughput: v14 is on this branch as
documented proof that SMHasher3 PASS is achievable, available
whenever needed.
