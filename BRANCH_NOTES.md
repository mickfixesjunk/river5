# v13c-hybrid-shuffle — branch notes

**Status:** abandoned, matches v6 essentially. **DO NOT merge.**

## What v13c tried

After v13's content-dependent shuffle showed broad keyset improvement
(1.14-1.33× excess on most keysets vs v6's 1.5×) but catastrophically
regressed on the 8-byte-cyclic killer (152× spike), v13c attempted
a hybrid that combines both defenses:

```c
shuf_v6      = PSHUFB(in_self, FIXED_PATTERN[i])    ← v6 fixed shuffle
shuf_partner = PSHUFB(in_partner, in_partner & 0x0F) ← v13 content-dep
mixed        = shuf_v6 XOR shuf_partner
lane[i]      = AESENC(lane[i], mixed)
```

v6's distinct fixed patterns defend against cyclic input (each lane
sees a different byte ordering even when inputs match across lanes);
v13's content-dependent mixing adds data-driven variation on top.

## What actually happened

v13c **eliminated the 152× cyclic spike** (down to 1.65× on that
keyset — comparable to v6's behavior there) — the hybrid did
preserve v6's structural defense. But the overall MAX excess is:

| metric | v6 | v13c | v13 |
|---|---|---|---|
| max collision excess | 1.61× | **1.65×** | 152× |
| max distribution bias | 4.78× | **4.82×** | 112× |
| !!!!! count | 49 | 48 | 63 |

**v13c essentially matches v6**, within noise. The hybrid neither
helped nor hurt.

## What this proves

**The ~1.5× Permutation residual is structural to butterfly_mix
itself, not to the input mixing primitive.** Six different input-mixing
variants (v6 fixed PSHUFB, v11 PCLMULQDQ, v12 ADD+MUL, v13 content-
dep, v13c hybrid, v6+changes in v7/v8/v9/v10) all converge on the
same ~1.5× collision excess ceiling. The common factor across all of
them is the `butterfly_mix` pair-AESENC structure (i, i^8) and the
4-round tree finalize.

To break this ceiling, we'd need to change butterfly_mix's pair-wise
structure OR change the lane geometry (not 16×128-bit), OR use
fundamentally different cross-lane mixing entirely.

## What's preserved on this branch

- `csrc/river5_aesni_v13c.c` — hybrid implementation
- `bench/hashes.c` — `river5-v13c` registered
- `Makefile`, `build.rs` — v13c compiled
- `csrc/river5_internal.h` — vtable declaration
- `diagnostics/v13c-permutation-full.log` — raw SMHasher3 output

Public dispatcher unchanged; main routes to v6.

## What's next

Moving to v14 (two-stream). Math suggests XOR-combining two streams
with INDEPENDENT bias structures can cancel both biases (combined
excess ≈ 1.0 if biases are uncorrelated). Cost: 2× v6 throughput.
Tradeoff worth one attempt to know if it works.
