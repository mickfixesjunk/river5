# v13-content-shuffle — branch notes

**Status:** mixed result, abandoned for now. **DO NOT merge.**
Genuinely interesting: best non-killer performance of any
non-v6 attempt, but a catastrophic 152× spike on the structural
8-byte-cyclic keyset.

## What v13 tried (final form, v13b)

Content-dependent PSHUFB shuffles. v6 uses 16 FIXED shuffle patterns;
v13 derives the shuffle from partner-lane input data:

```c
shuffled = PSHUFB(partner_input, partner_input & 0x0F)
mixed    = self_input XOR shuffled
lane[i]  = AESENC(lane[i], mixed)
```

self_input is XOR'd directly so EVERY input bit always contributes
(v13a without this XOR failed Sanity check 2 — flipping a bit at
some position produced identical output because the PSHUFB mask
sometimes didn't reference that position).

Hypothesis: data-dependent shuffles defeat the fixed-structure
alignment that gives v6 its 1.5× Permutation ceiling. Attackers can't
predict the shuffle pattern without knowing partner input bytes too.

## What actually happened

**Two-faced result:**

- On MOST keysets, v13 BEATS v6: many keysets cluster at 1.14-1.33×
  excess (vs v6's typical 1.5×). This is the first non-v6 attempt
  that does better than v6 on the bulk of keysets.

- On the SPECIFIC structural killer ('Combination 8-bytes [0, low bit;
  LE]'), v13 REGRESSES catastrophically: **152.9× excess** at 32-bit
  truncation, 136.4× on the differential analysis. v3 had 9.37× on
  this keyset; v6 brought it to 1.53×; v13 took it to 152.9×.

## Why the 152× regression

For 8-byte-cyclic input (e.g., `ABABABAB | ABABABAB | ABABABAB | ABABABAB`
filling all 256 bytes), the partner inputs `in_partner = in_self` (since
the cyclic pattern is the same across all 16-byte slices). So:

- `mask = in_partner & 0x0F` is the SAME for every lane
- `PSHUFB(in_partner, mask)` is the SAME for every lane
- `mixed = in_self XOR shuffled` is the SAME for every lane

ALL 16 lanes get the SAME AESENC argument. The lane independence
that v6's distinct fixed shuffles provide is COMPLETELY LOST for
this specific input pattern. Massive collision.

The 1.14× improvement on other keysets isn't valuable enough to offset
losing v6's structural defense.

## What WOULD work (v13c, v13d ideas)

- **v13c**: keep v6's FIXED PSHUFB *and* ADD content-dependent XOR mix.
  Combines both protections: v6's structural defense for cyclic input
  +
  v13's content-dependence for other keysets.
- **v13d**: derive the content-dependent mask from a HASH of multiple
  lanes (e.g., XOR of 4 partner inputs), so cyclic inputs still
  produce varied masks because the hash of 4 partners differs from
  the masks of individual partners.

Per overnight plan: moving to v14 (two-stream) first. Will revisit
v13c/v13d if v14 fails — v13's broad keyset improvement is the most
interesting signal we've seen all night.

## What's preserved on this branch

- `csrc/river5_aesni_v13.c` — content-dependent shuffle implementation (v13b form, with sanity fix)
- `bench/hashes.c` — `river5-v13` registered for A/B
- `Makefile`, `build.rs` — v13 compiled
- `csrc/river5_internal.h` — `RIVER5_VTABLE_AESNI_V13` declaration
- `diagnostics/v13-permutation-full.log` — raw SMHasher3 output

Public dispatcher unchanged; main routes to v6.

## Performance on i7-7700K (v13 vs v6)

Notable: v13 throughput is essentially IDENTICAL to v6 (within noise).
The extra AND per lane pipelines freely with AESENC's port-0
bottleneck. Cost of the content-dependent shuffle is ~0%.

This is rare: every other non-v6 attempt cost meaningful throughput.
v13 is the first that's both algorithmically distinct AND free.

## Sanity bug in v13a (worth recording)

Initial v13 used `AESENC(lane[i], PSHUFB(self_input, partner_input & 0x0F))`
directly. Sanity check 2 failed: flipping certain input bits at
specific positions produced identical hash output.

Root cause: PSHUFB with control byte values in 0..15 outputs `input[mask[j]]`
at position j. If a partner input's low nibbles happened to not include
some position P, bit P of self input was never read → had no effect on
hash. By pigeonhole this happens for some partner-input distribution.

Fix: XOR self_input back into the AESENC arg so every bit contributes
unconditionally. Final v13b form: `AESENC(lane[i], self XOR PSHUFB(partner, partner_mask))`.
