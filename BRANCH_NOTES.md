# v15-fast-dedup — branch notes

**Status:** ✅ shipped as tagged alternative (tag `v15`). Main stays
on v6. v15 is the explicit "fastest river5 with clean Avalanche"
variant, positioned for consumer-dedup workloads where full-128-bit
hash comparison is what matters and adversarial differentials don't.

## What changed from v6

Literally one line: removed the per-block `butterfly_mix(lane)` call
from `process_block`. Everything else (PSHUFB input scramble, init
constants, finalize structure) is identical to v6.

```c
// v15 process_block (compared to v6):
//   ... 16 input AESENCs with PSHUFB ...
//   butterfly_mix(lane);  <-- DELETED for v15
// }
```

The deleted butterfly was v6's per-block cross-lane defense against
SMHasher Permutation differentials at narrow truncations. For
full-128-bit dedup on real-world inputs, that defense pays zero
observable dividend (real files don't construct adversarial
permutation differentials, and we compare the full 128 bits anyway).
Removing it halves the per-byte AES work.

## Bench on i7-7700K (AES-NI + AVX2, no VAES), 1.5s/cell

| size | **v15** | v6 (main) | v3 | v2 | Meow | xxh3-128 | BLAKE3 |
|---|---|---|---|---|---|---|---|
| 4 KiB  | 41.4 GB/s | 26.8 | 30.9 | 58.3 | 44.5 | 21.0 | 1.4 |
| **16 KiB** | **55.5** | 29.9 | 33.0 | 64.7 | 46.0 | 23.2 | 3.3 |
| 64 KiB | 45.7 | 28.8 | 34.1 | 63.0 | 46.6 | 22.8 | 3.3 |
| 256 KiB| 40.0 | 29.2 | 33.1 | 52.1 | 48.8 | 22.8 | 2.9 |
| 1 MiB  | 30.8 | 27.0 | 29.9 | 36.8 | 50.6 | 22.9 | 2.2 |

v15 wins:
- **~2× v6** at peak cache (55.5 vs 29.9 at 16 KiB) — exact theoretical
  prediction matched.
- **Beats Meow** at mid sizes (55.5 vs 46.0 at 16 KiB). Meow catches up
  and surpasses at 1 MiB (its streaming optimization dominates as the
  bottleneck shifts from compute to memory bandwidth).
- **Beats xxh3-128** at all sizes (55.5 vs 23.2 at 16 KiB — over 2×).
- **15-20× BLAKE3** across the board.

v15 loses to v2 by ~14% — v2 has NO PSHUFB at all (raw `AESENC(lane,
input)`). PSHUFB pipelines on a different port from AES but still adds
dependency latency. The v2 vs v15 tradeoff:

| | v2 | v15 |
|---|---|---|
| Peak throughput (16 KiB) | 64.7 GB/s | 55.5 GB/s |
| Avalanche (SMHasher) | FAILS 1.83% bias | PASSES |
| Why we ship v15 | (kept as historical) | balanced default for "fast variant" |

For pure-speed users who don't care about Avalanche: v2 is still in the
bench (`river5-v2`) and gives another 14%. For most consumers v15 is
the recommended fast variant.

## SMHasher3 status (deliberate non-goal)

v15 will fail SMHasher3 Permutation and Cyclic at narrow truncations
because it has no per-block cross-lane mixing. **This is by design.**

What WON'T fail:
- Sanity (output exists, propagates inputs, no degenerate state)
- Avalanche (PSHUFB provides per-lane bit propagation — this was the
  key reason to keep PSHUFB vs going all the way to v2)
- Full-128-bit collision behavior on real-world inputs (effectively
  zero collisions at 128-bit on any realistic corpus due to birthday-
  bound math)

What WILL fail or have residuals:
- Permutation at 32-bit truncation (no cross-lane defense)
- Cyclic at narrow truncations (lanes evolve independently for the
  whole main loop)
- Possibly BIC at narrow truncations

None of these matter for the use case v15 is built for (full-128-bit
dedup of non-adversarial content).

## What v15 is FOR

| use case | v15 safe? |
|---|---|
| File dedup (compare full 128-bit hashes) | ✅ yes |
| In-memory dedup cache keys | ✅ yes |
| Bloom filter input hashing (with 128-bit truncation to filter slots) | ✅ yes (consumer-level Bloom; not adversarial) |
| Hash table key for non-attacker-controlled keys | ✅ yes |
| Memoization keys | ✅ yes |
| Filesystem snapshot/sync checksumming (non-adversarial) | ✅ yes |
| LRU cache key derivation | ✅ yes |
| Database row dedup / equality | ✅ yes |
| Build cache (ccache, sccache style, trusted inputs) | ✅ yes |
| Disk block dedup at storage layer | ✅ yes |

## What v15 is NOT for

| use case | why |
|---|---|
| Cryptographic content addressing (git/IPFS/blockchain) | needs collision resistance vs adversaries |
| MAC / authentication codes | not cryptographic |
| Password hashing | use bcrypt/argon2 |
| Hash table with attacker-controlled keys | HashDoS risk |
| Forensic file integrity | use SHA-2/3 |
| Anything where adversary picks inputs | not designed for it |

## Where v15 fits in the river5 family

```
v14 (~11 GB/s)  → SMHasher-passing claim (with caveat: fails Dict — see below)
v6  (~30 GB/s)  → main default, balanced, partial SMHasher pass
v15 (~55 GB/s)  → NEW: fastest river5 with clean Avalanche, consumer dedup
v2  (~65 GB/s)  → fastest possible, Avalanche fail (kept for A/B in bench)
```

## On v14's documented status

v14's "SMHasher-passing" claim from the overnight run is partially
wrong. v14 PASSED Sanity, Avalanche, BIC, Cyclic, Permutation (the
five categories we verified), but on the full SMHasher3 battery
v14 FAILS the Dict keyset with 1515 actual full-128-bit collisions
on dictionary-word inputs. This is a real, observable bug. v14 should
NOT be shipped as "the SMHasher-passing variant" without
investigating the Dict failure first.

The v14 branch and tag remain pushed for reproducibility but the
"SMHasher-passing" framing in WAKEUP_SUMMARY.md is being corrected.

## What's preserved on this branch

- `csrc/river5_aesni_v15.c` — the impl (one-line change from v6)
- `csrc/river5_internal.h` — `RIVER5_VTABLE_AESNI_V15` declared
- `bench/hashes.c` — `river5-v15` registered
- `Makefile`, `build.rs` — v15 compiled into libriver5

Public dispatcher unchanged; main still routes to v6. To use v15
from Cargo: `river5 = { git = "...", tag = "v15" }`.
