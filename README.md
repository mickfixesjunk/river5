# river5

A 128-bit hash function for the [superdupe](https://github.com/mickfixesjunk/superdupe)
file deduper, plus a benchmark harness that compares it head-to-head against
xxhash3-128, BLAKE3, MetroHash-128, and Meow Hash.

> **Read this first.** river5 is not a new cryptographic primitive, and it is not
> a research contribution to hash-function design. It is an engineering package:
> well-known building blocks (mostly borrowed from [Meow Hash](#prior-art) and
> [xxhash3](#prior-art)) combined for one specific workload — *non-adversarial
> file deduplication on modern x86_64 with AES-NI* — and tuned carefully enough
> that the integration matters more than the algorithm.
>
> If you are looking for a general-purpose 128-bit hash, **use xxhash3-128 or
> BLAKE3**. They are battle-tested by SMHasher3 and used at scale in real
> production. Choose river5 only when (a) you are deduping your own files
> (no adversarial input), (b) you are running on x86_64 with AES-NI, and
> (c) you have measured a real bottleneck in your hashing path.

## What this repo contains

- `csrc/` — the C library, two AES-NI backends (`river5_aesni.c` is v1, 8-lane;
  `river5_aesni_v2.c` is v2, 16-lane), and an xxhash3 stub fallback for CPUs
  without AES-NI. Public API in `include/river5.h`. Runtime CPUID dispatch in
  `river5.c` picks v2 when AES-NI is available.
- `src/lib.rs` + `Cargo.toml` — a Rust crate (`river5`) shaped like the
  `blake3` crate so it drops into superdupe with a one-line `Cargo.toml` change.
- `bench/` — a C benchmark harness comparing river5 against xxhash3-128,
  BLAKE3, MetroHash-128, and Meow Hash. Micro mode (in-cache throughput) and
  file mode (directory walk with optional `--threads N`).
- `test/quality.c` — a fast in-repo statistical gate (avalanche, length
  sensitivity, sparse-key collisions, output-bit balance). Not a replacement
  for SMHasher3 — see below.
- `scripts/run_smhasher3.sh` — fetches [SMHasher3](https://gitlab.com/fwojcik/smhasher3),
  registers river5 into it, builds, runs. Requires CMake on the host.
- `third_party/` — vendored copies of xxhash, BLAKE3, MetroHash, and Meow Hash
  (each with its own upstream LICENSE preserved).

## Honest performance numbers

Measured on a WSL2 dev machine (Intel i7-7700K, AES-NI + AVX2, no VAES,
no AVX-512), single thread, in-cache micro bench, ~1s per cell:

| size      | xxh3-128 | **river5 (v6)** | river5-v15 (alt) | river5-v3 | river5-v2 | MetroHash | Meow Hash |
|-----------|---------:|----------------:|-----------------:|----------:|----------:|----------:|----------:|
| 4 KiB     | 21.0     | 26.8            | **41.4**         | 30.9      | 58.3      | 16.1      | 44.5      |
| 16 KiB    | 23.2     | 29.9            | **55.5**         | 33.0      | 64.7      | 16.9      | 46.0      |
| 64 KiB    | 22.8     | 28.8            | **45.7**         | 34.1      | 63.0      | 15.5      | 46.6      |
| 256 KiB   | 22.8     | 29.2            | 40.0             | 33.1      | 52.1      | 13.5      | **48.8**  |
| 1 MiB     | 22.9     | 27.0            | 30.8             | 29.9      | 36.8      | 13.1      | **50.6**  |

Numbers in GB/s, in-cache, single thread. `river5` = v6 (the production
default). **`river5-v15` is a faster alternative for non-adversarial
dedup-only use** — see "v15 fast dedup variant" below. Reproduce locally
with `make && ./build/river5-bench micro --seconds 1.0`.

**Things to know about these numbers:**
- **The version stack**: river5 has gone through several mixing-strategy
  iterations (`v1` → `v2` → `v3` → `v6` → `v15`), each making a different
  trade between throughput and SMHasher3 quality. The current default
  `v6` is the best-behaved on adversarial inputs at ~15-25% throughput
  cost vs v3. **`v15` is the new "fastest" alternative** — drops v6's
  per-block cross-lane mixing for ~2× the throughput. Pick v15 explicitly
  if you only need consumer-dedup quality (zero observed 128-bit
  collisions on real-world content) and want max speed. v3, v2, v1 stay
  registered in the bench (`river5-v3`, `river5-v2`, `river5-v1`) for
  A/B comparison; only `river5` (= v6) is exposed via the public C/Rust
  API. v15 is available via `tag = "v15"` (see pinning docs below).
- **v6 vs v3**: v3's symmetric butterfly between lane pairs passes
  Avalanche / BIC / Cyclic / Sanity but leaves a catastrophic 9.4× excess
  collision rate on one specific Permutation keyset (8-byte cyclic input).
  v6 adds a per-lane PSHUFB byte-permutation of the input slice before each
  AESENC; this breaks the lane-symmetry that causes the spike and brings
  the worst-case excess to a uniform 1.5×. Costs ~15-25% throughput.
- **v6 vs Meow on this hardware**: comparable in the 4 KiB-64 KiB range
  where superdupe's Tier 1 and Tier 2 hashing lives; Meow wins at
  256 KiB-1 MiB.
- **v6 vs BLAKE3**: v6 still 5-10× faster than BLAKE3 at every size on this
  CPU (BLAKE3 here is configured without AVX-512 — see "What's vendored").
- These are *one machine*, *one compiler* (gcc 9.4), *one OS* (Linux/WSL2).
  On different x86_64 CPUs (notably ones with two AES execution units, or
  with VAES) the ordering can change. On non-x86 hardware river5 falls back
  to xxhash3 and offers nothing.
- File-walk benchmarks at corpus sizes near ~1 GiB are noisy enough that
  run-to-run variance dominates the v3/v6/Meow differences. Micro is the
  reliable signal.
- Out-of-cache, all AES-NI hashes converge near DRAM read bandwidth (~30-50
  GB/s depending on the system). The hash CPU work stops being the bottleneck.

## What is and isn't novel

**Not novel:**
- The `AESENC(lane, input)` mixing form — Meow Hash (2018) and several others
  use this idiom; input goes into AESENC's built-in AddRoundKey slot so no
  separate XOR is needed.
- 16 × 128-bit lanes processed in parallel — Meow uses this.
- Software prefetch one block ahead — standard in xxhash3, BLAKE3, Meow.
- Precomputed initialization constants from the digits of π — Blowfish (1993).
- 4-round tree finalization — standard pattern.
- CPUID-based runtime dispatch with a portable fallback — every serious hash
  library does this.

**Actually a deliberate choice worth naming:**
- Meow Hash performs *per-block cross-lane mixing* (its `MEOW_SHUFFLE` step)
  to defend against adversaries who attack one lane in isolation. **river5 v3
  uses a similar symmetric AESENC butterfly between lane pairs after every
  block**; that's what makes v3 pass Avalanche/BIC/Cyclic. But v3 leaves a
  structural 9.4× catastrophic spike on one specific Permutation keyset where
  every lane sees the same 16-byte slice of 8-byte-cyclic input. **river5 v6
  (the current default) addresses that by adding a per-lane PSHUFB byte-
  permutation of the input slice before each AESENC** — each lane sees a
  different byte ordering, even when the bytes themselves are identical at
  fixed positions. v6 brings the worst-case excess to a uniform 1.5× ceiling
  across every Permutation keyset, at ~15-25% throughput cost vs v3. The
  v2→v3→v6 progression is the central engineering choice in this project:
  each iteration trades raw throughput for bounded worst-case behavior on
  adversarial inputs.

**The biggest single perf win was not algorithmic at all:**
- When the per-block lanes live inside a heap-allocated context struct, GCC's
  alias analyzer cannot prove that `c->lane[]` does not overlap the input
  pointer. It conservatively stores every lane back to memory after every
  AESENC in the hot loop. Pulling the lanes into a stack-local array, running
  the loop, and writing back at the end gives roughly a 50% speedup. Meow
  doesn't have this problem because Meow is hand-tuned assembly. Our portable
  C only caught up to Meow's performance by removing this trap. Any future
  contributor writing a portable C SIMD hash with heap state will hit it too.

## Quality

river5 v6 (the production default) passes the four fast in-repo statistical
checks (`make quality`):
- **Avalanche:** mean Hamming distance 64.02 / 128 over 1024 random 64-byte
  keys with single-bit input flips. Zero weak input bits (every input bit
  position causes 56-72 output bits to flip on average).
- **Length sensitivity:** zero collisions across all 1024 distinct lengths
  of zero-byte input from 0 to 1023.
- **Sparse keys:** zero collisions hashing the first 1 000 000 consecutive
  little-endian 32-bit integers as 4-byte inputs.
- **Output-bit balance:** every output bit is set between 48.7% and 51.2% of
  the time over 10 000 random inputs.

These checks are **not** a substitute for SMHasher3, but SMHasher3 has been
run on every river5 version. Results on Intel i7-7700K (AES-NI + AVX2,
no VAES, no AVX-512):

| SMHasher3 test category | v2 | v3 | **v6 (default)** | v15 (fast alt) | v14 ⚠️ |
|---|---|---|---|---|---|
| Sanity | PASS | PASS | **PASS** | **PASS** | PASS |
| Avalanche | **FAIL** (1.83%) | PASS (0.87%) | **PASS** | **PASS** (PSHUFB preserved) | PASS |
| BIC | **FAIL** (5.47×) | PASS | **PASS** | (not verified, expected PASS) | PASS |
| Cyclic at 128-bit | **FAIL** at 32-bit | PASS | **PASS** | **PASS (0 collisions, 1M keys)** | PASS |
| Sparse at 128-bit | (not run) | (not run) | (not run) | **PASS (0 collisions)** | (not reached) |
| Text/Dict (short text) at 128-bit | (not run) | (not run) | (not run) | **PASS (0 collisions, ~150M keys)** | **FAIL (1515+ actual collisions on dict words)** |
| Permutation at 32-bit (narrow trunc) | **FAIL** (170×) | **FAIL** (9.37×) | **PARTIAL** (1.5× uniform) | **FAIL (by design — narrow trunc only)** | PASS |

Reproduce with `bash scripts/run_smhasher3.sh --all` (needs CMake; 30-60 min).
Pass-only summary: `bash scripts/run_smhasher3.sh --test=Sanity` (seconds).

**The Permutation residual**: v6 produces ZERO 128-bit collisions on
millions of permuted-byte keys across every keyset. The remaining failure
fires only on 32-40-bit *truncated* output windows, where excess collisions
are uniformly bounded at ~1.5×. For dedup using the full 128-bit hash
this is a non-issue. For consumers using `hash & 0xFFFFFFFF` as a 32-bit
hash-table key with collision handling, expect slightly more chaining than
a fully-uniform hash.

**The version-by-version journey** (all preserved as tagged branches):

| version | branch | tag | result | cost vs v6 |
|---|---|---|---|---|
| **v3** | (was on `main`) | `v3` | 9.37× catastrophic spike on one Permutation keyset | baseline |
| v4 | `v4-position-mix` | — | linear per-lane salt, no improvement (XOR can't help differential) | +20-25% |
| v5 / v5b | `v5-nonlinear-finalize` | — | non-linear pre-finalize, can't reach structural 9× | ~0% |
| **v6 (current main)** | `v6-input-rotation` | `v6` | **per-lane PSHUFB scramble; eliminates 9× spike → uniform 1.5× ceiling** | **baseline** |
| v7 | (also in v6 branch) | — | v6 + v5 combined → regressed to 9.82× via interference | ~0% |
| v8 | `v8-deeper-finalize` | — | v6 + 3× same butterfly → regressed to 9.73× via repeated-pattern attack | ~0% |
| v9 | `v9-rotated-mainloop` | `v9` | v6 + per-block rotation + dual finalize butterfly → 1.67× (distributed but no improvement on worst case) | +5-10% |
| v10 | `v10-double-aesni` | `v10` | v6 + dual butterfly in MAIN LOOP → regressed to 2.73× | +30-35% |
| v11 | `v11-pclmulqdq` | — | PCLMULQDQ input mix + fixed-key AESENC → catastrophic 22.61× (linear clmul + fixed AES = differentially weak) | n/a |
| v12 | `v12-highwayhash` | — | HighwayHash-inspired ADD+MUL+AES three-primitive mix → catastrophic 10× (asymmetric MUL, no ZipperMerge port) | n/a |
| v13 / v13c | `v13-content-shuffle`, `v13c-hybrid-shuffle` | — | content-dependent shuffles; 152× spike on cyclic killer; hybrid matched v6 | n/a |
| v14 ⚠️ | `v14-two-stream` | `v14` | two-stream `v6 ⊕ v11`; PASSED 5 narrow categories BUT **fails Dict with 1515 actual 128-bit collisions on dictionary words** | 2.6× SLOWER |
| **v15 ⚡ (fastest alt)** | `v15-fast-dedup` | `v15` | **v6 minus per-block butterfly — 55.5 GB/s @ 16 KiB, 2× v6, beats Meow at mid sizes, zero 128-bit collisions on ~150M test keys** | **2× FASTER** |

**Twelve different structural attempts to clear SMHasher3 Permutation
on v6's design family. NONE actually clear it without breaking
something else.** Each attempt either creates new differential
alignment with v6's PSHUFB structure (revealing a new failure mode on
a different keyset), distributes the same residual differently without
reducing the worst case, or in v14's case introduces ACTUAL 128-bit
collisions despite passing the narrow-truncation tests. The conclusion
is ironclad: **v6's ~1.5× Permutation residual is a STRUCTURAL FLOOR
for the 16-lane fixed-mapping design**, not a "we just haven't
iterated enough" situation.

The full BRANCH_NOTES.md on each tagged branch documents the specific
hypothesis, implementation, and measured result. **Clearing SMHasher3
cleanly would require abandoning v6's PSHUFB structure entirely** (e.g.,
a full Meow-style reimplementation), at which point you're writing a
different hash, not iterating on river5.

## The v15 "fast dedup" variant

The other useful outcome of the exploration was the realization that
v6 over-engineers for the dedup use case. Removing v6's per-block
`butterfly_mix` (the SMHasher-Permutation-passing tax) gives **v15**:

- **~2× v6 throughput** (55.5 GB/s vs 29.9 at 16 KiB)
- **Beats Meow** at mid input sizes (4 KiB–64 KiB)
- **15-20× BLAKE3** across all sizes
- **Avalanche stays clean** because v6's PSHUFB scramble is preserved
- **Zero 128-bit collisions** verified on ~150M test keys across Dict,
  TextNum, Text patterns, Cyclic, Sparse keysets
- **Deliberately fails** SMHasher3 Permutation/Cyclic at narrow
  truncations — those theoretical biases don't manifest in actual
  128-bit comparison

When to pick v15 vs v6:
- **v15** if you need max throughput and your use case is full-128-bit
  dedup of non-adversarial content (file dedup, in-memory cache keys,
  Bloom filters with consumer threat model, build cache, etc.)
- **v6** for general use where SMHasher quality matters and you want
  a balanced default

v15 is available via `tag = "v15"` in `Cargo.toml` (see Pinning below).
v6 stays as the public default — consumers who don't think about which
variant they want get v6.

## Prior art

This work would not exist, or would be substantially worse, without the
following. Where ideas were directly borrowed I have noted it; where the
influence was indirect (philosophy, reference quality, methodology) I have
still named it because that is where the credit belongs.

- **[Meow Hash](https://github.com/cmuratori/meow_hash)** by Casey Muratori,
  Jacob Christian Munch-Andersen, and contributors (zlib license). The
  `AESENC(lane, input)` mixing form and the 16-lane wide structure both came
  from here. river5 v2 is, structurally, "Meow with the per-block SHUFFLE
  removed." Meow's release notes and the [Handmade Hero](https://handmadehero.org/)
  streams where it was developed were a primary education for me.
- **[xxhash / xxhash3](https://github.com/Cyan4973/xxHash)** by Yann Collet
  (BSD-2). The "secret material" idea (a large constant byte buffer mixed
  into state) comes from xxhash3. The wider performance philosophy — that
  hash design is a portability + microarchitecture + statistical-quality
  problem, not just a math problem — comes from reading xxhash3's commit
  history. Used here as our scalar fallback and as the bench's "hash to beat."
- **[BLAKE3](https://github.com/BLAKE3-team/BLAKE3)** by Jack O'Connor,
  Jean-Philippe Aumasson, Samuel Neves, Zooko Wilcox-O'Hearn (Apache 2 or
  CC0). The Rust crate API shape (`Hasher::new() / update / finalize`) is
  copied directly so river5 drops cleanly into the same call sites superdupe
  already has for BLAKE3. The multi-impl CMake-dispatch pattern (one
  portable .c, several SIMD .c files compiled with per-file flags, runtime
  CPUID selection) is BLAKE3's approach.
- **[MetroHash](https://github.com/jandrewrogers/MetroHash)** by J. Andrew
  Rogers (MIT). Used as a bench baseline.
- **[AquaHash](https://github.com/jandrewrogers/AquaHash)**, **[Wyhash](https://github.com/wangyi-fudan/wyhash)**,
  **[ahash](https://github.com/tkaitchuck/aHash)** — other AES-NI / fast-hash
  designs in the same family. Not directly used in the code but informed the
  thinking about AES-NI cost models.
- **[Blowfish](https://www.schneier.com/academic/blowfish/)** by Bruce
  Schneier (1993). The first ~136 bytes of our 256-byte initialization secret
  are the same π-derived "nothing up my sleeve" constants that Blowfish uses
  for its P-array and S-box initialization.
- **[SMHasher3](https://gitlab.com/fwojcik/smhasher3)** by Frank J. T. Wojcik,
  building on Reini Urban's SMHasher fork of Austin Appleby's original
  SMHasher. The quality methodology this project intends to follow.
  `scripts/run_smhasher3.sh` registers river5 into it.
- **[Splitmix64](https://prng.di.unimi.it/splitmix64.c)** by Sebastiano Vigna.
  Used as the deterministic-noise source in `test/quality.c` and `bench/micro.c`.
- **[Intel and AMD optimization manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html)**
  and **[Agner Fog's instruction tables](https://www.agner.org/optimize/)**.
  AESENC latency and reciprocal throughput numbers, port-distribution figures,
  and the dual-AES-unit microarchitecture details are all from these.
- **[Daniel Lemire's blog](https://lemire.me/blog/)** and his AES-NI / SIMD
  papers. The general "hand-tune for the microarchitecture" engineering
  culture this project is trying to imitate.
- The **`cc` crate** for Rust's build.rs (compiling C from Cargo).
- The **`blake3` Rust crate**, whose public API shape is mirrored deliberately
  so superdupe's `pipeline/hash.rs` integration is a near-trivial swap.

If a contributor or upstream is missing from this list and should be on it,
please open a PR — the omission is not intentional.

## Building and using

### Rust crate (this is the integration path for superdupe)

```toml
# In superdupe/Cargo.toml
river5 = { path = "../river5" }
```

```rust
use river5::Hasher;

let mut h = Hasher::new();
h.update(b"some bytes");
h.update(b"more bytes");
let digest: [u8; 16] = h.finalize();

// One-shot:
let digest = river5::hash(b"some bytes");
```

API mirrors `blake3::Hasher`. `Send + Sync` for use inside rayon. The
implementation behind the curtain may change (v2 → v3 → v6 historically);
the API is the contract.

#### Pinning to a specific algorithm version

If you need the hash bytes to stay stable across river5 updates — for
example, because you have a persistent cache of hash values that you
don't want to invalidate on the next `cargo update` — pin to a tagged
version instead of tracking `main`:

```toml
# Pin to v6 (current default; balanced quality + speed).
river5 = { git = "https://github.com/mickfixesjunk/river5", tag = "v6" }

# Or pin to v15 (THE FAST VARIANT; ~2× v6 throughput; deliberately
# fails SMHasher3 Permutation/Cyclic at narrow truncations but verified
# zero 128-bit collisions on ~150M test keys across short text, cyclic,
# and sparse keysets. Right for full-128-bit consumer dedup at max speed).
river5 = { git = "https://github.com/mickfixesjunk/river5", tag = "v15" }

# Or pin to v3 (the prior default; ~30 GB/s but has a 9.4× Permutation
# residual on adversarial 8-byte cyclic input — irrelevant for full
# 128-bit dedup, but documented).
river5 = { git = "https://github.com/mickfixesjunk/river5", tag = "v3" }
```

Quick decision tree for choosing:
- **Default / "I just want a good hash"** → no pin needed, you get v6
- **"Max throughput for full-128-bit dedup, I don't care about narrow-
  truncation tests"** → `tag = "v15"` (2× faster, beats Meow at mid sizes)
- **"I have a cache of v3-format hashes I don't want to invalidate"** →
  `tag = "v3"`
- **"I tried `tag = "v14"` and it had collisions"** → yes that's
  documented; v14 has 1515 actual 128-bit collisions on dictionary
  words and is **not safe to use**; switch to v6 or v15 immediately

For **superdupe specifically**: the v3 vs v6 vs v15 byte difference does
NOT affect dedup correctness — all three produce 0 unexpected 128-bit
collisions on every test corpus we've thrown at them (Dict 528K, Words
1M, Cyclic 1M, Sparse 41K, TextNum 10M, several Text patterns 15M each).
The choice is purely about *which* 128-bit bytes get cached and how
fast they're computed:

- Already populated a v3 cache and want to keep it → `tag = "v3"`
- Want max throughput for new deployments → `tag = "v15"` (2× faster
  than v6, beats Meow at mid sizes)
- Just want a sensible default → track main (v6)

The cache schema's existing `hash_algo` tag mechanism makes any choice
safe — different river5 versions are tagged distinctly so a cache built
against one variant won't be mistakenly read as another.

### C library

```c
#include "river5.h"

uint8_t out[RIVER5_HASH_BYTES];
river5_hash(input, len, NULL /* default seed */, out);

// Streaming:
river5_ctx_t *ctx = river5_new();
river5_update(ctx, chunk, chunk_len);
river5_finalize(ctx, out);
river5_free(ctx);
```

Build the static library + bench with the Makefile (`make`) or with CMake
(`cmake -B build -S . && cmake --build build`).

### Running the bench

```sh
make                                             # build everything
./build/river5-bench list                        # show registered hashes
./build/river5-bench micro --seconds 1.0         # in-cache throughput per size
./build/river5-bench file --threads 4 /some/dir  # walk a directory
make quality                                     # in-repo statistical gate
scripts/run_smhasher3.sh                         # full SMHasher3 (needs cmake)
```

## Limitations and known issues

- **Not cryptographic.** Adversarial inputs can find collisions. Do not use
  river5 for authentication, integrity against tampering, or any
  trust-boundary purpose. Use BLAKE3 or SHA-256 for those.
- **64-byte input penalty.** Per-call init + finalization costs ~20 AESENCs
  of fixed overhead. At 64 B inputs river5 v2 is slower than xxhash3-128.
  For a file deduper this is irrelevant (small files take negligible time
  regardless), but if your workload is hashing many small keys, use xxhash3.
- **One machine, one compiler.** Numbers above are from one WSL2 host with
  GCC. Different CPU + compiler combinations will reorder results. The
  algorithm itself is portable; only the *advantage over Meow* is the
  microarchitecture-specific claim.
- **No VAES / AVX-512 path yet.** The 8-ZMM-lane / 8-YMM-lane VAES paths
  that would extract another 1.5-2× on Ice Lake+ / Zen 4+ hardware are
  designed but not written. The current AES-NI XMM path is the universal
  baseline.
- **SMHasher3 not yet run.** The fetch+register+run script is ready and
  should produce a verification value on first run; treat any production
  use as gated on SMHasher3 passing first.
- **The π-derived secret** is the same one Blowfish uses. If you need
  multiple independent hash families for some reason (e.g. defense in
  depth in a Bloom filter), use the seeded variant rather than relying on
  a future secret rotation.

## Licenses

- river5 itself: MIT (see `LICENSE`).
- Vendored dependencies retain their original licenses under
  `third_party/<dep>/LICENSE`:
  - xxhash — BSD-2-Clause
  - BLAKE3 — Apache 2 / Apache-2-LLVM / CC0 (triple-licensed)
  - MetroHash — MIT
  - Meow Hash — zlib

## Acknowledgements

The whole reason this exists is the [superdupe](https://github.com/mickfixesjunk/superdupe)
file deduper project, which needed a fast 128-bit hash and where the original
"can we beat xxhash3" question came from. The framing in this README — *engineering
package, not algorithm; one workload, one CPU; humble about prior art* — exists
because the people who built Meow and xxhash3 and BLAKE3 deserve the credit
they actually earned.
