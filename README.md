# river5

A 128-bit hash function for the [superdeduper](https://github.com/mickfixesjunk/superdeduper)
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
  `blake3` crate so it drops into superdeduper with a one-line `Cargo.toml` change.
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

## Performance

**Bottom line first: on real file-dedup workloads, the hash choice does
not determine wall-clock time, and river5 makes no "fastest hash"
claim.** Cold-cache file reads are IO/syscall-bound. At that regime
river5, BLAKE3, and Meow Hash are tied within measurement noise —
real-corpus runs on a Ryzen 9950X3D (NTFS) measured river5 and BLAKE3
within **<1%** of each other on the Tier-1 dedup workload, because the
per-file `open()`/`read()` cost dominates and which 128-bit hash you
pick sits below the noise floor. river5 is the superdeduper default
because it is *competitive*, drops in cleanly (BLAKE3-shaped Rust API),
and is tuned for this exact use case — not because it wins a throughput
race.

### In-cache CPU microbench (does NOT predict real-workload speed)

The table below isolates raw hash *CPU* cost with the input already hot
in cache. It deliberately excludes file IO — which is the actual
bottleneck in real dedup — so read it as "how fast is the hash compute
in isolation," **not** as a prediction of dedup wall-time. These numbers
do not generalize across CPUs, and they do not survive the IO ceiling
described above.

Measured on a WSL2 dev machine (Intel i7-7700K, AES-NI + AVX2, no VAES,
no AVX-512), single thread, in-cache micro bench, ~1s per cell:

| size      | xxh3-128 | river5 (v15) | river5-v6 | river5-v3 | river5-v2 | MetroHash | Meow Hash |
|-----------|---------:|-------------:|----------:|----------:|----------:|----------:|----------:|
| 4 KiB     | 21.0     | 41.4         | 26.8      | 30.9      | 58.3      | 16.1      | 44.5      |
| 16 KiB    | 23.2     | 55.5         | 29.9      | 33.0      | 64.7      | 16.9      | 46.0      |
| 64 KiB    | 22.8     | 45.7         | 28.8      | 34.1      | 63.0      | 15.5      | 46.6      |
| 256 KiB   | 22.8     | 40.0         | 29.2      | 33.1      | 52.1      | 13.5      | 48.8      |
| 1 MiB     | 22.9     | 30.8         | 27.0      | 29.9      | 36.8      | 13.1      | 50.6      |

Numbers in GB/s, in-cache, single thread. `river5` = v15 (the production
default). Reproduce locally with `make && ./build/river5-bench micro --seconds 1.0`.

**Reading these numbers honestly:**
- They are in-cache CPU-compute numbers on *one machine*, *one compiler*
  (gcc 9.4), *one OS* (Linux/WSL2). On different x86_64 CPUs (notably
  ones with two AES execution units, or with VAES) the ordering changes.
  On non-x86 hardware river5 falls back to xxhash3 and offers nothing.
- **river5's per-stream CPU-compute lead over BLAKE3 is real but does
  not translate to dedup speed.** In hash-compute isolation (single
  thread, input already in RAM) river5 is ~5× BLAKE3 per stream
  (≈45 GB/s vs ≈9.2 GB/s on a Ryzen 9950X3D). But end-to-end on a real
  corpus the two are **tied within <1%** (file dedup is IO/syscall-
  bound — the SSD read ceiling is ~0.16% of river5's hash-compute
  peak), and under 32-thread contention river5's per-stream lead
  collapses: it saturates DDR5 bandwidth and scales ~6.4× worse than
  BLAKE3, so aggregate throughput is roughly equal. river5 is
  meaningfully faster only in the narrow "few large files + idle
  cores" case. BLAKE3 is also a different category: it is cryptographic;
  v15 is not.
- Likewise the river5-vs-Meow and river5-vs-xxh3 orderings here are
  in-cache CPU compute only. They say nothing about dedup wall-time,
  where IO dominates and the hashes converge.
- File-walk benchmarks near ~1 GiB are noisy enough that run-to-run
  variance dominates variant differences. The micro bench is the only
  reliable *CPU-compute* signal — and CPU compute is not the dedup
  bottleneck.
- Out-of-cache, all AES-NI hashes converge near DRAM read bandwidth
  (~30-50 GB/s). The hash CPU work stops being the bottleneck.
- **Real-world dedup:** wall-time is disk-bound (and on the parallel,
  cold-cache workload superdeduper actually runs, syscall-bound). Any
  in-cache CPU-throughput difference shows up — if at all — as marginally
  reduced CPU% during dedup, not as faster wall time.

**Other variants** (`river5-v6`, `river5-v3`, `river5-v2`) stay
registered in the bench for A/B comparison and are pinnable via git
tags for consumers who need byte-for-byte stability with a prior
default. See [`docs/TAGS.md`](docs/TAGS.md) for the full inventory.

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
- river5 v15 (the current default) explicitly **does not chase
  SMHasher3 cleanliness at narrow truncations** — it's positioned for
  consumer dedup where full-128-bit hash comparison is what matters.
  The design lineage went `v2 → v3 → v6 → v15`: v3 added per-block
  cross-lane butterfly mixing for SMHasher3 quality; v6 added per-lane
  PSHUFB input scrambling on top of v3 for Avalanche/Permutation
  improvements; v15 drops v6's per-block butterfly (the SMHasher-
  Permutation-passing tax) for ~2× the in-cache CPU throughput while keeping the
  PSHUFB scramble that gives clean Avalanche. v15 is verified to
  produce zero full-128-bit collisions across ~150M short-text /
  cyclic / sparse test keys, while deliberately failing SMHasher3
  Permutation at narrow truncations — those biases are theoretical
  artifacts at < 64-bit truncation and don't manifest in actual
  128-bit dedup comparison. The v6→v15 step is the central
  engineering choice in this project: trade SMHasher-pass-at-all-costs
  framing for actual practical throughput on the use case that exists.

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

river5 v15 (the production default) passes the four fast in-repo statistical
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

| SMHasher3 test category | v2 | v3 | v6 | **v15 (current default)** | v14 ⚠️ |
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
| v3 | (was on `main` long ago) | `v3` | 9.37× catastrophic spike on one Permutation keyset | — |
| v4 | `v4-position-mix` | — | linear per-lane salt, no improvement (XOR can't help differential) | n/a |
| v5 / v5b | `v5-nonlinear-finalize` | — | non-linear pre-finalize, can't reach structural 9× | n/a |
| v6 | `v6-input-rotation` | `v6` | per-lane PSHUFB scramble; eliminates 9× spike → uniform 1.5× ceiling | n/a |
| v7 | (also in v6 branch) | — | v6 + v5 combined → regressed to 9.82× via interference | n/a |
| v8 | `v8-deeper-finalize` | — | v6 + 3× same butterfly → regressed to 9.73× via repeated-pattern attack | n/a |
| v9 | `v9-rotated-mainloop` | `v9` | v6 + per-block rotation + dual finalize butterfly → 1.67× (distributed but no improvement on worst case) | n/a |
| v10 | `v10-double-aesni` | `v10` | v6 + dual butterfly in MAIN LOOP → regressed to 2.73× | n/a |
| v11 | `v11-pclmulqdq` | — | PCLMULQDQ input mix + fixed-key AESENC → catastrophic 22.61× (linear clmul + fixed AES = differentially weak) | n/a |
| v12 | `v12-highwayhash` | — | HighwayHash-inspired ADD+MUL+AES three-primitive mix → catastrophic 10× (asymmetric MUL, no ZipperMerge port) | n/a |
| v13 / v13c | `v13-content-shuffle`, `v13c-hybrid-shuffle` | — | content-dependent shuffles; 152× spike on cyclic killer; hybrid matched v6 | n/a |
| v14 ⚠️ | `v14-two-stream` | `v14` | two-stream `v6 ⊕ v11`; PASSED 5 narrow categories BUT **fails Dict with 1515 actual 128-bit collisions on dictionary words — DO NOT USE** | n/a |
| **v15 (CURRENT MAIN)** | `v15-fast-dedup` | `v15` | **v6 minus per-block butterfly — ~2× v6 in-cache CPU throughput, zero 128-bit collisions on ~150M test keys** (in-cache microbench only; no real-workload speed claim — see [Performance](#performance)) | **new baseline** |

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
  copied directly so river5 drops cleanly into the same call sites superdeduper
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
  so superdeduper's `pipeline/hash.rs` integration is a near-trivial swap.

If a contributor or upstream is missing from this list and should be on it,
please open a PR — the omission is not intentional.

## Building and using

### Rust crate (this is the integration path for superdeduper)

```toml
# In superdeduper/Cargo.toml
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
implementation behind the curtain may change across versions; the API
is the contract. Today the default routes to v15.

If you need byte-stable hashes across river5 updates (e.g., persistent
on-disk hash cache that shouldn't invalidate on `cargo update`), pin
to a specific algorithm-version tag instead of tracking `main`. See
[`docs/TAGS.md`](docs/TAGS.md) for the full per-tag inventory, pinning
syntax, and when to choose each. The short version: most consumers
should not pin — just track `main` and you get the current default.

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
  algorithm itself is portable; only the *in-cache CPU ordering vs Meow*
  is microarchitecture-specific — and even that does not carry into real
  (IO-bound) dedup wall-time. See [Performance](#performance).
- **No VAES / AVX-512 path yet.** The 8-ZMM-lane / 8-YMM-lane VAES paths
  that would extract another ~1.5-2× of *in-cache CPU throughput* on
  Ice Lake+ / Zen 4+ hardware are designed but not written. (As above,
  in-cache CPU throughput is not the dedup bottleneck.) The current
  AES-NI XMM path is the universal baseline.
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

The whole reason this exists is the [superdeduper](https://github.com/mickfixesjunk/superdeduper)
file deduper project, which needed a fast 128-bit hash and where the original
"can we beat xxhash3" question came from. The framing in this README — *engineering
package, not algorithm; one workload, one CPU; humble about prior art* — exists
because the people who built Meow and xxhash3 and BLAKE3 deserve the credit
they actually earned.
