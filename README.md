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

Measured on a WSL2 dev machine (AVX2 + AES-NI, no VAES, no AVX-512), single
thread, in-cache micro bench, 1s per cell:

| size      | xxh3-128 | river5 v1 | **river5 v2** | MetroHash | Meow Hash |
|-----------|---------:|-----------:|---------------:|----------:|----------:|
| 64 B      | **6.0**  | 1.9        | 1.5            | 2.2       | 3.8       |
| 256 B     | 7.2      | 11.9       | **16.2**       | 5.3       | 11.3      |
| 1 KiB     | 12.4     | 28.7       | **35.4**       | 8.3       | 24.2      |
| 4 KiB     | 15.6     | 40.7       | **50.6**       | 9.3       | 42.5      |
| 16 KiB    | 15.2     | 46.7       | **58.0**       | 10.9      | 38.9      |
| 64 KiB    | 14.8     | 43.3       | **57.0**       | 8.4       | 34.4      |
| 256 KiB   | 17.2     | 41.7       | **48.4**       | 11.3      | 27.7      |
| 1 MiB     | 10.4     | 32.5       | **33.9**       | 8.7       | 28.9      |

Numbers in GB/s. Reproduce locally with `make && ./build/river5-bench micro --seconds 1.0`.

**Things to know about these numbers:**
- river5 v2 is fastest at every size from 256 B through 1 MiB, but loses
  significantly at 64 B due to fixed init/finalization overhead.
- These are *one machine*, *one compiler* (gcc), *one OS* (Linux/WSL2).
  On different x86_64 CPUs (notably ones with two AES execution units, or
  with VAES) the ordering can change. On non-x86 hardware river5 falls back
  to xxhash3 and offers nothing.
- File-walk benchmarks at this corpus size (~1 GiB) are noisy enough that
  run-to-run variance dominates the v1/v2/Meow differences. Micro is the
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
  to defend against adversaries who attack one lane in isolation. **river5 v2
  defers all cross-lane mixing to the 4-round tree finalization.** That removes
  work from the hot loop. The hash is weaker against adversarial collision
  attacks on a single lane — but a file deduper is hashing its own files, so
  that risk doesn't apply. The result is faster bytes-per-cycle for non-adversarial
  inputs. This is a positioning choice, not an algorithmic invention.

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

river5 v2 passes the four fast in-repo statistical checks (`make quality`):
- **Avalanche:** mean Hamming distance 64.02 / 128 over 1024 random 64-byte
  keys with single-bit input flips. Zero weak input bits (every input bit
  position causes 56-72 output bits to flip on average).
- **Length sensitivity:** zero collisions across all 1024 distinct lengths
  of zero-byte input from 0 to 1023.
- **Sparse keys:** zero collisions hashing the first 1 000 000 consecutive
  little-endian 32-bit integers as 4-byte inputs.
- **Output-bit balance:** every output bit is set between 48.7% and 51.2% of
  the time over 10 000 random inputs.

These checks are **not** a substitute for SMHasher3. The full SMHasher3
battery has not been run yet — `scripts/run_smhasher3.sh` is ready and
handles fetching, registration, building, and running; it needs CMake on the
host (which the WSL2 dev environment doesn't have). **Until SMHasher3 passes,
do not deploy river5 in any role that matters.** v2 is currently
"plausible-looking" by the easy checks; SMHasher3 is what would make it
"actually safe to ship."

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
implementation behind the curtain may change (v2 today, v3 later); the API
is the contract.

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
