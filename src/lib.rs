//! river5 — 128-bit content hash for the superdupe deduper.
//!
//! API shaped to match the `blake3` crate so it slots into superdupe's
//! `ContentHasher` enum cleanly: `Hasher::new()`, `update(&[u8])`,
//! `finalize(self) -> [u8; 16]`. `Send + Sync` so it works inside
//! rayon parallel hashers.
//!
//! Stub stage: internally delegates to xxhash3-128 so outputs are real
//! and stable. The AES-NI core will replace the internals without
//! touching this API.

use std::ffi::{c_void, CStr};
use std::os::raw::{c_char, c_uchar};
use std::ptr::NonNull;

pub const OUTPUT_BYTES: usize = 16;
pub const SEED_BYTES: usize = 32;

#[repr(C)]
struct river5_ctx {
    _opaque: [u8; 0],
}

extern "C" {
    fn river5_hash(input: *const c_void, len: usize, seed: *const c_uchar, out: *mut c_uchar);
    fn river5_new() -> *mut river5_ctx;
    fn river5_new_seeded(seed: *const c_uchar) -> *mut river5_ctx;
    fn river5_update(ctx: *mut river5_ctx, data: *const c_void, len: usize);
    fn river5_finalize(ctx: *mut river5_ctx, out: *mut c_uchar);
    fn river5_free(ctx: *mut river5_ctx);
    fn river5_impl_name() -> *const c_char;

    fn river5_init_in(
        storage: *mut c_void,
        storage_size: usize,
        seed: *const c_uchar,
    ) -> *mut river5_ctx;
}

/* Mirror of include/river5.h's RIVER5_CTX_BYTES / RIVER5_CTX_ALIGN.
 * The static-assert on the C side guarantees every variant's actual
 * ctx size fits within this number. If a future variant grows beyond,
 * bump RIVER5_CTX_BYTES in both places (the C static_assert will
 * refuse to compile otherwise). */
const RIVER5_CTX_BYTES: usize = 1024;
const RIVER5_CTX_ALIGN: usize = 16;

/* Compile-time assertion that AlignedCtxStorage's repr(C, align(16))
 * matches RIVER5_CTX_ALIGN. If a future change to RIVER5_CTX_ALIGN
 * makes them diverge, this fails to compile. */
const _: () = assert!(
    std::mem::align_of::<AlignedCtxStorage>() >= RIVER5_CTX_ALIGN,
    "AlignedCtxStorage alignment must meet RIVER5_CTX_ALIGN"
);

/// Streaming 128-bit hasher.
pub struct Hasher {
    ctx: NonNull<river5_ctx>,
}

// The context is heap-allocated state owned exclusively by this struct.
// All FFI mutation goes through `&mut self`, so `&Hasher` cannot mutate it;
// safe to share across threads.
unsafe impl Send for Hasher {}
unsafe impl Sync for Hasher {}

impl Hasher {
    pub fn new() -> Self {
        let ctx = unsafe { river5_new() };
        Self {
            ctx: NonNull::new(ctx).expect("river5_new returned NULL"),
        }
    }

    pub fn new_seeded(seed: &[u8; SEED_BYTES]) -> Self {
        let ctx = unsafe { river5_new_seeded(seed.as_ptr()) };
        Self {
            ctx: NonNull::new(ctx).expect("river5_new_seeded returned NULL"),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        unsafe {
            river5_update(
                self.ctx.as_ptr(),
                data.as_ptr() as *const c_void,
                data.len(),
            );
        }
        self
    }

    pub fn finalize(mut self) -> [u8; OUTPUT_BYTES] {
        let mut out = [0u8; OUTPUT_BYTES];
        unsafe {
            river5_finalize(self.ctx.as_ptr(), out.as_mut_ptr());
        }
        // Drop runs after we return `out`, freeing the ctx.
        let _ = &mut self;
        out
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Hasher {
    fn drop(&mut self) {
        unsafe { river5_free(self.ctx.as_ptr()) };
    }
}

/// Stack-allocated streaming hasher — avoids the per-call heap alloc
/// that [`Hasher::new`] does.
///
/// On AES-NI-capable hosts this stores the hash state inline in the
/// struct (no heap traffic at construction). On hosts without AES-NI
/// (where `river5_init_in` is unsupported by the xxhash stub), `new`
/// falls back to the heap-allocating path via an internal [`Hasher`].
///
/// API mirrors [`Hasher`]: `new`, `update`, `finalize`. Output and
/// final hash bytes are identical to [`Hasher`] for the same input.
///
/// Right tool for hot paths that hash many short buffers — for example
/// a streaming format-aware fingerprinter that constructs one hasher
/// per file. For one-shot single-buffer hashing, prefer [`hash`] which
/// is even cheaper (no streaming state at all).
pub struct StackHasher {
    /// Inline ctx storage. `repr(C, align(16))` so the bytes are
    /// suitable for the C-side `river5_init_in` contract.
    ///
    /// NOTE: the ctx pointer is computed FRESH on every `update`/
    /// `finalize` call from `&mut self.storage` — never stored. This
    /// is what makes the struct safe to move after construction.
    /// (Earlier revisions stored a `NonNull<river5_ctx>` here, which
    /// captured an address inside `storage`; on struct move the
    /// captured pointer was left dangling and `update` crashed.)
    storage: AlignedCtxStorage,
    backing: Backing,
}

#[repr(C, align(16))]
struct AlignedCtxStorage {
    bytes: [u8; RIVER5_CTX_BYTES],
}

enum Backing {
    /// ctx lives inside `self.storage`; compute pointer from
    /// `self.storage.bytes.as_mut_ptr()` on each call. No free
    /// on Drop (storage owned by the struct).
    InPlace,
    /// Stub host fallback — heap-allocated ctx, must be freed
    /// on Drop. Pointer is stable across moves because the heap
    /// allocation doesn't move when the wrapper does.
    Fallback(NonNull<river5_ctx>),
}

unsafe impl Send for StackHasher {}
unsafe impl Sync for StackHasher {}

impl StackHasher {
    pub fn new() -> Self {
        Self::with_seed_opt(std::ptr::null())
    }

    pub fn new_seeded(seed: &[u8; SEED_BYTES]) -> Self {
        Self::with_seed_opt(seed.as_ptr())
    }

    fn with_seed_opt(seed_ptr: *const c_uchar) -> Self {
        let mut sh = Self {
            storage: AlignedCtxStorage {
                bytes: [0u8; RIVER5_CTX_BYTES],
            },
            // Placeholder; overwritten below once we know the backend.
            backing: Backing::InPlace,
        };
        // Safety: storage is repr(C, align(16)) — meets RIVER5_CTX_ALIGN
        // (16). Storage size is RIVER5_CTX_BYTES. `river5_init_in`
        // validates both and returns NULL on the stub variant.
        //
        // The returned pointer is INTENTIONALLY DISCARDED — we don't
        // store it because the struct may be moved before the next
        // call. Subsequent update/finalize compute a fresh pointer
        // from `&mut self.storage`. The C-side init writes plain
        // bytes (POD: __m128i lane[], counters, buf[]) so byte-level
        // relocation is safe.
        let ctx = unsafe {
            river5_init_in(
                sh.storage.bytes.as_mut_ptr() as *mut c_void,
                RIVER5_CTX_BYTES,
                seed_ptr,
            )
        };
        sh.backing = if ctx.is_null() {
            // Stub host — fall back to heap-allocated Hasher.
            let heap_ctx = unsafe {
                if seed_ptr.is_null() {
                    river5_new()
                } else {
                    river5_new_seeded(seed_ptr)
                }
            };
            Backing::Fallback(
                NonNull::new(heap_ctx)
                    .expect("river5_new fallback returned NULL"),
            )
        } else {
            // ctx == storage start; we don't capture the pointer
            // because the struct can move.
            Backing::InPlace
        };
        sh
    }

    /// Compute the live ctx pointer from `&mut self`. For `InPlace`
    /// this re-derives from `self.storage` every call (move-safe);
    /// for `Fallback` this returns the stable heap pointer.
    fn ctx_ptr(&mut self) -> *mut river5_ctx {
        match &self.backing {
            Backing::InPlace => self.storage.bytes.as_mut_ptr() as *mut river5_ctx,
            Backing::Fallback(p) => p.as_ptr(),
        }
    }

    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        let ctx = self.ctx_ptr();
        unsafe {
            river5_update(
                ctx,
                data.as_ptr() as *const c_void,
                data.len(),
            );
        }
        self
    }

    pub fn finalize(mut self) -> [u8; OUTPUT_BYTES] {
        let ctx = self.ctx_ptr();
        let mut out = [0u8; OUTPUT_BYTES];
        unsafe {
            river5_finalize(ctx, out.as_mut_ptr());
        }
        let _ = &mut self;
        out
    }
}

impl Default for StackHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for StackHasher {
    fn drop(&mut self) {
        // Only the heap-allocated fallback needs an explicit free.
        // The in-place variant points into `self.storage` which is
        // freed when the struct itself is dropped.
        if let Backing::Fallback(p) = self.backing {
            unsafe { river5_free(p.as_ptr()) };
        }
    }
}

/// One-shot hash.
pub fn hash(input: &[u8]) -> [u8; OUTPUT_BYTES] {
    let mut out = [0u8; OUTPUT_BYTES];
    unsafe {
        river5_hash(
            input.as_ptr() as *const c_void,
            input.len(),
            std::ptr::null(),
            out.as_mut_ptr(),
        );
    }
    out
}

/// One-shot hash with a 32-byte seed.
pub fn hash_seeded(input: &[u8], seed: &[u8; SEED_BYTES]) -> [u8; OUTPUT_BYTES] {
    let mut out = [0u8; OUTPUT_BYTES];
    unsafe {
        river5_hash(
            input.as_ptr() as *const c_void,
            input.len(),
            seed.as_ptr(),
            out.as_mut_ptr(),
        );
    }
    out
}

/// Implementation tag, useful in benchmark output.
/// Returns `"river5-stub-xxh3"` today; will change once AES-NI lands.
pub fn impl_name() -> &'static str {
    unsafe { CStr::from_ptr(river5_impl_name()) }
        .to_str()
        .unwrap_or("river5-unknown")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_shot_is_stable() {
        let a = hash(b"hello");
        let b = hash(b"hello");
        assert_eq!(a, b);
    }

    #[test]
    fn empty_input_hashes() {
        let h = hash(b"");
        // Should not be all-zero — that would be a real bug.
        assert_ne!(h, [0u8; OUTPUT_BYTES]);
    }

    #[test]
    fn streaming_matches_one_shot() {
        let data = b"the quick brown fox jumps over the lazy dog";
        let one = hash(data);

        let mut h = Hasher::new();
        h.update(&data[..10]);
        h.update(&data[10..25]);
        h.update(&data[25..]);
        let streamed = h.finalize();

        assert_eq!(one, streamed);
    }

    #[test]
    fn different_inputs_differ() {
        assert_ne!(hash(b"foo"), hash(b"bar"));
    }

    #[test]
    fn seeded_differs_from_default() {
        let seed = [0x42u8; SEED_BYTES];
        assert_ne!(hash(b"foo"), hash_seeded(b"foo", &seed));
    }

    #[test]
    fn stack_hasher_survives_move() {
        // Regression test for the self-referential-struct bug:
        // a StackHasher constructed inside one function MUST work
        // correctly after being moved to the caller's stack frame.
        // The original implementation stored a NonNull<river5_ctx>
        // captured at construction time; that pointer was left
        // dangling after the struct moved, and update() crashed
        // with ACCESS_VIOLATION on Windows / segfault on Linux.
        fn make() -> StackHasher {
            StackHasher::new()
        }
        let mut h = make();
        h.update(b"the quick brown fox");
        h.update(b" jumps over the lazy dog");
        let out = h.finalize();
        assert_eq!(out, hash(b"the quick brown fox jumps over the lazy dog"));
    }

    #[test]
    fn stack_hasher_survives_multi_move() {
        // Twice-moved StackHasher. Even more pointer dangling
        // opportunities.
        fn outer() -> StackHasher {
            inner()
        }
        fn inner() -> StackHasher {
            let mut h = StackHasher::new();
            h.update(b"first chunk");  // partial update before move
            h
        }
        let mut h = outer();
        h.update(b" + second chunk");
        let out = h.finalize();
        let expected = hash(b"first chunk + second chunk");
        assert_eq!(out, expected);
    }

    #[test]
    fn stack_hasher_in_vec_round_trip() {
        // Storing StackHasher in a Vec forces moves on push/pop and
        // potentially on reallocation. Verify everything still works.
        let mut v: Vec<StackHasher> = Vec::new();
        for _ in 0..16 {
            v.push(StackHasher::new());
        }
        for h in v.iter_mut() {
            h.update(b"round-tripped through Vec");
        }
        let outs: Vec<[u8; OUTPUT_BYTES]> =
            v.into_iter().map(|h| h.finalize()).collect();
        let expected = hash(b"round-tripped through Vec");
        for o in &outs {
            assert_eq!(*o, expected);
        }
    }

    #[test]
    fn stack_hasher_matches_hasher() {
        let data = b"the quick brown fox jumps over the lazy dog";

        let heap_out = {
            let mut h = Hasher::new();
            h.update(&data[..10]);
            h.update(&data[10..25]);
            h.update(&data[25..]);
            h.finalize()
        };

        let stack_out = {
            let mut h = StackHasher::new();
            h.update(&data[..10]);
            h.update(&data[10..25]);
            h.update(&data[25..]);
            h.finalize()
        };

        assert_eq!(heap_out, stack_out,
            "StackHasher and Hasher must produce identical bytes for the same input");
    }

    #[test]
    fn stack_hasher_one_shot_matches() {
        // Single-buffer update via StackHasher must match river5::hash().
        let data = b"some bytes for the stack hasher";
        let one = hash(data);
        let stacked = {
            let mut h = StackHasher::new();
            h.update(data);
            h.finalize()
        };
        assert_eq!(one, stacked);
    }

    #[test]
    fn stack_hasher_seeded() {
        let seed = [0xA5u8; SEED_BYTES];
        let data = b"seeded test input";

        let heap_out = {
            let mut h = Hasher::new_seeded(&seed);
            h.update(data);
            h.finalize()
        };
        let stack_out = {
            let mut h = StackHasher::new_seeded(&seed);
            h.update(data);
            h.finalize()
        };
        assert_eq!(heap_out, stack_out);
        assert_ne!(heap_out, hash(data),
            "seeded output should differ from unseeded");
    }

    #[test]
    fn stack_hasher_streaming_random_chunks_matches_one_shot() {
        // Mirror the existing streaming_random_chunking_matches_one_shot
        // test but with StackHasher to ensure split-buffer streaming
        // also matches.
        let data: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
        let one = hash(&data);

        let chunk_sizes = [1usize, 3, 7, 16, 31, 64, 127, 256, 1023, 4096];
        for &chunk in &chunk_sizes {
            let mut h = StackHasher::new();
            for slice in data.chunks(chunk) {
                h.update(slice);
            }
            let streamed = h.finalize();
            assert_eq!(one, streamed,
                "StackHasher with chunk_size={chunk} must match one-shot");
        }
    }

    #[test]
    fn impl_name_is_known() {
        // On any x86_64 dev machine from the last decade this should
        // resolve to AES-NI. If you see "stub-xxh3" here, your CPU
        // lacks AES-NI or CPUID dispatch is broken.
        let name = impl_name();
        assert!(
            name == "river5-aesni-v15"
                || name == "river5-aesni-v6"
                || name == "river5-aesni-v3"
                || name == "river5-aesni-v2"
                || name == "river5-aesni-v1"
                || name == "river5-stub-xxh3",
            "unexpected impl name: {name}"
        );
    }

    #[test]
    fn block_boundaries_are_stable() {
        // The AES-NI core processes 128-byte blocks. Sizes around the
        // boundary (127, 128, 129) exercise the tail-padding code path.
        for n in [
            0usize, 1, 15, 16, 17, 63, 64, 127, 128, 129, 255, 256, 257, 1000, 4096,
        ] {
            let data: Vec<u8> = (0..n).map(|i| (i as u8).wrapping_mul(31)).collect();
            let a = hash(&data);
            let b = hash(&data);
            assert_eq!(a, b, "instability at len={n}");
        }
    }

    #[test]
    fn streaming_one_byte_at_a_time_matches_one_shot() {
        // Extreme chunking — every byte buffered separately.
        let data: Vec<u8> = (0..513u16).map(|i| i as u8).collect();
        let one = hash(&data);

        let mut h = Hasher::new();
        for byte in &data {
            h.update(std::slice::from_ref(byte));
        }
        assert_eq!(one, h.finalize());
    }

    #[test]
    fn streaming_random_chunking_matches_one_shot() {
        let data: Vec<u8> = (0..10_000u32)
            .map(|i| ((i * 2654435761) >> 8) as u8)
            .collect();
        let one = hash(&data);

        // Pseudorandom chunk sizes covering < block, == block, > block.
        let chunks = [37usize, 128, 1, 256, 64, 1000, 2, 512, 7777, 53, 173];
        let mut h = Hasher::new();
        let mut off = 0;
        for &sz in chunks.iter().cycle() {
            if off >= data.len() {
                break;
            }
            let end = (off + sz).min(data.len());
            h.update(&data[off..end]);
            off = end;
        }
        assert_eq!(one, h.finalize());
    }

    #[test]
    fn long_input_is_stable() {
        // 1 MiB of data — many block iterations.
        let data = vec![0xA5u8; 1024 * 1024];
        let a = hash(&data);
        let b = hash(&data);
        assert_eq!(a, b);

        // Streamed in 64K chunks should match one-shot.
        let mut h = Hasher::new();
        for chunk in data.chunks(64 * 1024) {
            h.update(chunk);
        }
        assert_eq!(a, h.finalize());
    }

    #[test]
    fn distinct_seeds_distinct_outputs() {
        let s1 = [0x11u8; SEED_BYTES];
        let s2 = [0x22u8; SEED_BYTES];
        assert_ne!(
            hash_seeded(b"identical input", &s1),
            hash_seeded(b"identical input", &s2),
        );
    }
}
