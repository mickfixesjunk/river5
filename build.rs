use std::path::PathBuf;

fn main() {
    let root: PathBuf = std::env::var_os("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR")
        .into();

    // Only compile the AES-NI sources on archs whose intrinsics
    // (__m128i / _mm_aesenc_si128) actually exist. aarch64 + others
    // fall back to the scalar stub path that csrc/river5.c already
    // routes to when cpu_has_aesni() returns 0.
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let has_aesni_sources = arch == "x86_64" || arch == "x86";

    println!("cargo:rustc-check-cfg=cfg(river5_has_aesni)");
    if has_aesni_sources {
        println!("cargo:rustc-cfg=river5_has_aesni");
    }

    let mut build = cc::Build::new();
    build
        .file(root.join("csrc").join("river5.c"))
        .file(root.join("csrc").join("river5_stub.c"))
        .file(root.join("third_party").join("xxhash").join("xxhash.c"))
        .include(root.join("include"))
        .include(root.join("csrc"))
        .include(root.join("third_party").join("xxhash"))
        .warnings(true)
        .opt_level(3);

    if has_aesni_sources {
        build
            .define("RIVER5_HAS_AESNI", None)
            .file(root.join("csrc").join("river5_aesni.c"))
            .file(root.join("csrc").join("river5_aesni_v2.c"))
            .file(root.join("csrc").join("river5_aesni_v3.c"))
            .file(root.join("csrc").join("river5_aesni_v6.c"))
            .file(root.join("csrc").join("river5_aesni_v15.c"));
    }

    // river5_aesni.c uses GCC/Clang `target` attributes on every
    // function, so we don't need -maes globally. xxhash is happy
    // with default flags.
    //
    // C11 is required everywhere because each `*_aesni*.c` ends in a
    // `_Static_assert(sizeof(struct river5_ctx) <= RIVER5_CTX_BYTES, …)`
    // that guards the StackHasher ABI. MSVC defaults to C89 and
    // rejects `_Static_assert` without `/std:c11`.
    if cfg!(target_env = "msvc") {
        build.flag_if_supported("/std:c11");
    } else {
        build.flag_if_supported("-std=c11");
        build.flag_if_supported("-fno-strict-aliasing");
    }

    build.compile("river5");

    for f in [
        "csrc/river5.c",
        "csrc/river5_stub.c",
        "csrc/river5_aesni.c",
        "csrc/river5_aesni_v2.c",
        "csrc/river5_aesni_v3.c",
        "csrc/river5_aesni_v6.c",
        "csrc/river5_aesni_v15.c",
        "csrc/river5_internal.h",
        "include/river5.h",
        "third_party/xxhash/xxhash.c",
        "third_party/xxhash/xxhash.h",
        "build.rs",
    ] {
        println!("cargo:rerun-if-changed={f}");
    }
}
