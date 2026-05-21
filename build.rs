use std::path::PathBuf;

fn main() {
    let root: PathBuf = std::env::var_os("CARGO_MANIFEST_DIR")
        .expect("CARGO_MANIFEST_DIR")
        .into();

    let mut build = cc::Build::new();
    build
        .file(root.join("csrc").join("river5.c"))
        .file(root.join("csrc").join("river5_stub.c"))
        .file(root.join("csrc").join("river5_aesni.c"))
        .file(root.join("csrc").join("river5_aesni_v2.c"))
        .file(root.join("csrc").join("river5_aesni_v3.c"))
        .file(root.join("csrc").join("river5_aesni_v6.c"))
        .file(root.join("csrc").join("river5_aesni_v15.c"))
        .file(root.join("csrc").join("river5_aesni_v15p.c"))
        .file(root.join("third_party").join("xxhash").join("xxhash.c"))
        .include(root.join("include"))
        .include(root.join("csrc"))
        .include(root.join("third_party").join("xxhash"))
        .warnings(true)
        .opt_level(3);

    // river5_aesni.c uses GCC/Clang `target` attributes on every
    // function, so we don't need -maes globally. xxhash is happy
    // with default flags.
    if !cfg!(target_env = "msvc") {
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
        "csrc/river5_aesni_v15p.c",
        "csrc/river5_internal.h",
        "include/river5.h",
        "third_party/xxhash/xxhash.c",
        "third_party/xxhash/xxhash.h",
        "build.rs",
    ] {
        println!("cargo:rerun-if-changed={f}");
    }
}
