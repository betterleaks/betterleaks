//! Links the Betterleaks native engine, in one of two modes:
//!
//! 1. Bundled (default): compile the Go engine in this repository into a
//!    C archive with the host Go toolchain, like other `-sys` crates build a
//!    vendored C library. Requires Go 1.26+ and a C compiler; `go build`'s
//!    cache makes rebuilds cheap.
//! 2. Prebuilt: set `BETTERLEAKS_LIB_DIR` to a directory containing
//!    `libbetterleaks.a` built from the same crate version. No Go needed.

use std::{env, path::PathBuf, process::Command};

fn main() {
    println!("cargo::rerun-if-env-changed=BETTERLEAKS_LIB_DIR");
    println!("cargo::rerun-if-env-changed=BETTERLEAKS_SRC_DIR");

    let target_os = env::var("CARGO_CFG_TARGET_OS").expect("Cargo must set CARGO_CFG_TARGET_OS");
    let target_env = env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();
    if target_os == "windows" {
        // Windows links betterleaks.dll via raw-dylib declarations in the
        // source; there is nothing to build or locate at compile time. The DLL
        // must be beside the executable (or on the DLL search path) at runtime.
        return;
    }
    if target_os == "linux" && target_env == "musl" {
        panic!(
            "musl is unsupported: Go C archives can crash during startup; \
             see https://github.com/golang/go/issues/13492"
        );
    }

    let lib_dir = match env::var_os("BETTERLEAKS_LIB_DIR") {
        Some(dir) => PathBuf::from(dir)
            .canonicalize()
            .expect("BETTERLEAKS_LIB_DIR must exist"),
        None => build_archive(),
    };
    let archive = lib_dir.join("libbetterleaks.a");
    assert!(
        archive.is_file(),
        "libbetterleaks.a not found in {}",
        lib_dir.display()
    );

    // A prebuilt archive may be replaced without changing BETTERLEAKS_LIB_DIR.
    // Rerun so Cargo relinks consumers against the updated engine.
    println!("cargo::rerun-if-changed={}", archive.display());

    println!("cargo::rustc-link-search=native={}", lib_dir.display());
    println!("cargo::rustc-link-lib=static=betterleaks");
    match target_os.as_str() {
        "macos" => {
            println!("cargo::rustc-link-lib=framework=CoreFoundation");
            println!("cargo::rustc-link-lib=framework=Security");
            println!("cargo::rustc-link-lib=dylib=resolv");
        }
        "linux" => {
            for library in ["pthread", "dl", "m", "resolv"] {
                println!("cargo::rustc-link-lib={library}");
            }
        }
        other => panic!("unsupported Betterleaks target OS {other}; see bindings/README.md"),
    }
}

/// Compile `bindings/c` into a C archive in OUT_DIR using the Go toolchain.
fn build_archive() -> PathBuf {
    // Cargo cannot see the Go source graph, so always rerun and let Go's own
    // build cache decide whether anything must be recompiled.
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo must set OUT_DIR"));
    println!(
        "cargo::rerun-if-changed={}",
        out_dir.join("rebuild-sentinel-never-created").display()
    );

    // The Go module root: overridable for consumers that vendor this crate
    // outside the Betterleaks repository checkout.
    let root = match env::var_os("BETTERLEAKS_SRC_DIR") {
        Some(dir) => PathBuf::from(dir),
        None => PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
            .join("../../..")
            .canonicalize()
            .expect("cannot resolve the repository root"),
    };
    assert!(
        root.join("bindings/c/betterleaks.h").is_file(),
        "{} is not a Betterleaks checkout; set BETTERLEAKS_SRC_DIR or BETTERLEAKS_LIB_DIR",
        root.display()
    );

    // Follow Cargo's target, not the host: `cargo build --target ...` must not
    // produce a host-architecture archive. Cross builds need a C compiler for
    // the target, taken from the `cc` crate's conventional variables.
    let goos = match env::var("CARGO_CFG_TARGET_OS").unwrap().as_str() {
        "macos" => "darwin",
        "linux" => "linux",
        other => panic!("unsupported Betterleaks target OS {other}"),
    };
    let goarch = match env::var("CARGO_CFG_TARGET_ARCH").unwrap().as_str() {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => panic!("unsupported Betterleaks target architecture {other}"),
    };
    let triple = env::var("TARGET").unwrap();
    let target_cc =
        env::var(format!("CC_{}", triple.replace('-', "_"))).or_else(|_| env::var("TARGET_CC"));

    let archive = out_dir.join("libbetterleaks.a");
    let mut command = Command::new("go");
    command
        .current_dir(&root)
        .env("CGO_ENABLED", "1")
        .env("GOOS", goos)
        .env("GOARCH", goarch)
        .args(["build", "-mod=readonly", "-trimpath"]);
    if let Ok(cc) = target_cc {
        command.env("CC", cc);
    }
    let status = command
        .args(["-tags", "betterleaks_ffi", "-buildmode=c-archive"])
        .arg("-o")
        .arg(&archive)
        .arg("./bindings/c")
        .status()
        .expect(
            "cannot run `go`: install Go 1.26+ for the bundled build, \
             or set BETTERLEAKS_LIB_DIR to a prebuilt archive",
        );
    assert!(status.success(), "go build -buildmode=c-archive failed");
    out_dir
}
