use sha2::{Digest, Sha256};
use std::{env, fs, io, path::PathBuf};

fn main() {
    println!("cargo::rerun-if-env-changed=BETTERLEAKS_LIB_DIR");
    println!("cargo::rerun-if-env-changed=MACOSX_DEPLOYMENT_TARGET");
    println!("cargo::rerun-if-changed=targets.json");
    let target = env::var("TARGET").expect("Cargo must set TARGET");
    assert!(
        !target.ends_with("-linux-musl"),
        "musl targets are unsupported by the native artifact build"
    );
    let targets: Vec<serde_json::Value> = serde_json::from_str(include_str!("targets.json"))
        .expect("invalid built-in target catalog");
    let spec = targets
        .iter()
        .find(|spec| spec["target"].as_str() == Some(target.as_str()))
        .unwrap_or_else(|| {
            panic!("unsupported Betterleaks target {target}; see the native bindings support table")
        });
    let directory = env::var_os("BETTERLEAKS_LIB_DIR").map(PathBuf::from);
    let directory = directory.unwrap_or_else(|| {
        panic!("set BETTERLEAKS_LIB_DIR to the prebuilt archive's lib directory; see the betterleaks README")
    });
    let directory = directory
        .canonicalize()
        .expect("BETTERLEAKS_LIB_DIR must exist");
    let manifest_path = directory.join("betterleaks-native.json");
    let archive_path = directory.join("libbetterleaks.a");
    println!("cargo::rerun-if-changed={}", manifest_path.display());
    println!("cargo::rerun-if-changed={}", archive_path.display());

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(&manifest_path).expect("native artifact manifest is missing"),
    )
    .expect("invalid native artifact manifest");
    assert_eq!(
        manifest["target"].as_str(),
        Some(target.as_str()),
        "native target mismatch"
    );
    assert_eq!(
        manifest["abi_version"].as_u64(),
        Some(1),
        "native ABI mismatch"
    );
    assert_eq!(
        manifest["package_version"].as_str(),
        Some(env!("CARGO_PKG_VERSION")),
        "native artifact and Rust crate versions must match"
    );
    if let Some(minimum) = spec["minimum_macos_version"].as_str() {
        assert_eq!(
            manifest["minimum_macos_version"].as_str(),
            Some(minimum),
            "unexpected native deployment baseline"
        );
        if let Ok(deployment) = env::var("MACOSX_DEPLOYMENT_TARGET") {
            let major: u32 = deployment
                .split('.')
                .next()
                .unwrap_or("")
                .parse()
                .expect("invalid MACOSX_DEPLOYMENT_TARGET");
            assert!(
                major >= 12,
                "the native Go runtime requires macOS 12 or newer"
            );
        }
    }
    let mut archive = fs::File::open(&archive_path).expect("libbetterleaks.a is missing");
    let mut digest = Sha256::new();
    io::copy(&mut archive, &mut digest).expect("cannot read native archive");
    let checksum = format!("{:x}", digest.finalize());
    assert_eq!(
        manifest["archive_sha256"].as_str(),
        Some(checksum.as_str()),
        "native archive checksum mismatch"
    );

    println!("cargo::rustc-link-search=native={}", directory.display());
    println!("cargo::rustc-link-lib=static=betterleaks");
    for library in spec["libraries"].as_array().expect("target libraries") {
        println!(
            "cargo::rustc-link-lib={}",
            library.as_str().expect("library name")
        );
    }
}
