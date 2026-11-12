# Betterleaks for Rust (experimental)

Safe Rust bindings to the Betterleaks Go engine, statically linked into your
binary on **macOS and glibc Linux (x86-64 and ARM64)**. On **Windows (MSVC)**
the engine is `betterleaks.dll` instead: the crate builds with no native
inputs at all, and the DLL must sit beside the executable at runtime (see
`bindings/README.md`). Musl is unsupported because of a Go C archive startup
limitation (golang/go#13492). The crate has not been published to crates.io.

Add a local dependency and build. With Go 1.26+ and a C compiler installed,
`cargo build` compiles the Go engine itself — no other setup:

```toml
[dependencies]
betterleaks = { path = "/path/to/betterleaks/bindings/rust" }
```

Without a Go toolchain, point Cargo at a prebuilt archive instead (see
`bindings/README.md` for producing one):

```sh
export BETTERLEAKS_LIB_DIR=/path/to/native/lib
cargo build
```

After linking, the application embeds the engine, the default rules, and the Go
runtime; nothing else is needed at runtime.

```rust
use betterleaks::Scanner;
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Scanner::builder().workers(4).build()?;
    let content = std::fs::read_to_string("config.env")?;
    let attributes = BTreeMap::from([("path".into(), "config.env".into())]);
    let result = scanner.scan_with_attributes(&content, &attributes)?;
    for finding in result.findings {
        println!("{} at line {}", finding.rule_id, finding.location.start_line);
    }
    Ok(())
}
```

Use `scan_str` when no source metadata is needed. `Scanner` is `Send + Sync` and
can be shared using `Arc`; its worker limit applies across all calls. Results
own their data and outlive the scanner. Dropping the scanner and temporary
native result buffers releases their native resources automatically.

Builder options include custom TOML, its origin path, workers, decoding depth,
maximum input bytes, and maximum findings. Defaults are the embedded rules,
standard Go regex engine, no decoding, 8 MiB inputs, and 10,000 findings. Both
source prefilters and finding filters are honored. Configuration errors fail at
construction. Scan errors and exceeded limits return `Err`, without partial
findings. Match values can contain secrets; they are omitted from `Match`'s
`Debug` representation, but other metadata is not automatically sanitized.

This is a synchronous detection API. Provider validation, filesystem traversal,
streaming, and cancellation are not exposed. Input is UTF-8 text, including NULs;
JSON result text follows Go's UTF-8 conversion semantics. Lines and byte columns
are one-based, with zero for missing coordinates. Finding order is unspecified.
The Go runtime is embedded in the process; fatal native failures can terminate
the application. Updating the static engine requires relinking the application.

The repository's `examples/rust` is a standalone Cargo consumer:

```sh
cargo run --manifest-path examples/rust/Cargo.toml
cargo test --manifest-path bindings/rust/Cargo.toml --workspace
```
