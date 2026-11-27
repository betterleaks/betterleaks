# Betterleaks for Rust (experimental)

Safe Rust bindings to the existing Betterleaks Go engine using prebuilt static
archives for **macOS and glibc Linux, on x86-64 and ARM64**. macOS requires version
12 or newer. The current artifacts cover macOS and glibc Linux. The crate
has not been published to crates.io.

Build the archive with `go run ./bindings/cmd/build-native` from a Betterleaks checkout,
or obtain a matching artifact from its maintainer. Go is only needed to produce
the archive, not to build a Rust application using an existing archive.

Add a local dependency to your application:

```toml
[dependencies]
betterleaks = { path = "/path/to/betterleaks/bindings/rust" }
```

Then set the location of the prebuilt library and build:

```sh
export BETTERLEAKS_LIB_DIR=/path/to/native/aarch64-apple-darwin/lib
export MACOSX_DEPLOYMENT_TARGET=12.0
cargo build
```

That example uses Apple Silicon macOS. On Linux, omit `MACOSX_DEPLOYMENT_TARGET`
and select the artifact matching your Rust GNU target. Glibc archives cannot be
used with musl targets. The builder rejects that combination.

The directory must contain `libbetterleaks.a` and `betterleaks-native.json` from
the same build. Cargo checks the target, binding version, ABI, and archive hash.
It does not invoke Go or download a native binary. Platform SDK/linker tools
are still needed. After linking, the application includes the engine and Go
runtime, so the native archive is not needed at runtime.

```rust
use betterleaks::Scanner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Scanner::builder().workers(4).build()?;
    let result = scanner.scan_file("config.env")?;
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

Builder options include custom TOML, a configuration file path, workers, decoding depth,
maximum input bytes, and maximum findings. Defaults are the embedded rules,
RE2 engine, no decoding, 8 MiB inputs, and 10,000 findings. Both
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

The repository's `examples/rust` is a standalone Cargo consumer. Run the crate's
tests with the same `BETTERLEAKS_LIB_DIR`:

```sh
cargo test --manifest-path bindings/rust/Cargo.toml --workspace
```
