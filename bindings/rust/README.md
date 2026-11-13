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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Scanner::builder().workers(4).build()?;
    let result = scanner.scan_file("config.env")?;
    for finding in result.findings {
        println!("{} at line {}", finding.rule_id, finding.location.start_line);
    }
    Ok(())
}
```

`scan_file` accepts a `Path` or string and lets Go open, stream, and close one
regular UTF-8 file. `scan_file_with_attributes` also accepts custom metadata.
The supplied path and `resource = "fs.content"` override those attribute keys.
Paths must be nonempty UTF-8 without NULs, at most 1 MiB; relative paths use the
process working directory. Symlinks to regular files are followed, and Windows
path separators are normalized to `/` in findings. Keep the file unchanged until
the call returns. Directory recursion and archive expansion are not performed.
Paths are not confined to a root; callers must authorize untrusted paths.
Path-only rules also apply to empty files.
Missing/unreadable files return `Error::Scan`; invalid paths, non-regular files,
and invalid UTF-8 content return `Error::InvalidArgument`.

File scans use the same per-call input, detection, and result limits as buffer
scans. The input limit is enforced while reading, including if the file grows;
errors never return partial findings. Prebuilt libraries must include the new
`bl_scanner_scan_file` export, so rebuild older archives/DLLs before using this
crate version with file scanning.

Use `scan_str` or `scan_with_attributes` for text already in memory.
`Scanner` is `Send + Sync` and
can be shared using `Arc`; its worker limit applies across all calls. Results
own their data and outlive the scanner. Dropping the scanner and temporary
native result buffers releases their native resources automatically.

Builder options include custom TOML, its origin path, workers, decoding depth,
maximum input bytes, and maximum findings. Defaults are the embedded rules,
standard Go regex engine, no decoding, 8 MiB inputs, and 10,000 findings.
Decode depth accepts 0 through 32; larger values fail at construction with
`Error::InvalidArgument`. These limits do not enforce a CPU-time deadline.
Both source prefilters and finding filters are honored. Configuration errors
fail at construction. Scan errors and exceeded limits return `Err`, without partial
findings. Match values can contain secrets; they are omitted from `Match`'s
`Debug` representation, but other metadata is not automatically sanitized.

Detection also enforces 100,000 candidates, 64 MiB of cumulative allocation
charges, 8 MiB of shared regex-index scratch, and 128 KiB per source fragment.
The reader splits inputs into fragments automatically. Filtered matches,
components, and decoding consume these budgets, so `Error::LimitExceeded` can
occur below `max_findings`. Exceeded limits never return partial findings;
the scanner remains reusable. Budgets are shared by a call's workers and are
independent across concurrent calls.

Allocation charges are conservative estimates, not a peak-memory ceiling.
Configuration, regex-engine internals, custom expressions, runtime overhead,
and caller-owned copies are outside the accounting. Use trusted configurations;
use a separate process with OS resource limits when a hard ceiling is required.
See `bindings/README.md` for the complete resource-limit contract.

This is a synchronous detection API. Provider validation, directory traversal,
caller-supplied streams, and cancellation are not exposed. Input is UTF-8 text, including NULs;
JSON result text follows Go's UTF-8 conversion semantics. Lines and byte columns
are one-based, with zero for missing coordinates. Finding order is unspecified.
The Go runtime is embedded in the process; fatal native failures can terminate
the application. Updating the static engine requires relinking the application.

The repository's `examples/rust` is a standalone Cargo consumer:

```sh
cargo run --manifest-path examples/rust/Cargo.toml
cargo run --manifest-path examples/rust/Cargo.toml -- config.env
cargo test --manifest-path bindings/rust/Cargo.toml --workspace
```
