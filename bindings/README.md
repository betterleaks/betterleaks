# Native bindings (experimental)

Betterleaks can be embedded in non-Go applications through a small C ABI and a
safe Rust wrapper. The linked artifact contains the Go engine, the embedded
default rules, and the Go runtime; consumers need a platform linker but no
Betterleaks CLI at runtime.

## Design

The C ABI is the product; language wrappers are thin veneers over it. The
surface is deliberately minimal — five functions:

```
bl_abi_version()   ABI revision for fail-fast mismatch detection
bl_scanner_new()   compile a configuration once, returns an opaque handle
bl_scanner_scan()  scan one input against a handle (concurrency-safe)
bl_scanner_free()  release a handle
bl_buffer_free()   release any buffer the library returned
```

Only integers and byte buffers cross the boundary. Scanner options, source
attributes, and scan results are JSON, so the result schema can evolve without
breaking the ABI; the C struct surface never grows per-field. Inputs are
borrowed and copied before Go workers start; outputs are C allocations owned by
the caller. `bindings/c/betterleaks.h` documents the full ownership contract.

Alternatives considered and rejected for the first iteration:

- **Subprocess sidecar** (drive the CLI over pipes): total runtime isolation
  and no cgo, but rule compilation is the expensive step and the CLI has no
  persistent serve mode, so every scan would pay full startup. Revisit if a
  long-lived server mode lands.
- **WASM** (engine compiled to wasip1, embedded via wasmtime): one artifact for
  every platform and real sandboxing, but single-threaded, measurably slower
  for a regex-heavy workload, and a heavyweight runtime dependency.

In-process static linking keeps per-scan latency low and compiled rules warm,
which is what embedding (editors, proxies, other scanners) actually needs. The
trade-off: the Go runtime shares the host process, so fatal Go failures are not
isolated from the embedding application.

## Resource limits

Each scan enforces limits inside detection, before collecting an unrestricted
regex match list or copying findings for delivery. All workers in the call
share these limits:

| Limit | Value |
| --- | --- |
| Input bytes | 8 MiB by default; configurable up to 64 MiB |
| Returned findings | 10,000 by default; configurable up to 100,000 |
| Detection candidates | 100,000 |
| Cumulative detection allocation charges | 64 MiB |
| Concurrent regex match-index scratch | 8 MiB |
| Source fragment bytes | 128 KiB |
| Source attributes JSON | 1 MiB |
| Serialized result JSON | 64 MiB |

Candidates include raw matches later removed by filters or suppression,
component matches, and matches from subsequent decoding passes. Detection
charges cover match collection, intermediate findings, metadata copies,
component combinations, decoding, and output-size estimates. Charges are
conservative and are not refunded when a candidate is discarded. A scan can
therefore reach a detection limit while returning fewer than `max_findings`.
The input reader splits large inputs into fragments automatically.

Regex collection reserves scratch before calling the backend and requests only
a bounded number of matches. If that collection might be incomplete, the scan
fails instead of returning a truncated success. Final finding counts are checked
after fragment filtering, before detaching text and copying output metadata.
Any exceeded limit returns `BL_LIMIT_EXCEEDED` (`Error::LimitExceeded` in Rust)
with no partial result. The scanner remains reusable with fresh limits on the
next call. Concurrent calls each have their own budgets.

The byte charges are an allocation model, **not a heap or process-memory
ceiling**. Regex scratch is additional to the cumulative detection budget.
Configuration loading, compiled regexes and regex-engine internals, source
prefilters and custom expression execution, runtime overhead, and the host's
input/output copies are outside that accounting. Treat custom configurations
as trusted code. Applications requiring a hard memory ceiling or isolation
from fatal native failures must run the engine in a separate process with OS
resource limits and control concurrent requests.

Go SDK consumers can opt into the same mechanism through `Scanner.ScanWithLimits`;
ordinary `Scan` and `ScanString` retain their existing behavior.

## Supported targets

| Platform | Rust target | Linkage |
| --- | --- | --- |
| macOS ARM64 (12+) | `aarch64-apple-darwin` | static archive |
| macOS x86-64 (12+) | `x86_64-apple-darwin` | static archive |
| Linux ARM64, glibc | `aarch64-unknown-linux-gnu` | static archive |
| Linux x86-64, glibc | `x86_64-unknown-linux-gnu` | static archive |
| Windows x86-64 | `x86_64-pc-windows-msvc` | `betterleaks.dll` (build verified; untested at runtime) |

Musl is explicitly rejected: Go C archives can crash during startup on musl
(golang/go#13492), reproduced during testing.

### Windows

Static linking is impossible on Windows: cgo requires a MinGW toolchain, and a
MinGW static archive cannot be linked into the default MSVC Rust target. The
engine is therefore a DLL there, and the crate declares its imports with
Rust's `raw-dylib` linking, so **building a Windows consumer needs no Go, no
MinGW, no import library, and not even the DLL** — only `cargo build`. At
runtime `betterleaks.dll` must sit beside the executable or on the DLL search
path; `Scanner::builder().build()` checks `bl_abi_version` first, so a
mismatched DLL fails fast instead of misbehaving. Never call `FreeLibrary` on
it: a Go runtime cannot be unloaded from a process.

Produce the DLL from any host with Go and MinGW-w64 (self-contained; imports
only KERNEL32 and the Universal CRT):

```sh
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
  go build -trimpath -tags betterleaks_ffi -buildmode=c-shared \
  -o betterleaks.dll ./bindings/c
```

Windows ARM64 compiles on the Rust side (`aarch64-pc-windows-msvc`) but a DLL
build needs an ARM64 MinGW (llvm-mingw). Neither Windows target has been
executed on real hardware yet; per the support policy above, add a CI run
before relying on one.

## Building

**Bundled (default).** With Go 1.26+ and a C compiler installed, the Rust build
script compiles the engine itself; `cargo build` / `cargo test` / `cargo run`
just work from a checkout:

```sh
cargo test --manifest-path bindings/rust/Cargo.toml --workspace
cargo run --manifest-path examples/rust/Cargo.toml
```

**Prebuilt.** Produce an archive once, then consumers build without Go:

```sh
go build -tags betterleaks_ffi -buildmode=c-archive \
  -o dist/native/lib/libbetterleaks.a ./bindings/c
export BETTERLEAKS_LIB_DIR="$PWD/dist/native/lib"
```

An archive must match the consumer's full target triple, including libc; a
glibc archive is not usable from an Alpine/musl application. The bundled build
follows Cargo's `--target` (same-OS cross builds like macOS ARM64 → x86-64
work out of the box); crossing to another OS or libc requires a target C
compiler in `CC_<target-triple>` or `TARGET_CC` (bundled) or `CC` (manual
`go build`). The earlier `exp/rust-bindings`
branch carries a full artifact builder (manifests, checksums, CI workflow) to
resurrect when prebuilt distribution becomes real.

The build uses the Go standard regex engine and SDK defaults; the optional RE2
backend used by the CLI is not included.

## Using the C API directly

Link `libbetterleaks.a` plus the platform libraries (macOS: CoreFoundation and
Security frameworks, libresolv; Linux: pthread, dl, m, resolv) and include
`bindings/c/betterleaks.h`. `bindings/c/tests/boundary.c` is a minimal C
consumer exercising the pointer contract.

## Testing

```sh
go test -tags betterleaks_ffi ./bindings/c          # bridge vs Go SDK parity
cargo test --manifest-path bindings/rust/Cargo.toml --workspace
```
