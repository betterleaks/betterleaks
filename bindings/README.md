# Native bindings (experimental)

Betterleaks can be embedded through a C ABI, a safe Rust wrapper, or the
[Node.js API](node/README.md) on macOS and glibc Linux, on both x86-64 and ARM64.
Windows bindings are deferred. The native archive
contains the Go engine, embedded rules, and Go runtime. Consumers need a platform
linker but do not need Go or the Betterleaks CLI.

The Rust crates are not published to crates.io and standalone C library downloads are not yet
part of the public release pipeline. The Native bindings CI workflow builds and
tests the following targets and uploads artifacts only after the tests pass.
You can also build locally and give the entire output directory to a consumer.
The C API is usable independently of Rust.

| Platform | Rust target | Native build toolchain |
| --- | --- | --- |
| macOS ARM64 | `aarch64-apple-darwin` | Apple Clang and macOS SDK, macOS 12+ |
| macOS x86-64 | `x86_64-apple-darwin` | Apple Clang and macOS SDK, macOS 12+ |
| Linux ARM64, glibc | `aarch64-unknown-linux-gnu` | GCC or Clang with a glibc sysroot |
| Linux x86-64, glibc | `x86_64-unknown-linux-gnu` | GCC or Clang with a glibc sysroot |

An archive must match the full target triple, including libc. CI's glibc builds
use Ubuntu 22.04 (glibc 2.35); artifacts built on newer distributions can require
a newer glibc. The current Linux artifacts require glibc. Use the
CI result for the target you intend to distribute.

## Build the native artifact

With Go 1.26.x and a C toolchain, run from the repository root. The builder pins
the Go release series because newer runtimes can change platform requirements:

```sh
go run ./bindings/cmd/build-native
```

The default target matches the host's OS and architecture, using glibc on Linux.
The output is `dist/native/<target>/`:

```text
include/betterleaks.h          Public C API and ownership contract
include/cgo-generated.h        Generated declarations, useful for ABI inspection
lib/libbetterleaks.a           Static native library
lib/libbetterleaks_ffi.dylib   Shared native library (.so on Linux)
lib/betterleaks-native.json    Versions, target, shared library name and library hashes
LICENSE
```

Select a target and optional output directory explicitly:

```sh
go run ./bindings/cmd/build-native -list-targets
go run ./bindings/cmd/build-native -target x86_64-unknown-linux-gnu -output /tmp/native
```

Linux builds check the C headers during compilation to reject a musl compiler
accidentally supplied for a glibc target.

Cross builds require setting `CC` to a compiler for the target architecture and
OS. Pass `-target` to the builder instead of setting `GOOS`/`GOARCH` on `go run`,
because the builder itself must execute on the host. Cross compilation does not
test execution; CI uses native hardware for each architecture. The shell wrapper
`bash bindings/build-native.sh` remains available and accepts the same arguments.

The native bindings use the CLI's default RE2 backend for detection rules and
source prefilters. Recursive decoding is disabled unless requested.

## Use from Python

After building the native libraries, load the shared library directly with
Python’s standard library. On Apple Silicon:

```sh
BETTERLEAKS_LIB_DIR="$PWD/dist/native/aarch64-apple-darwin/lib" python3 examples/python/native_smoke.py
```

The [runnable example](../examples/python/native_smoke.py) creates one scanner,
scans text and a local file, decodes the result, and releases native allocations.
`bl_scanner_scan_file` accepts a length-delimited filesystem path and scans one
regular file through the Go filesystem source. It applies the configured input
limit and prefilters and returns an error for archive inputs that need expansion.
The process opens the supplied path with its own filesystem permissions. For a
service that accepts uploaded content, pass the bytes to `bl_scanner_scan`. Use
`bl_scanner_scan_file` for paths the caller is authorized to read.

## Use from Rust

With Rust installed, from the repository root (Apple Silicon example):

```sh
export BETTERLEAKS_LIB_DIR="$PWD/dist/native/aarch64-apple-darwin/lib"
export MACOSX_DEPLOYMENT_TARGET=12.0
cargo run --manifest-path examples/rust/Cargo.toml
```

For Linux, omit `MACOSX_DEPLOYMENT_TARGET` and point `BETTERLEAKS_LIB_DIR` at the
matching Linux artifact. For example, on x86-64 glibc Linux:

```sh
export BETTERLEAKS_LIB_DIR="$PWD/dist/native/x86_64-unknown-linux-gnu/lib"
cargo run --manifest-path examples/rust/Cargo.toml
```

The example scans a synthetic GitHub token and prints the rule and location. It
also accepts a UTF-8 file path as an argument. To integrate in another repository,
use a path dependency on `bindings/rust` and supply the same native directory.
See the [Rust API documentation](rust/README.md).

Cargo only reads the prebuilt archive; it never invokes Go or downloads native
code. Its build script checks the artifact's target, binding package version,
ABI revision, and archive hash. The scanner also checks the ABI at runtime.
After linking, deploy the application's executable. The `.a` and manifest are
build inputs and are not required at runtime. Static linking of Betterleaks does
not automatically make every system dependency static. The Go runtime shares
the host process on every platform.

## Use from C

Include `betterleaks.h` and link the archive with the platform libraries listed
below. For example, build and run the macOS boundary test:

```sh
cc -I dist/native/aarch64-apple-darwin/include \
  bindings/c/tests/boundary.c \
  dist/native/aarch64-apple-darwin/lib/libbetterleaks.a \
  -framework CoreFoundation -framework Security -lresolv \
  -o /tmp/betterleaks-boundary
/tmp/betterleaks-boundary
```

Linux glibc uses `-lpthread -ldl -lm -lresolv`. Rust's build script selects these
libraries from the same target catalog used by the native builder.

`bl_scanner_new` accepts a UTF-8 JSON object with these optional fields:

| Field | Default | Meaning |
| --- | --- | --- |
| `config_toml` | Embedded rules | Custom configuration text |
| `config_path` | Empty | Load TOML from this path, or use as the origin label for inline TOML |
| `workers` | `0` | Set 1–1024 workers shared across calls. Zero uses the Go SDK default. |
| `max_decode_depth` | `0` | Recursive decoding passes |
| `max_input_bytes` | `8388608` | Per-call byte limit, from 1 through 67108864 |
| `max_findings` | `10000` | Per-call finding limit, from 1 through 100000 |

An empty options buffer selects defaults. An empty attributes buffer in
`bl_scanner_scan` means no source metadata. Nonempty options and attributes must
be JSON objects; attribute values are strings. The in-memory text input must be UTF-8, and can
contain embedded NUL bytes. Inputs are copied before Go begins scanning.

Successful scans return this JSON envelope, whose `findings` use the existing
Betterleaks report representation:

```json
{
  "schema_version": 1,
  "engine_version": "dev",
  "config_hash": "...",
  "findings": [],
  "summary": { "bytes_inspected": 0, "findings": 0 }
}
```

Return codes are declared in the header. On failure, an error buffer contains
UTF-8 text, and no partial result is returned. Free every result and error buffer
with `bl_buffer_free`, and every scanner with `bl_scanner_free`. Buffers are
length-delimited, not NUL-terminated. Scanners support concurrent calls;
buffers are owned by each individual call.

## Scope and limits

- Detection only: there is no provider validation, revocation, directory or Git
  traversal, Rust callback interface, or cancellation API in this version.
- Default scans perform no network requests. Custom TOML extensions can read
  local files, according to the existing config loader's behavior.
- Source prefilters and finding filters use the existing SDK behavior, including
  keeping input if prefilter evaluation fails. The SDK is silent by default.
- Rules compile during construction. Input and finding limits fail explicitly;
  no partial result is presented as a completed scan.
- Options are limited to 8 MiB, attributes to 1 MiB, and serialized results to
  64 MiB. The result limit is checked after serialization, so it is not a bound
  on peak process memory. Findings are collected before serialization.
- Text fields follow Go's JSON reporting semantics. Invalid UTF-8 produced by
  decoding is replaced during JSON serialization; arbitrary-byte preservation
  is not promised. Finding order is unspecified. Lines and byte columns are
  one-based; missing coordinates are represented as zero in Rust.
- Scanning blocks the calling thread. Async callers should use their runtime's
  blocking pool. The embedded Go runtime uses its own threads and signal handlers.
- Recovery at the C entry points covers panics on the calling goroutine only.
  Native crashes, fatal Go failures, and panics on other goroutines can terminate
  the host process. This is an in-process library, not an isolation boundary.
- Static linking requires rebuilding the Rust application to update the engine.
  Native artifact changes must be released with corresponding crate versions.
  Target/ABI/hash checks detect mismatches; they do not authenticate a distributor.

## Tests

```sh
go test -race -tags betterleaks_ffi ./bindings/c
go test ./bindings/cmd/build-native
go run ./bindings/cmd/build-native
export BETTERLEAKS_LIB_DIR="$PWD/dist/native/aarch64-apple-darwin/lib"
export MACOSX_DEPLOYMENT_TARGET=12.0
cargo test --manifest-path bindings/rust/Cargo.toml --workspace
cargo run --manifest-path examples/rust/Cargo.toml
```

For another platform, select its archive and pass `--target <triple>` to Cargo.
The [CI workflow](../.github/workflows/native-bindings.yml) exercises each target's
C ABI, Rust integration tests, and a separate consumer with Go unavailable. The
Go race detector is run on all four target platforms.

The Go bridge is opt-in through `betterleaks_ffi` and `cgo` build constraints;
ordinary CLI builds keep their existing package graph and `CGO_ENABLED=0` support.

## Node.js and npm releases

The [npm package README](node/README.md) covers the Node.js API and CLI. To build
the addon for the host, use an official Node.js distribution with its C headers,
Go 1.26.x, and a C compiler. Run `npm --prefix bindings/node run build:addon`
from the repository root.

The [npm workflow](../.github/workflows/npm-cli.yml) builds an addon on each
supported macOS and Linux target. To rehearse packaging locally, run
`goreleaser build --snapshot --clean` first, then collect the four addons from
the same checkout under `dist/node-addons/`. Run the following from the root.

```sh
npm --prefix bindings/node run pack:cli
python3 bindings/node/scripts/verify-pack.py
npm --prefix bindings/node run test:pack
```

The packer writes twelve tarballs in `dist/npm/<version>/`: the combined
`betterleaks` package, the standalone [Node.js SDK](node/sdk/README.md), six
CLI binaries, and four native addons. CI checks their exact
members and manifests against source, compares the executables and addons to
the original builds, and tests offline installation before signing.

After a successful v2 RC release, **Publish npm RC** runs on `main`. It uses
GitHub OIDC and verifies the signing identity and all tarball hashes. It publishes
the platform packages first, then `@betterleaks/sdk`, then `betterleaks` under `next`. To retry
while the signed artifact is available, run the workflow on `main` with the
original **Release** run ID. It skips identical published versions and stops
on conflicting contents or an attempt to move `next` backwards.

## Python packages

The Python bindings live under [`bindings/python/`](python/README.md) as three complementary distributions sharing one engine without duplicating native code:

- `betterleaks` ([`bindings/python/`](python/README.md)) — meta-package providing `import betterleaks` (re-exporting `betterleaks_sdk` on macOS/Linux, falling back to `betterleaks_cli` on Windows) plus the `betterleaks` CLI entrypoint.
- `betterleaks-sdk` ([`bindings/python/sdk/`](python/sdk/README.md)) — standalone native C ABI SDK (`import betterleaks_sdk`) for macOS and glibc Linux (no CLI binary, Windows unsupported).
- `betterleaks-cli` ([`bindings/python/cli/`](python/cli/README.md)) — standalone CGO-free `betterleaks` CLI distribution (`import betterleaks_cli`) for macOS, Linux, and Windows.
