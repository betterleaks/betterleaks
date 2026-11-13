# betterleaks-sys (experimental)

Raw ABI declarations and static linking for Betterleaks. Prefer the safe
`betterleaks` crate for application code.

The build script links the native engine in one of two modes:

1. **Bundled** (default): compiles `bindings/c` from this repository into a
   C archive using the host Go toolchain (Go 1.26+ and a C compiler required).
   `BETTERLEAKS_SRC_DIR` overrides the checkout location when the crate is
   vendored elsewhere.
2. **Prebuilt**: set `BETTERLEAKS_LIB_DIR` to a directory containing a
   `libbetterleaks.a` built from the same crate version with
   `go build -tags betterleaks_ffi -buildmode=c-archive ./bindings/c`.
   No Go toolchain is needed.

Supported targets are macOS and glibc Linux on x86-64 and ARM64. Windows is
deferred. Musl is rejected because Go C archives can crash during startup
(golang/go#13492).

The public C header lives at `bindings/c/betterleaks.h` in the Betterleaks
repository. Callers must uphold its pointer, length, and ownership contract.
Release every returned buffer exactly once using `bl_buffer_free`. Scanners
support concurrent calls and must be released using `bl_scanner_free`. The
native library shares the host process and its failure domain.

`bl_scanner_scan_file` accepts a length-delimited UTF-8 path and optional JSON
attributes. The native engine opens and streams one regular UTF-8 file, using
the same detection limits as `bl_scanner_scan`. Rebuild prebuilt libraries made
before this export was added; no Rust-side file reading is required.
