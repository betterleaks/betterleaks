# betterleaks-sys (experimental)

Raw ABI declarations and static linking for Betterleaks. Prefer the safe
`betterleaks` crate for application code. This crate does not build Go source or
download native binaries.

Set `BETTERLEAKS_LIB_DIR` to a prebuilt artifact's `lib` directory, containing
`libbetterleaks.a` and `betterleaks-native.json`. The build script verifies the
target, package version, ABI revision, and SHA-256 of the archive. The initial
targets are macOS and glibc Linux on x86-64 and ARM64. See `targets.json` for the
complete target triples and link libraries. Windows is deferred. Musl is rejected
because Go C archives can crash during startup (golang/go#13492).
On macOS, set `MACOSX_DEPLOYMENT_TARGET=12.0` when building
the application. A platform linker and SDK/sysroot are required; Go is not.

The public C header lives at `bindings/c/betterleaks.h` in the Betterleaks
repository. Callers must uphold its pointer, length, and ownership contract.
Release every returned buffer exactly once using `bl_buffer_free`. Scanners
support concurrent calls and must be released using `bl_scanner_free`. The
native library shares the host process and its failure domain.
