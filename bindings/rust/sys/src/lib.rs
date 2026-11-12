//! Raw C ABI for Betterleaks. Prefer the safe `betterleaks` crate.
//!
//! Inputs are borrowed and never mutated or retained. Null inputs require zero
//! length. Output pointers must be valid, distinct, writable, and initialized.
//! Native buffers must be freed exactly once by `bl_buffer_free`, never by Rust.

use std::ptr;

pub const ABI_VERSION: u32 = 1;
pub const OK: i32 = 0;
pub const INVALID_ARGUMENT: i32 = 1;
pub const CONFIG_ERROR: i32 = 2;
pub const SCAN_ERROR: i32 = 3;
pub const LIMIT_EXCEEDED: i32 = 4;
pub const INTERNAL_ERROR: i32 = 5;

#[repr(C)]
pub struct Buffer {
    pub data: *mut u8,
    pub len: usize,
}

impl Default for Buffer {
    fn default() -> Self {
        Self {
            data: ptr::null_mut(),
            len: 0,
        }
    }
}

// On Windows the engine is a DLL (betterleaks.dll next to the executable);
// raw-dylib makes the compiler synthesize the imports, so building needs no
// Go toolchain, import library, or even the DLL itself. Elsewhere the build
// script links a static archive into the binary.
#[cfg_attr(windows, link(name = "betterleaks", kind = "raw-dylib"))]
extern "C" {
    pub fn bl_abi_version() -> u32;
    pub fn bl_scanner_new(
        options: *const u8,
        options_len: usize,
        out_scanner: *mut u64,
        out_error: *mut Buffer,
    ) -> i32;
    pub fn bl_scanner_scan(
        scanner: u64,
        input: *const u8,
        input_len: usize,
        attributes: *const u8,
        attributes_len: usize,
        out_result: *mut Buffer,
        out_error: *mut Buffer,
    ) -> i32;
    pub fn bl_scanner_free(scanner: u64) -> i32;
    pub fn bl_buffer_free(buffer: Buffer);
}
