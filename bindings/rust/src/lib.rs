//! Safe, synchronous bindings to the Betterleaks Go scanner.
//!
//! With Go 1.26+ installed the build compiles the engine itself; otherwise set
//! `BETTERLEAKS_LIB_DIR` to a prebuilt static archive. No Betterleaks
//! executable is required at runtime. A scanner can be shared across threads
//! with `Arc`; each call owns its input and results.
//!
//! Detection enforces per-call candidate and allocation budgets shared by its
//! workers, including filtered matches, components, and decoding. Exceeded
//! limits return [`Error::LimitExceeded`] without partial findings; the scanner
//! remains reusable. These budgets are not a process-memory ceiling: custom
//! configurations and expressions must be trusted, and hard resource guarantees
//! require a separate process with OS limits. See the native bindings README.
//!
//! ```no_run
//! let scanner = betterleaks::Scanner::builder().workers(4).build()?;
//! let result = scanner.scan_str("some source text")?;
//! for finding in result.findings {
//!     println!("{} at line {}", finding.rule_id, finding.location.start_line);
//! }
//! # Ok::<(), betterleaks::Error>(())
//! ```

use betterleaks_sys as sys;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt, num::NonZeroU64, slice};

/// A failed call never returns partial findings as a successful result.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    InvalidArgument(String),
    Configuration(String),
    Scan(String),
    LimitExceeded(String),
    Internal(String),
    Protocol(String),
    AbiMismatch { expected: u32, actual: u32 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidArgument(message) => write!(f, "invalid argument: {message}"),
            Self::Configuration(message) => write!(f, "invalid configuration: {message}"),
            Self::Scan(message) => write!(f, "scan failed: {message}"),
            Self::LimitExceeded(message) => write!(f, "scan limit exceeded: {message}"),
            Self::Internal(message) => write!(f, "native error: {message}"),
            Self::Protocol(message) => write!(f, "native protocol error: {message}"),
            Self::AbiMismatch { expected, actual } => {
                write!(f, "native ABI mismatch: expected {expected}, got {actual}")
            }
        }
    }
}

impl std::error::Error for Error {}

#[derive(Default)]
struct NativeBuffer(sys::Buffer);

impl NativeBuffer {
    fn bytes(&self) -> Result<&[u8], Error> {
        if self.0.len == 0 {
            return Ok(&[]);
        }
        if self.0.data.is_null() || self.0.len > isize::MAX as usize {
            return Err(Error::Protocol("invalid native buffer".into()));
        }
        // SAFETY: The matched ABI returns a contiguous allocation of len bytes,
        // owned by this guard. It stays alive until Drop and is never mutated.
        Ok(unsafe { slice::from_raw_parts(self.0.data, self.0.len) })
    }
}

impl Drop for NativeBuffer {
    fn drop(&mut self) {
        // SAFETY: This guard exclusively owns the native allocation. Moving the
        // buffer out leaves an empty value and ensures it is freed exactly once.
        unsafe { sys::bl_buffer_free(std::mem::take(&mut self.0)) };
    }
}

fn check_status(status: i32, error: &NativeBuffer) -> Result<(), Error> {
    if status == sys::OK {
        return Ok(());
    }
    let message = String::from_utf8_lossy(error.bytes()?).into_owned();
    Err(match status {
        sys::INVALID_ARGUMENT => Error::InvalidArgument(message),
        sys::CONFIG_ERROR => Error::Configuration(message),
        sys::SCAN_ERROR => Error::Scan(message),
        sys::LIMIT_EXCEEDED => Error::LimitExceeded(message),
        sys::INTERNAL_ERROR => Error::Internal(message),
        other => Error::Protocol(format!("unknown status {other}: {message}")),
    })
}

/// Construction options. Defaults use embedded rules, the Go standard regex
/// engine, no recursive decoding, 8 MiB per input, and at most 10,000 findings.
#[derive(Serialize)]
pub struct ScannerBuilder {
    #[serde(skip_serializing_if = "Option::is_none")]
    config_toml: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    config_path: Option<String>,
    workers: u32,
    max_decode_depth: u32,
    max_input_bytes: usize,
    max_findings: usize,
}

impl Default for ScannerBuilder {
    fn default() -> Self {
        Self {
            config_toml: None,
            config_path: None,
            workers: 0,
            max_decode_depth: 0,
            max_input_bytes: 8 << 20,
            max_findings: 10_000,
        }
    }
}

impl ScannerBuilder {
    /// Use custom TOML instead of embedded defaults. TOML may extend defaults.
    pub fn config_toml(mut self, toml: impl Into<String>) -> Self {
        self.config_toml = Some(toml.into());
        self
    }

    /// Origin label for custom TOML, used in configuration diagnostics.
    /// Requires `config_toml`. Note that a relative `[extend].path` inside the
    /// TOML is read from the process working directory (matching the CLI), not
    /// from this path; config extensions may read the local filesystem.
    pub fn config_path(mut self, path: impl Into<String>) -> Self {
        self.config_path = Some(path.into());
        self
    }

    /// Limit detection workers across all calls on this scanner.
    /// Zero selects the Go SDK default, four times GOMAXPROCS at construction.
    pub fn workers(mut self, workers: u32) -> Self {
        self.workers = workers;
        self
    }

    /// Enable up to this many recursive decoding passes; zero disables them.
    pub fn max_decode_depth(mut self, depth: u32) -> Self {
        self.max_decode_depth = depth;
        self
    }

    /// Input limit in bytes, from 1 through 64 MiB.
    pub fn max_input_bytes(mut self, bytes: usize) -> Self {
        self.max_input_bytes = bytes;
        self
    }

    /// Returned finding limit, from 1 through 100,000, checked after fragment
    /// filtering and before output copying. Separate detection budgets also
    /// cover discarded candidates, components, and decoding, and may cause
    /// `Error::LimitExceeded` below this count. A failure returns no findings.
    pub fn max_findings(mut self, findings: usize) -> Self {
        self.max_findings = findings;
        self
    }

    /// Validate configuration and compile rules once, then reuse the scanner.
    pub fn build(self) -> Result<Scanner, Error> {
        // SAFETY: This function has no arguments or ownership requirements.
        let actual = unsafe { sys::bl_abi_version() };
        if actual != sys::ABI_VERSION {
            return Err(Error::AbiMismatch {
                expected: sys::ABI_VERSION,
                actual,
            });
        }
        let options = serde_json::to_vec(&self).map_err(|e| Error::Protocol(e.to_string()))?;
        let mut handle = 0;
        let mut error = NativeBuffer::default();
        // SAFETY: Inputs live throughout this synchronous call and are copied by
        // Go. Output locations are initialized, writable, and disjoint.
        let status = unsafe {
            sys::bl_scanner_new(options.as_ptr(), options.len(), &mut handle, &mut error.0)
        };
        check_status(status, &error)?;
        let handle = NonZeroU64::new(handle)
            .ok_or_else(|| Error::Protocol("native scanner returned a zero handle".into()))?;
        Ok(Scanner { handle })
    }
}

/// Reusable scanner. Safe to share using `Arc<Scanner>`; results are owned by Rust.
///
/// The private handle is never cloned. `&self` keeps it alive during calls and
/// the Go registry supports concurrent scans. Consequently the automatically
/// derived Send/Sync traits are sound without an unsafe implementation.
pub struct Scanner {
    handle: NonZeroU64,
}

impl Scanner {
    pub fn builder() -> ScannerBuilder {
        ScannerBuilder::default()
    }

    /// Scan UTF-8 text, including embedded NULs. No source metadata is inferred.
    pub fn scan_str(&self, input: &str) -> Result<ScanResult, Error> {
        self.scan_encoded(input, &[])
    }

    /// Scan with source metadata, such as `path` and `resource`. Attributes feed
    /// source prefilters and finding filters. `path` becomes Location.path.
    pub fn scan_with_attributes(
        &self,
        input: &str,
        attributes: &BTreeMap<String, String>,
    ) -> Result<ScanResult, Error> {
        let attributes =
            serde_json::to_vec(attributes).map_err(|e| Error::Protocol(e.to_string()))?;
        self.scan_encoded(input, &attributes)
    }

    fn scan_encoded(&self, input: &str, attributes: &[u8]) -> Result<ScanResult, Error> {
        let mut result = NativeBuffer::default();
        let mut error = NativeBuffer::default();
        // SAFETY: &self retains the live handle; borrowed input allocations live
        // throughout the call. Go copies them and joins its workers before
        // returning. Both initialized output locations are distinct.
        let status = unsafe {
            sys::bl_scanner_scan(
                self.handle.get(),
                input.as_ptr(),
                input.len(),
                attributes.as_ptr(),
                attributes.len(),
                &mut result.0,
                &mut error.0,
            )
        };
        check_status(status, &error)?;
        let result: ScanResult =
            serde_json::from_slice(result.bytes()?).map_err(|e| Error::Protocol(e.to_string()))?;
        if result.schema_version != sys::ABI_VERSION {
            return Err(Error::Protocol(format!(
                "unsupported result schema {}",
                result.schema_version
            )));
        }
        Ok(result)
    }
}

impl Drop for Scanner {
    fn drop(&mut self) {
        // SAFETY: Drop has exclusive access and no borrowed call can still be
        // running. The handle is private, has a single owner, and is freed once.
        unsafe { sys::bl_scanner_free(self.handle.get()) };
    }
}

#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct ScanResult {
    pub schema_version: u32,
    pub engine_version: String,
    pub config_hash: String,
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
}

#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct ScanSummary {
    pub bytes_inspected: u64,
    pub findings: u64,
}

#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct Finding {
    pub rule_id: String,
    #[serde(default)]
    pub rule_hash: String,
    pub description: String,
    pub confidence: String,
    #[serde(default)]
    pub encodings: Vec<String>,
    #[serde(default)]
    pub decode_depth: u32,
    #[serde(rename = "match")]
    pub matched: Match,
    #[serde(default)]
    pub attributes: BTreeMap<String, String>,
    pub location: Location,
    #[serde(default)]
    pub component_sets: Vec<ComponentSet>,
    #[serde(default)]
    pub component_sets_truncated: bool,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Match contents can contain secrets. Debug deliberately omits source text.
#[derive(Deserialize)]
#[non_exhaustive]
pub struct Match {
    pub full: String,
    pub value: String,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default)]
    pub captures: BTreeMap<String, String>,
    #[serde(default)]
    pub context: String,
}

impl fmt::Debug for Match {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Match").finish_non_exhaustive()
    }
}

/// Coordinates use one-based lines and byte columns. Zero means unspecified.
#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct Location {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub start_line: u64,
    #[serde(default)]
    pub end_line: u64,
    #[serde(default)]
    pub start_column: u64,
    #[serde(default)]
    pub end_column: u64,
}

#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct ComponentSet {
    pub components: Vec<ComponentFinding>,
}

#[derive(Debug, Deserialize)]
#[non_exhaustive]
pub struct ComponentFinding {
    pub rule_id: String,
    #[serde(default)]
    pub rule_hash: String,
    #[serde(default)]
    pub optional: bool,
    #[serde(rename = "match")]
    pub matched: Match,
    pub location: Location,
    #[serde(default)]
    pub encodings: Vec<String>,
    #[serde(default)]
    pub decode_depth: u32,
}
