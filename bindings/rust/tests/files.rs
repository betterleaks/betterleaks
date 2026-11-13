use betterleaks::{Error, Scanner};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    thread,
};

const CONFIG: &str =
    "[[rules]]\nid = 'example'\nregex = 'example_[a-f0-9]{32}'\nkeywords = ['example_']";
const TOKEN: &str = "example_0123456789abcdef0123456789abcdef";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        // create_dir refuses to reuse any existing directory.
        loop {
            let path = std::env::temp_dir().join(format!(
                "betterleaks-file-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("create test directory: {err}"),
            }
        }
    }

    fn write(&self, name: &str, content: impl AsRef<[u8]>) -> PathBuf {
        let path = self.0.join(name);
        fs::write(&path, content).unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn reported_path(path: &Path) -> String {
    let path = path.to_str().unwrap();
    if cfg!(windows) {
        path.replace('\\', "/")
    } else {
        path.into()
    }
}

#[test]
fn scans_native_files_with_metadata_and_owned_results() {
    let fixture = Fixture::new();
    let content = format!("{}😀\nTOKEN={TOKEN}\0\n", "x".repeat(99_999));
    // A suffix does not trigger archive expansion or silently skip content.
    let path = fixture.write("配置.zip", &content);
    let attributes = BTreeMap::from([
        ("path".into(), "spoofed".into()),
        ("resource".into(), "spoofed".into()),
        ("custom".into(), "preserved".into()),
    ]);
    let result = {
        let scanner = Scanner::builder().config_toml(CONFIG).build().unwrap();
        scanner
            .scan_file_with_attributes(&path, &attributes)
            .unwrap()
    };
    // The descriptor is closed and findings outlive both scanner and file.
    fs::remove_file(&path).unwrap();
    assert_eq!(result.findings.len(), 1);
    let finding = &result.findings[0];
    assert_eq!(finding.matched.value, TOKEN);
    assert_eq!(finding.location.path, reported_path(&path));
    assert_eq!(finding.location.start_line, 2);
    assert_eq!(finding.location.start_column, 7);
    assert_eq!(finding.attributes["resource"], "fs.content");
    assert_eq!(finding.attributes["custom"], "preserved");
    assert_eq!(result.summary.bytes_inspected, content.len() as u64);
}

#[test]
fn native_file_errors_limits_and_reuse() {
    let fixture = Fixture::new();
    let scanner = Scanner::builder()
        .config_toml(CONFIG)
        .max_input_bytes(100)
        .max_findings(1)
        .build()
        .unwrap();
    assert!(matches!(
        scanner.scan_file(fixture.0.join("missing")),
        Err(Error::Scan(_))
    ));
    for path in [fixture.0.as_path(), Path::new(""), Path::new("bad\0path")] {
        assert!(matches!(
            scanner.scan_file(path),
            Err(Error::InvalidArgument(_))
        ));
    }
    let invalid = fixture.write("invalid.env", [0xff]);
    assert!(matches!(
        scanner.scan_file(invalid),
        Err(Error::InvalidArgument(_))
    ));
    let large = fixture.write("large.env", "x".repeat(101));
    assert!(matches!(
        scanner.scan_file(large),
        Err(Error::LimitExceeded(_))
    ));
    let dense = fixture.write("dense.env", format!("{TOKEN}\n{TOKEN}"));
    assert!(matches!(
        scanner.scan_file(dense),
        Err(Error::LimitExceeded(_))
    ));
    let exact = fixture.write("exact.env", "x".repeat(100));
    assert_eq!(
        scanner.scan_file(exact).unwrap().summary.bytes_inspected,
        100
    );
    let empty = fixture.write("empty.env", "");
    assert_eq!(scanner.scan_file(empty).unwrap().summary.bytes_inspected, 0);
    let valid = fixture.write("valid.env", TOKEN);
    assert_eq!(scanner.scan_file(valid).unwrap().findings.len(), 1);
}

#[test]
fn native_files_use_prefilters_finding_filters_and_independent_budgets() {
    let fixture = Fixture::new();
    let path = fixture.write("token.env", TOKEN);
    let scanner = Arc::new(Scanner::builder()
        .config_toml(format!(
            "prefilter = '''attributes[\"custom\"] == \"skip-source\"'''\nfilter = '''attributes[\"custom\"] == \"skip-finding\"'''\n{CONFIG}"
        ))
        .workers(2).max_findings(1).build().unwrap());
    for value in ["skip-source", "skip-finding"] {
        let attrs = BTreeMap::from([("custom".into(), value.into())]);
        let result = scanner.scan_file_with_attributes(&path, &attrs).unwrap();
        assert!(result.findings.is_empty());
        assert_eq!(
            result.summary.bytes_inspected,
            if value == "skip-source" {
                0
            } else {
                TOKEN.len() as u64
            }
        );
    }
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let scanner = Arc::clone(&scanner);
            let path = path.clone();
            thread::spawn(move || {
                let attrs = BTreeMap::from([("custom".into(), "keep".into())]);
                for _ in 0..10 {
                    assert_eq!(
                        scanner
                            .scan_file_with_attributes(&path, &attrs)
                            .unwrap()
                            .findings
                            .len(),
                        1
                    );
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
}

#[cfg(unix)]
#[test]
fn rejects_non_utf8_paths_and_follows_file_symlinks() {
    use std::os::unix::{ffi::OsStrExt, fs::symlink};
    let fixture = Fixture::new();
    let scanner = Scanner::builder().config_toml(CONFIG).build().unwrap();
    let invalid = Path::new(std::ffi::OsStr::from_bytes(b"bad-\xff"));
    assert!(matches!(
        scanner.scan_file(invalid),
        Err(Error::InvalidArgument(_))
    ));
    let file = fixture.write("target.env", TOKEN);
    let link = fixture.0.join("link.env");
    symlink(file, &link).unwrap();
    assert_eq!(
        scanner.scan_file(&link).unwrap().findings[0].location.path,
        reported_path(&link)
    );
}
