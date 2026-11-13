use betterleaks::{Error, Scanner};
use std::{collections::BTreeMap, sync::Arc, thread};

const CONFIG: &str = r#"
[[rules]]
id = "example"
description = "Example token"
regex = '''example_[a-f0-9]{32}'''
keywords = ["example_"]
"#;
const TOKEN: &str = "example_0123456789abcdef0123456789abcdef";

#[test]
fn embedded_rules_find_a_github_token() {
    let scanner = Scanner::builder().workers(2).build().unwrap();
    let result = scanner
        .scan_str("GITHUB_TOKEN=ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5")
        .unwrap();
    assert!(result.findings.iter().any(|f| f.rule_id == "github-pat"));
    assert_eq!(result.schema_version, 1);
    assert!(!result.engine_version.is_empty());
    assert_eq!(result.config_hash.len(), 64);
}

#[test]
fn results_outlive_the_scanner_and_preserve_nuls_and_byte_coordinates() {
    let input = format!("é\0TOKEN={TOKEN}\n");
    let result = {
        let scanner = Scanner::builder().config_toml(CONFIG).build().unwrap();
        scanner.scan_str(&input).unwrap()
    };
    let finding = &result.findings[0];
    assert_eq!(finding.matched.value, TOKEN);
    assert_eq!(finding.location.start_line, 1);
    assert_eq!(finding.location.start_column, 10);
    assert_eq!(result.summary.bytes_inspected, input.len() as u64);
    assert_eq!(result.summary.findings, 1);
    assert!(!format!("{:?}", finding.matched).contains(TOKEN));
}

#[test]
fn shares_one_scanner_across_threads() {
    let scanner = Arc::new(
        Scanner::builder()
            .config_toml(CONFIG)
            .workers(2)
            .build()
            .unwrap(),
    );
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let scanner = Arc::clone(&scanner);
            thread::spawn(move || {
                for _ in 0..25 {
                    let result = scanner.scan_str(TOKEN).unwrap();
                    assert_eq!(result.findings.len(), 1);
                    assert_eq!(result.findings[0].matched.value, TOKEN);
                }
            })
        })
        .collect();
    drop(scanner);
    for thread in threads {
        thread.join().unwrap();
    }
}

#[test]
fn applies_source_prefilters_and_path_metadata() {
    let config = format!("prefilter = '''attributes[\"path\"] == \"ignored.env\"'''\n{CONFIG}");
    let scanner = Scanner::builder().config_toml(config).build().unwrap();
    let mut attrs = BTreeMap::from([("path".into(), "ignored.env".into())]);
    assert!(scanner
        .scan_with_attributes(TOKEN, &attrs)
        .unwrap()
        .findings
        .is_empty());
    attrs.insert("path".into(), "config.env".into());
    let result = scanner.scan_with_attributes(TOKEN, &attrs).unwrap();
    assert_eq!(result.findings[0].location.path, "config.env");
}

#[test]
fn reports_invalid_configuration_and_limits_and_remains_reusable() {
    assert!(matches!(
        Scanner::builder().config_toml("bad = [").build(),
        Err(Error::Configuration(_))
    ));
    assert!(matches!(
        Scanner::builder().max_input_bytes(0).build(),
        Err(Error::InvalidArgument(_))
    ));
    let scanner = Scanner::builder()
        .config_toml(CONFIG)
        .max_input_bytes(100)
        .max_findings(1)
        .build()
        .unwrap();
    assert!(matches!(
        scanner.scan_str(&"x".repeat(101)),
        Err(Error::LimitExceeded(_))
    ));
    assert!(matches!(
        scanner.scan_str(&format!("{TOKEN} {TOKEN}")),
        Err(Error::LimitExceeded(_))
    ));
    assert_eq!(scanner.scan_str(TOKEN).unwrap().findings.len(), 1);
    let empty = scanner.scan_str("").unwrap();
    assert!(empty.findings.is_empty());
    assert_eq!(empty.summary.bytes_inspected, 0);
}

#[test]
fn detection_budget_failure_preserves_scanner_reuse() {
    let scanner = Scanner::builder()
        .config_toml(CONFIG)
        .max_findings(100_000)
        .build()
        .unwrap();
    let attributes: BTreeMap<String, String> = (0..1024)
        .map(|i| (format!("key{i:04}"), "v".into()))
        .collect();
    assert!(matches!(
        scanner.scan_with_attributes(&format!("{TOKEN}\n").repeat(2000), &attributes),
        Err(Error::LimitExceeded(_))
    ));
    assert_eq!(scanner.scan_str(TOKEN).unwrap().findings.len(), 1);
}

#[test]
fn bounds_decoding_depth_at_construction() {
    for depth in [0, 32] {
        let scanner = Scanner::builder()
            .config_toml(CONFIG)
            .max_decode_depth(depth)
            .build()
            .unwrap();
        assert_eq!(scanner.scan_str(TOKEN).unwrap().findings.len(), 1);
    }
    for depth in [33, u32::MAX] {
        assert!(matches!(
            Scanner::builder()
                .config_toml(CONFIG)
                .max_decode_depth(depth)
                .build(),
            Err(Error::InvalidArgument(_))
        ));
    }
}

#[test]
fn honors_allow_markers_and_decoding_options() {
    let scanner = Scanner::builder()
        .config_toml(CONFIG)
        .max_decode_depth(1)
        .build()
        .unwrap();
    assert!(scanner
        .scan_str(&format!("{TOKEN} # betterleaks:allow"))
        .unwrap()
        .findings
        .is_empty());
    // Base64 of the fixture token.
    let result = scanner
        .scan_str("ZXhhbXBsZV8wMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZg==")
        .unwrap();
    assert_eq!(result.findings[0].matched.value, TOKEN);
    assert_eq!(result.findings[0].decode_depth, 1);
}

#[test]
fn preserves_component_sets_captures_and_finding_filters() {
    let config = r#"
filter = '''attributes["path"] == "ignored.env"'''
[[rules]]
id = "primary"
regex = '''primary-[a-z]+'''
components = [{ id = "account" }, { id = "region", optional = true }]
[[rules]]
id = "account"
regex = '''account=(?P<account>[a-z]+)'''
skipReport = true
[[rules]]
id = "region"
regex = '''region-[a-z]+'''
skipReport = true
"#;
    let scanner = Scanner::builder().config_toml(config).build().unwrap();
    let input = "primary-first\naccount=acme\nregion-east";
    let mut attrs = BTreeMap::from([("path".into(), "included.env".into())]);
    let result = scanner.scan_with_attributes(input, &attrs).unwrap();
    let components = &result.findings[0].component_sets[0].components;
    let account = components.iter().find(|c| c.rule_id == "account").unwrap();
    assert!(!account.optional);
    assert_eq!(account.matched.captures["account"], "acme");
    assert!(
        components
            .iter()
            .find(|c| c.rule_id == "region")
            .unwrap()
            .optional
    );
    attrs.insert("path".into(), "ignored.env".into());
    let filtered = scanner.scan_with_attributes(input, &attrs).unwrap();
    assert!(filtered.findings.is_empty());
    assert_eq!(filtered.summary.bytes_inspected, input.len() as u64);
}
