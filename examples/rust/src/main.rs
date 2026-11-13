use betterleaks::Scanner;
use std::collections::BTreeMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Scanner::builder().workers(2).build()?;
    let (content, path) = match std::env::args().nth(1) {
        Some(path) => (std::fs::read_to_string(&path)?, path),
        None => (
            "GITHUB_TOKEN=ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5\n".into(),
            "example.env".into(),
        ),
    };
    let attributes = BTreeMap::from([("path".into(), path)]);
    let result = scanner.scan_with_attributes(&content, &attributes)?;
    for finding in &result.findings {
        println!(
            "{} at {}:{}",
            finding.rule_id, finding.location.path, finding.location.start_line
        );
    }
    println!(
        "{} findings; {} bytes inspected",
        result.summary.findings, result.summary.bytes_inspected
    );
    Ok(())
}
