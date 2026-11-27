use betterleaks::Scanner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let scanner = Scanner::builder().workers(2).build()?;
    let result = match std::env::args_os().nth(1) {
        Some(path) => scanner.scan_file(path)?,
        None => scanner.scan_str("GITHUB_TOKEN=ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5")?,
    };
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
