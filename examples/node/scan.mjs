// Run in a project with betterleaks installed: node scan.mjs [path]
import { scanFile, scanText } from "betterleaks";

const path = process.argv[2];
const sample = "GITHUB_TOKEN=ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5"; // betterleaks:allow
const report = path === undefined ? await scanText(sample) : await scanFile(path);

console.log(`Findings: ${report.summary.findings}`);
for (const { rule_id, location } of report.findings) {
  console.log(rule_id, location.path ?? "<text>", location.start_line);
}
