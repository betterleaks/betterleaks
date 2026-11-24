// Copied into the clean npm consumer so both import styles use the installed package.
import assert from "node:assert/strict";
import { unlink, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { once } from "node:events";
import { isMainThread, Worker } from "node:worker_threads";

const packageName = process.argv[2];
const { createScanner, scanText, scanFile } = await import(packageName);
const require = createRequire(import.meta.url);
assert.equal(createScanner, require(packageName).createScanner);
assert.equal(scanText, require(packageName).scanText);
assert.equal(scanFile, require(packageName).scanFile);

const inlineConfig = "[[rules]]\nid = 'inline-rule'\nregex = 'INLINE_[A-Z]{6}'\n";
async function testConfiguredScanners(defaultToken) {
  await writeFile("rules.toml", "[[rules]]\nid = 'file-rule'\nregex = 'FILE_[A-Z]{6}'\n");
  const [inline, fromFile] = await Promise.all([
    createScanner({ configToml: inlineConfig, configPath: "inline-source.toml" }),
    createScanner({ configPath: "rules.toml" }),
  ]);
  await unlink("rules.toml"); // The scanner has compiled its own copy.
  const input = "INLINE_ABCDEF FILE_ABCDEF";
  await writeFile("custom.txt", input);
  const pending = [inline.scanText(input), inline.scanFile("custom.txt"), fromFile.scanText(input),
    fromFile.scanFile("custom.txt"), scanText(input)];
  inline.close();
  inline.close();
  const [inlineText, inlineFile, fileText, fileScan, defaults] = await Promise.all(pending);
  for (const report of [inlineText, inlineFile]) assert.deepEqual(report.findings.map(f => f.rule_id), ["inline-rule"]);
  for (const report of [fileText, fileScan]) assert.deepEqual(report.findings.map(f => f.rule_id), ["file-rule"]);
  assert.equal(fileScan.findings[0].location.path, "custom.txt");
  assert.equal(inlineText.config_hash, inlineFile.config_hash);
  assert.notEqual(inlineText.config_hash, fileText.config_hash);
  assert.deepEqual(defaults.findings, []);
  await assert.rejects(inline.scanText(input), /closed/);
  assert.equal((await fromFile.scanText(input)).summary.findings, 1);
  fromFile.close();

  const extended = await createScanner({ configToml: "[extend]\nuseDefault = true\n" + inlineConfig });
  try {
    const report = await extended.scanText(defaultToken + "\n" + input);
    assert.ok(report.findings.some(f => f.rule_id === "github-pat"));
    assert.ok(report.findings.some(f => f.rule_id === "inline-rule"));
  } finally {
    extended.close();
  }

  await assert.rejects(createScanner({ configPath: "missing.toml" }), /missing\.toml/);
  await assert.rejects(createScanner({ configToml: "bad = [", configPath: "bad.toml" }), /bad\.toml/);
  await assert.rejects(createScanner({ config_path: "typo.toml" }), /Unknown scanner option/);
  await assert.rejects(createScanner({ configToml: 42 }), TypeError);
  await assert.rejects(createScanner({ configPath: "" }), TypeError);
  await assert.rejects(createScanner({ configPath: "bad\0path" }), TypeError);
}

if (process.platform === "win32") {
  await assert.rejects(scanText("hello"), /bindings support macOS and glibc Linux/);
  await assert.rejects(createScanner({ configToml: inlineConfig }), /bindings support macOS and glibc Linux/);
} else if (!isMainThread) {
  assert.equal((await scanText("hello")).summary.findings, 0);
  // Exercise finalization when the Worker exits with an open scanner.
  const scanner = await createScanner({ configToml: inlineConfig });
  assert.equal((await scanner.scanText("INLINE_ABCDEF")).summary.findings, 1);
} else {
  // Load the Go runtime first in a short-lived Worker, then reuse it in the main thread.
  const worker = new Worker(new URL(import.meta.url), { argv: [packageName] });
  assert.deepEqual(await once(worker, "exit"), [0]);
  const token = "GITHUB_TOKEN=ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5"; // betterleaks:allow
  const path = "settings.env";
  await writeFile(path, token);
  const input = "ñ\0text\n" + token;
  const [empty, text, file] = await Promise.all([
    require(packageName).scanText(""), scanText(input), scanFile(path),
  ]);
  assert.deepEqual(empty.findings, []);
  assert.equal(text.schema_version, 1);
  assert.equal(text.summary.bytes_inspected, Buffer.byteLength(input));
  assert.equal(text.findings.find((f) => f.rule_id === "github-pat")?.location.start_line, 2);
  const match = file.findings.find((f) => f.rule_id === "github-pat");
  assert.equal(match?.location.path, path);
  assert.equal(match.location.start_line, 1);
  assert.equal(file.summary.findings, file.findings.length);
  assert.ok(file.config_hash);
  const { version } = require(`${packageName}/package.json`);
  if (!version.includes("-SNAPSHOT-")) assert.equal(file.engine_version, `v${version}`);
  await assert.rejects(scanText(null), TypeError);
  await assert.rejects(scanText("é".repeat((4 << 20) + 1)), /exceeds/);
  await assert.rejects(scanFile("missing.env"), /missing\.env/);
  await assert.rejects(scanFile("."), /regular file/);
  await assert.rejects(scanFile(path + "\0suffix"), /NUL/);
  await testConfiguredScanners(token);
}
