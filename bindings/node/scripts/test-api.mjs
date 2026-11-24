// Copied into the clean npm consumer so both import styles use the installed package.
import assert from "node:assert/strict";
import { writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { once } from "node:events";
import { isMainThread, Worker } from "node:worker_threads";
import { scanText, scanFile } from "betterleaks";

if (process.platform === "win32") {
  await assert.rejects(scanText("hello"), /bindings support macOS and glibc Linux/);
} else if (!isMainThread) {
  assert.equal((await scanText("hello")).summary.findings, 0);
} else {
  // Load the Go runtime first in a short-lived Worker, then reuse it in the main thread.
  const worker = new Worker(new URL(import.meta.url));
  assert.deepEqual(await once(worker, "exit"), [0]);
  const token = "GITHUB_TOKEN=ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5"; // betterleaks:allow
  const path = "settings.env";
  await writeFile(path, token);
  const require = createRequire(import.meta.url);
  const input = "ñ\0text\n" + token;
  const [empty, text, file] = await Promise.all([
    require("betterleaks").scanText(""), scanText(input), scanFile(path),
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
  const { version } = require("betterleaks/package.json");
  if (!version.includes("-SNAPSHOT-")) assert.equal(file.engine_version, `v${version}`);
  await assert.rejects(scanText(null), TypeError);
  await assert.rejects(scanText("é".repeat((4 << 20) + 1)), /exceeds/);
  await assert.rejects(scanFile("missing.env"), /missing\.env/);
  await assert.rejects(scanFile("."), /regular file/);
  await assert.rejects(scanFile(path + "\0suffix"), /NUL/);
}
