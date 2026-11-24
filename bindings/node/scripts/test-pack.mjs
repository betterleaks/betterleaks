import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { copyFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const dist = fileURLToPath(new URL("../../../dist/", import.meta.url));
const { version } = JSON.parse(await readFile(join(dist, "metadata.json"), "utf8"));
const tarballs = join(dist, "npm", version);
const consumer = await mkdtemp(join(tmpdir(), "betterleaks-npm-test-"));

function npm(args, input) {
  const result = spawnSync(process.execPath, [process.env.npm_execpath, "--offline", ...args], {
    cwd: consumer, encoding: "utf8", input,
    env: { ...process.env, npm_config_cache: join(consumer, "cache") },
  });
  if (result.error) throw result.error;
  return result;
}

try {
  await writeFile(join(consumer, "package.json"), '{"name":"consumer","private":true}');
  const platform = `betterleaks-cli-${process.platform}-${process.arch}-${version}.tgz`;
  const install = npm(["install", "--ignore-scripts", "--no-audit", "--no-fund",
    join(tarballs, `betterleaks-${version}.tgz`), join(tarballs, platform)]);
  assert.equal(install.status, 0, install.stderr);
  const installed = JSON.parse(await readFile(join(consumer, "node_modules/betterleaks/package.json"), "utf8"));
  assert.equal(installed.optionalDependencies[`@betterleaks/cli-${process.platform}-${process.arch}`], version);
  const engine = npm(["exec", "--", "betterleaks", "--version"]);
  assert.equal(engine.status, 0, engine.stderr);
  assert.equal(engine.stdout.trim(), version);
  const scan = npm(["exec", "--", "betterleaks", "stdin", "--exit-code", "17", "--output", "-"],
    "GITHUB_TOKEN=ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5\n"); // betterleaks:allow
  assert.equal(scan.status, 17, scan.stderr);
  assert.ok(JSON.parse(scan.stdout).findings.some((finding) => finding.rule_id === "github-pat"));
  await copyFile(new URL("./test-api.mjs", import.meta.url), join(consumer, "test-api.mjs"));
  const api = spawnSync(process.execPath, ["test-api.mjs"], { cwd: consumer, encoding: "utf8" });
  if (api.error) throw api.error;
  assert.equal(api.status, 0, api.stderr || api.signal);
  console.log(`Verified offline install, CLI and Node.js API on ${process.platform}/${process.arch}`);
} finally {
  await rm(consumer, { recursive: true, force: true });
}
