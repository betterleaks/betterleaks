import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { access, copyFile, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const dist = fileURLToPath(new URL("../../../dist/", import.meta.url));
const { version } = JSON.parse(await readFile(join(dist, "metadata.json"), "utf8"));
const tarball = name => join(dist, "npm", version, `${name}-${version}.tgz`);
const platform = `${process.platform}-${process.arch}`;

function npm(cwd, args, input) {
  const result = spawnSync(process.execPath, [process.env.npm_execpath, "--offline", ...args], {
    cwd, encoding: "utf8", input, env: { ...process.env, npm_config_cache: join(cwd, "cache") },
  });
  if (result.error) throw result.error;
  return result;
}

function testCli(consumer) {
  const engine = npm(consumer, ["exec", "--", "betterleaks", "--version"]);
  assert.equal(engine.status, 0, engine.stderr);
  assert.equal(engine.stdout.trim(), version);
  const scan = npm(consumer, ["exec", "--", "betterleaks", "stdin", "--exit-code", "17", "--output", "-"],
    "GITHUB_TOKEN=ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5\n"); // betterleaks:allow
  assert.equal(scan.status, 17, scan.stderr);
  assert.ok(JSON.parse(scan.stdout).findings.some((finding) => finding.rule_id === "github-pat"));
}

for (const entry of ["@betterleaks/sdk", "betterleaks"]) {
  const consumer = await mkdtemp(join(tmpdir(), "betterleaks-npm-test-"));
  try {
    // Direct npm to local tarballs for transitive dependencies without adding them to the app.
    const overrides = {};
    if (process.platform !== "win32") {
      overrides[`@betterleaks/sdk-${platform}`] = pathToFileURL(tarball(`betterleaks-sdk-${platform}`)).href;
    }
    let entryTarball = tarball("betterleaks-sdk");
    if (entry === "betterleaks") {
      overrides["@betterleaks/sdk"] = pathToFileURL(entryTarball).href;
      overrides[`@betterleaks/cli-${platform}`] = pathToFileURL(tarball(`betterleaks-cli-${platform}`)).href;
      entryTarball = tarball("betterleaks");
    }
    await writeFile(join(consumer, "package.json"), JSON.stringify({ name: "consumer", private: true, overrides }));
    const install = npm(consumer, ["install", "--ignore-scripts", "--no-audit", "--no-fund", entryTarball]);
    assert.equal(install.status, 0, install.stderr);

    if (entry === "betterleaks") {
      testCli(consumer);
    } else {
      const modules = join(consumer, "node_modules");
      const scoped = await readdir(join(modules, "@betterleaks"));
      assert.deepEqual(scoped.sort(), process.platform === "win32" ? ["sdk"] : ["sdk", `sdk-${platform}`]);
      await assert.rejects(access(join(modules, "betterleaks")), { code: "ENOENT" });
      await assert.rejects(access(join(modules, ".bin", "betterleaks")), { code: "ENOENT" });
    }

    await copyFile(new URL("./test-api.mjs", import.meta.url), join(consumer, "test-api.mjs"));
    const api = spawnSync(process.execPath, ["test-api.mjs", entry], { cwd: consumer, encoding: "utf8" });
    if (api.error) throw api.error;
    assert.equal(api.status, 0, api.stderr || api.signal);
    console.log(`Verified offline install and runtime for ${entry} on ${platform}`);
  } finally {
    await rm(consumer, { recursive: true, force: true });
  }
}
