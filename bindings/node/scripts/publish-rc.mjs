// Called after Cosign has authenticated SHA256SUMS for this tag and release commit.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFile, readdir } from "node:fs/promises";
import { join, resolve } from "node:path";

const [directory, tag, mode] = process.argv.slice(2);
const rcVersion = /^2\.(0|[1-9]\d*)\.(0|[1-9]\d*)-rc\.(0|[1-9]\d*)$/;
const version = tag?.slice(1);
if (!directory || !tag?.startsWith("v") || !rcVersion.test(version) || !["bootstrap", "oidc"].includes(mode)) {
  throw new Error("Expected an artifact directory, v2 release-candidate tag, and bootstrap or oidc mode");
}
const bootstrap = mode === "bootstrap";
if (bootstrap && !process.env.NODE_AUTH_TOKEN) throw new Error("Configure the npm environment's NPM_STAGE_TOKEN");

const registry = "https://registry.npmjs.org";
const hash = (algorithm, data, encoding) => createHash(algorithm).update(data).digest(encoding);
const names = ["darwin", "linux", "win32"].flatMap(os => ["arm64", "x64"].map(cpu => `@betterleaks/cli-${os}-${cpu}`));
names.push("betterleaks"); // The launcher depends on all six platform packages.
const packages = names.map(name => {
  const filename = `${name.replace("@", "").replace("/", "-")}-${version}.tgz`;
  return { name, filename, path: resolve(directory, filename) };
});

const entries = await readdir(directory, { withFileTypes: true });
const expected = new Set([...packages.map(pkg => pkg.filename), "SHA256SUMS", "SHA256SUMS.sigstore.json"]);
if (entries.length !== expected.size || entries.some(entry => !entry.isFile() || !expected.has(entry.name))) {
  throw new Error("Unexpected files in the signed release artifact");
}
const checksums = [];
for (const pkg of packages) {
  const bytes = await readFile(pkg.path);
  checksums.push(`${hash("sha256", bytes, "hex")}  ${pkg.filename}`);
  pkg.integrity = `sha512-${hash("sha512", bytes, "base64")}`;
}
const signed = (await readFile(join(directory, "SHA256SUMS"), "utf8")).trimEnd().split("\n");
if (signed.sort().join("\n") !== checksums.sort().join("\n")) throw new Error("Signed tarball checksums differ");

function npm(args, capture = false) {
  return execFileSync("npm", [...args, `--registry=${registry}`], {
    encoding: "utf8", stdio: capture ? ["ignore", "pipe", "inherit"] : "inherit",
  });
}

// Preflight the entire set before submitting anything. A retry may find some
// versions live and, during the first release, others still awaiting approval.
const pending = [];
for (const pkg of packages) {
  const response = await fetch(`${registry}/${encodeURIComponent(pkg.name)}`);
  if (response.status !== 404) {
    if (!response.ok) throw new Error(`Registry lookup for ${pkg.name} returned ${response.status}`);
    const metadata = await response.json();
    const live = metadata.versions?.[version];
    if (live) {
      if (live.dist?.integrity !== pkg.integrity) throw new Error(`Published bytes differ for ${pkg.name}@${version}`);
      console.log(`Already published: ${pkg.name}@${version}`);
      continue;
    }
    const next = metadata["dist-tags"]?.next;
    if (next && next !== "0.0.0-stage" && (!rcVersion.test(next) || next.localeCompare(version, "en", { numeric: true }) > 0)) {
      throw new Error(`Refusing to replace ${pkg.name}@next (${next}) with ${version}`);
    }
  }
  const stages = bootstrap ? JSON.parse(npm(["stage", "list", pkg.name, "--json"], true)) : [];
  const staged = stages.filter(item => item.packageName === pkg.name && item.version === version);
  if (staged.length) {
    const [item] = staged;
    if (staged.length !== 1 || item.tag !== "next" || !/^[0-9a-f-]{36}$/i.test(item.id)) {
      throw new Error(`Conflicting npm stage for ${pkg.name}@${version}`);
    }
    const tarball = await fetch(`${registry}/-/stage/${item.id}/tarball`, {
      headers: { Authorization: `Bearer ${process.env.NODE_AUTH_TOKEN}` },
    });
    if (!tarball.ok || `sha512-${hash("sha512", Buffer.from(await tarball.arrayBuffer()), "base64")}` !== pkg.integrity) {
      throw new Error(`Cannot verify the staged bytes for ${pkg.name}@${version}`);
    }
    console.log(`Already staged: ${pkg.name}@${version}`);
    continue;
  }
  pending.push(pkg);
}
for (const pkg of pending) {
  const command = bootstrap ? ["stage", "publish"] : ["publish"];
  npm([...command, pkg.path, "--access=public", "--tag=next", "--ignore-scripts"]);
}
