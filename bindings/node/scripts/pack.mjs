import { execFileSync } from "node:child_process";
import { chmod, copyFile, mkdir, mkdtemp, readFile, rename, rm, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const source = fileURLToPath(new URL("../", import.meta.url));
const root = resolve(source, "../..");
const dist = join(root, "dist");
const load = async (path) => JSON.parse(await readFile(path, "utf8"));
const { version, project_name: project } = await load(join(dist, "metadata.json"));
const artifacts = await load(join(dist, "artifacts.json"));
const template = await load(join(source, "package.json"));
const npm = process.env.npm_execpath;
if (!npm) throw new Error("Run npm --prefix bindings/node run pack:cli");
if (project !== template.name || !/^2\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
  throw new Error("Expected a Betterleaks v2 GoReleaser build");
}

const staging = await mkdtemp(join(dist, ".npm-"));
const output = join(dist, "npm", version);
const cliPlatforms = {};
const sdkPlatforms = {};
const tarballs = [];
async function pack(directory, manifest) {
  await copyFile(join(root, "LICENSE"), join(directory, "LICENSE"));
  await writeFile(join(directory, "package.json"), JSON.stringify(manifest, null, 2) + "\n");
  const packed = execFileSync(process.execPath, [
    npm, "pack", "--ignore-scripts", "--json", "--pack-destination", staging, directory,
  ], { encoding: "utf8" });
  const [{ filename }] = JSON.parse(packed);
  tarballs.push(filename);
}

try {
  for (const [goos, os] of [["darwin", "darwin"], ["linux", "linux"], ["windows", "win32"]]) {
    for (const [goarch, cpu] of [["amd64", "x64"], ["arm64", "arm64"]]) {
      const matches = artifacts.filter((a) =>
        a.type === "Binary" && a.extra?.ID === "betterleaks" && a.goos === goos && a.goarch === goarch);
      const binary = os === "win32" ? "betterleaks.exe" : "betterleaks";
      if (matches.length !== 1 || basename(matches[0].path) !== binary) {
        throw new Error(`Expected one ${binary} for ${goos}/${goarch}`);
      }
      const platform = `${os}-${cpu}`;
      const cliName = `@betterleaks/cli-${platform}`;
      const directory = join(staging, `cli-${platform}`);
      const target = join(directory, "bin", binary);
      await mkdir(join(directory, "bin"), { recursive: true });
      await copyFile(resolve(root, matches[0].path), target);
      await chmod(target, 0o755);
      const platformManifest = {
        version, os: [os], cpu: [cpu], license: template.license, repository: template.repository,
        publishConfig: { access: "public" },
      };
      await pack(directory, {
        ...platformManifest, name: cliName, description: `Betterleaks CLI for ${os}/${cpu}`,
      });
      cliPlatforms[cliName] = version;
      if (os !== "win32") {
        const sdkName = `@betterleaks/sdk-${platform}`;
        const addon = join(staging, `sdk-${platform}`);
        await mkdir(addon);
        await copyFile(join(dist, "node-addons", `betterleaks-${platform}.node`), join(addon, "betterleaks.node"));
        await pack(addon, {
          ...platformManifest, name: sdkName, description: `Betterleaks Node.js addon for ${os}/${cpu}`,
        });
        sdkPlatforms[sdkName] = version;
      }
    }
  }
  const sdk = join(staging, "sdk");
  await mkdir(sdk);
  for (const file of ["README.md", "index.js", "index.d.ts"]) {
    await copyFile(join(source, "sdk", file), join(sdk, file));
  }
  await pack(sdk, {
    name: "@betterleaks/sdk", version, description: "Scan text and files for leaked secrets from Node.js",
    license: template.license, repository: { ...template.repository, directory: "bindings/node/sdk" },
    main: "index.js", types: "index.d.ts", optionalDependencies: sdkPlatforms,
    publishConfig: { access: "public" },
  });
  // The repository manifest also contains private build scripts.
  const { private: _private, scripts: _scripts, ...entry } = template;
  const directory = join(staging, "launcher");
  await mkdir(join(directory, "bin"), { recursive: true });
  await copyFile(join(source, entry.bin.betterleaks), join(directory, entry.bin.betterleaks));
  for (const file of ["README.md", entry.main, entry.types]) {
    await copyFile(join(source, file), join(directory, file));
  }
  await pack(directory, {
    ...entry, version, dependencies: { "@betterleaks/sdk": version }, optionalDependencies: cliPlatforms,
  });
  await mkdir(output, { recursive: true });
  for (const filename of tarballs) await rename(join(staging, filename), join(output, filename));
  console.log(`Packed ${tarballs.length} packages in ${output}`);
} finally {
  await rm(staging, { recursive: true, force: true });
}
