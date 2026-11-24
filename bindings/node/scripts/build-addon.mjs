import { execFileSync } from "node:child_process";
import { mkdir, readFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const catalog = JSON.parse(await readFile(join(root, "bindings/rust/sys/targets.json"), "utf8"));
const target = catalog.find(({ goos, goarch }) =>
  goos === process.platform && goarch === ({ x64: "amd64", arm64: "arm64" })[process.arch]);
if (!target) throw new Error(`Unsupported native target ${process.platform}/${process.arch}`);

const archive = join(root, "dist/native", target.target);
execFileSync("go", ["run", "./bindings/cmd/build-native", "-target", target.target], { cwd: root, stdio: "inherit" });
const out = join(root, "dist/node-addons");
await mkdir(out, { recursive: true });
const libraries = target.libraries.flatMap((name) => {
  if (name.startsWith("framework=")) return ["-framework", name.slice("framework=".length)];
  return [`-l${name.replace(/^dylib=/, "")}`];
});
const linker = process.platform === "darwin"
  ? ["-bundle", "-undefined", "dynamic_lookup", `-mmacosx-version-min=${target.minimum_macos_version}`,
     "-Wl,-exported_symbol,_napi_register_module_v1", "-Wl,-exported_symbol,_node_api_module_get_api_version_v1"]
  : ["-shared", "-Wl,--exclude-libs,ALL"];
execFileSync(process.env.CC || "cc", [
  "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC", "-fvisibility=hidden",
  "-I", join(dirname(process.execPath), "../include/node"), "-I", join(archive, "include"),
  ...linker, "bindings/node/native/addon.c", join(archive, "lib/libbetterleaks.a"), ...libraries,
  "-o", join(out, `betterleaks-${process.platform}-${process.arch}.node`),
], { cwd: root, stdio: "inherit" });
