"use strict";

let addon;
function native() {
  if (addon) return addon;
  const { platform, arch } = process;
  if (!["darwin", "linux"].includes(platform) || !["x64", "arm64"].includes(arch)) {
    throw new Error(`Betterleaks bindings support macOS and glibc Linux on x64 and arm64 (running ${platform}/${arch})`);
  }
  const name = `@betterleaks/sdk-${platform}-${arch}`;
  const version = require("./package.json").version;
  let manifest;
  try {
    manifest = require(`${name}/package.json`);
  } catch (cause) {
    throw new Error(`Install @betterleaks/sdk with optional dependencies enabled to load ${name}@${version}`, { cause });
  }
  if (manifest.version !== version) throw new Error(`Expected ${name}@${version}, found ${manifest.version}`);
  addon = require(`${name}/betterleaks.node`);
  return addon;
}

exports.scanText = async function scanText(text) {
  return JSON.parse(await native().scanText(text));
};

exports.scanFile = async function scanFile(path) {
  return JSON.parse(await native().scanFile(path));
};

exports.createScanner = async function createScanner(options = {}) {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw new TypeError("Expected a scanner options object");
  }
  const config = Object.create(null);
  for (const [key, value] of Object.entries(options)) {
    if (key !== "configPath" && key !== "configToml") throw new TypeError(`Unknown scanner option: ${key}`);
    if (value === undefined) continue;
    if (typeof value !== "string") throw new TypeError(`${key} must be a string`);
    if (value.length > (8 << 20)) throw new RangeError("Scanner options exceed 8 MiB");
    if (key === "configPath" && (!value || value.includes("\0"))) {
      throw new TypeError("configPath must be a nonempty path without NUL");
    }
    config[key === "configPath" ? "config_path" : "config_toml"] = value;
  }

  const scanner = await native().createScanner(JSON.stringify(config));
  return {
    async scanText(text) { return JSON.parse(await scanner.scanText(text)); },
    async scanFile(path) { return JSON.parse(await scanner.scanFile(path)); },
    close() { scanner.close(); },
  };
};
