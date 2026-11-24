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
