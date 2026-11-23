#!/usr/bin/env node
"use strict";

const { spawn } = require("node:child_process");
const { constants } = require("node:os");

const platformPackage = `@betterleaks/cli-${process.platform}-${process.arch}`;
const executable = process.platform === "win32" ? "betterleaks.exe" : "betterleaks";
let binary;
try {
  binary = require.resolve(`${platformPackage}/bin/${executable}`);
} catch {
  console.error(`Missing Betterleaks binary for ${process.platform}/${process.arch}. Install betterleaks with optional dependencies enabled.`);
  process.exit(1);
}

const child = spawn(binary, process.argv.slice(2), { stdio: "inherit" });
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => child.kill(signal));
}
child.on("error", (error) => {
  console.error(`Could not run Betterleaks: ${error.message}`);
  process.exitCode = 1;
});
child.on("exit", (code, signal) => {
  process.exitCode = code ?? 128 + constants.signals[signal];
});
