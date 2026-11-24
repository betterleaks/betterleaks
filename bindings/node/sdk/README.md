# @betterleaks/sdk

Scan text and local files for leaked credentials from a Node.js application. npm installs the prebuilt native addon for your OS and CPU. Scans run in the Node process, off the JavaScript thread. The SDK installation includes no CLI executable.

## Try it in a new project

```sh
mkdir secret-scanner
cd secret-scanner
npm init -y
npm install @betterleaks/sdk@next
```

Save the following as `scan.mjs`.

```js
import { scanFile, scanText } from "@betterleaks/sdk";

const path = process.argv[2];
const report = path ? await scanFile(path) : await scanText("hello world");
console.log(`Findings: ${report.summary.findings}`);
for (const { rule_id, location } of report.findings) {
  console.log(rule_id, location.path ?? "<text>", location.start_line);
}
```

Run `node scan.mjs` for an empty result, or `node scan.mjs settings.env` to scan an existing file. Findings can contain credentials in `match.full` and `match.value`. The example logs only rule IDs and locations.

CommonJS supports `const { scanText, scanFile, createScanner } = require("@betterleaks/sdk")`. TypeScript declarations are included. Both scan functions return a promise. The SDK allows up to 8 MiB of input and 10,000 findings per scan. A file error or an exceeded limit rejects the promise.

## Use your own rules

```js
import { createScanner } from "@betterleaks/sdk";

const scanner = await createScanner({ configPath: "./betterleaks.toml" });
try {
  const report = await scanner.scanFile("settings.env");
  console.log(report.summary.findings);
} finally {
  scanner.close();
}
```

You can also pass TOML directly. This example adds a rule to the built-in rules.

```js
const scanner = await createScanner({
  configToml: `
[extend]
useDefault = true

[[rules]]
id = "internal-token"
regex = 'INTERNAL_[A-Z]{12}'
`,
});
try {
  const report = await scanner.scanText("token=INTERNAL_ABCDEFGHIJKL");
  console.log(report.findings.map(finding => finding.rule_id));
} finally {
  scanner.close();
}
```

`createScanner` reads and compiles the configuration once, off the JavaScript thread. A missing file or invalid configuration rejects its promise. If you pass both options, the scanner reads `configToml` and uses `configPath` as its source name for diagnostics. Use configuration you trust, since TOML extensions can read local files.

Reuse a scanner for concurrent text and file scans. Call `close()` when finished to release the native scanner as soon as pending scans complete. Each scanner has its own rules. The top-level `scanText` and `scanFile` functions always use the built-in rules.

The native addon supports macOS 12+ and glibc Linux 2.35+ on x64 and arm64. Keep optional dependencies enabled and install them for the platform where Node will run. Installation works with `--ignore-scripts`.

For Git history, directories, archives, or the `betterleaks` command, install the [combined CLI and SDK package](https://www.npmjs.com/package/betterleaks).
