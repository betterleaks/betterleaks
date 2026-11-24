# Betterleaks

Find leaked credentials in text, files, and Git history. The `betterleaks` npm package includes the Betterleaks CLI and an in-process scanner for Node.js.

## Install the v2 release candidate

```sh
npm install betterleaks@next
```

npm installs the prebuilt binary for your platform through an exact-version optional dependency. Keep optional dependencies enabled. Installation works with `--ignore-scripts` and requires no compiler or Go installation.

## Scan from Node.js

```js
import { scanFile, scanText } from "betterleaks";

const text = await scanText("hello world");
console.log(text.summary.findings); // 0

const report = await scanFile("settings.env");
for (const finding of report.findings) {
  console.log(finding.rule_id, finding.location.path, finding.location.start_line);
}
```

CommonJS supports `const { scanText, scanFile } = require("betterleaks")`. TypeScript declarations are included.

Try the [runnable Node.js example](https://github.com/betterleaks/betterleaks/blob/main/examples/node/scan.mjs) in a project with `betterleaks` installed. Run `node scan.mjs` to scan a synthetic token or `node scan.mjs settings.env` to scan a file.

Both functions return a promise and run the scan off the JavaScript thread using the built-in rules. A scan with no matches resolves with an empty `findings` array. File reads, invalid input, and scan limits can reject the promise. The default limits are 8 MiB of input and 10,000 findings per scan. Findings can contain raw credentials in `match.value` and `match.full`. Log rule IDs and locations when reporting detections.

`scanFile(path)` accepts one local regular file and applies filesystem rules. Use the CLI to scan directories, archives, or Git history.

## Run the CLI

```sh
npx betterleaks --version
npx betterleaks git .
```

| Platform (x64 and arm64) | CLI | Node.js API |
| --- | --- | --- |
| macOS | Yes | macOS 12+ |
| Linux | Yes | glibc 2.35+ |
| Windows | Yes | — |

See the [Betterleaks project](https://github.com/betterleaks/betterleaks) for rule configuration, scan sources, and CLI usage.
