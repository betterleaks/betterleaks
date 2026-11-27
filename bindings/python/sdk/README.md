# betterleaks-sdk

Native in-process Python SDK for [Betterleaks](https://github.com/betterleaks/betterleaks), powered by Go (`bindings/c`).

`pip install betterleaks-sdk` installs **only** the C ABI shared library and Python bindings (`import betterleaks_sdk`) on macOS and glibc Linux — no CLI binary is bundled, and Windows is not supported.

For the full bundle (Python SDK + `betterleaks` CLI), install [`betterleaks`](https://github.com/betterleaks/betterleaks/blob/main/bindings/python/README.md). For the standalone CLI binary, install [`betterleaks-cli`](https://github.com/betterleaks/betterleaks/blob/main/bindings/python/cli/README.md).

---

## Installation

```bash
pip install betterleaks-sdk
```

### Platform Support

| Platform | Architecture | Python API (`scan_string` / `scan_file`) |
| --- | --- | --- |
| macOS 12+ | ARM64 & x86-64 | Native C ABI (`libbetterleaks_ffi.dylib`) |
| Linux (glibc) | x86-64 & ARM64 | Native C ABI (`libbetterleaks_ffi.so`) |
| Windows | — | **Not supported** (install `betterleaks` or `betterleaks-cli` instead) |

### Building from Source

```bash
git clone https://github.com/betterleaks/betterleaks.git
cd betterleaks
pip install ./bindings/python/sdk
```

---

## Quickstart & Typed Data Models

All scan results are returned as strongly typed Python dataclasses (`Finding`, `Match`, `Location`) with `collections.abc.Mapping` compatibility:

```python
from typing import List
import betterleaks_sdk
from betterleaks_sdk import BetterleaksError, Finding

try:
    findings: List[Finding] = betterleaks_sdk.scan_string(
        "GITHUB_TOKEN=ghp_example..."
    )
    for finding in findings:
        print(finding.rule_id, finding.location.start_line)
except BetterleaksError as err:
    print(f"Scan failed: {err}")
```

Use `scanner.scan_string_report(text)` or `scanner.scan_file_report(path)` to obtain the full engine report, including `engine_version`, `config_hash`, and `summary`. The existing scan methods return typed findings.

## License

MIT License. See [LICENSE](https://github.com/betterleaks/betterleaks/blob/main/LICENSE) for details.
