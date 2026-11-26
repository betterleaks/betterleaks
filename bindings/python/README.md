# betterleaks

Python bindings and CLI for [Betterleaks](https://github.com/betterleaks/betterleaks), the fast secret and credential detection engine written in Go.

A single `pip install betterleaks` installs the modular Betterleaks Python stack:
- **`betterleaks-cli`** — standalone Go CLI executable (`betterleaks git .`, `betterleaks filesystem .`, `betterleaks stdin`) across macOS, Linux, and Windows.
- **`betterleaks-sdk`** *(macOS & glibc Linux)* — fast in-process C ABI library (`bindings/c`).
- **`betterleaks`** — unified `import betterleaks` API (re-exporting `betterleaks_sdk` directly on macOS/Linux and falling back cleanly to `betterleaks_cli` on Windows).

If you only want the CLI or only the C ABI SDK, you can also install them individually:
- CLI only: `pip install betterleaks-cli` ([`cli/README.md`](cli/README.md))
- SDK only (macOS/Linux): `pip install betterleaks-sdk` ([`sdk/README.md`](sdk/README.md))

---

## Installation

```bash
pip install betterleaks
```

### Platform Support

| Platform | Architecture | CLI (`betterleaks`) | Python API (`scan_string` / `scan_file`) |
| --- | --- | --- | --- |
| macOS 12+ | ARM64 & x86-64 | Via `betterleaks-cli` | Native C ABI (`betterleaks-sdk`) |
| Linux (glibc) | x86-64 & ARM64 | Via `betterleaks-cli` | Native C ABI (`betterleaks-sdk`) |
| Windows | x86-64 | Via `betterleaks-cli` | CLI subprocess fallback (`betterleaks-cli`) |

### Building from Source

Installing all workspace packages from a repository checkout requires Python `>= 3.8`, Go `>= 1.26`, and a C compiler (for `betterleaks-sdk` on macOS/Linux):

```bash
git clone https://github.com/betterleaks/betterleaks.git
cd betterleaks
pip install ./bindings/python/cli ./bindings/python/sdk ./bindings/python
```

---

## Python Quickstart

All scan results are returned as strongly typed Python dataclasses (`Finding`, `Match`, `Location`) with full type annotations across `scan_string`, `scan_file`, and `Scanner`.

### Scanning Strings & Files

```python
from typing import List
import betterleaks
from betterleaks import BetterleaksError, Finding

content = """
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
"""

try:
    findings: List[Finding] = betterleaks.scan_string(content)
    for finding in findings:
        print(f"[{finding.rule_id}] Secret: {finding.secret}")
        print(f"  Confidence: {finding.confidence}")
        print(f"  Line: {finding.location.start_line}, Col: {finding.location.start_column}")
        print(f"  Fingerprint: {finding.match.fingerprint}")

        if finding.component_sets:
            print(f"  Correlated components: {len(finding.component_sets)}")

    file_findings: List[Finding] = betterleaks.scan_file("path/to/settings.env")
except BetterleaksError as err:
    print(f"Scan failed: {err}")
```

### Reusable Scanners & Custom Configuration

```python
from typing import List
import betterleaks
from betterleaks import Finding, Scanner

toml_rules = """
[extend]
useDefault = true

[[rules]]
id = "internal-token"
description = "Internal token"
regex = '''INTERNAL_[A-Z0-9]{16}'''
keywords = ["INTERNAL_"]
"""

scanner: Scanner
with betterleaks.create_scanner(config_toml=toml_rules) as scanner:
    findings: List[Finding] = scanner.scan_string(
        "token = INTERNAL_1234567890ABCDEF",
        attributes={"path": "config.env"},
    )
    file_findings: List[Finding] = scanner.scan_file("config.py")
```

---

## Public API & Typed Data Models

### Functions & Classes

| Symbol | Signature | Description |
| --- | --- | --- |
| `scan_string` | `(content: str, config_path: Optional[str] = None) -> List[Finding]` | Scan in-memory text using a cached scanner. |
| `scan_file` | `(file_path: str, config_path: Optional[str] = None) -> List[Finding]` | Scan a regular file using a cached scanner. |
| `create_scanner` | `(config_path: Optional[str] = None, config_toml: Optional[str] = None, workers: int = 0, max_decode_depth: int = 0, max_input_bytes: Optional[int] = None, max_findings: Optional[int] = None) -> Scanner` | Create a reusable `Scanner` context manager with custom rules and limits. |
| `Scanner` | `.scan_string(content: str, attributes: Optional[Dict[str, str]] = None) -> List[Finding]`<br>`.scan_file(file_path: str) -> List[Finding]`<br>`.close() -> None` | Handle-backed scanner supporting `with` statements. |
| `BetterleaksError` | `class BetterleaksError(Exception)` | Raised on invalid config, missing/non-regular files, limit errors, or runtime failures. |

### `Finding` (dataclass, `collections.abc.Mapping`)

| Attribute | Type | Description |
| --- | --- | --- |
| `rule_id` | `str` | Identifier of the triggered rule (e.g. `github-pat`, `aws-access-token`). |
| `description` | `str` | Description of the credential risk. |
| `confidence` | `str` | Detection confidence rating (`low`, `medium`, `high`). |
| `match` | `Match` | Match details (`full`, `value`, `fingerprint`, `line`, `captures`). |
| `location` | `Location` | Source coordinates (`path`, `start_line`, `end_line`, `start_column`, `end_column`). |
| `tags` | `List[str]` | Rule tags. |
| `raw` | `Dict[str, Any]` | Raw decoded JSON object for any additional engine fields. |
| `secret` *(property)* | `str` | Convenience alias for `match.value`. |
| `file` *(property)* | `Optional[str]` | Convenience alias for `location.path`. |
| `component_sets` *(property)* | `List[Dict[str, Any]]` | Correlated multi-part component findings. |
| `encodings` *(property)* | `List[str]` | Encodings detected during decode passes. |

`Finding` implements `collections.abc.Mapping` and supports both typed attribute access (`finding.rule_id`) and dictionary subscripting (`finding["rule_id"]`, `finding.to_dict()`).

### `Match` (dataclass)

| Attribute | Type | Default | Description |
| --- | --- | --- | --- |
| `full` | `str` | `""` | Full matched text including surrounding pattern context. |
| `value` | `str` | `""` | Extracted secret/credential value. |
| `fingerprint` | `Optional[str]` | `None` | Deterministic finding fingerprint. |
| `line` | `Optional[str]` | `None` | Matched line text, if included. |
| `captures` | `Dict[str, str]` | `{}` | Named regex capture groups. |

### `Location` (dataclass)

| Attribute | Type | Default | Description |
| --- | --- | --- | --- |
| `path` | `Optional[str]` | `None` | Target file path (populated by `scan_file`). |
| `start_line` | `int` | `0` | 1-based start line number. |
| `end_line` | `int` | `0` | 1-based end line number. |
| `start_column` | `int` | `0` | 1-based start byte column. |
| `end_column` | `int` | `0` | 1-based end byte column. |

---

## Benchmarks & Tests

See [docs/benchmarks.md](docs/benchmarks.md) and [scripts/bench.py](scripts/bench.py).

```bash
pytest -v bindings/python/tests
```

## License

MIT License. See [LICENSE](../../LICENSE) for details.
