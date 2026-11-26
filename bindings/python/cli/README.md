# betterleaks-cli

Standalone Python-packaged CLI distribution for [Betterleaks](https://github.com/betterleaks/betterleaks), the fast secret and credential detection engine written in Go.

This package ships **only** the compiled `betterleaks` CLI executable (`pip install betterleaks-cli`).
For the in-process Python SDK, install `betterleaks-sdk` or `betterleaks`.

---

## Installation

```bash
pip install betterleaks-cli
```

| Platform | Architecture | CLI (`betterleaks`) |
| --- | --- | --- |
| macOS 12+ | ARM64 & x86-64 | Bundled `betterleaks` binary |
| Linux (glibc) | x86-64 & ARM64 | Bundled `betterleaks` binary |
| Windows | x86-64 | Bundled `betterleaks.exe` binary |

### Building from Source

```bash
git clone https://github.com/betterleaks/betterleaks.git
cd betterleaks
pip install ./bindings/python/cli
```

---

## CLI Usage

```bash
betterleaks --version
betterleaks git .
betterleaks filesystem path/to/project
betterleaks stdin < file.txt
```

```python
from betterleaks_cli import get_binary_path

print(get_binary_path())
```

## License

MIT License. See [LICENSE](../../../LICENSE) for details.
