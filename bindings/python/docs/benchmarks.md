# Benchmarks: Library vs. CLI Subprocess

> **One-liner:** the in-process Python library is **1,000x - 10,000x faster than spawning the CLI via `subprocess.run()`** for repeated scans, and **~15-25% faster even on a single cold start**.

---

## Overview

Installing `betterleaks` provides both execution paths through its component packages:

| Mode | How it works |
|------|---|
| **Python library** (`betterleaks.scan_string` / `scan_file`) | On macOS and Linux, `betterleaks` re-exports `betterleaks_sdk`, loading the Go shared library (`libbetterleaks_ffi.so/.dylib`) **once** into the Python process via `ctypes`. |
| **CLI subprocess** (`subprocess.run(["betterleaks", ...])`) | Each call spawns `betterleaks-cli` as a brand-new OS process. |

The benchmark script lives in [`scripts/bench.py`](../scripts/bench.py).

```bash
pip install ./bindings/python/cli ./bindings/python/sdk ./bindings/python
python bindings/python/scripts/bench.py
```
