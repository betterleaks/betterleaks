# Benchmarks: Library vs. CLI Subprocess

The benchmark measures the installed SDK and CLI on the same workload. Warm runs reuse the native scanner. Cold runs include scanner initialization. The results depend on input size, rules and host.

| Mode | How it works |
|------|---|
| **Python library** (`betterleaks.scan_string` / `scan_file`) | On macOS and Linux, `betterleaks` re-exports `betterleaks_sdk`, loading the Go shared library (`libbetterleaks_ffi.so/.dylib`) **once** into the Python process via `ctypes`. |
| **CLI subprocess** (`subprocess.run(["betterleaks", ...])`) | Each call spawns `betterleaks-cli` as a brand-new OS process. |

The benchmark script lives in [`scripts/bench.py`](../scripts/bench.py).

```bash
pip install ./bindings/python/cli ./bindings/python/sdk ./bindings/python
python bindings/python/scripts/bench.py
```
