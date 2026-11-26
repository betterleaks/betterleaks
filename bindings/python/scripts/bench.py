"""
Betterleaks Python Benchmark Suite
==================================

Compares two execution modes:
  1. Python Library  – in-process C ABI / ctypes (betterleaks.scan_string / scan_file)
  2. Subprocess CLI  – subprocess.run(["betterleaks", ...]) from Python

Run modes:
  python bindings/python/scripts/bench.py          # hot-run benchmark (default)
  python bindings/python/scripts/bench.py --cold   # cold-run benchmark (fresh process per call)
"""

from __future__ import annotations

import argparse
import gc
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List

_PY_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _find_cli_binary() -> str:
    which_cli = shutil.which("betterleaks")
    if which_cli:
        return which_cli
    try:
        from betterleaks_cli import get_binary_path

        return get_binary_path()
    except ImportError:
        bin_name = "betterleaks.exe" if sys.platform == "win32" else "betterleaks"
        return os.path.join(_PY_ROOT, "cli", "src", "betterleaks_cli", "bin", bin_name)


CLI_PATH = _find_cli_binary()

# Tokens constructed dynamically so static push-protection is not triggered.
_GH_TOKEN = "gh" + "p_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5"
_SLACK_TOKEN = "xo" + "xb-123456789012-1234567890123-123456789012345678901234"


def _generate_code(size_bytes: int, secret_density: str = "none") -> str:
    clean_block = (
        "def process_transaction(record_id: str, payload: dict) -> dict:\n"
        "    # Validate and transform the incoming record.\n"
        "    if not record_id or not payload:\n"
        "        raise ValueError('Invalid transaction payload')\n"
        "    normalized = {k.strip().lower(): v for k, v in payload.items()}\n"
        "    return {'status': 'processed', 'data': normalized}\n\n"
    )

    if secret_density == "pathological":
        secret_block = f"GITHUB_TOKEN = '{_GH_TOKEN}'\nSLACK_BOT = '{_SLACK_TOKEN}'\n"
        unit = clean_block + secret_block
        return (unit * max(1, size_bytes // len(unit)))[:size_bytes]

    code = (clean_block * max(1, size_bytes // len(clean_block)))[:size_bytes]

    if secret_density == "realistic":
        mid = len(code) // 2
        code = code[:mid] + f"\nAPI_KEY = '{_GH_TOKEN}'\n" + code[mid:]

    return code


def _check_cli() -> None:
    if not os.path.isfile(CLI_PATH):
        sys.exit(
            f"ERROR: CLI binary not found at {CLI_PATH}\n"
            "Install the packages first: pip install ./bindings/python/cli ./bindings/python/sdk ./bindings/python"
        )


def _cli_stdin(content: str) -> List[Dict[str, Any]]:
    proc = subprocess.run(
        [
            CLI_PATH,
            "stdin",
            "--exit-code=0",
            "--no-banner",
            "--no-color",
            "--log-level=error",
            "-o",
            "-",
        ],
        input=content.encode(),
        capture_output=True,
        check=False,
    )
    return json.loads(proc.stdout).get("findings", [])


def _cli_file(path: str) -> List[Dict[str, Any]]:
    proc = subprocess.run(
        [
            CLI_PATH,
            path,
            "--exit-code=0",
            "--no-banner",
            "--no-color",
            "--log-level=error",
            "-o",
            "-",
        ],
        capture_output=True,
        check=False,
    )
    return json.loads(proc.stdout).get("findings", [])


def _measure(
    fn: Callable[[], Any], iterations: int, warmup: int = 2
) -> Dict[str, float]:
    for _ in range(warmup):
        fn()

    times: List[float] = []
    gc.disable()
    try:
        for _ in range(iterations):
            t0 = time.perf_counter()
            fn()
            times.append((time.perf_counter() - t0) * 1000.0)
    finally:
        gc.enable()

    s = sorted(times)

    def _pct(p: float) -> float:
        return s[min(int(len(s) * p), len(s) - 1)]

    return {
        "mean_ms": statistics.mean(times),
        "median_ms": _pct(0.50),
        "p95_ms": _pct(0.95),
        "min_ms": s[0],
        "max_ms": s[-1],
        "iterations": iterations,
    }


_LIB_SNIPPET = """\
import time, sys, json
content = sys.stdin.read()
t0 = time.perf_counter()
import betterleaks
t1 = time.perf_counter()
findings = betterleaks.scan_string(content)
t2 = time.perf_counter()
print(json.dumps({
    "import_ms": (t1 - t0) * 1000.0,
    "scan_ms": (t2 - t1) * 1000.0,
    "in_py_total_ms": (t2 - t0) * 1000.0,
}))
"""


def _mk_cli_snippet(cli_path: str) -> str:
    return f"""\
import time, sys, json, subprocess
content = sys.stdin.read()
t0 = time.perf_counter()
proc = subprocess.run(
    [{json.dumps(cli_path)}, "stdin", "--exit-code=0", "--no-banner", "--no-color", "--log-level=error", "-o", "-"],
    input=content.encode("utf-8"),
    capture_output=True,
    check=True,
)
t1 = time.perf_counter()
json.loads(proc.stdout)
t2 = time.perf_counter()
print(json.dumps({{
    "subproc_ms": (t1 - t0) * 1000.0,
    "parse_ms": (t2 - t1) * 1000.0,
    "in_py_total_ms": (t2 - t0) * 1000.0,
}}))
"""


def _cold_lib(content: str) -> Dict[str, float]:
    t0 = time.perf_counter()
    p = subprocess.run(
        [sys.executable, "-c", _LIB_SNIPPET],
        input=content,
        capture_output=True,
        text=True,
        check=True,
    )
    wall = (time.perf_counter() - t0) * 1000.0
    res = json.loads(p.stdout.strip())
    res["wall_clock_ms"] = wall
    return res


def _cold_cli_subproc(content: str, cli_snippet: str) -> Dict[str, float]:
    t0 = time.perf_counter()
    p = subprocess.run(
        [sys.executable, "-c", cli_snippet],
        input=content,
        capture_output=True,
        text=True,
        check=True,
    )
    wall = (time.perf_counter() - t0) * 1000.0
    res = json.loads(p.stdout.strip())
    res["wall_clock_ms"] = wall
    return res


def _cold_cli_direct(content: str) -> float:
    t0 = time.perf_counter()
    subprocess.run(
        [
            CLI_PATH,
            "stdin",
            "--exit-code=0",
            "--no-banner",
            "--no-color",
            "--log-level=error",
            "-o",
            "-",
        ],
        input=content.encode(),
        capture_output=True,
        check=True,
    )
    return (time.perf_counter() - t0) * 1000.0


def _pct(series: List[float], p: float) -> float:
    s = sorted(series)
    return s[min(int(len(s) * p), len(s) - 1)]


def run_hot_benchmark() -> None:
    import betterleaks

    print("=" * 90)
    print("BETTERLEAKS HOT-RUN BENCHMARK")
    print(f"  Library version : {betterleaks.__version__}")
    print(f"  CLI binary      : {CLI_PATH}")
    print("=" * 90)

    workloads = [
        (
            "Single String (~100 B, 1 secret)",
            f"const token = '{_GH_TOKEN}';",
            "string",
            30,
        ),
        ("Single String (~100 B, clean)", "No credentials here at all.", "string", 30),
        (
            "Medium String (~50 KB, 1 secret)",
            _generate_code(50 * 1024, "realistic"),
            "string",
            20,
        ),
        (
            "Large String (~1 MB, 1 secret)",
            _generate_code(1024 * 1024, "realistic"),
            "string",
            15,
        ),
        (
            "Large String (~1 MB, clean)",
            _generate_code(1024 * 1024, "none"),
            "string",
            15,
        ),
        ("File on Disk (~100 KB, 1 secret)", None, "file", 20),
        ("Batch: 20 files × 10 KB (sequential)", None, "batch", 5),
    ]

    results = []

    for name, payload, wtype, iters in workloads:
        print(f"  Running : {name}  ({iters} iters)...")
        tmp_files: List[str] = []

        try:
            if wtype == "file":
                with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
                    f.write(_generate_code(100 * 1024, "realistic"))
                    tmp_files.append(f.name)
                content_path = tmp_files[0]
                res_lib = _measure(
                    lambda cp=content_path: betterleaks.scan_file(cp), iters
                )
                res_cli = _measure(lambda cp=content_path: _cli_file(cp), iters)

            elif wtype == "batch":
                for i in range(20):
                    density = "realistic" if i % 4 == 0 else "none"
                    with tempfile.NamedTemporaryFile(
                        "w", suffix=f"_{i}.py", delete=False
                    ) as f:
                        f.write(_generate_code(10 * 1024, density))
                        tmp_files.append(f.name)

                batch_files = list(tmp_files)

                def _batch_lib(files=batch_files):
                    for fp in files:
                        betterleaks.scan_file(fp)

                def _batch_cli(files=batch_files):
                    for fp in files:
                        _cli_file(fp)

                res_lib = _measure(_batch_lib, iters)
                res_cli = _measure(_batch_cli, iters)

            else:
                res_lib = _measure(lambda p=payload: betterleaks.scan_string(p), iters)  # type: ignore[arg-type]
                res_cli = _measure(lambda p=payload: _cli_stdin(p), iters)  # type: ignore[arg-type]

        finally:
            for fp in tmp_files:
                if os.path.exists(fp):
                    os.remove(fp)

        speedup = (
            res_cli["mean_ms"] / res_lib["mean_ms"] if res_lib["mean_ms"] > 0 else 0
        )
        results.append((name, res_lib, res_cli, speedup))

    w = 36
    print("\n" + "=" * 105)
    print(
        f"{'Workload':<{w}} | {'Lib Mean':>10} | {'CLI Mean':>10} | {'Speedup':>9} | {'Lib p95':>9} | {'CLI p95':>9}"
    )
    print("-" * 105)
    for name, r_lib, r_cli, spd in results:
        print(
            f"{name:<{w}} | {r_lib['mean_ms']:>8.2f}ms | {r_cli['mean_ms']:>8.2f}ms"
            f" | {spd:>8.1f}x | {r_lib['p95_ms']:>7.2f}ms | {r_cli['p95_ms']:>7.2f}ms"
        )
    print("=" * 105)


def run_cold_benchmark(num_runs: int = 100) -> None:
    cli_snippet = _mk_cli_snippet(CLI_PATH)
    content = f"const token = '{_GH_TOKEN}';\n"

    print("=" * 90)
    print(f"BETTERLEAKS COLD-RUN BENCHMARK  ({num_runs} iterations)")
    print(f"  CLI binary : {CLI_PATH}")
    print("=" * 90)

    lib_total: List[float] = []
    lib_imports: List[float] = []
    lib_scans: List[float] = []
    sub_total: List[float] = []
    direct_total: List[float] = []
    lib_wins_sub = 0
    lib_wins_direct = 0

    for i in range(1, num_runs + 1):
        r_lib = _cold_lib(content)
        r_sub = _cold_cli_subproc(content, cli_snippet)
        t_direct = _cold_cli_direct(content)

        lib_total.append(r_lib["in_py_total_ms"])
        lib_imports.append(r_lib["import_ms"])
        lib_scans.append(r_lib["scan_ms"])
        sub_total.append(r_sub["in_py_total_ms"])
        direct_total.append(t_direct)

        if r_lib["in_py_total_ms"] < r_sub["in_py_total_ms"]:
            lib_wins_sub += 1
        if r_lib["in_py_total_ms"] < t_direct:
            lib_wins_direct += 1

        if i % 20 == 0:
            print(f"  {i}/{num_runs} iterations completed...")

    def _stats(series: List[float]) -> Dict[str, float]:
        s = sorted(series)
        return {
            "mean": statistics.mean(series),
            "median": statistics.median(series),
            "stddev": statistics.stdev(series),
            "min": s[0],
            "max": s[-1],
            "p90": _pct(series, 0.90),
            "p95": _pct(series, 0.95),
            "p99": _pct(series, 0.99),
        }

    s_lib = _stats(lib_total)
    s_sub = _stats(sub_total)
    s_dir = _stats(direct_total)

    print("\n" + "=" * 90)
    print("STATISTICAL SUMMARY  (all times in ms)")
    print("=" * 90)
    print(
        f"{'Metric':<18} | {'Lib (in-Python)':>18} | {'CLI Subprocess':>16} | {'CLI Direct OS':>15}"
    )
    print("-" * 90)
    for metric in ("mean", "median", "stddev", "min", "max", "p90", "p95", "p99"):
        print(
            f"{metric:<18} | {s_lib[metric]:>16.2f}ms | {s_sub[metric]:>14.2f}ms | {s_dir[metric]:>13.2f}ms"
        )
    print("=" * 90)
    print(
        f"  Lib faster than CLI Subprocess : {lib_wins_sub}/{num_runs} ({lib_wins_sub / num_runs * 100:.1f}%)"
    )
    print(
        f"  Lib faster than Direct CLI     : {lib_wins_direct}/{num_runs} ({lib_wins_direct / num_runs * 100:.1f}%)"
    )


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="betterleaks Python benchmark: in-process library vs subprocess CLI.",
    )
    parser.add_argument(
        "--cold",
        action="store_true",
        help="Run cold-start benchmark (each call in a fresh OS process).",
    )
    parser.add_argument(
        "--cold-runs",
        type=int,
        default=100,
        metavar="N",
        help="Number of cold-run iterations (default: 100).",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    _check_cli()

    if args.cold:
        run_cold_benchmark(num_runs=args.cold_runs)
    else:
        run_hot_benchmark()


if __name__ == "__main__":
    main()
