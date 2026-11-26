"""Windows CLI subprocess fallback powered by betterleaks-cli."""

from __future__ import annotations

import atexit
import contextlib
import json
import os
import subprocess
import threading
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple

from betterleaks._models import BetterleaksError, Finding
from betterleaks_cli import get_binary_path

_DEFAULT_MAX_INPUT_BYTES = 8 << 20
_MAX_INPUT_BYTES = 64 << 20
_DEFAULT_MAX_FINDINGS = 10_000
_MAX_FINDINGS = 100_000
_MAX_WORKERS = 1024
_SCANNER_CACHE_MAX_SIZE = 16

_ARCHIVE_EXTENSIONS = (
    ".zip",
    ".tar",
    ".gz",
    ".tgz",
    ".bz2",
    ".tbz2",
    ".xz",
    ".txz",
    ".zst",
    ".tzst",
    ".lz4",
    ".rar",
    ".7z",
    ".br",
    ".lz",
    ".sz",
    ".zz",
)

_ARCHIVE_MAGIC_PREFIXES = (
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"PK\x07\x08",
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"\x28\xb5\x2f\xfd",
    b"Rar!\x1a\x07",
    b"7z\xbc\xaf\x27\x1c",
    b'\x04"M\x18',
)


def _is_recognized_archive(file_path: str) -> bool:
    lower = file_path.lower()
    if lower.endswith(_ARCHIVE_EXTENSIONS):
        return True
    try:
        with open(file_path, "rb") as fh:
            head = fh.read(512)
    except OSError:
        return False
    if any(head.startswith(prefix) for prefix in _ARCHIVE_MAGIC_PREFIXES):
        return True
    # POSIX ustar tar magic at byte offset 257.
    return len(head) >= 263 and head[257:263] == b"ustar\x00"


def _validate_scanner_limits(
    workers: int,
    max_decode_depth: int,
    max_input_bytes: Optional[int],
    max_findings: Optional[int],
) -> Tuple[int, int]:
    if workers < 0 or workers > _MAX_WORKERS:
        raise BetterleaksError(f"workers must be between 0 and {_MAX_WORKERS}")
    if max_decode_depth < 0:
        raise BetterleaksError("max_decode_depth must be non-negative")
    effective_input = (
        _DEFAULT_MAX_INPUT_BYTES if max_input_bytes is None else max_input_bytes
    )
    if effective_input < 1 or effective_input > _MAX_INPUT_BYTES:
        raise BetterleaksError(
            f"max_input_bytes must be between 1 and {_MAX_INPUT_BYTES}"
        )
    effective_findings = _DEFAULT_MAX_FINDINGS if max_findings is None else max_findings
    if effective_findings < 1 or effective_findings > _MAX_FINDINGS:
        raise BetterleaksError(f"max_findings must be between 1 and {_MAX_FINDINGS}")
    return effective_input, effective_findings


class _CLIBacking:
    """Subprocess scanner using betterleaks_cli.get_binary_path()."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        config_toml: Optional[str] = None,
        workers: int = 0,
        max_decode_depth: int = 0,
        max_input_bytes: Optional[int] = None,
        max_findings: Optional[int] = None,
    ) -> None:
        if config_path is not None:
            if not config_path or "\x00" in config_path:
                raise BetterleaksError(
                    "config_path must be a non-empty path without NUL"
                )
            if config_toml is None and not os.path.isfile(config_path):
                raise BetterleaksError(
                    f"failed to load config from {config_path}: file not found"
                )
        effective_input, effective_findings = _validate_scanner_limits(
            workers, max_decode_depth, max_input_bytes, max_findings
        )
        self._config_path = config_path
        self._config_toml = config_toml
        self._workers = workers
        self._max_decode_depth = max_decode_depth
        self._max_input_bytes = effective_input
        self._max_findings = effective_findings
        self._closed = False
        self._lock = threading.Lock()

    def _ensure_open(self) -> None:
        with self._lock:
            if self._closed:
                raise BetterleaksError("Scanner is closed")

    def _build_env_and_args(self) -> Tuple[Dict[str, str], List[str]]:
        env = os.environ.copy()
        for var in (
            "BETTERLEAKS_VALIDATE",
            "BETTERLEAKS_ANALYZE",
            "BETTERLEAKS_CONFIG",
            "BETTERLEAKS_CONFIG_TOML",
        ):
            env.pop(var, None)

        args: List[str] = [
            f"--max-decode-depth={self._max_decode_depth}",
        ]
        if self._workers > 0:
            args.append(f"--jobs={self._workers}")

        if self._config_toml is not None:
            env["BETTERLEAKS_CONFIG_TOML"] = self._config_toml
        elif self._config_path:
            args.extend(["-c", self._config_path])
        return env, args

    def _parse_cli_output(self, proc: subprocess.CompletedProcess) -> Dict[str, Any]:
        if proc.returncode != 0:
            err = proc.stderr.decode("utf-8", errors="replace").strip()
            raise BetterleaksError(
                err or f"betterleaks CLI exited with status {proc.returncode}"
            )
        stdout = proc.stdout.decode("utf-8", errors="replace").strip()
        if not stdout:
            return {"findings": []}
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as err:
            raise BetterleaksError(f"Failed to parse CLI JSON output: {err}") from err
        if isinstance(payload, list):
            result: Dict[str, Any] = {"findings": payload}
        elif isinstance(payload, dict):
            result = payload
        else:
            raise BetterleaksError(
                "Unexpected JSON output structure from betterleaks CLI"
            )

        findings = result.get("findings") or []
        if len(findings) > self._max_findings:
            raise BetterleaksError("scan exceeds max_findings")
        return result

    def scan_string(
        self, content: str, attributes: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        self._ensure_open()
        encoded = content.encode("utf-8")
        if len(encoded) > self._max_input_bytes:
            raise BetterleaksError("input exceeds max_input_bytes")

        binary = get_binary_path()
        env, cfg_args = self._build_env_and_args()
        cmd = [
            binary,
            "stdin",
            "--exit-code=0",
            "--no-banner",
            "--no-color",
            "--log-level=error",
            "-o",
            "-",
            *cfg_args,
        ]
        if attributes:
            for k, v in attributes.items():
                cmd.extend(["--set-attr", f"{k}={v}"])
        proc = subprocess.run(
            cmd,
            input=encoded,
            env=env,
            capture_output=True,
            check=False,
        )
        return self._parse_cli_output(proc)

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        self._ensure_open()
        if not file_path or "\x00" in file_path:
            raise BetterleaksError("file_path must be a non-empty path without NUL")
        if not os.path.exists(file_path):
            raise BetterleaksError(f"failed to read file {file_path}: file not found")
        if not os.path.isfile(file_path):
            raise BetterleaksError("scan_file requires a regular file")
        if os.path.getsize(file_path) > self._max_input_bytes:
            raise BetterleaksError("file exceeds max_input_bytes")
        if _is_recognized_archive(file_path):
            raise BetterleaksError(
                "archive inputs are not supported by scan_file; use the CLI to scan archives"
            )

        binary = get_binary_path()
        env, cfg_args = self._build_env_and_args()
        cmd = [
            binary,
            file_path,
            "--exit-code=0",
            "--no-banner",
            "--no-color",
            "--log-level=error",
            "--max-archive-depth=0",
            "-o",
            "-",
            *cfg_args,
        ]
        proc = subprocess.run(
            cmd,
            env=env,
            capture_output=True,
            check=False,
        )
        data = self._parse_cli_output(proc)
        for finding in data.get("findings") or []:
            loc = finding.setdefault("location", {})
            reported = loc.get("path")
            if not reported or os.path.normpath(reported) == os.path.normpath(
                file_path
            ):
                loc["path"] = file_path
        return data

    def close(self) -> None:
        with self._lock:
            self._closed = True


_default_scanner: Optional[_CLIBacking] = None
_scanner_cache: OrderedDict[str, _CLIBacking] = OrderedDict()
_scanner_cache_lock = threading.Lock()


def get_cached_backing(config_path: Optional[str] = None) -> _CLIBacking:
    global _default_scanner
    if config_path is None:
        if _default_scanner is not None:
            return _default_scanner
        with _scanner_cache_lock:
            if _default_scanner is None:
                _default_scanner = _CLIBacking(config_path=None)
            return _default_scanner

    if not config_path or "\x00" in config_path:
        raise BetterleaksError("config_path must be a non-empty path without NUL")
    resolved_path = os.path.abspath(config_path)

    with _scanner_cache_lock:
        cached = _scanner_cache.get(resolved_path)
        if cached is not None:
            _scanner_cache.move_to_end(resolved_path)
            return cached

        backing = _CLIBacking(config_path=resolved_path)
        _scanner_cache[resolved_path] = backing
        while len(_scanner_cache) > _SCANNER_CACHE_MAX_SIZE:
            _, evicted = _scanner_cache.popitem(last=False)
            with contextlib.suppress(BetterleaksError, OSError):
                evicted.close()
        return backing


def _cleanup_cached_scanners() -> None:
    global _default_scanner
    with _scanner_cache_lock:
        scanners = list(_scanner_cache.values())
        _scanner_cache.clear()
        if _default_scanner is not None:
            scanners.append(_default_scanner)
            _default_scanner = None
    for scanner in scanners:
        with contextlib.suppress(BetterleaksError, OSError):
            scanner.close()


atexit.register(_cleanup_cached_scanners)


class Scanner:
    """Reusable Betterleaks scanner instance backed by the CLI binary (Windows)."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        config_toml: Optional[str] = None,
        workers: int = 0,
        max_decode_depth: int = 0,
        max_input_bytes: Optional[int] = None,
        max_findings: Optional[int] = None,
    ) -> None:
        self._backing = _CLIBacking(
            config_path=config_path,
            config_toml=config_toml,
            workers=workers,
            max_decode_depth=max_decode_depth,
            max_input_bytes=max_input_bytes,
            max_findings=max_findings,
        )

    def scan_string(
        self, content: str, attributes: Optional[Dict[str, str]] = None
    ) -> List[Finding]:
        """Scan a string for secrets and credentials."""
        resp = self._backing.scan_string(content, attributes=attributes)
        findings_data = resp.get("findings") or []
        return [Finding.from_dict(item) for item in findings_data]

    def scan_file(self, file_path: str) -> List[Finding]:
        """Scan a regular file for secrets and credentials."""
        resp = self._backing.scan_file(file_path)
        findings_data = resp.get("findings") or []
        return [Finding.from_dict(item) for item in findings_data]

    def close(self) -> None:
        """Release resources held by this scanner."""
        self._backing.close()

    def __enter__(self) -> Scanner:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


def create_scanner(
    config_path: Optional[str] = None,
    config_toml: Optional[str] = None,
    workers: int = 0,
    max_decode_depth: int = 0,
    max_input_bytes: Optional[int] = None,
    max_findings: Optional[int] = None,
) -> Scanner:
    """Create a configured reusable Betterleaks scanner."""
    return Scanner(
        config_path=config_path,
        config_toml=config_toml,
        workers=workers,
        max_decode_depth=max_decode_depth,
        max_input_bytes=max_input_bytes,
        max_findings=max_findings,
    )


def scan_string(content: str, config_path: Optional[str] = None) -> List[Finding]:
    """Scan a string for secrets and credentials."""
    backing = get_cached_backing(config_path=config_path)
    resp = backing.scan_string(content)
    findings_data = resp.get("findings") or []
    return [Finding.from_dict(item) for item in findings_data]


def scan_file(file_path: str, config_path: Optional[str] = None) -> List[Finding]:
    """Scan a file for secrets and credentials."""
    backing = get_cached_backing(config_path=config_path)
    resp = backing.scan_file(file_path)
    findings_data = resp.get("findings") or []
    return [Finding.from_dict(item) for item in findings_data]
