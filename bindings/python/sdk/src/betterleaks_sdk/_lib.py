"""Internal C ABI bindings for Betterleaks SDK (macOS and Linux)."""

from __future__ import annotations

import atexit
import contextlib
import ctypes
import json
import os
import platform
import sys
import threading
from collections import OrderedDict
from typing import Any, Dict, Iterator, List, Optional

from betterleaks_sdk.models import BetterleaksError

_EXPECTED_ABI_VERSION = 1
_SCANNER_CACHE_MAX_SIZE = 16


class _BlBuffer(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("len", ctypes.c_size_t)]


def _candidate_library_names() -> List[str]:
    system = platform.system().lower()
    if system == "darwin":
        return ["libbetterleaks_ffi.dylib", "libbetterleaks_ffi.so"]
    return ["libbetterleaks_ffi.so"]


def _native_target_dir_name() -> Optional[str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin":
        return (
            "aarch64-apple-darwin"
            if machine in ("arm64", "aarch64")
            else "x86_64-apple-darwin"
        )
    if system == "linux":
        return (
            "aarch64-unknown-linux-gnu"
            if machine in ("arm64", "aarch64")
            else "x86_64-unknown-linux-gnu"
        )
    return None


def _find_library() -> Optional[str]:
    """Locate the compiled Betterleaks FFI shared library, or None if unavailable."""
    custom_path = os.environ.get("BETTERLEAKS_LIB_PATH")
    if custom_path:
        if os.path.isfile(custom_path):
            return custom_path
        raise BetterleaksError(
            f"BETTERLEAKS_LIB_PATH points to a missing file: {custom_path}"
        )

    candidate_names = _candidate_library_names()

    custom_dir = os.environ.get("BETTERLEAKS_LIB_DIR")
    if custom_dir:
        for name in candidate_names:
            candidate = os.path.join(custom_dir, name)
            if os.path.isfile(candidate):
                return candidate
        raise BetterleaksError(
            f"Could not find {candidate_names} in BETTERLEAKS_LIB_DIR={custom_dir}"
        )

    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    for name in candidate_names:
        candidate = os.path.join(pkg_dir, name)
        if os.path.isfile(candidate):
            return candidate

    target = _native_target_dir_name()
    if target:
        repo_root = os.path.abspath(os.path.join(pkg_dir, "..", "..", "..", "..", ".."))
        for name in candidate_names:
            candidate = os.path.join(repo_root, "dist", "native", target, "lib", name)
            if os.path.isfile(candidate):
                return candidate

    return None


class _NativeLibrary:
    """Thin ctypes wrapper around bindings/c/betterleaks.h."""

    def __init__(self, lib_path: str) -> None:
        self._lib = ctypes.CDLL(lib_path)

        self._lib.bl_abi_version.argtypes = []
        self._lib.bl_abi_version.restype = ctypes.c_uint32

        self._lib.bl_scanner_new.argtypes = [
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint64),
            ctypes.POINTER(_BlBuffer),
        ]
        self._lib.bl_scanner_new.restype = ctypes.c_int32

        self._lib.bl_scanner_scan.argtypes = [
            ctypes.c_uint64,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(_BlBuffer),
            ctypes.POINTER(_BlBuffer),
        ]
        self._lib.bl_scanner_scan.restype = ctypes.c_int32

        self._lib.bl_scanner_scan_file.argtypes = [
            ctypes.c_uint64,
            ctypes.c_char_p,
            ctypes.c_size_t,
            ctypes.POINTER(_BlBuffer),
            ctypes.POINTER(_BlBuffer),
        ]
        self._lib.bl_scanner_scan_file.restype = ctypes.c_int32

        self._lib.bl_scanner_free.argtypes = [ctypes.c_uint64]
        self._lib.bl_scanner_free.restype = ctypes.c_int32

        self._lib.bl_buffer_free.argtypes = [_BlBuffer]
        self._lib.bl_buffer_free.restype = None

        abi = self._lib.bl_abi_version()
        if abi != _EXPECTED_ABI_VERSION:
            raise BetterleaksError(
                f"Incompatible Betterleaks native ABI version: expected {_EXPECTED_ABI_VERSION}, got {abi}"
            )

    @staticmethod
    def _decode_buffer(buf: _BlBuffer) -> bytes:
        if not buf.data or buf.len == 0:
            return b""
        return ctypes.string_at(buf.data, buf.len)

    def _raise_error(self, status: int, err_buf: _BlBuffer) -> None:
        raw = self._decode_buffer(err_buf)
        msg = raw.decode("utf-8", errors="replace").strip() if raw else ""
        raise BetterleaksError(msg or f"Betterleaks native error (status {status})")

    def new_scanner(self, options_json: Optional[bytes]) -> int:
        handle = ctypes.c_uint64()
        err_buf = _BlBuffer()
        try:
            opt_ptr = options_json if options_json else None
            opt_len = len(options_json) if options_json else 0
            status = self._lib.bl_scanner_new(
                opt_ptr, opt_len, ctypes.byref(handle), ctypes.byref(err_buf)
            )
            if status != 0:
                self._raise_error(status, err_buf)
            return int(handle.value)
        finally:
            self._lib.bl_buffer_free(err_buf)

    def scan_bytes(
        self,
        handle: int,
        data: bytes,
        attributes_json: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        res_buf = _BlBuffer()
        err_buf = _BlBuffer()
        try:
            data_ptr = data if data else None
            data_len = len(data)
            attr_ptr = attributes_json if attributes_json else None
            attr_len = len(attributes_json) if attributes_json else 0
            status = self._lib.bl_scanner_scan(
                handle,
                data_ptr,
                data_len,
                attr_ptr,
                attr_len,
                ctypes.byref(res_buf),
                ctypes.byref(err_buf),
            )
            if status != 0:
                self._raise_error(status, err_buf)
            raw = self._decode_buffer(res_buf)
            if not raw:
                raise BetterleaksError("Empty response from Betterleaks native library")
            try:
                return json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as err:
                raise BetterleaksError(
                    f"Failed to parse response from Betterleaks library: {err}"
                ) from err
        finally:
            self._lib.bl_buffer_free(res_buf)
            self._lib.bl_buffer_free(err_buf)

    def scan_file(self, handle: int, path_bytes: bytes) -> Dict[str, Any]:
        res_buf = _BlBuffer()
        err_buf = _BlBuffer()
        try:
            status = self._lib.bl_scanner_scan_file(
                handle,
                path_bytes,
                len(path_bytes),
                ctypes.byref(res_buf),
                ctypes.byref(err_buf),
            )
            if status != 0:
                self._raise_error(status, err_buf)
            raw = self._decode_buffer(res_buf)
            if not raw:
                raise BetterleaksError("Empty response from Betterleaks native library")
            try:
                return json.loads(raw.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError) as err:
                raise BetterleaksError(
                    f"Failed to parse response from Betterleaks library: {err}"
                ) from err
        finally:
            self._lib.bl_buffer_free(res_buf)
            self._lib.bl_buffer_free(err_buf)

    def free_scanner(self, handle: int) -> None:
        self._lib.bl_scanner_free(handle)


class _NativeScannerBacking:
    """Handle-backed native scanner wrapping bindings/c."""

    def __init__(
        self,
        lib: _NativeLibrary,
        config_path: Optional[str] = None,
        config_toml: Optional[str] = None,
        workers: int = 0,
        max_decode_depth: int = 0,
        max_input_bytes: Optional[int] = None,
        max_findings: Optional[int] = None,
    ) -> None:
        options: Dict[str, Any] = {}
        if config_toml is not None:
            options["config_toml"] = config_toml
        if config_path is not None:
            if not config_path or "\x00" in config_path:
                raise BetterleaksError(
                    "config_path must be a non-empty path without NUL"
                )
            options["config_path"] = config_path
        if workers:
            options["workers"] = workers
        if max_decode_depth:
            options["max_decode_depth"] = max_decode_depth
        if max_input_bytes is not None:
            options["max_input_bytes"] = max_input_bytes
        if max_findings is not None:
            options["max_findings"] = max_findings

        options_bytes = json.dumps(options).encode("utf-8") if options else None
        self._lib = lib
        self._handle: Optional[int] = lib.new_scanner(options_bytes)
        self._lock = threading.RLock()

    def scan_string(
        self, content: str, attributes: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        encoded = content.encode("utf-8")
        attr_bytes = json.dumps(attributes).encode("utf-8") if attributes else None
        with self._lock:
            if self._handle is None:
                raise BetterleaksError("Scanner is closed")
            return self._lib.scan_bytes(self._handle, encoded, attr_bytes)

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        if not file_path or "\x00" in file_path:
            raise BetterleaksError("file_path must be a non-empty path without NUL")
        encoded_path = os.fsencode(file_path)
        with self._lock:
            if self._handle is None:
                raise BetterleaksError("Scanner is closed")
            return self._lib.scan_file(self._handle, encoded_path)

    def close(self) -> None:
        with self._lock:
            if self._handle is not None:
                handle = self._handle
                self._handle = None
                self._lib.free_scanner(handle)

    def __del__(self) -> None:
        if (
            getattr(self, "_handle", None) is not None
            and getattr(self, "_lib", None) is not None
        ):
            with contextlib.suppress(BetterleaksError, OSError, ctypes.ArgumentError):
                self.close()


_native_lib_instance: Optional[_NativeLibrary] = None
_native_lib_lock = threading.Lock()

_default_scanner: Optional[_NativeScannerBacking] = None
_scanner_cache: OrderedDict[str, _NativeScannerBacking] = OrderedDict()
_active_leases: Dict[int, int] = {}
_evicted_pending: Dict[int, _NativeScannerBacking] = {}
_scanner_cache_lock = threading.Lock()


def _get_native_library() -> _NativeLibrary:
    if sys.platform == "win32":
        raise BetterleaksError(
            "betterleaks-sdk supports macOS and glibc Linux only; Windows is not supported. "
            "Install 'betterleaks' or 'betterleaks-cli' on Windows."
        )

    global _native_lib_instance
    if _native_lib_instance is None:
        with _native_lib_lock:
            if _native_lib_instance is None:
                lib_path = _find_library()
                if not lib_path:
                    raise BetterleaksError(
                        "Could not find Betterleaks native shared library "
                        f"({_candidate_library_names()}). "
                        "Build the native library or set BETTERLEAKS_LIB_PATH / BETTERLEAKS_LIB_DIR."
                    )
                _native_lib_instance = _NativeLibrary(lib_path)
    return _native_lib_instance


def create_backing(
    config_path: Optional[str] = None,
    config_toml: Optional[str] = None,
    workers: int = 0,
    max_decode_depth: int = 0,
    max_input_bytes: Optional[int] = None,
    max_findings: Optional[int] = None,
) -> _NativeScannerBacking:
    lib = _get_native_library()
    return _NativeScannerBacking(
        lib,
        config_path=config_path,
        config_toml=config_toml,
        workers=workers,
        max_decode_depth=max_decode_depth,
        max_input_bytes=max_input_bytes,
        max_findings=max_findings,
    )


def _acquire_cached_backing(
    config_path: Optional[str] = None,
) -> _NativeScannerBacking:
    global _default_scanner
    if config_path is None:
        with _scanner_cache_lock:
            if _default_scanner is None:
                _default_scanner = create_backing(config_path=None)
            key = id(_default_scanner)
            _active_leases[key] = _active_leases.get(key, 0) + 1
            return _default_scanner

    if not config_path or "\x00" in config_path:
        raise BetterleaksError("config_path must be a non-empty path without NUL")
    resolved_path = os.path.abspath(config_path)

    evicted_idle: List[_NativeScannerBacking] = []
    with _scanner_cache_lock:
        cached = _scanner_cache.get(resolved_path)
        if cached is not None:
            _scanner_cache.move_to_end(resolved_path)
            backing = cached
        else:
            backing = create_backing(config_path=resolved_path)
            _scanner_cache[resolved_path] = backing
            _active_leases[id(backing)] = 0
            while len(_scanner_cache) > _SCANNER_CACHE_MAX_SIZE:
                _, evicted = _scanner_cache.popitem(last=False)
                ev_key = id(evicted)
                if _active_leases.get(ev_key, 0) == 0:
                    _active_leases.pop(ev_key, None)
                    evicted_idle.append(evicted)
                else:
                    _evicted_pending[ev_key] = evicted

        b_key = id(backing)
        _active_leases[b_key] = _active_leases.get(b_key, 0) + 1

    for scanner in evicted_idle:
        with contextlib.suppress(BetterleaksError, OSError, ctypes.ArgumentError):
            scanner.close()
    return backing


def _release_cached_backing(backing: _NativeScannerBacking) -> None:
    pending: Optional[_NativeScannerBacking] = None
    with _scanner_cache_lock:
        key = id(backing)
        remaining = _active_leases.get(key, 0) - 1
        if remaining <= 0:
            _active_leases.pop(key, None)
            pending = _evicted_pending.pop(key, None)
        else:
            _active_leases[key] = remaining

    if pending is not None:
        with contextlib.suppress(BetterleaksError, OSError, ctypes.ArgumentError):
            pending.close()


@contextlib.contextmanager
def use_cached_backing(
    config_path: Optional[str] = None,
) -> Iterator[_NativeScannerBacking]:
    backing = _acquire_cached_backing(config_path=config_path)
    try:
        yield backing
    finally:
        _release_cached_backing(backing)


def get_cached_backing(config_path: Optional[str] = None) -> _NativeScannerBacking:
    global _default_scanner
    if config_path is None:
        if _default_scanner is not None:
            return _default_scanner
        with _scanner_cache_lock:
            if _default_scanner is None:
                _default_scanner = create_backing(config_path=None)
            return _default_scanner

    if not config_path or "\x00" in config_path:
        raise BetterleaksError("config_path must be a non-empty path without NUL")
    resolved_path = os.path.abspath(config_path)

    evicted_idle: List[_NativeScannerBacking] = []
    with _scanner_cache_lock:
        cached = _scanner_cache.get(resolved_path)
        if cached is not None:
            _scanner_cache.move_to_end(resolved_path)
            return cached

        backing = create_backing(config_path=resolved_path)
        _scanner_cache[resolved_path] = backing
        _active_leases[id(backing)] = 0
        while len(_scanner_cache) > _SCANNER_CACHE_MAX_SIZE:
            _, evicted = _scanner_cache.popitem(last=False)
            ev_key = id(evicted)
            if _active_leases.get(ev_key, 0) == 0:
                _active_leases.pop(ev_key, None)
                evicted_idle.append(evicted)
            else:
                _evicted_pending[ev_key] = evicted

    for scanner in evicted_idle:
        with contextlib.suppress(BetterleaksError, OSError, ctypes.ArgumentError):
            scanner.close()
    return backing


def _cleanup_cached_scanners() -> None:
    global _default_scanner
    with _scanner_cache_lock:
        scanners = list(_scanner_cache.values())
        _scanner_cache.clear()
        scanners.extend(_evicted_pending.values())
        _evicted_pending.clear()
        _active_leases.clear()
        if _default_scanner is not None:
            scanners.append(_default_scanner)
            _default_scanner = None
    for scanner in scanners:
        with contextlib.suppress(BetterleaksError, OSError, ctypes.ArgumentError):
            scanner.close()


atexit.register(_cleanup_cached_scanners)
