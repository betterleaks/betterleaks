"""Internal C ABI bindings for Betterleaks SDK (macOS and Linux)."""

from __future__ import annotations

import atexit
import contextlib
import ctypes
import json
import os
import sys
import threading
from typing import Any, Dict, Iterator, Optional

from betterleaks_sdk.models import BetterleaksError

_EXPECTED_ABI_VERSION = 1


class _BlBuffer(ctypes.Structure):
    _fields_ = [("data", ctypes.c_void_p), ("len", ctypes.c_size_t)]


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

    def _decode_report(self, buf: _BlBuffer) -> Dict[str, Any]:
        raw = self._decode_buffer(buf)
        try:
            report = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as err:
            raise BetterleaksError("Invalid JSON report from Betterleaks") from err
        if not isinstance(report, dict) or not isinstance(report.get("findings"), list):
            raise BetterleaksError("Betterleaks report is missing a findings array")
        return report

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
            return self._decode_report(res_buf)
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
            return self._decode_report(res_buf)
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
_default_lock = threading.Lock()


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
                name = "libbetterleaks_ffi.dylib" if sys.platform == "darwin" else "libbetterleaks_ffi.so"
                lib_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), name)
                try:
                    _native_lib_instance = _NativeLibrary(lib_path)
                except OSError as exc:
                    raise BetterleaksError(f"Could not load packaged native library {lib_path}: {exc}") from exc
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


@contextlib.contextmanager
def scan_backing(config_path: Optional[str] = None) -> Iterator[_NativeScannerBacking]:
    """Share the default scanner. Each custom-config call owns its scanner."""
    if config_path is not None:
        backing = create_backing(config_path=config_path)
        try:
            yield backing
        finally:
            backing.close()
        return

    global _default_scanner
    with _default_lock:
        if _default_scanner is None:
            _default_scanner = create_backing()
        backing = _default_scanner
    yield backing


@atexit.register
def _close_default() -> None:
    if _default_scanner is not None:
        _default_scanner.close()
