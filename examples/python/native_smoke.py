"""Smoke-test the Betterleaks C ABI using only Python's standard library."""

import ctypes as c
import hashlib
import json
import os
import tempfile
from pathlib import Path


class Buffer(c.Structure):
    _fields_ = [("data", c.c_void_p), ("length", c.c_size_t)]


def main():
    lib_dir = Path(os.environ["BETTERLEAKS_LIB_DIR"])
    manifest = json.loads((lib_dir / "betterleaks-native.json").read_text())
    library = (lib_dir / manifest["shared_library"]).resolve()
    digest = hashlib.sha256()
    with library.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if digest.hexdigest() != manifest["shared_sha256"]:
        raise ValueError("shared library checksum differs from the build manifest")
    lib = c.CDLL(str(library))
    handle = c.c_uint64()
    out = c.POINTER(Buffer)
    lib.bl_abi_version.argtypes = []
    lib.bl_abi_version.restype = c.c_uint32
    lib.bl_scanner_new.argtypes = [c.c_char_p, c.c_size_t, c.POINTER(c.c_uint64), out]
    lib.bl_scanner_new.restype = c.c_int32
    lib.bl_scanner_scan.argtypes = [
        c.c_uint64, c.c_char_p, c.c_size_t, c.c_char_p, c.c_size_t, out, out
    ]
    lib.bl_scanner_scan.restype = c.c_int32
    lib.bl_scanner_scan_file.argtypes = [c.c_uint64, c.c_char_p, c.c_size_t, out, out]
    lib.bl_scanner_scan_file.restype = c.c_int32
    lib.bl_scanner_free.argtypes = [c.c_uint64]
    lib.bl_scanner_free.restype = c.c_int32
    lib.bl_buffer_free.argtypes = [Buffer]
    lib.bl_buffer_free.restype = None

    def check(status, error):
        if status:
            raise RuntimeError(c.string_at(error.data, error.length).decode())

    def scan(function, *args):
        result, error = Buffer(), Buffer()
        try:
            check(function(handle, *args, c.byref(result), c.byref(error)), error)
            return json.loads(c.string_at(result.data, result.length))
        finally:
            lib.bl_buffer_free(result)
            lib.bl_buffer_free(error)

    assert lib.bl_abi_version() == 1
    error = Buffer()
    try:
        check(lib.bl_scanner_new(None, 0, c.byref(handle), c.byref(error)), error)
    finally:
        lib.bl_buffer_free(error)

    try:
        clean = b"ordinary text"
        assert scan(lib.bl_scanner_scan, clean, len(clean), None, 0)["findings"] == []
        sample = b"GITHUB_TOKEN=ghp_aB3dE5fG7hI9jK1mN3pQ5rS7tU9vW1xY3zA5\n"  # betterleaks:allow
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "config.env")
            path.write_bytes(sample)
            name = os.fsencode(path)
            response = scan(lib.bl_scanner_scan_file, name, len(name))
            assert response["engine_version"] == manifest["engine_version"]
            assert response["summary"]["findings"] == 1
            finding = response["findings"][0]
            assert finding["rule_id"] == "github-pat"
            assert finding["location"]["path"] == str(path)
    finally:
        status = lib.bl_scanner_free(handle)
        if status:
            raise RuntimeError(f"could not release scanner (status {status})")
    print("Python ctypes smoke test passed")


if __name__ == "__main__":
    main()
