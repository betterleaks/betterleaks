import os
import platform
import shutil
import subprocess
import sys
from typing import Optional

from setuptools import setup
from setuptools.command.build_py import build_py
from setuptools.command.develop import develop
from setuptools.dist import Distribution

# Ensure minimum macOS deployment target compatible with the Go runtime toolchain.
if sys.platform == "darwin" and "MACOSX_DEPLOYMENT_TARGET" not in os.environ:
    os.environ["MACOSX_DEPLOYMENT_TARGET"] = "12.0"

_HERE = os.path.dirname(os.path.abspath(__file__))


def _ensure_supported_platform() -> None:
    if platform.system().lower() == "windows" or sys.platform == "win32":
        err_msg = """
================================================================================
BETTERLEAKS SDK UNSUPPORTED PLATFORM: Windows
================================================================================
'betterleaks-sdk' wraps the C shared library ABI (bindings/c), which supports
macOS and glibc Linux only. Windows is not supported.

On Windows, install one of:
  pip install betterleaks       # Python API (CLI fallback) + CLI
  pip install betterleaks-cli   # Standalone CLI
================================================================================
"""
        print(err_msg, file=sys.stderr)
        raise SystemExit(1)


def get_lib_filename() -> str:
    return (
        "libbetterleaks_ffi.dylib"
        if platform.system().lower() == "darwin"
        else "libbetterleaks_ffi.so"
    )


def get_package_version() -> str:
    version = "2.0.0"
    version_file = os.path.join(_HERE, "src", "betterleaks_sdk", "_version.py")
    try:
        with open(version_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("__version__"):
                    version = line.split("=", 1)[1].strip().strip("\"'")
                    break
    except OSError:
        pass
    return version


def get_engine_version(repo_root: str) -> str:
    try:
        out = subprocess.check_output(
            ["git", "describe", "--tags", "--match", "v2.*", "--always"],
            cwd=repo_root,
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if out and not any(ch in out for ch in " \t\r\n\"'\\"):
            return out.lstrip("v")
    except (OSError, subprocess.CalledProcessError):
        pass
    return get_package_version()


def find_go_binary() -> Optional[str]:
    """Search for the go compiler in PATH and standard system installation paths."""
    go_bin = shutil.which("go")
    if go_bin:
        return go_bin

    home = os.path.expanduser("~")
    candidates = [
        "/opt/homebrew/bin/go",
        "/usr/local/bin/go",
        "/usr/local/go/bin/go",
        os.path.join(home, "go", "bin", "go"),
        os.path.join(home, ".asdf", "shims", "go"),
        "/usr/bin/go",
        "/snap/bin/go",
    ]

    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


def find_repo_root() -> Optional[str]:
    """Locate the Betterleaks Go repository root containing go.mod and bindings/c."""
    candidates = []
    env_root = os.environ.get("BETTERLEAKS_REPO_ROOT")
    if env_root:
        candidates.append(os.path.abspath(env_root))
    candidates.extend(
        [
            os.path.join(_HERE, "_upstream"),
            os.path.abspath(os.path.join(_HERE, "..", "..", "..")),
        ]
    )

    for candidate in candidates:
        if os.path.isfile(os.path.join(candidate, "go.mod")) and os.path.isfile(
            os.path.join(candidate, "bindings", "c", "betterleaks.h")
        ):
            return candidate

    return None


def _raise_missing_toolchain(reason: str) -> None:
    err_msg = f"""
================================================================================
BETTERLEAKS SDK BUILD ERROR: {reason}
================================================================================
Building 'betterleaks-sdk' from source requires:
  • A Betterleaks Go source tree (included in sdist or full git checkout)
  • Go compiler (version 1.26+) and a C compiler (for CGO on macOS/Linux)

Please install a pre-built binary wheel instead:
  pip install betterleaks-sdk
================================================================================
"""
    print(err_msg, file=sys.stderr)
    raise SystemExit(1)


def _use_prebuilt() -> bool:
    return os.environ.get("BETTERLEAKS_USE_PREBUILT") == "1"


def _find_prebuilt_native_lib(repo_root: Optional[str]) -> Optional[str]:
    lib_name = get_lib_filename()
    local_lib = os.path.join(_HERE, "src", "betterleaks_sdk", lib_name)
    if os.path.isfile(local_lib) and os.path.getsize(local_lib) > 0:
        return local_lib

    if repo_root:
        system = platform.system().lower()
        machine = platform.machine().lower()
        if system == "darwin":
            target = (
                "aarch64-apple-darwin"
                if machine in ("arm64", "aarch64")
                else "x86_64-apple-darwin"
            )
        elif system == "linux":
            target = (
                "aarch64-unknown-linux-gnu"
                if machine in ("arm64", "aarch64")
                else "x86_64-unknown-linux-gnu"
            )
        else:
            target = ""

        if target:
            dist_lib = os.path.join(
                repo_root, "dist", "native", target, "lib", lib_name
            )
            if os.path.isfile(dist_lib) and os.path.getsize(dist_lib) > 0:
                return dist_lib

    return None


def build_go_shared_library(target_dir: str) -> str:
    _ensure_supported_platform()

    target_dir = os.path.abspath(target_dir)
    os.makedirs(target_dir, exist_ok=True)
    lib_name = get_lib_filename()
    out_lib = os.path.join(target_dir, lib_name)

    repo_root = find_repo_root()
    if _use_prebuilt() or repo_root is None:
        prebuilt = _find_prebuilt_native_lib(repo_root)
        if prebuilt:
            if os.path.abspath(prebuilt) != os.path.abspath(out_lib):
                shutil.copy2(prebuilt, out_lib)
            return out_lib

    go_bin = find_go_binary()
    if not go_bin:
        _raise_missing_toolchain("Go compiler ('go') not found in PATH")
    if not repo_root:
        _raise_missing_toolchain(
            "Betterleaks Go source tree (go.mod / bindings/c) not found"
        )

    engine_version = get_engine_version(repo_root)
    ldflags = (
        f"-X github.com/betterleaks/betterleaks/v2/version.Version={engine_version}"
    )
    if sys.platform == "darwin":
        ldflags += f" -extldflags=-Wl,-install_name,@rpath/{lib_name}"

    cmd = [
        go_bin,
        "build",
        "-mod=readonly",
        "-trimpath",
        "-tags",
        "betterleaks_ffi",
        "-buildmode=c-shared",
        "-ldflags",
        ldflags,
        "-o",
        out_lib,
        "./bindings/c",
    ]
    env = os.environ.copy()
    env["CGO_ENABLED"] = "1"
    if sys.platform == "darwin" and "MACOSX_DEPLOYMENT_TARGET" not in env:
        env["MACOSX_DEPLOYMENT_TARGET"] = "12.0"

    print(f"--> Compiling Go shared library: {' '.join(cmd)} in {repo_root}")
    try:
        subprocess.check_call(cmd, cwd=repo_root, env=env)
    except subprocess.CalledProcessError as e:
        print(f"\nERROR: Failed to compile Go native bindings: {e}", file=sys.stderr)
        raise SystemExit(e.returncode)

    header_path = os.path.splitext(out_lib)[0] + ".h"
    if os.path.isfile(header_path):
        os.remove(header_path)

    return out_lib


class CustomBuildPy(build_py):
    def run(self):
        super().run()
        target_dir = (
            os.path.join(_HERE, "src", "betterleaks_sdk")
            if getattr(self, "editable_mode", False)
            else os.path.join(self.build_lib, "betterleaks_sdk")
        )
        build_go_shared_library(target_dir)


class CustomDevelop(develop):
    def run(self):
        local_dir = os.path.join(_HERE, "src", "betterleaks_sdk")
        build_go_shared_library(local_dir)
        super().run()


class BinaryDistribution(Distribution):
    """Marks package as containing binary platform-specific artifacts."""

    def has_ext_modules(self):
        return True


setup(
    distclass=BinaryDistribution,
    cmdclass={
        "build_py": CustomBuildPy,
        "develop": CustomDevelop,
    },
    package_data={
        "betterleaks_sdk": [
            "*.so",
            "*.dylib",
            "py.typed",
        ],
    },
)
