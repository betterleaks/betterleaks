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

if sys.platform == "darwin" and "MACOSX_DEPLOYMENT_TARGET" not in os.environ:
    os.environ["MACOSX_DEPLOYMENT_TARGET"] = "12.0"

_HERE = os.path.dirname(os.path.abspath(__file__))


def get_cli_filename() -> str:
    return "betterleaks.exe" if platform.system().lower() == "windows" else "betterleaks"


def get_package_version() -> str:
    version = "2.0.0"
    version_file = os.path.join(_HERE, "src", "betterleaks_cli", "_version.py")
    try:
        with open(version_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("__version__"):
                    version = line.split("=", 1)[1].strip().strip("\"'")
                    break
    except OSError:
        pass
    return version


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
        r"C:\Program Files\Go\bin\go.exe",
        r"C:\Go\bin\go.exe",
    ]

    for candidate in candidates:
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return None


def find_repo_root() -> Optional[str]:
    """Locate the Betterleaks Go repository root containing go.mod."""
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
        if os.path.isfile(os.path.join(candidate, "go.mod")):
            return candidate

    return None


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


def _raise_missing_toolchain(reason: str) -> None:
    err_msg = f"""
================================================================================
BETTERLEAKS CLI BUILD ERROR: {reason}
================================================================================
Building 'betterleaks-cli' from source requires:
  • A Betterleaks Go source tree (included in sdist or full git checkout)
  • Go compiler (version 1.26+)

Please install a pre-built binary wheel instead:
  pip install betterleaks-cli
================================================================================
"""
    print(err_msg, file=sys.stderr)
    raise SystemExit(1)


def _use_prebuilt() -> bool:
    return os.environ.get("BETTERLEAKS_USE_PREBUILT") == "1"


def build_go_cli_binary(target_dir: str) -> str:
    bin_dir = os.path.abspath(os.path.join(target_dir, "bin"))
    os.makedirs(bin_dir, exist_ok=True)
    cli_name = get_cli_filename()
    out_bin = os.path.join(bin_dir, cli_name)

    repo_root = find_repo_root()
    if _use_prebuilt() or repo_root is None:
        local_bin = os.path.join(_HERE, "src", "betterleaks_cli", "bin", cli_name)
        if os.path.isfile(local_bin) and os.path.getsize(local_bin) > 0:
            if os.path.abspath(local_bin) != os.path.abspath(out_bin):
                shutil.copy2(local_bin, out_bin)
            if sys.platform != "win32":
                os.chmod(out_bin, 0o755)
            return out_bin

    go_bin = find_go_binary()
    if not go_bin:
        _raise_missing_toolchain("Go compiler ('go') not found in PATH")
    if not repo_root:
        _raise_missing_toolchain("Betterleaks Go source tree (go.mod) not found")

    engine_version = get_engine_version(repo_root)
    ldflags = (
        f"-s -w -X=github.com/betterleaks/betterleaks/v2/version.Version={engine_version}"
    )
    cmd = [
        go_bin,
        "build",
        "-mod=readonly",
        "-trimpath",
        "-ldflags",
        ldflags,
        "-o",
        out_bin,
        ".",
    ]
    env = os.environ.copy()
    env["CGO_ENABLED"] = "0"

    print(f"--> Compiling Betterleaks CLI binary: {' '.join(cmd)} in {repo_root}")
    try:
        subprocess.check_call(cmd, cwd=repo_root, env=env)
    except subprocess.CalledProcessError as e:
        print(f"\nERROR: Failed to compile Go CLI binary: {e}", file=sys.stderr)
        raise SystemExit(e.returncode)

    if sys.platform != "win32" and os.path.isfile(out_bin):
        os.chmod(out_bin, 0o755)

    return out_bin


class CustomBuildPy(build_py):
    def run(self):
        super().run()
        target_dir = os.path.join(self.build_lib, "betterleaks_cli")
        build_go_cli_binary(target_dir)


class CustomDevelop(develop):
    def run(self):
        local_dir = os.path.join(_HERE, "src", "betterleaks_cli")
        build_go_cli_binary(local_dir)
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
        "betterleaks_cli": [
            "bin/*",
            "py.typed",
        ],
    },
)
