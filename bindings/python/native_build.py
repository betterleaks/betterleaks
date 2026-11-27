"""Setuptools backend commands shared by the CLI and ctypes distributions."""

import os
import platform
import re
import shutil
import subprocess
from pathlib import Path

from setuptools import Distribution, setup
from setuptools.command.bdist_wheel import bdist_wheel
from setuptools.command.build_py import build_py
from setuptools.command.sdist import sdist


class PlatformDistribution(Distribution):
    def has_ext_modules(self):
        return True


class PlatformWheel(bdist_wheel):
    def get_tag(self):
        # Both native payloads have a platform ABI, but neither uses the CPython ABI.
        _, _, plat = super().get_tag()
        if platform.system() == "Darwin":
            minimum = 12
            # A signed CLI may come from a newer Go toolchain than the SDK.
            # Editable wheels are local and omit the payload from the wheel.
            module = self.distribution.get_name().replace("-", "_")
            filename = "bin/betterleaks" if module == "betterleaks_cli" else "libbetterleaks_ffi.dylib"
            payload = Path(self.bdist_dir) / module / filename
            if payload.is_file():
                headers = subprocess.check_output(["otool", "-l", str(payload)], text=True)
                target = re.search(r"^\s*minos (\d+)\.(\d+)", headers, re.MULTILINE)
                if not target:
                    raise ValueError(f"Missing macOS deployment target in {payload.name}")
                major, minor = map(int, target.groups())
                # pip's macOS 11+ compatibility tags represent whole major versions.
                minimum = max(minimum, major + int(minor > 0))
            plat = f"macosx_{minimum}_0_{platform.machine()}"
        return "py3", "none", plat


def configure(package_dir, module):
    is_sdk = module == "betterleaks_sdk"
    root = package_dir / "_upstream"
    if not root.is_dir():
        root = package_dir.parents[2]
    helper = Path(__file__).resolve()

    class BuildNative(build_py):
        def run(self):
            super().run()
            dest = package_dir / "src" if self.editable_mode else Path(self.build_lib)
            dest = (dest / module).resolve()
            if is_sdk:
                if platform.system() not in ("Darwin", "Linux") or platform.machine().lower() not in (
                    "arm64", "aarch64", "x86_64", "amd64"
                ):
                    raise RuntimeError("betterleaks-sdk requires macOS or glibc Linux on ARM64 or x86-64")
                if platform.system() == "Linux":
                    try:
                        glibc = os.confstr("CS_GNU_LIBC_VERSION")
                    except (OSError, ValueError):
                        glibc = None
                    if not glibc:
                        raise RuntimeError("betterleaks-sdk requires glibc on Linux")
            package_version = self.distribution.get_version()
            flags = "-s -w"
            # Untagged checkouts use the Go engine's built-in "dev" version.
            if ".dev" not in package_version:
                engine_version = package_version.replace("rc", "-rc.")
                flags += " -X github.com/betterleaks/betterleaks/v2/version.Version=" + engine_version
            cmd = ["go", "build", "-mod=readonly", "-trimpath"]
            env = os.environ.copy()
            env["CGO_ENABLED"] = "1" if is_sdk else "0"
            if is_sdk:
                name = "libbetterleaks_ffi.so"
                if platform.system() == "Darwin":
                    name = "libbetterleaks_ffi.dylib"
                    env["MACOSX_DEPLOYMENT_TARGET"] = "12.0"
                    flags += " -extldflags=-Wl,-install_name,@rpath/" + name
                out = dest / name
                cmd.extend(["-tags", "betterleaks_ffi", "-buildmode=c-shared"])
                target = "./bindings/c"
            else:
                out = dest / "bin" / ("betterleaks.exe" if os.name == "nt" else "betterleaks")
                target = "."
            out.parent.mkdir(parents=True, exist_ok=True)
            # This directory is populated only in the release wheel build from
            # a signed GoReleaser payload. Source distributions exclude it.
            release_binary = package_dir / ".release-bin" / out.name
            if not is_sdk and release_binary.is_file():
                shutil.copyfile(release_binary, out)
                out.chmod(0o755)
                return
            subprocess.run(cmd + ["-ldflags", flags, "-o", str(out), target],
                           cwd=root, env=env, check=True)
            if is_sdk:
                out.with_suffix(".h").unlink(missing_ok=True)

    class SourceDistribution(sdist):
        def make_release_tree(self, base_dir, files):
            super().make_release_tree(base_dir, files)
            output = Path(base_dir)
            shutil.copyfile(helper, output / "native_build.py")
            # Carry the tracked engine and embedded data into standalone source installs.
            if root == package_dir / "_upstream":
                shutil.copytree(root, output / "_upstream", dirs_exist_ok=True)
                return
            paths = subprocess.check_output([
                "git", "ls-files", "-z", "--", ".", ":!bindings/python", ":!bindings/node",
                ":!bindings/rust", ":!docs", ":!testdata", ":!.github",
            ], cwd=root)
            for name in paths.split(b"\0"):
                if name:
                    path = Path(os.fsdecode(name))
                    destination = output / "_upstream" / path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(root / path, destination)

    setup(distclass=PlatformDistribution, cmdclass={
        "bdist_wheel": PlatformWheel, "build_py": BuildNative, "sdist": SourceDistribution,
    })
