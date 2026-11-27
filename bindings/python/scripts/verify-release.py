"""Check the complete distribution set before promoting the tested build."""

import argparse
import hashlib
import re
from email.parser import BytesParser
from pathlib import Path
from zipfile import ZipFile

from packaging.requirements import Requirement
from packaging.utils import parse_sdist_filename, parse_wheel_filename

SDK_PLATFORMS = {"darwin-arm64", "darwin-x86_64", "linux-aarch64", "linux-x86_64"}
WINDOWS_PE_MACHINE = {"win_amd64": 0x8664, "win_arm64": 0xAA64}


def platform_name(tag):
    if tag.interpreter != "py3" or tag.abi != "none":
        raise ValueError(f"Unexpected wheel tag {tag}")
    plat = tag.platform
    if plat == "any":
        return "any"
    mac = re.fullmatch(r"macosx_([0-9]+)_0_(arm64|x86_64)", plat)
    if mac and int(mac.group(1)) >= 12:
        return "darwin-" + mac.group(2)
    if plat in WINDOWS_PE_MACHINE:
        return plat
    for arch in ("aarch64", "x86_64"):
        if plat.startswith("manylinux") and plat.endswith("_" + arch):
            return "linux-" + arch
    raise ValueError(f"Unexpected platform {plat}")


def verify(source, output, version):
    targets = {
        "betterleaks": {"sdist", "any"},
        "betterleaks-sdk": {"sdist", *SDK_PLATFORMS},
        "betterleaks-cli": {"sdist", *SDK_PLATFORMS, *WINDOWS_PE_MACHINE},
    }
    for path in sorted(source.iterdir()):
        if path.suffix == ".whl":
            project, ver, _, tags = parse_wheel_filename(path.name)
            platforms = {platform_name(tag) for tag in tags}
            if len(platforms) != 1:
                raise ValueError(f"Ambiguous targets in {path.name}")
            target = platforms.pop()
            if project == "betterleaks-sdk" and target.startswith("darwin"):
                if any(not tag.platform.startswith("macosx_12_0_") for tag in tags):
                    raise ValueError(f"SDK wheel requires a newer macOS than 12: {path.name}")
            with ZipFile(path) as wheel:
                members = [item.filename for item in wheel.infolist() if not item.is_dir()]
                module = project.replace("-", "_")
                metadata = BytesParser().parsebytes(wheel.read(f"{module}-{ver}.dist-info/METADATA"))
                if metadata["Name"] != project or metadata["Version"] != version:
                    raise ValueError(f"Unexpected metadata in {path.name}")
                runtime_deps = {
                    str(dep) for dep in map(Requirement, metadata.get_all("Requires-Dist", []))
                    if str(dep.marker) != 'extra == "dev"'
                }
                expected_deps = set()
                if project == "betterleaks":
                    expected_deps = {
                        f"betterleaks-cli=={version}",
                        f'betterleaks-sdk=={version}; sys_platform != "win32"',
                    }
                if runtime_deps != expected_deps:
                    raise ValueError(f"Unexpected runtime dependencies in {path.name}: {runtime_deps}")
                if not all(name.startswith((module + "/", f"{module}-{ver}.dist-info/")) for name in members):
                    raise ValueError(f"Unexpected wheel contents: {path.name}")
                expected = []
                if project == "betterleaks-cli":
                    executable = module + "/bin/betterleaks"
                    if target in WINDOWS_PE_MACHINE:
                        executable += ".exe"
                        # Windows ARM64 can run an x64 executable under emulation.
                        # Check the PE machine type so a mislabeled wheel cannot pass.
                        with wheel.open(executable) as binary:
                            binary.seek(0x3C)
                            pe_offset = int.from_bytes(binary.read(4), "little")
                            binary.seek(pe_offset)
                            signature = binary.read(4)
                            machine = int.from_bytes(binary.read(2), "little")
                        if signature != b"PE\0\0" or machine != WINDOWS_PE_MACHINE[target]:
                            raise ValueError(f"Executable architecture does not match {path.name}")
                    expected = [executable]
                if project == "betterleaks-sdk":
                    expected = [module + "/libbetterleaks_ffi." + ("dylib" if target.startswith("darwin") else "so")]
                binaries = [name for name in members if "/bin/" in name or name.endswith((".so", ".dylib", ".exe", ".dll", ".a", ".pyd"))]
                if binaries != expected:
                    raise ValueError(f"Unexpected binary contents in {path.name}: {binaries}")
        else:
            project, ver = parse_sdist_filename(path.name)
            target = "sdist"
        if str(ver) != version or target not in targets.get(project, set()):
            raise ValueError(f"Unexpected or duplicate release file {path.name}")
        targets[project].remove(target)
        dest = output / project / path.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        path.rename(dest)
        print(hashlib.sha256(dest.read_bytes()).hexdigest(), path.name)
    if any(targets.values()):
        raise ValueError(f"Missing release artifacts: {targets}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("version")
    args = parser.parse_args()
    verify(args.source, args.output, args.version)
