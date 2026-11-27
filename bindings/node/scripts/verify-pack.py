"""Check npm tarballs against the checkout, GoReleaser binaries and native addon builds."""

import argparse
import json
import re
import tarfile
from pathlib import Path


def verify_tarball(path, manifest, files, executable):
    expected = {"package/package.json", *files}
    with tarfile.open(path, "r|gz") as archive:
        for member in archive:
            if member.name not in expected or not member.isfile() or member.mode & 0o7000:
                raise ValueError(f"{path.name}: unexpected or duplicate member {member.name!r}")
            expected.remove(member.name)
            if member.name == executable and not member.mode & 0o111:
                raise ValueError(f"{path.name}: {executable} is not executable")
            with archive.extractfile(member) as packed:
                if member.name == "package/package.json":
                    if member.size > 16384 or json.load(packed) != manifest:
                        raise ValueError(f"{path.name}: unexpected package manifest")
                    continue
                source = files[member.name]
                if member.size != source.stat().st_size:
                    raise ValueError(f"{path.name}: {member.name} differs from {source.name}")
                with source.open("rb") as original:
                    while chunk := original.read(1024 * 1024):
                        if packed.read(len(chunk)) != chunk:
                            raise ValueError(f"{path.name}: {member.name} differs from {source.name}")
    if expected:
        raise ValueError(f"{path.name}: missing {sorted(expected)}")


def main():
    root = Path(__file__).resolve().parents[3]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dist", type=Path, default=root / "dist")
    parser.add_argument("--tag", help="expected release tag, including the leading v")
    args = parser.parse_args()
    dist = args.dist
    metadata = json.loads((dist / "metadata.json").read_text())
    version = metadata["version"]
    if metadata["project_name"] != "betterleaks" or not re.fullmatch(r"2\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?", version):
        raise ValueError("Unexpected GoReleaser project or version")
    if args.tag is not None and args.tag != f"v{version}":
        raise ValueError(f"GoReleaser version {version} does not match tag {args.tag}")

    node = root / "bindings/node"
    template = json.loads((node / "package.json").read_text())
    common = {"version": version, "license": template["license"], "repository": template["repository"]}
    license_file = {"package/LICENSE": root / "LICENSE"}
    directory = dist / "npm" / version
    launcher = f"betterleaks-{version}.tgz"
    sdk = f"betterleaks-sdk-{version}.tgz"
    filenames = {launcher, sdk}
    cli_platforms = {}
    sdk_platforms = {}
    for goos, os in (("darwin", "darwin"), ("linux", "linux"), ("windows", "win32")):
        binary = "betterleaks.exe" if os == "win32" else "betterleaks"
        for goarch, cpu in (("amd64", "x64"), ("arm64", "arm64")):
            name = f"@betterleaks/cli-{os}-{cpu}"
            filename = f"betterleaks-cli-{os}-{cpu}-{version}.tgz"
            filenames.add(filename)
            cli_platforms[name] = version
            # Look up the original by its GoReleaser target, independently of the packer's manifest.
            sources = list(dist.glob(f"betterleaks_{goos}_{goarch}*/{binary}"))
            if len(sources) != 1 or not sources[0].is_file():
                raise ValueError(f"Expected one GoReleaser binary for {goos}/{goarch}")
            manifest = {
                **common, "name": name, "os": [os], "cpu": [cpu],
                "description": f"Betterleaks CLI for {os}/{cpu}",
                "publishConfig": {"access": "public"},
            }
            member = f"package/bin/{binary}"
            files = {**license_file, member: sources[0]}
            verify_tarball(directory / filename, manifest, files, member)
            if os != "win32":
                name = f"@betterleaks/sdk-{os}-{cpu}"
                filename = f"betterleaks-sdk-{os}-{cpu}-{version}.tgz"
                filenames.add(filename)
                sdk_platforms[name] = version
                addon_manifest = {**manifest, "name": name, "description": f"Betterleaks Node.js addon for {os}/{cpu}"}
                addon = dist / "node-addons" / f"betterleaks-{os}-{cpu}.node"
                verify_tarball(directory / filename, addon_manifest, {**license_file, "package/betterleaks.node": addon}, None)

    if {file.name for file in directory.iterdir()} != filenames:
        raise ValueError(f"Unexpected files in {directory}")
    script = "bin/betterleaks.cjs"
    manifest = {
        **common, "name": "betterleaks", "description": template["description"],
        "main": "index.js", "types": "index.d.ts",
        "bin": {"betterleaks": script}, "optionalDependencies": cli_platforms,
        "dependencies": {"@betterleaks/sdk": version},
    }
    files = {**license_file, "package/README.md": node / "README.md", f"package/{script}": node / script}
    for filename in ("index.js", "index.d.ts"):
        files[f"package/{filename}"] = node / filename
    verify_tarball(directory / launcher, manifest, files, f"package/{script}")
    sdk_manifest = {
        **common, "name": "@betterleaks/sdk", "description": "Scan text and files for leaked secrets from Node.js",
        "repository": {**common["repository"], "directory": "bindings/node/sdk"},
        "main": "index.js", "types": "index.d.ts", "optionalDependencies": sdk_platforms,
        "publishConfig": {"access": "public"},
    }
    sdk_files = {f"package/{name}": node / "sdk" / name for name in ("README.md", "index.js", "index.d.ts")}
    verify_tarball(directory / sdk, sdk_manifest, {**license_file, **sdk_files}, None)
    print(f"Verified the manifests and contents of all {len(filenames)} npm tarballs for {version}")


if __name__ == "__main__":
    main()
