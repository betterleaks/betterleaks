"""Stamp the three distributions from the version of one Betterleaks tag."""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def python_version(tag):
    number = r"(?:0|[1-9][0-9]*)"
    if not re.fullmatch(rf"v2\.{number}\.{number}(?:-rc\.{number})?", tag):
        raise ValueError(f"Expected a v2 release or release candidate tag, got {tag!r}")
    return tag[1:].replace("-rc.", "rc")


def stamp(tag):
    version = python_version(tag)
    for package, module in [(".", "betterleaks"), ("cli", "betterleaks_cli"), ("sdk", "betterleaks_sdk")]:
        path = ROOT / package / "src" / module / "_version.py"
        path.write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    project = ROOT / "pyproject.toml"
    source = project.read_text(encoding="utf-8")
    for component in ("cli", "sdk"):
        source, count = re.subn(rf'("betterleaks-{component}==)[0-9.rcdev]+(?=[";])',
                                rf"\g<1>{version}", source)
        if count != 1:
            raise ValueError(f"Missing exact dependency on betterleaks-{component}")
    project.write_text(source, encoding="utf-8")
    return version


if __name__ == "__main__":
    print(stamp(sys.argv[1]))
