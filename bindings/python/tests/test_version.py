import importlib.metadata
import re
import subprocess
import sys

import betterleaks
import betterleaks_cli


def test_version():
    assert re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+((a|b|rc)[0-9]+)?", betterleaks.__version__
    )
    assert importlib.metadata.version("betterleaks") == betterleaks.__version__
    assert importlib.metadata.version("betterleaks-cli") == betterleaks_cli.__version__
    if sys.platform != "win32":
        import betterleaks_sdk

        assert (
            importlib.metadata.version("betterleaks-sdk") == betterleaks_sdk.__version__
        )


def test_cli_entrypoint():
    proc = subprocess.run(
        [betterleaks_cli.get_binary_path(), "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert proc.stdout.strip() != ""
