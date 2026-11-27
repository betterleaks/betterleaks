import importlib.metadata
import re
import subprocess
import sys

import pytest

import betterleaks


def test_version():
    assert re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+(rc[0-9]+|\.dev[0-9]+)?", betterleaks.__version__
    )
    assert importlib.metadata.version("betterleaks") == betterleaks.__version__
    assert importlib.metadata.version("betterleaks-cli") == betterleaks.__version__
    if sys.platform != "win32":
        assert (
            importlib.metadata.version("betterleaks-sdk") == betterleaks.__version__
        )


def test_cli_entrypoint():
    proc = subprocess.run(
        ["betterleaks", "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert proc.stdout.strip() == betterleaks.__version__.replace("rc", "-rc.")


@pytest.mark.skipif(sys.platform != "win32", reason="Windows CLI-only distribution")
def test_windows_scanner_unavailable():
    with pytest.raises(betterleaks.BetterleaksError, match="unavailable on Windows"):
        betterleaks.scan_string("clean")
