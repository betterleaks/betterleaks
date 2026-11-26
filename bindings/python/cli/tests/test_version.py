import importlib.metadata
import re

import betterleaks_cli


def test_version():
    assert re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+((a|b|rc)[0-9]+)?", betterleaks_cli.__version__
    )
    assert importlib.metadata.version("betterleaks-cli") == betterleaks_cli.__version__
    assert not hasattr(betterleaks_cli, "scan_string")
    assert not hasattr(betterleaks_cli, "scan_file")
