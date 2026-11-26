import importlib.metadata
import re

import betterleaks_sdk


def test_version():
    assert re.fullmatch(
        r"[0-9]+\.[0-9]+\.[0-9]+((a|b|rc)[0-9]+)?", betterleaks_sdk.__version__
    )
    assert importlib.metadata.version("betterleaks-sdk") == betterleaks_sdk.__version__
    assert not hasattr(betterleaks_sdk, "main")
    assert not hasattr(betterleaks_sdk, "get_binary_path")
