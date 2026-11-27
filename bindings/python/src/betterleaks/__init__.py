"""Betterleaks CLI and native scanning API on supported platforms."""

import sys

from betterleaks._version import __version__

if sys.platform != "win32":
    from betterleaks_sdk import (
        BetterleaksError,
        Finding as Finding,
        Location as Location,
        Match as Match,
        Scanner,
        create_scanner,
        scan_file,
        scan_string,
    )
else:
    class BetterleaksError(RuntimeError):
        """This platform supports the CLI only."""

    def _unsupported(*args, **kwargs):
        raise BetterleaksError(
            "The native Betterleaks Python SDK is unavailable on Windows. "
            "Use the betterleaks CLI to scan on this platform."
        )

    create_scanner = Scanner = scan_file = scan_string = _unsupported

__all__ = [
    "BetterleaksError",
    "Scanner",
    "__version__",
    "create_scanner",
    "scan_file",
    "scan_string",
]

if sys.platform != "win32":
    __all__ += ["Finding", "Location", "Match"]
