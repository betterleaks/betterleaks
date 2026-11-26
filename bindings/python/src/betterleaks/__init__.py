"""Betterleaks Python bindings and CLI.

On macOS and glibc Linux, re-exports the in-process native SDK (betterleaks_sdk).
On Windows, falls back cleanly to the bundled betterleaks CLI (betterleaks_cli).
"""

import sys

from betterleaks._version import __version__

if sys.platform != "win32":
    from betterleaks_sdk import (
        BetterleaksError,
        Finding,
        Location,
        Match,
        Scanner,
        create_scanner,
        scan_file,
        scan_string,
    )
else:
    from betterleaks._models import BetterleaksError, Finding, Location, Match
    from betterleaks._win_cli import (
        Scanner,
        create_scanner,
        scan_file,
        scan_string,
    )

__all__ = [
    "BetterleaksError",
    "Finding",
    "Location",
    "Match",
    "Scanner",
    "__version__",
    "create_scanner",
    "scan_file",
    "scan_string",
]
