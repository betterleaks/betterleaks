"""Native Betterleaks Python SDK.

High-performance in-process secret and credential detection powered by Go (bindings/c).
"""

from typing import Dict, List, Optional

from betterleaks_sdk._lib import create_backing, get_cached_backing
from betterleaks_sdk._version import __version__
from betterleaks_sdk.models import BetterleaksError, Finding, Location, Match

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


class Scanner:
    """Reusable Betterleaks scanner instance backed by the compiled Go C ABI."""

    def __init__(
        self,
        config_path: Optional[str] = None,
        config_toml: Optional[str] = None,
        workers: int = 0,
        max_decode_depth: int = 0,
        max_input_bytes: Optional[int] = None,
        max_findings: Optional[int] = None,
    ) -> None:
        self._backing = create_backing(
            config_path=config_path,
            config_toml=config_toml,
            workers=workers,
            max_decode_depth=max_decode_depth,
            max_input_bytes=max_input_bytes,
            max_findings=max_findings,
        )

    def scan_string(
        self, content: str, attributes: Optional[Dict[str, str]] = None
    ) -> List[Finding]:
        """Scan a string for secrets and credentials."""
        resp = self._backing.scan_string(content, attributes=attributes)
        findings_data = resp.get("findings") or []
        return [Finding.from_dict(item) for item in findings_data]

    def scan_file(self, file_path: str) -> List[Finding]:
        """Scan a regular file for secrets and credentials."""
        resp = self._backing.scan_file(file_path)
        findings_data = resp.get("findings") or []
        return [Finding.from_dict(item) for item in findings_data]

    def close(self) -> None:
        """Release native resources held by this scanner."""
        self._backing.close()

    def __enter__(self) -> "Scanner":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


def create_scanner(
    config_path: Optional[str] = None,
    config_toml: Optional[str] = None,
    workers: int = 0,
    max_decode_depth: int = 0,
    max_input_bytes: Optional[int] = None,
    max_findings: Optional[int] = None,
) -> Scanner:
    """Create a configured reusable Betterleaks scanner."""
    return Scanner(
        config_path=config_path,
        config_toml=config_toml,
        workers=workers,
        max_decode_depth=max_decode_depth,
        max_input_bytes=max_input_bytes,
        max_findings=max_findings,
    )


def scan_string(content: str, config_path: Optional[str] = None) -> List[Finding]:
    """Scan a string for secrets and credentials.

    Args:
        content: String content to scan.
        config_path: Optional path to a custom Betterleaks configuration TOML file.

    Returns:
        A list of Finding objects.

    Raises:
        BetterleaksError: If scanning fails.
    """
    backing = get_cached_backing(config_path=config_path)
    resp = backing.scan_string(content)
    findings_data = resp.get("findings") or []
    return [Finding.from_dict(item) for item in findings_data]


def scan_file(file_path: str, config_path: Optional[str] = None) -> List[Finding]:
    """Scan a file for secrets and credentials.

    Args:
        file_path: Path to the file to scan.
        config_path: Optional path to a custom Betterleaks configuration TOML file.

    Returns:
        A list of Finding objects.

    Raises:
        BetterleaksError: If the file cannot be read or scanning fails.
    """
    backing = get_cached_backing(config_path=config_path)
    resp = backing.scan_file(file_path)
    findings_data = resp.get("findings") or []
    return [Finding.from_dict(item) for item in findings_data]
