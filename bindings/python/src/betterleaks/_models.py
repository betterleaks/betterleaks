"""Data models for Betterleaks scan findings (reused from betterleaks_sdk when installed)."""

from __future__ import annotations

try:
    from betterleaks_sdk.models import (
        BetterleaksError,
        Finding,
        Location,
        Match,
    )
except ImportError:
    from collections.abc import Iterator, Mapping
    from dataclasses import dataclass, field
    from typing import Any, Dict, List, Optional

    class BetterleaksError(Exception):  # type: ignore[no-redef]
        """Exception raised for Betterleaks scanning or runtime errors."""

    @dataclass
    class Match:  # type: ignore[no-redef]
        full: str = ""
        value: str = ""
        fingerprint: Optional[str] = None
        line: Optional[str] = None
        captures: Dict[str, str] = field(default_factory=dict)

        @classmethod
        def from_dict(cls, data: Dict[str, Any]) -> Match:
            return cls(
                full=data.get("full", ""),
                value=data.get("value", ""),
                fingerprint=data.get("fingerprint"),
                line=data.get("line"),
                captures=data.get("captures") or {},
            )

        def to_dict(self) -> Dict[str, Any]:
            res: Dict[str, Any] = {
                "full": self.full,
                "value": self.value,
                "captures": self.captures,
            }
            if self.fingerprint:
                res["fingerprint"] = self.fingerprint
            if self.line:
                res["line"] = self.line
            return res

    @dataclass
    class Location:  # type: ignore[no-redef]
        path: Optional[str] = None
        start_line: int = 0
        end_line: int = 0
        start_column: int = 0
        end_column: int = 0

        @classmethod
        def from_dict(cls, data: Dict[str, Any]) -> Location:
            return cls(
                path=data.get("path"),
                start_line=data.get("start_line", 0),
                end_line=data.get("end_line", 0),
                start_column=data.get("start_column", 0),
                end_column=data.get("end_column", 0),
            )

        def to_dict(self) -> Dict[str, Any]:
            return {
                "path": self.path,
                "start_line": self.start_line,
                "end_line": self.end_line,
                "start_column": self.start_column,
                "end_column": self.end_column,
            }

    @dataclass
    class Finding(Mapping):  # type: ignore[no-redef]
        rule_id: str
        description: str
        confidence: str
        match: Match
        location: Location
        tags: List[str] = field(default_factory=list)
        raw: Dict[str, Any] = field(default_factory=dict)

        @property
        def secret(self) -> str:
            """Convenience property returning the matched secret value."""
            return self.match.value

        @property
        def file(self) -> Optional[str]:
            """Convenience property returning the file path if present."""
            return self.location.path

        @property
        def component_sets(self) -> List[Dict[str, Any]]:
            """Combinations of component findings for multi-part rules (e.g. AWS access/secret keys)."""
            return self.raw.get("component_sets") or []

        @property
        def encodings(self) -> List[str]:
            """List of encodings detected during decode passes."""
            return self.raw.get("encodings") or []

        @classmethod
        def from_dict(cls, data: Dict[str, Any]) -> Finding:
            match_data = data.get("match") or {}
            location_data = data.get("location") or {}
            return cls(
                rule_id=data.get("rule_id", ""),
                description=data.get("description", ""),
                confidence=data.get("confidence", ""),
                match=Match.from_dict(match_data),
                location=Location.from_dict(location_data),
                tags=data.get("tags") or [],
                raw=data,
            )

        def to_dict(self) -> Dict[str, Any]:
            """Convert finding back to a dictionary, preserving extra report fields."""
            res = dict(self.raw)
            res.update(
                {
                    "rule_id": self.rule_id,
                    "description": self.description,
                    "confidence": self.confidence,
                    "secret": self.secret,
                    "file": self.file,
                    "match": self.match.to_dict(),
                    "location": self.location.to_dict(),
                    "tags": list(self.tags),
                }
            )
            return res

        def __getitem__(self, key: str) -> Any:
            """Allow dictionary-style access (e.g., finding['rule_id'] or finding['secret'])."""
            data = self.to_dict()
            if key in data:
                return data[key]
            raise KeyError(key)

        def __iter__(self) -> Iterator[str]:
            return iter(self.to_dict())

        def __len__(self) -> int:
            return len(self.to_dict())

        def __contains__(self, key: object) -> bool:
            if not isinstance(key, str):
                return False
            return key in self.to_dict()

        def get(self, key: str, default: Any = None) -> Any:
            return self.to_dict().get(key, default)


__all__ = [
    "BetterleaksError",
    "Finding",
    "Location",
    "Match",
]
