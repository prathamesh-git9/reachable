"""Advisory ingestion and version-range matching.

OSV is the most useful interchange format for open source vulnerability data,
but reachability analysis needs one field that OSV advisories often do not
include: the affected symbols. This module keeps the model close to OSV while
making that gap explicit. Missing symbols later force UNKNOWN, never
NOT_REACHABLE, because absence of symbol metadata is not evidence that code is
safe.

The built-in version parser intentionally covers common PEP 440 release shapes
seen in advisories: numeric release segments plus pre/dev/post tags such as
``1.2.3rc1`` and ``2.0.0.post1``. It does not implement epochs, local versions,
arbitrary equality, or every normalization rule from the packaging library.
The project avoids an external dependency here so the core triage engine can run
in constrained environments, but callers needing full PEP 440 should swap this
for ``packaging.version`` at the application boundary.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VersionKey = tuple[tuple[int, ...], int, int]


@dataclass(frozen=True)
class AffectedPackage:
    ecosystem: str
    package_name: str
    introduced: str | None = None
    fixed: str | None = None
    vulnerable_symbols: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Advisory:
    advisory_id: str
    aliases: list[str] = field(default_factory=list)
    summary: str = ""
    details: str = ""
    severity: str | None = None
    cvss_vector: str | None = None
    affected: list[AffectedPackage] = field(default_factory=list)
    published: str | None = None
    modified: str | None = None
    references: list[str] = field(default_factory=list)


def parse_version(version: str | None) -> VersionKey:
    """Return a small comparable key for common PEP 440-style versions."""
    if not version:
        return ((0,), 0, 0)
    normalized = version.strip().lower().replace("_", ".").replace("-", ".")
    normalized = normalized.split("+", 1)[0]
    match = re.match(
        r"^v?(?P<release>\d+(?:\.\d+)*)"
        r"(?:\.?(?P<tag>a|b|rc|dev|post)\.?(?P<tagnum>\d+)?)?",
        normalized,
    )
    if not match:
        parts = tuple(int(part) for part in re.findall(r"\d+", normalized))
        return (parts or (0,), 0, 0)

    release_parts = [int(part) for part in match.group("release").split(".")]
    release = tuple([*release_parts, *([0] * (8 - len(release_parts)))])
    tag = match.group("tag")
    tagnum = int(match.group("tagnum") or "0")
    phase_order = {
        "dev": -4,
        "a": -3,
        "b": -2,
        "rc": -1,
        None: 0,
        "post": 1,
    }
    return (release, phase_order[tag], tagnum)


def _severity(data: dict[str, Any]) -> tuple[str | None, str | None]:
    severities = data.get("severity") or []
    if not severities:
        return None, None
    first = severities[0]
    return first.get("type"), first.get("score")


def _symbols(affected: dict[str, Any]) -> list[str]:
    symbols: set[str] = set()
    database_specific = affected.get("database_specific") or {}
    ecosystem_specific = affected.get("ecosystem_specific") or {}
    for source in (affected, database_specific, ecosystem_specific):
        values = source.get("vulnerable_symbols") or source.get("symbols") or []
        symbols.update(str(value) for value in values if value)
    return sorted(symbols)


RangePair = tuple[str | None, str | None]


def _events_to_ranges(ranges: list[dict[str, Any]]) -> list[RangePair]:
    parsed: list[tuple[str | None, str | None]] = []
    for range_data in ranges:
        introduced: str | None = None
        fixed: str | None = None
        for event in range_data.get("events") or []:
            if "introduced" in event:
                introduced = str(event["introduced"])
            if "fixed" in event:
                fixed = str(event["fixed"])
                parsed.append((introduced, fixed))
                introduced = None
                fixed = None
        if introduced is not None or fixed is not None:
            parsed.append((introduced, fixed))
    return parsed or [(None, None)]


def load_osv(path_or_dict: str | Path | dict[str, Any]) -> Advisory:
    """Load one OSV-shaped advisory from a path or already-decoded dict."""
    if isinstance(path_or_dict, str | Path):
        with Path(path_or_dict).open(encoding="utf-8") as handle:
            data = json.load(handle)
    else:
        data = path_or_dict

    severity, cvss_vector = _severity(data)
    affected_packages: list[AffectedPackage] = []
    for item in data.get("affected") or []:
        package = item.get("package") or {}
        ecosystem = str(package.get("ecosystem") or "")
        package_name = str(package.get("name") or "")
        symbols = _symbols(item)
        for introduced, fixed in _events_to_ranges(item.get("ranges") or []):
            affected_packages.append(
                AffectedPackage(
                    ecosystem=ecosystem,
                    package_name=package_name,
                    introduced=introduced,
                    fixed=fixed,
                    vulnerable_symbols=symbols,
                )
            )

    return Advisory(
        advisory_id=str(data.get("id") or ""),
        aliases=[str(alias) for alias in data.get("aliases") or []],
        summary=str(data.get("summary") or ""),
        details=str(data.get("details") or ""),
        severity=severity,
        cvss_vector=cvss_vector,
        affected=affected_packages,
        published=data.get("published"),
        modified=data.get("modified"),
        references=[
            str(ref.get("url"))
            for ref in data.get("references") or []
            if isinstance(ref, dict) and ref.get("url")
        ],
    )


class AdvisoryDatabase:
    """In-memory advisory lookup keyed by package name and version range."""

    def __init__(self) -> None:
        self._advisories: list[Advisory] = []

    def add(self, advisory: Advisory) -> None:
        self._advisories.append(advisory)

    def all(self) -> list[Advisory]:
        return list(self._advisories)

    def count(self) -> int:
        return len(self._advisories)

    def for_package(self, name: str, version: str | None) -> list[Advisory]:
        normalized_name = _normalize_name(name)
        version_key = parse_version(version)
        matches: list[Advisory] = []
        for advisory in self._advisories:
            for package in advisory.affected:
                if _normalize_name(package.package_name) != normalized_name:
                    continue
                if _in_range(version_key, package.introduced, package.fixed):
                    matches.append(advisory)
                    break
        return matches


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _in_range(version: VersionKey, introduced: str | None, fixed: str | None) -> bool:
    lower_ok = introduced in (None, "0") or version >= parse_version(introduced)
    upper_ok = fixed is None or version < parse_version(fixed)
    return lower_ok and upper_ok
