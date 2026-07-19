"""Dependency discovery for reachability triage.

Reachability has to be evaluated against what the project actually ships, not
only what a scanner happened to report. This module reads the common Python
dependency surfaces without trying to become a package installer. Where a file
format exposes directness, that is preserved; where it does not, ``direct`` is
set to ``False`` rather than guessed. The caller can decide how to display that
uncertainty.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str | None
    direct: bool
    source_file: str


def normalize_name(name: str) -> str:
    """Normalize package names per PEP 503."""
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(path: str | Path) -> list[Dependency]:
    """Parse a requirements.txt-like file, following ``-r`` includes."""
    source = Path(path)
    seen: set[Path] = set()
    return _parse_requirements_file(source, seen)


def _parse_requirements_file(path: Path, seen: set[Path]) -> list[Dependency]:
    resolved = path.resolve()
    if resolved in seen or not path.exists():
        return []
    seen.add(resolved)
    dependencies: list[Dependency] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith(("-r ", "--requirement ")):
            include = line.split(maxsplit=1)[1]
            dependencies.extend(_parse_requirements_file(path.parent / include, seen))
            continue
        if line.startswith("-"):
            continue
        requirement = line.split(";", 1)[0].strip()
        parsed = _parse_requirement(requirement)
        if parsed is not None:
            name, version = parsed
            dependencies.append(
                Dependency(
                    name=normalize_name(name),
                    version=version,
                    direct=True,
                    source_file=str(path),
                )
            )
    return dependencies


def parse_pyproject(path: str | Path) -> list[Dependency]:
    """Parse PEP 621 project dependencies and optional dependency groups."""
    source = Path(path)
    if not source.exists():
        return []
    data = tomllib.loads(source.read_text(encoding="utf-8"))
    project = data.get("project") or {}
    dependencies: list[Dependency] = []
    for requirement in project.get("dependencies") or []:
        parsed = _parse_requirement(str(requirement).split(";", 1)[0].strip())
        if parsed is None:
            continue
        name, version = parsed
        dependencies.append(Dependency(normalize_name(name), version, True, str(source)))
    optional = project.get("optional-dependencies") or {}
    for group_requirements in optional.values():
        for requirement in group_requirements:
            parsed = _parse_requirement(str(requirement).split(";", 1)[0].strip())
            if parsed is None:
                continue
            name, version = parsed
            dependencies.append(
                Dependency(normalize_name(name), version, True, str(source))
            )
    return dependencies


def parse_lockfile(path: str | Path) -> list[Dependency]:
    """Parse simple uv.lock or poetry.lock TOML; return empty on unfamiliar data."""
    source = Path(path)
    if not source.exists():
        return []
    try:
        data = tomllib.loads(source.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        return []
    packages = data.get("package")
    if not isinstance(packages, list):
        return []
    dependencies: list[Dependency] = []
    for package in packages:
        if not isinstance(package, dict) or "name" not in package:
            continue
        dependencies.append(
            Dependency(
                name=normalize_name(str(package["name"])),
                version=str(package["version"]) if package.get("version") else None,
                direct=False,
                source_file=str(source),
            )
        )
    return dependencies


def _parse_requirement(requirement: str) -> tuple[str, str | None] | None:
    match = re.match(
        r"^\s*(?P<name>[A-Za-z0-9_.-]+)(?:\[[^\]]+\])?"
        r"\s*(?P<op>===|==|~=|>=|<=|>|<)?\s*(?P<version>[^,\s]+)?",
        requirement,
    )
    if not match:
        return None
    name = match.group("name")
    operator = match.group("op")
    version = match.group("version")
    pinned = version if operator in {"==", "==="} else version
    return name, pinned
