"""Pipeline orchestration for dependency reachability triage.

The scanner composes parsers, call graph construction, reachability analysis,
optional explanation, and VEX emission. Keeping this as a thin orchestrator
prevents presentation layers from re-running or reinterpreting analysis.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from time import perf_counter
from typing import Any

from reachable.advisories import AdvisoryDatabase
from reachable.callgraph import build_call_graph
from reachable.dependencies import Dependency, parse_pyproject, parse_requirements
from reachable.explain import Explainer, Explanation
from reachable.providers.base import ChatProvider, PermanentProviderError
from reachable.reachability import Finding, analyse
from reachable.report import summary as findings_summary
from reachable.vex import to_openvex


@dataclass
class ScanResult:
    """Complete scan output shared by the CLI, API, and MCP server."""

    project_root: str
    dependencies: list[Dependency]
    findings: list[Finding]
    explanations: dict[str, Explanation]
    summary: dict[str, Any]
    call_graph_stats: dict[str, int]
    duration_ms: int
    openvex: dict[str, Any]


class Scanner:
    """Run the full reachability triage pipeline once per project."""

    def __init__(
        self,
        advisory_db: AdvisoryDatabase,
        provider: ChatProvider | None = None,
        *,
        explain: bool = True,
    ) -> None:
        self.advisory_db = advisory_db
        self.provider = provider
        self.explain = explain

    def scan(
        self,
        project_root: str | Path,
        *,
        entrypoints: list[str] | None = None,
        author: str = "reachable",
        product_id: str | None = None,
    ) -> ScanResult:
        started = perf_counter()
        root = Path(project_root)
        product = product_id or root.name
        dependencies, dependency_reason = _load_dependencies(root)

        if not dependencies:
            openvex = to_openvex([], author, product)
            return ScanResult(
                project_root=str(root),
                dependencies=[],
                findings=[],
                explanations={},
                summary={"total": 0, "reason": dependency_reason},
                call_graph_stats={
                    "nodes": 0,
                    "edges": 0,
                    "dynamic_sites": 0,
                    "unparsed_files": 0,
                },
                duration_ms=_elapsed_ms(started),
                openvex=openvex,
            )

        call_graph = build_call_graph(root)
        roots = set(entrypoints or [])
        findings = analyse(call_graph, dependencies, self.advisory_db, roots)
        explanations: dict[str, Explanation] = {}
        if self.explain:
            explainer = Explainer(self.provider)
            try:
                explanations = explainer.explain_batch(findings)
            except PermanentProviderError:
                explanations = {}

        openvex = to_openvex(findings, author, product)
        scan_summary = findings_summary(findings)
        if not isinstance(scan_summary, dict):
            scan_summary = {"summary": scan_summary}

        return ScanResult(
            project_root=str(root),
            dependencies=dependencies,
            findings=findings,
            explanations=explanations,
            summary=scan_summary,
            call_graph_stats=_call_graph_stats(call_graph),
            duration_ms=_elapsed_ms(started),
            openvex=openvex,
        )


def to_jsonable(value: Any) -> Any:
    """Convert scan objects into JSON-compatible primitives."""

    if is_dataclass(value):
        return {key: to_jsonable(item) for key, item in asdict(value).items()}
    if isinstance(value, dict):
        return {str(key): to_jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [to_jsonable(item) for item in value]
    if isinstance(value, Path):
        return str(value)
    if hasattr(value, "value"):
        return value.value
    return value


def _load_dependencies(root: Path) -> tuple[list[Dependency], str | None]:
    dependencies: list[Dependency] = []
    requirement_files = sorted(root.glob("requirements*.txt"))
    for path in requirement_files:
        dependencies.extend(parse_requirements(path))

    pyproject = root / "pyproject.toml"
    if pyproject.exists():
        dependencies.extend(parse_pyproject(pyproject))

    if not requirement_files and not pyproject.exists():
        return [], "no requirements.txt or pyproject.toml found"
    if not dependencies:
        return [], "dependency files were found but no dependencies were parsed"
    return _deduplicate_dependencies(dependencies), None


def _deduplicate_dependencies(dependencies: list[Dependency]) -> list[Dependency]:
    seen: set[tuple[str, str | None]] = set()
    unique: list[Dependency] = []
    for dependency in dependencies:
        key = (dependency.name, dependency.version)
        if key in seen:
            continue
        seen.add(key)
        unique.append(dependency)
    return unique


def _call_graph_stats(call_graph: object) -> dict[str, int]:
    edges = getattr(call_graph, "edges", {}) or {}
    return {
        "nodes": _node_count(edges),
        "edges": _edge_count(edges),
        "dynamic_sites": len(getattr(call_graph, "dynamic_sites", []) or []),
        "unparsed_files": len(getattr(call_graph, "unparsed_files", []) or []),
    }


def _node_count(edges: object) -> int:
    if not isinstance(edges, dict):
        return 0
    nodes = set(edges)
    for callees in edges.values():
        nodes.update(callees)
    return len(nodes)


def _edge_count(edges: object) -> int:
    if not isinstance(edges, dict):
        return 0
    try:
        return sum(len(callees) for callees in edges.values())
    except TypeError:
        return 0


def _elapsed_ms(started: float) -> int:
    return int((perf_counter() - started) * 1000)
