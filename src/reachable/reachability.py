"""Verdict engine for dependency vulnerability reachability.

This module is intentionally conservative. Static call graphs can prove that a
visible path exists, but they cannot prove a path does not exist if dynamic
dispatch or unparsed code may hide edges. The engine therefore has three
verdicts: REACHABLE, NOT_REACHABLE, and UNKNOWN. Collapsing UNKNOWN into
NOT_REACHABLE would create the dangerous failure mode this project is built to
avoid: telling a security team to ignore vulnerable code that may execute.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from reachable.advisories import Advisory, AdvisoryDatabase
from reachable.callgraph import CallGraph, DynamicSite
from reachable.dependencies import Dependency, normalize_name


class Verdict(StrEnum):
    REACHABLE = "REACHABLE"
    NOT_REACHABLE = "NOT_REACHABLE"
    UNKNOWN = "UNKNOWN"


@dataclass
class Finding:
    advisory: Advisory
    dependency: Dependency
    verdict: Verdict
    confidence: float
    rationale: list[str] = field(default_factory=list)
    call_paths: list[list[str]] = field(default_factory=list)
    dynamic_sites_considered: list[DynamicSite] = field(default_factory=list)
    vulnerable_symbols_checked: list[str] = field(default_factory=list)


def analyse(
    call_graph: CallGraph,
    dependencies: list[Dependency],
    advisory_db: AdvisoryDatabase,
    entrypoints: set[str],
) -> list[Finding]:
    roots = entrypoints or call_graph.entrypoints
    reachable = call_graph.reachable_from(roots)
    findings: list[Finding] = []
    for dependency in dependencies:
        advisories = advisory_db.for_package(dependency.name, dependency.version)
        for advisory in advisories:
            symbols = _symbols_for_dependency(advisory, dependency)
            rationale: list[str] = []
            paths: list[list[str]] = []

            # Rule e, evaluated BEFORE rule a. A package that is never
            # imported anywhere cannot execute any of its symbols, so knowing
            # *which* symbol is vulnerable is unnecessary - the conclusion
            # follows from the package being absent from the import graph
            # entirely.
            #
            # This ordering is what makes the tool useful rather than merely
            # safe. Most real OSV advisories carry no vulnerable_symbols, so
            # letting rule (a) short-circuit first returned UNKNOWN for nearly
            # every real advisory, leaving the triage burden exactly where it
            # was.
            #
            # The gate is import-capable dynamic constructs specifically, not
            # dynamic dispatch generally: getattr or a dict lookup can only
            # reach a module that was already imported, whereas
            # importlib.import_module, __import__, eval and exec can pull in a
            # package that appears nowhere in the static import graph.
            if not _package_imported(call_graph, dependency.name):
                blocking = _import_capable_sites(call_graph)
                if not blocking and not call_graph.unparsed_files:
                    findings.append(
                        _finding(
                            advisory,
                            dependency,
                            Verdict.NOT_REACHABLE,
                            symbols,
                            [
                                "package declared but never imported",
                                "no dynamic import mechanism present in the "
                                "codebase, so the package cannot be loaded",
                            ],
                            paths,
                            [],
                            call_graph,
                        )
                    )
                    continue

            # Rule a: without symbol data there is no target to search for.
            # Treating this as not reachable would confuse absent metadata with
            # proof that the vulnerable function cannot execute.
            if not symbols:
                rationale.append(
                    "advisory does not identify a vulnerable symbol; "
                    "cannot determine reachability"
                )
                findings.append(
                    _finding(
                        advisory,
                        dependency,
                        Verdict.UNKNOWN,
                        symbols,
                        rationale,
                        paths,
                        [],
                        call_graph,
                    )
                )
                continue

            for symbol in symbols:
                if symbol in reachable:
                    paths.extend(call_graph.paths_to(symbol, roots))

            # Rule b: a visible static path to a vulnerable symbol is enough to
            # prioritize remediation and attach concrete evidence.
            if paths:
                rationale.append("vulnerable symbol is reachable from an entrypoint")
                findings.append(
                    _finding(
                        advisory,
                        dependency,
                        Verdict.REACHABLE,
                        symbols,
                        rationale,
                        paths,
                        [],
                        call_graph,
                    )
                )
                continue

            relevant_dynamic = _relevant_dynamic_sites(call_graph, dependency)
            imported = _package_imported(call_graph, dependency.name)
            if not imported:
                rationale.append("package declared but never imported")

            # Rule c: dynamic dispatch or unparseable files mean the graph may
            # be missing an edge toward the package, so the safe answer is
            # UNKNOWN rather than NOT_REACHABLE.
            if relevant_dynamic or call_graph.unparsed_files:
                for site in relevant_dynamic:
                    rationale.append(
                        f"dynamic dispatch may hide a call: {site.kind} "
                        f"at {site.module}:{site.lineno}"
                    )
                for file_path in call_graph.unparsed_files:
                    rationale.append(f"could not parse source file: {file_path}")
                findings.append(
                    _finding(
                        advisory,
                        dependency,
                        Verdict.UNKNOWN,
                        symbols,
                        rationale,
                        paths,
                        relevant_dynamic,
                        call_graph,
                    )
                )
                continue

            # Rule d and e: only a cleanly parsed graph with no relevant dynamic
            # uncertainty may issue NOT_REACHABLE. A never-imported direct
            # dependency is eligible, but the rationale must say exactly that.
            rationale.append("no static path from entrypoints to vulnerable symbol")

            # A generic dynamic importer elsewhere in the codebase (a plugin
            # loader, say) could in principle import this package and call into
            # it with no static edge. That does not justify downgrading the
            # verdict - nearly every real codebase has such a loader, and
            # marking everything UNKNOWN would return the reviewer to the
            # six-hours-a-day triage problem this tool exists to remove. But it
            # must not be hidden either, so the caveat rides along with the
            # verdict and the engineer decides what it is worth.
            importers = _import_capable_sites(call_graph)
            if importers:
                sample = importers[0]
                rationale.append(
                    "caveat: codebase contains a dynamic import mechanism "
                    f"({sample.kind} at {sample.module}:{sample.lineno}); "
                    "static analysis cannot rule out a load-and-call path"
                )

            findings.append(
                _finding(
                    advisory,
                    dependency,
                    Verdict.NOT_REACHABLE,
                    symbols,
                    rationale,
                    paths,
                    relevant_dynamic,
                    call_graph,
                )
            )
    return findings


def _finding(
    advisory: Advisory,
    dependency: Dependency,
    verdict: Verdict,
    symbols: list[str],
    rationale: list[str],
    paths: list[list[str]],
    dynamic_sites: list[DynamicSite],
    graph: CallGraph,
) -> Finding:
    return Finding(
        advisory=advisory,
        dependency=dependency,
        verdict=verdict,
        confidence=_confidence(verdict, symbols, paths, dynamic_sites, graph),
        rationale=rationale,
        call_paths=paths,
        dynamic_sites_considered=dynamic_sites,
        vulnerable_symbols_checked=symbols,
    )


def _symbols_for_dependency(advisory: Advisory, dependency: Dependency) -> list[str]:
    wanted = normalize_name(dependency.name)
    symbols: set[str] = set()
    for package in advisory.affected:
        if normalize_name(package.package_name) == wanted:
            symbols.update(package.vulnerable_symbols)
    return sorted(symbols)


# Constructs that can load a package absent from the static import graph.
# getattr/setattr/lookup_call are deliberately excluded: they can only reach
# something already imported, so they cannot resurrect a never-imported package.
_IMPORT_CAPABLE_KINDS = frozenset({"dynamic_import", "eval", "exec"})


def _import_capable_sites(call_graph: CallGraph) -> list:
    return [s for s in call_graph.dynamic_sites if s.kind in _IMPORT_CAPABLE_KINDS]


def _package_imported(call_graph: CallGraph, name: str) -> bool:
    normalized = normalize_name(name)
    return any(
        normalize_name(imported) == normalized
        for imports in call_graph.imports.values()
        for imported in imports
    )


def _relevant_dynamic_sites(
    call_graph: CallGraph,
    dependency: Dependency,
) -> list[DynamicSite]:
    imported_modules = {
        module
        for module, imports in call_graph.imports.items()
        if any(normalize_name(imported) == dependency.name for imported in imports)
    }
    if not imported_modules:
        return []
    return [site for site in call_graph.dynamic_sites if site.module in imported_modules]


def _confidence(
    verdict: Verdict,
    symbols: list[str],
    paths: list[list[str]],
    dynamic_sites: list[DynamicSite],
    graph: CallGraph,
) -> float:
    score = 0.35 if symbols else 0.1
    if verdict is Verdict.REACHABLE:
        shortest = min((len(path) for path in paths), default=5)
        score += 0.55 - min(shortest, 10) * 0.02
    elif verdict is Verdict.NOT_REACHABLE:
        score += 0.45
    else:
        score += 0.2
    score -= min(len(dynamic_sites), 5) * 0.06
    score -= min(len(graph.unparsed_files), 5) * 0.08
    return max(0.05, min(0.99, round(score, 2)))
