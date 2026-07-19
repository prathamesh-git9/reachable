from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from reachable.advisories import AdvisoryDatabase, load_osv
from reachable.callgraph import build_call_graph
from reachable.dependencies import Dependency, parse_requirements
from reachable.reachability import Finding, Verdict, analyse


def _findings_by_package(findings: list[Finding]) -> dict[str, Finding]:
    return {finding.dependency.name: finding for finding in findings}


def _analyse_project(project: Path, database: AdvisoryDatabase) -> dict[str, Finding]:
    graph = build_call_graph(project)
    dependencies = parse_requirements(project / "requirements.txt")
    findings = analyse(graph, dependencies, database, graph.entrypoints)
    return _findings_by_package(findings)


def test_fixture_ground_truth_verdicts_exact(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    findings = _analyse_project(sample_app_path, advisory_db)

    assert findings["dangerlib"].verdict is Verdict.REACHABLE
    assert findings["unusedlib"].verdict is Verdict.NOT_REACHABLE
    assert findings["dynamiclib"].verdict is Verdict.UNKNOWN
    assert findings["neverimported"].verdict is Verdict.NOT_REACHABLE


def test_imported_package_without_symbol_metadata_is_unknown_not_not_reachable(
    call_graph,
) -> None:
    """Missing advisory metadata cannot prove the vulnerable code is absent."""

    database = AdvisoryDatabase()
    database.add(
        load_osv(
            {
                "id": "OSV-NOSYMBOL",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "unusedlib"},
                        "ranges": [{"events": [{"introduced": "0"}]}],
                    }
                ],
            }
        )
    )
    dependencies = [Dependency("unusedlib", "2.0.0", True, "test")]

    finding = analyse(call_graph, dependencies, database, call_graph.entrypoints)[0]

    assert finding.verdict is Verdict.UNKNOWN


def test_never_imported_package_without_symbol_metadata_is_not_reachable(
    call_graph,
) -> None:
    """Absence from the import graph settles execution even without symbols."""

    database = AdvisoryDatabase()
    database.add(
        load_osv(
            {
                "id": "OSV-ABSENT",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "absentlib"},
                        "ranges": [{"events": [{"introduced": "0"}]}],
                    }
                ],
            }
        )
    )
    dependencies = [Dependency("absentlib", "1.0.0", True, "test")]

    finding = analyse(call_graph, dependencies, database, call_graph.entrypoints)[0]

    assert finding.verdict is Verdict.NOT_REACHABLE


def test_dynamic_importer_flips_never_imported_package_back_to_unknown(
    sample_app_copy: Callable[[], Path],
    advisory_db: AdvisoryDatabase,
) -> None:
    """Import-capable dynamic constructs defeat never-imported certainty."""

    project = sample_app_copy()
    (project / "sample_app" / "plugin_loader.py").write_text(
        "import importlib\n\n\ndef load(name: str) -> object:\n"
        "    return importlib.import_module(name)\n",
        encoding="utf-8",
    )

    findings = _analyse_project(project, advisory_db)

    assert findings["neverimported"].verdict is Verdict.UNKNOWN


def test_getattr_dynamic_site_does_not_contaminate_unrelated_package_verdict(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    """Dynamic sites are scoped to imported modules, not global uncertainty."""

    findings = _analyse_project(sample_app_path, advisory_db)

    assert findings["unusedlib"].verdict is Verdict.NOT_REACHABLE
    assert findings["unusedlib"].dynamic_sites_considered == []


def test_not_reachable_with_dynamic_importer_carries_caveat(
    sample_app_copy: Callable[[], Path],
    advisory_db: AdvisoryDatabase,
) -> None:
    project = sample_app_copy()
    (project / "sample_app" / "plugin_loader.py").write_text(
        "import importlib\n\n\ndef load(name: str) -> object:\n"
        "    return importlib.import_module(name)\n",
        encoding="utf-8",
    )

    findings = _analyse_project(project, advisory_db)

    assert findings["unusedlib"].verdict is Verdict.NOT_REACHABLE
    assert any(
        reason.startswith("caveat:") and "dynamic_import" in reason
        for reason in findings["unusedlib"].rationale
    )


def test_unparsed_file_forces_unknown_rather_than_not_reachable(
    sample_app_copy: Callable[[], Path],
    advisory_db: AdvisoryDatabase,
) -> None:
    project = sample_app_copy()
    (project / "sample_app" / "bad.py").write_text("def broken(:\n", encoding="utf-8")

    findings = _analyse_project(project, advisory_db)

    assert findings["unusedlib"].verdict is Verdict.UNKNOWN


def test_reachable_findings_carry_call_paths_and_unknowns_explain_why(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    findings = _analyse_project(sample_app_path, advisory_db)

    assert findings["dangerlib"].call_paths
    assert findings["dynamiclib"].rationale


def test_confidence_is_float_between_zero_and_one(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    findings = _analyse_project(sample_app_path, advisory_db)

    for finding in findings.values():
        assert isinstance(finding.confidence, float)
        assert 0.0 <= finding.confidence <= 1.0
