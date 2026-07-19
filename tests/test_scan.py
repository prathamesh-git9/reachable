from __future__ import annotations

from pathlib import Path

from reachable.advisories import AdvisoryDatabase
from reachable.reachability import Verdict
from reachable.scan import Scanner


def test_scanner_end_to_end_fixture_verdicts(
    scanner: Scanner,
    sample_app_path: Path,
) -> None:
    result = scanner.scan(sample_app_path)
    verdicts = {finding.dependency.name: finding.verdict for finding in result.findings}

    assert verdicts == {
        "dangerlib": Verdict.REACHABLE,
        "unusedlib": Verdict.NOT_REACHABLE,
        "dynamiclib": Verdict.UNKNOWN,
        "neverimported": Verdict.NOT_REACHABLE,
    }
    assert result.call_graph_stats["nodes"] > 0
    assert result.call_graph_stats["edges"] > 0
    assert result.call_graph_stats["dynamic_sites"] == 1
    assert result.openvex["statements"]
    assert result.duration_ms >= 0


def test_project_with_no_dependency_file_returns_empty_result(
    tmp_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    result = Scanner(advisory_db, explain=False).scan(tmp_path)

    assert result.findings == []
    assert result.dependencies == []
    assert result.summary["reason"] == "no requirements.txt or pyproject.toml found"
    assert result.openvex["statements"] == []
