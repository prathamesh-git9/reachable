from __future__ import annotations

from pathlib import Path

from reachable.advisories import AdvisoryDatabase
from reachable.callgraph import build_call_graph
from reachable.dependencies import parse_requirements
from reachable.explain import Explainer
from reachable.providers.fake import FakeProvider
from reachable.reachability import Finding, Verdict, analyse
from reachable.scan import Scanner


def _findings(sample_app_path: Path, advisory_db: AdvisoryDatabase) -> list[Finding]:
    graph = build_call_graph(sample_app_path)
    dependencies = parse_requirements(sample_app_path / "requirements.txt")
    return analyse(graph, dependencies, advisory_db, graph.entrypoints)


def test_explanation_copies_verdict_without_changing_it(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    finding = _findings(sample_app_path, advisory_db)[0]

    explanation = Explainer(FakeProvider()).explain(finding)

    assert explanation.verdict is finding.verdict


def test_contradictory_provider_text_is_flagged_but_verdict_is_unchanged(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    finding = next(
        item
        for item in _findings(sample_app_path, advisory_db)
        if item.verdict is Verdict.REACHABLE
    )
    provider = FakeProvider(responses=["This advisory is not reachable."])

    explanation = Explainer(provider).explain(finding)

    assert explanation.verdict is Verdict.REACHABLE
    assert explanation.contradiction_detected is True


def test_explain_batch_skips_not_reachable_by_default(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    explanations = Explainer(FakeProvider()).explain_batch(
        _findings(sample_app_path, advisory_db)
    )

    assert "unusedlib:OSV-2026-0002" not in explanations
    assert "neverimported:OSV-2026-0004" not in explanations


def test_explain_batch_can_include_not_reachable_findings(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    explanations = Explainer(FakeProvider()).explain_batch(
        _findings(sample_app_path, advisory_db),
        include_not_reachable=True,
    )

    assert "unusedlib:OSV-2026-0002" in explanations
    assert "neverimported:OSV-2026-0004" in explanations


def test_permanent_provider_error_does_not_crash_scan(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    result = Scanner(
        advisory_db,
        FakeProvider(always_fail=True),
        explain=True,
    ).scan(sample_app_path)

    assert result.findings
    assert result.explanations == {}
