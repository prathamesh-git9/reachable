from __future__ import annotations

import json
from pathlib import Path

from reachable.advisories import AdvisoryDatabase
from reachable.callgraph import build_call_graph
from reachable.dependencies import parse_requirements
from reachable.reachability import Finding, analyse
from reachable.vex import to_openvex


def _fixture_findings(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> list[Finding]:
    graph = build_call_graph(sample_app_path)
    dependencies = parse_requirements(sample_app_path / "requirements.txt")
    return analyse(graph, dependencies, advisory_db, graph.entrypoints)


def test_openvex_document_has_required_fields(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    document = to_openvex(_fixture_findings(sample_app_path, advisory_db), "me", "app")

    assert {"@context", "@id", "author", "timestamp", "version", "statements"} <= set(
        document
    )


def test_status_mapping_and_not_affected_justification(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    findings = _fixture_findings(sample_app_path, advisory_db)
    document = to_openvex(findings, "me", "app")
    statuses = {
        statement["vulnerability"]["name"]: statement
        for statement in document["statements"]
    }

    assert statuses["OSV-2026-0001"]["status"] == "affected"
    assert statuses["OSV-2026-0002"]["status"] == "not_affected"
    assert statuses["OSV-2026-0003"]["status"] == "under_investigation"
    assert statuses["OSV-2026-0002"]["justification"] == (
        "vulnerable_code_not_in_execute_path"
    )


def test_document_is_json_serialisable(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    document = to_openvex(_fixture_findings(sample_app_path, advisory_db), "me", "app")

    encoded = json.dumps(document)
    assert encoded


def test_every_finding_produces_exactly_one_statement(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    findings = _fixture_findings(sample_app_path, advisory_db)
    document = to_openvex(findings, "me", "app")

    assert len(document["statements"]) == len(findings)
