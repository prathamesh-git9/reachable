"""OpenVEX emission for reachability findings.

VEX is the machine-readable way to tell a downstream consumer "we ship this
dependency but the vulnerable path is not reachable". Emitting OpenVEX matters
because that assertion is exactly what stops a scanner from re-raising the same
finding forever, while still preserving UNKNOWN when static analysis cannot
support a not-affected claim.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from reachable.reachability import Finding, Verdict


def to_openvex(findings: list[Finding], author: str, product_id: str) -> dict:
    timestamp = datetime.now(UTC).replace(microsecond=0).isoformat()
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"urn:uuid:{uuid4()}",
        "author": author,
        "timestamp": timestamp,
        "version": 1,
        "statements": [
            _statement(finding, product_id, timestamp) for finding in findings
        ],
    }


def to_json(document: dict) -> str:
    return json.dumps(document, indent=2, sort_keys=True)


def _statement(finding: Finding, product_id: str, timestamp: str) -> dict:
    status = _status(finding.verdict)
    statement = {
        "vulnerability": {
            "name": finding.advisory.advisory_id,
            "aliases": finding.advisory.aliases,
        },
        "timestamp": timestamp,
        "products": [{"@id": product_id}],
        "status": status,
    }
    if finding.verdict is Verdict.NOT_REACHABLE:
        statement["justification"] = "vulnerable_code_not_in_execute_path"
        statement["impact_statement"] = "; ".join(finding.rationale)
    elif finding.verdict is Verdict.UNKNOWN:
        statement["impact_statement"] = "; ".join(finding.rationale)
    elif finding.call_paths:
        statement["action_statement"] = "Reachable path: " + " -> ".join(
            finding.call_paths[0]
        )
    return statement


def _status(verdict: Verdict) -> str:
    if verdict is Verdict.REACHABLE:
        return "affected"
    if verdict is Verdict.NOT_REACHABLE:
        return "not_affected"
    return "under_investigation"
