"""SARIF 2.1.0 output for GitHub and other code-scanning consumers."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from reachable.callgraph import SourceLocation
from reachable.reachability import Finding, Verdict

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def to_sarif(findings: list[Finding]) -> dict[str, Any]:
    """Emit actionable findings; defensible NOT_REACHABLE results are not alerts."""
    actionable = [item for item in findings if item.verdict is not Verdict.NOT_REACHABLE]
    rules = _rules(actionable)
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "reachable",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://github.com/prathamesh-git9/reachable",
                        "rules": rules,
                    }
                },
                "results": [_result(finding) for finding in actionable],
            }
        ],
    }


def to_json(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=2, sort_keys=True)


def _rules(findings: list[Finding]) -> list[dict[str, Any]]:
    by_id = {finding.advisory.advisory_id: finding.advisory for finding in findings}
    rules: list[dict[str, Any]] = []
    for advisory_id, advisory in sorted(by_id.items()):
        rule: dict[str, Any] = {
            "id": advisory_id,
            "name": _rule_name(advisory_id),
            "shortDescription": {"text": advisory.summary or advisory_id},
            "fullDescription": {
                "text": advisory.details or advisory.summary or advisory_id
            },
            "properties": {
                "aliases": advisory.aliases,
                "severity": advisory.severity or "unknown",
                "tags": ["dependency", "vulnerability", "reachability"],
            },
        }
        if advisory.references:
            rule["helpUri"] = advisory.references[0]
        rules.append(rule)
    return rules


def _result(finding: Finding) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": finding.advisory.advisory_id,
        "level": "error" if finding.verdict is Verdict.REACHABLE else "warning",
        "kind": "fail" if finding.verdict is Verdict.REACHABLE else "review",
        "message": {
            "text": (
                f"{finding.dependency.name} {finding.dependency.version or ''}: "
                f"{finding.verdict.value}. {'; '.join(finding.rationale)}"
            ).strip()
        },
        "partialFingerprints": {
            "reachableFinding/v1": _fingerprint(finding),
        },
        "properties": {
            "verdict": finding.verdict.value,
            "confidence": finding.confidence,
            "dependency": finding.dependency.name,
            "dependencyVersion": finding.dependency.version,
            "vulnerableSymbols": finding.vulnerable_symbols_checked,
            "callPaths": finding.call_paths,
            "rationale": finding.rationale,
        },
    }
    located_paths = [path for path in finding.call_path_locations if path]
    if located_paths:
        result["locations"] = [_location(located_paths[0][-1])]
        result["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": _location(location),
                                "nestingLevel": index,
                            }
                            for index, location in enumerate(path)
                        ]
                    }
                ]
            }
            for path in located_paths
        ]
    return result


def _location(location: SourceLocation) -> dict[str, Any]:
    return {
        "physicalLocation": {
            "artifactLocation": {"uri": location.path, "uriBaseId": "%SRCROOT%"},
            "region": {"startLine": max(1, location.line)},
        },
        "logicalLocations": [
            {"fullyQualifiedName": location.symbol, "kind": "function"}
        ],
    }


def _fingerprint(finding: Finding) -> str:
    path = "->".join(finding.call_paths[0]) if finding.call_paths else "no-static-path"
    material = "\0".join(
        [
            finding.advisory.advisory_id,
            finding.dependency.name,
            finding.dependency.version or "",
            finding.verdict.value,
            path,
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _rule_name(advisory_id: str) -> str:
    cleaned = "".join(
        character if character.isalnum() else "_" for character in advisory_id
    )
    return f"Reachability_{cleaned}"
