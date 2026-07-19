"""Human-oriented prioritization for security triage.

Machine-readable VEX is necessary for automation, but humans still need a
ranked work queue with evidence. The report keeps REACHABLE items first,
UNKNOWN second, and NOT_REACHABLE last so engineers spend attention where risk
and uncertainty are highest before clearing defensible non-reachable findings.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from reachable.reachability import Finding, Verdict


def to_markdown(findings: list[Finding]) -> str:
    lines = ["# Reachability Triage Report", ""]
    for finding in _rank(findings):
        lines.extend(
            [
                f"## {finding.verdict.value}: {finding.advisory.advisory_id}",
                "",
                "- Dependency: "
                f"{finding.dependency.name} {finding.dependency.version or ''}",
                f"- Severity: {finding.advisory.severity or 'unknown'}",
                f"- Confidence: {finding.confidence:.2f}",
                f"- Rationale: {'; '.join(finding.rationale) or 'none'}",
            ]
        )
        if finding.verdict is Verdict.REACHABLE and finding.call_paths:
            lines.append(f"- Evidence path: {' -> '.join(finding.call_paths[0])}")
        if finding.verdict is Verdict.UNKNOWN:
            reasons = "; ".join(finding.rationale) or "unspecified uncertainty"
            lines.append(f"- Unknown reason: {reasons}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def to_table(findings: list[Finding]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for finding in _rank(findings):
        rows.append(
            {
                "advisory": finding.advisory.advisory_id,
                "dependency": finding.dependency.name,
                "version": finding.dependency.version,
                "verdict": finding.verdict.value,
                "severity": finding.advisory.severity or "unknown",
                "confidence": finding.confidence,
                "reason": "; ".join(finding.rationale),
            }
        )
    return rows


def summary(findings: list[Finding]) -> dict[str, dict[str, int]]:
    by_verdict = Counter(finding.verdict.value for finding in findings)
    by_severity = Counter(finding.advisory.severity or "unknown" for finding in findings)
    return {
        "by_verdict": dict(by_verdict),
        "by_severity": dict(by_severity),
    }


def _rank(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda finding: (
            _VERDICT_ORDER[finding.verdict],
            -_severity_score(finding.advisory.severity),
            -finding.confidence,
        ),
    )


def _severity_score(severity: str | None) -> float:
    if not severity:
        return 0.0
    lower = severity.lower()
    if lower in _SEVERITY_WORDS:
        return _SEVERITY_WORDS[lower]
    if lower.startswith("cvss"):
        return 5.0
    return 0.0


_VERDICT_ORDER = {
    Verdict.REACHABLE: 0,
    Verdict.UNKNOWN: 1,
    Verdict.NOT_REACHABLE: 2,
}

_SEVERITY_WORDS = {
    "critical": 4.0,
    "high": 3.0,
    "medium": 2.0,
    "low": 1.0,
}
