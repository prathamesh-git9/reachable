"""Advisory explanations for already-computed reachability findings.

This module is intentionally downstream of static analysis. Explanation text is
advisory only: the verdict is produced by the reachability engine and is not
model-influenced. The alternative, letting model prose change a verdict, would
turn an unreliable summary into a security decision.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime

from reachable.reachability import Finding, Verdict

from .providers.base import ChatProvider
from .providers.fake import FakeProvider


@dataclass
class Explanation:
    """Model-generated prose plus the immutable analysis verdict."""

    summary: str
    exploitability_notes: str
    suggested_action: str
    vex_justification_draft: str
    model: str
    generated_at: str
    verdict: Verdict
    contradiction_detected: bool = False


class Explainer:
    """Generate advisory explanations without modifying findings."""

    def __init__(
        self,
        provider: ChatProvider | None = None,
        *,
        max_tokens: int = 500,
    ) -> None:
        self.provider = provider or FakeProvider()
        self.max_tokens = max_tokens

    def explain(self, finding: Finding) -> Explanation:
        system = (
            "You explain security reachability findings. The static analysis "
            "verdict is an established fact. Do not change it, overrule it, or "
            "state a different verdict. Explain operational impact and draft "
            "short VEX justification prose."
        )
        prompt = _build_prompt(finding)
        output = self.provider.complete(
            system,
            prompt,
            max_tokens=self.max_tokens,
        ).strip()
        contradiction = _contradicts_verdict(output, finding.verdict)

        return Explanation(
            summary=_first_sentence(output),
            exploitability_notes=output,
            suggested_action=_suggested_action(finding.verdict),
            vex_justification_draft=output,
            model=f"{self.provider.name}:{self.provider.model}",
            generated_at=datetime.now(UTC).isoformat(),
            verdict=finding.verdict,
            contradiction_detected=contradiction,
        )

    def explain_batch(
        self,
        findings: Iterable[Finding],
        limit: int | None = None,
        *,
        include_not_reachable: bool = False,
    ) -> dict[str, Explanation]:
        """Explain actionable findings, skipping NOT_REACHABLE by default."""

        explanations: dict[str, Explanation] = {}
        count = 0
        for finding in findings:
            if not include_not_reachable and finding.verdict == Verdict.NOT_REACHABLE:
                continue
            if limit is not None and count >= limit:
                break
            key = _finding_key(finding)
            explanations[key] = self.explain(finding)
            count += 1
        return explanations


def _build_prompt(finding: Finding) -> str:
    advisory = finding.advisory
    dependency = finding.dependency
    paths = _format_call_paths(finding.call_paths)
    dynamic_sites = _format_dynamic_sites(finding.dynamic_sites_considered)
    symbols = ", ".join(finding.vulnerable_symbols_checked) or "none recorded"

    return "\n".join(
        [
            "Established static-analysis facts:",
            f"Verdict: {finding.verdict}",
            f"Confidence: {finding.confidence}",
            f"Rationale: {finding.rationale}",
            f"Advisory: {advisory.advisory_id}",
            f"Aliases: {', '.join(advisory.aliases)}",
            f"Summary: {advisory.summary}",
            f"Severity: {advisory.severity}",
            f"Package: {dependency.name} {dependency.version}",
            f"Vulnerable symbols checked: {symbols}",
            "Call paths:",
            paths,
            "Dynamic sites:",
            dynamic_sites,
            "",
            "Write concise prose for a security engineer. Explain what the "
            "facts mean and draft VEX justification text. Do not produce a "
            "new reachability verdict.",
        ]
    )


def _format_call_paths(paths: object) -> str:
    if not paths:
        return "none recorded"
    lines: list[str] = []
    for path in paths:  # type: ignore[assignment]
        if isinstance(path, (list, tuple)):
            lines.append(" -> ".join(str(part) for part in path))
        else:
            lines.append(str(path))
    return "\n".join(lines)


def _format_dynamic_sites(sites: object) -> str:
    if not sites:
        return "none recorded"
    lines: list[str] = []
    for site in sites:  # type: ignore[assignment]
        module = getattr(site, "module", "unknown")
        lineno = getattr(site, "lineno", "?")
        kind = getattr(site, "kind", "dynamic")
        snippet = getattr(site, "snippet", "")
        lines.append(f"{module}:{lineno} {kind} {snippet}".strip())
    return "\n".join(lines)


def _first_sentence(text: str) -> str:
    if not text:
        return ""
    match = re.search(r"(?<=[.!?])\s+", text)
    return text[: match.start()].strip() if match else text.strip()


def _suggested_action(verdict: Verdict) -> str:
    if verdict == Verdict.REACHABLE:
        return "Prioritise remediation or mitigation and retain call-path evidence."
    if verdict == Verdict.UNKNOWN:
        return "Investigate manually before accepting or deferring remediation."
    return "Record the static-analysis rationale and monitor for analysis changes."


def _contradicts_verdict(text: str, verdict: Verdict) -> bool:
    lowered = text.lower()
    says_not_reachable = bool(
        re.search(r"\b(not reachable|unreachable|cannot be reached)\b", lowered)
    )
    says_reachable = bool(
        re.search(r"\b(is reachable|are reachable|reachable from)\b", lowered)
    )
    if verdict == Verdict.REACHABLE:
        return says_not_reachable
    if verdict == Verdict.NOT_REACHABLE:
        return says_reachable and not says_not_reachable
    return says_reachable or says_not_reachable


def _finding_key(finding: Finding) -> str:
    return f"{finding.dependency.name}:{finding.advisory.advisory_id}"
