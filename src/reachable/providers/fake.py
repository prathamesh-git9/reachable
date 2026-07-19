"""Deterministic provider used as the default for local and test runs.

Real providers require credentials, network access, and sometimes paid quota.
The fake provider keeps the CLI, API, and scanner usable in those environments
while still exercising the same explanation boundary as live providers.
"""

from __future__ import annotations

from collections.abc import Sequence

from .base import PermanentProviderError, TransientProviderError


class FakeProvider:
    """A deterministic provider with optional canned responses and failures."""

    def __init__(
        self,
        name: str = "fake",
        model: str = "fake-1",
        responses: Sequence[str] | None = None,
        fail_times: int = 0,
        always_fail: bool = False,
    ) -> None:
        self.name = name
        self.model = model
        self._responses = list(responses or [])
        self._fail_times = fail_times
        self._always_fail = always_fail
        self.calls = 0

    def complete(
        self,
        system: str,
        prompt: str,
        *,
        max_tokens: int = 1024,
    ) -> str:
        self.calls += 1

        if self._always_fail:
            raise PermanentProviderError("fake provider configured to fail")
        if self.calls <= self._fail_times:
            raise TransientProviderError("fake transient provider failure")
        if self._responses:
            index = (self.calls - self._fail_times - 1) % len(self._responses)
            return self._responses[index]

        return _deterministic_explanation(prompt, max_tokens)


def _deterministic_explanation(prompt: str, max_tokens: int) -> str:
    package = _field(prompt, "Package") or "the affected dependency"
    advisory = _field(prompt, "Advisory") or "the advisory"
    severity = _field(prompt, "Severity") or "unknown severity"

    lowered = prompt.lower()
    has_paths = "call paths:" in lowered and "none recorded" not in lowered
    has_dynamic = "dynamic sites:" in lowered and "none recorded" not in lowered

    if has_paths:
        exposure = "Observed application call paths reach the vulnerable symbol."
    elif has_dynamic:
        exposure = (
            "Dynamic dispatch was observed, so static analysis cannot fully "
            "resolve exposure."
        )
    else:
        exposure = (
            "No concrete call path is included in the finding, so the result "
            "should be reviewed with the static analysis rationale."
        )

    text = (
        f"{advisory} affects {package} with {severity}. {exposure} "
        "Prioritise remediation evidence from the recorded call paths and "
        "capture compensating controls in the VEX justification."
    )
    words = text.split()
    return " ".join(words[:max_tokens])


def _field(prompt: str, label: str) -> str | None:
    prefix = f"{label}:"
    for line in prompt.splitlines():
        if line.startswith(prefix):
            value = line.removeprefix(prefix).strip()
            return value or None
    return None
