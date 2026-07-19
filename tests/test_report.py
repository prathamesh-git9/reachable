"""Tests for the prioritised report.

Ordering is the product here. A triage queue that lists a NOT_REACHABLE
finding above an UNKNOWN one inverts the value of the tool: the engineer works
top-down, so the top of the list must be the thing most likely to matter.
"""

from __future__ import annotations

from reachable.reachability import Verdict
from reachable.report import summary, to_markdown, to_table


def test_table_ranks_reachable_then_unknown_then_not_reachable(fixture_findings):
    verdicts = [row["verdict"] for row in to_table(fixture_findings)]
    order = {v: i for i, v in enumerate(verdicts)}

    assert order[Verdict.REACHABLE.value] < order[Verdict.UNKNOWN.value]
    assert order[Verdict.UNKNOWN.value] < order[Verdict.NOT_REACHABLE.value]


def test_every_row_explains_itself(fixture_findings):
    """A verdict with no reason cannot be actioned or challenged."""
    for row in to_table(fixture_findings):
        assert row["reason"].strip(), f"{row['dependency']} has no reason"


def test_reachable_rows_carry_a_call_path(fixture_findings):
    reachable = [f for f in fixture_findings if f.verdict is Verdict.REACHABLE]
    assert reachable
    for finding in reachable:
        assert finding.call_paths, "a REACHABLE claim with no path is unverifiable"


def test_summary_counts_match_the_findings(fixture_findings):
    counts = summary(fixture_findings)["by_verdict"]
    assert sum(counts.values()) == len(fixture_findings)


def test_markdown_renders_every_finding(fixture_findings):
    text = to_markdown(fixture_findings)
    for finding in fixture_findings:
        assert finding.dependency.name in text
