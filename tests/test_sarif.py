from __future__ import annotations

from reachable.reachability import Verdict
from reachable.sarif import to_sarif


def test_sarif_emits_actionable_results_with_rules_and_stable_fingerprints(
    fixture_findings,
):
    document = to_sarif(fixture_findings)
    assert document["version"] == "2.1.0"
    run = document["runs"][0]
    results = run["results"]
    assert results
    assert all(item["properties"]["verdict"] != Verdict.NOT_REACHABLE for item in results)
    assert {item["ruleId"] for item in results} <= {
        rule["id"] for rule in run["tool"]["driver"]["rules"]
    }
    assert all(
        len(item["partialFingerprints"]["reachableFinding/v1"]) == 64
        for item in results
    )
    assert to_sarif(fixture_findings) == document


def test_reachable_sarif_result_has_physical_location_and_code_flow(fixture_findings):
    results = to_sarif(fixture_findings)["runs"][0]["results"]
    reachable = next(
        item for item in results if item["properties"]["verdict"] == Verdict.REACHABLE
    )
    location = reachable["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"].endswith(".py")
    assert location["region"]["startLine"] >= 1
    assert reachable["codeFlows"][0]["threadFlows"][0]["locations"]
