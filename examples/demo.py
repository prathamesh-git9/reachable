from __future__ import annotations

import json
import sys
from pathlib import Path

from reachable.advisories import AdvisoryDatabase, load_osv
from reachable.explain import Explainer
from reachable.providers.fake import FakeProvider
from reachable.reachability import Verdict
from reachable.report import to_table
from reachable.scan import Scanner, to_jsonable


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    root = Path(__file__).resolve().parents[1]
    sample_app = root / "tests" / "fixtures" / "sample_app"
    advisory_dir = root / "tests" / "fixtures" / "advisories"

    database = AdvisoryDatabase()
    for advisory_path in sorted(advisory_dir.glob("*.json")):
        database.add(load_osv(advisory_path))

    result = Scanner(database, FakeProvider(), explain=False).scan(sample_app)

    # Render through report.to_table rather than walking result.findings
    # directly. That is the module that owns the ranking (REACHABLE, then
    # UNKNOWN, then NOT_REACHABLE), and re-implementing the loop here silently
    # lost it - the demo was printing NOT_REACHABLE above UNKNOWN, which
    # inverts the whole point of a prioritised queue.
    by_advisory = {f.advisory.advisory_id: f for f in result.findings}

    print("Prioritised findings")
    print("VERDICT        CONFIDENCE  PACKAGE        EVIDENCE / REASON")
    for row in to_table(result.findings):
        finding = by_advisory[row["advisory"]]
        if finding.call_paths:
            evidence = " -> ".join(finding.call_paths[0])
        else:
            # An UNKNOWN with no explanation is useless to the engineer who
            # has to action it, so fall back to the rationale.
            evidence = row["reason"] or "none"
        print(
            f"{row['verdict']:<14} "
            f"{row['confidence']:<10.2f} "
            f"{row['dependency']:<14} "
            f"{evidence[:88]}"
        )

    print("\nVerdict summary")
    print(json.dumps(result.summary, indent=2))

    print("\nOpenVEX")
    print(json.dumps(to_jsonable(result.openvex), indent=2))

    reachable = next(
        finding for finding in result.findings if finding.verdict is Verdict.REACHABLE
    )
    explanation = Explainer(FakeProvider()).explain(reachable)
    print("\nAI explanation for reachable finding")
    print(json.dumps(to_jsonable(explanation), indent=2))


if __name__ == "__main__":
    main()
