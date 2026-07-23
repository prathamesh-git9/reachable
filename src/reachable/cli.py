"""Command line interface for reachability triage.

The CLI gates CI on static-analysis verdicts and formats existing findings.
It never lets explanation text change exit decisions, avoiding the costliest
alternative: a model-generated false negative in an automated workflow.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import typer

from reachable.advisories import AdvisoryDatabase, load_osv
from reachable.explain import Explainer
from reachable.providers.fake import FakeProvider
from reachable.reachability import Finding, Verdict
from reachable.report import to_markdown, to_table
from reachable.sarif import to_sarif
from reachable.scan import Scanner, to_jsonable

app = typer.Typer(help="CVE reachability triage for Python projects.")


@app.command()
def scan(
    path: Path,
    advisories: Path | None = typer.Option(
        None,
        "--advisories",
        help="Directory of OSV JSON advisories.",
    ),
    output_format: str = typer.Option(
        "table",
        "--format",
        help="Output format: table, json, markdown, vex, or sarif.",
    ),
    entrypoint: list[str] = typer.Option(
        [],
        "--entrypoint",
        help="Application entrypoint. May be repeated.",
    ),
    no_explain: bool = typer.Option(False, "--no-explain"),
    fail_on: str = typer.Option(
        "never",
        "--fail-on",
        help="Exit 1 on reachable, unknown, or never.",
    ),
    output: Path | None = typer.Option(None, "--output"),
) -> None:
    """Scan a project and emit triage output."""

    _force_utf8_stdout()
    database = _load_advisory_database(advisories)
    result = Scanner(database, FakeProvider(), explain=not no_explain).scan(
        path,
        entrypoints=entrypoint,
    )
    text = _format_result(result, output_format)
    _write_or_print(text, output)
    raise typer.Exit(code=_exit_code(result.findings, fail_on))


@app.command()
def explain(
    path: Path,
    advisory_id: str,
    advisories: Path | None = typer.Option(
        None,
        "--advisories",
        help="Directory of OSV JSON advisories.",
    ),
    entrypoint: list[str] = typer.Option([], "--entrypoint"),
) -> None:
    """Explain one advisory finding without changing its verdict."""

    _force_utf8_stdout()
    database = _load_advisory_database(advisories)
    result = Scanner(database, FakeProvider(), explain=False).scan(
        path,
        entrypoints=entrypoint,
    )
    finding = _find_by_advisory_id(result.findings, advisory_id)
    if finding is None:
        raise typer.BadParameter(f"finding not found for advisory {advisory_id}")
    explanation = Explainer(FakeProvider()).explain(finding)
    typer.echo(json.dumps(to_jsonable(explanation), indent=2))


@app.command()
def vex(
    path: Path,
    author: str = typer.Option(..., "--author"),
    product: str = typer.Option(..., "--product"),
    advisories: Path | None = typer.Option(
        None,
        "--advisories",
        help="Directory of OSV JSON advisories.",
    ),
    entrypoint: list[str] = typer.Option([], "--entrypoint"),
) -> None:
    """Emit only the OpenVEX document."""

    _force_utf8_stdout()
    database = _load_advisory_database(advisories)
    result = Scanner(database, FakeProvider(), explain=False).scan(
        path,
        entrypoints=entrypoint,
        author=author,
        product_id=product,
    )
    typer.echo(json.dumps(to_jsonable(result.openvex), indent=2))


def _format_result(result: Any, output_format: str) -> str:
    if output_format == "json":
        return json.dumps(to_jsonable(result), indent=2)
    if output_format == "markdown":
        return to_markdown(result.findings)
    if output_format == "vex":
        return json.dumps(to_jsonable(result.openvex), indent=2)
    if output_format == "sarif":
        return json.dumps(to_sarif(result.findings), indent=2)
    if output_format == "table":
        return _table(result.findings)
    raise typer.BadParameter("format must be table, json, markdown, vex, or sarif")


def _table(findings: list[Finding]) -> str:
    headers = [
        "VERDICT",
        "SEVERITY",
        "PACKAGE",
        "ADVISORY",
        "CONFIDENCE",
        "EVIDENCE / REASON",
    ]
    rows = [headers]
    # Rank before rendering. report._rank owns the priority order (REACHABLE,
    # then UNKNOWN, then NOT_REACHABLE) and iterating raw findings silently
    # dropped it, printing NOT_REACHABLE above UNKNOWN - which inverts the
    # purpose of a queue the engineer works top-down.
    by_advisory = {f.advisory.advisory_id: f for f in findings}
    for row in to_table(findings):
        finding = by_advisory[row["advisory"]]
        first_path = ""
        if finding.verdict == Verdict.REACHABLE and finding.call_paths:
            first = finding.call_paths[0]
            first_path = " -> ".join(first) if isinstance(first, list) else str(first)
        if not first_path:
            # A verdict with no shown reason cannot be actioned or challenged.
            first_path = row["reason"] or ""
        rows.append(
            [
                str(finding.verdict),
                str(finding.advisory.severity),
                f"{finding.dependency.name} {finding.dependency.version}",
                str(finding.advisory.advisory_id),
                str(finding.confidence),
                first_path,
            ]
        )
    widths = [max(len(row[index]) for row in rows) for index in range(len(headers))]
    lines = []
    for row in rows:
        cells = [cell.ljust(widths[index]) for index, cell in enumerate(row)]
        lines.append("  ".join(cells))
    return "\n".join(lines)


def _load_advisory_database(path: Path | None) -> AdvisoryDatabase:
    if path is None:
        raise typer.BadParameter(
            "no advisory source configured; pass --advisories PATH pointing to "
            "an OSV JSON file or directory"
        )
    if not path.exists():
        raise typer.BadParameter(
            f"advisory source does not exist: {path}; pass --advisories PATH "
            "pointing to an OSV JSON file or directory"
        )
    database = AdvisoryDatabase()
    files = [path] if path.is_file() else sorted(path.glob("*.json"))
    if not files:
        raise typer.BadParameter(
            f"advisory source contains no JSON files: {path}; add OSV JSON "
            "documents or pass a different --advisories PATH"
        )
    for file_path in files:
        database.add(load_osv(file_path))
    return database


def _find_by_advisory_id(
    findings: list[Finding],
    advisory_id: str,
) -> Finding | None:
    for finding in findings:
        advisory = finding.advisory
        if advisory.advisory_id == advisory_id or advisory_id in advisory.aliases:
            return finding
    return None


def _exit_code(findings: list[Finding], fail_on: str) -> int:
    if fail_on == "never":
        return 0
    if fail_on == "reachable":
        return 1 if any(item.verdict == Verdict.REACHABLE for item in findings) else 0
    if fail_on == "unknown":
        return (
            1
            if any(
                item.verdict in {Verdict.REACHABLE, Verdict.UNKNOWN} for item in findings
            )
            else 0
        )
    raise typer.BadParameter("fail-on must be reachable, unknown, or never")


def _write_or_print(text: str, output: Path | None) -> None:
    if output is None:
        typer.echo(text)
        return
    output.write_text(text, encoding="utf-8")


def _force_utf8_stdout() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")


if __name__ == "__main__":
    app()
