from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from reachable.cli import app


def test_scan_fixture_prints_all_four_packages(
    sample_app_path: Path,
    advisory_dir: Path,
) -> None:
    result = CliRunner().invoke(
        app,
        ["scan", str(sample_app_path), "--advisories", str(advisory_dir)],
    )

    assert result.exit_code == 0
    for package in ("dangerlib", "unusedlib", "dynamiclib", "neverimported"):
        assert package in result.stdout


def test_scan_json_format_emits_valid_json(
    sample_app_path: Path,
    advisory_dir: Path,
) -> None:
    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(sample_app_path),
            "--advisories",
            str(advisory_dir),
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0
    assert len(json.loads(result.stdout)["findings"]) == 4


def test_fail_on_reachable_exits_one(
    sample_app_path: Path,
    advisory_dir: Path,
) -> None:
    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(sample_app_path),
            "--advisories",
            str(advisory_dir),
            "--fail-on",
            "reachable",
        ],
    )

    assert result.exit_code == 1


def test_fail_on_never_exits_zero(
    sample_app_path: Path,
    advisory_dir: Path,
) -> None:
    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(sample_app_path),
            "--advisories",
            str(advisory_dir),
            "--fail-on",
            "never",
        ],
    )

    assert result.exit_code == 0


def test_vex_format_emits_valid_openvex(
    sample_app_path: Path,
    advisory_dir: Path,
) -> None:
    result = CliRunner().invoke(
        app,
        [
            "scan",
            str(sample_app_path),
            "--advisories",
            str(advisory_dir),
            "--format",
            "vex",
        ],
    )

    assert result.exit_code == 0
    document = json.loads(result.stdout)
    assert document["@context"] == "https://openvex.dev/ns/v0.2.0"
    assert document["statements"]


def test_scan_without_advisories_fails_with_actionable_message(
    sample_app_path: Path,
) -> None:
    result = CliRunner().invoke(app, ["scan", str(sample_app_path)])

    assert result.exit_code != 0
    assert "pass --advisories PATH" in result.output
