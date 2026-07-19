from __future__ import annotations

import json
import re
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


# CSI colour sequences emitted by Rich.
_ANSI = re.compile("\x1b\[[0-9;]*m")


def _plain(text: str) -> str:
    """Strip ANSI codes and collapse whitespace.

    Typer renders errors through Rich, which hard-wraps to the terminal width
    and injects colour codes. Asserting on the raw string passes on a wide
    local terminal and fails on CI at 80 columns, where the same message is
    broken across lines - so normalise before matching on it.
    """
    return " ".join(re.sub(_ANSI, "", text).split())


def test_scan_without_advisories_fails_with_actionable_message(
    sample_app_path: Path,
) -> None:
    # COLUMNS pins the render width so the assertion does not depend on the
    # terminal the suite happens to run in.
    result = CliRunner().invoke(
        app, ["scan", str(sample_app_path)], env={"COLUMNS": "200"}
    )

    assert result.exit_code != 0
    output = _plain(result.output)
    assert "--advisories" in output, output[:400]
