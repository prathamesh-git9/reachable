# Contributing

Thanks for improving `reachable`. This project is a conservative CVE
reachability triage engine for Python. The most important invariant is that
`UNKNOWN` is preserved as its own verdict and is never treated as
`NOT_REACHABLE`.

## Development Setup

Use Python 3.11 or newer.

```bash
python -m venv .venv
.venv/Scripts/python.exe -m pip install -e .[dev]
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/python.exe -m ruff check .
```

On non-Windows shells, use the matching virtualenv Python path for your
environment.

## Project Layout

- `src/reachable/advisories.py`: OSV-shaped advisory loading, affected package
  ranges, and vulnerable symbol extraction.
- `src/reachable/dependencies.py`: dependency discovery from
  `requirements*.txt`, `pyproject.toml`, and simple lockfile data.
- `src/reachable/callgraph.py`: static Python AST call-graph construction and
  dynamic uncertainty recording.
- `src/reachable/reachability.py`: three-verdict reachability analysis.
- `src/reachable/scan.py`: shared scan pipeline used by CLI, API, and MCP.
- `src/reachable/vex.py`: OpenVEX emission.
- `src/reachable/report.py`: human-oriented prioritized reporting.
- `src/reachable/cli.py`: Typer command line interface.
- `src/reachable/api.py`: FastAPI app factory.
- `src/reachable/mcp_server.py`: optional MCP integration.
- `src/reachable/providers/`: explanation provider abstraction and provider
  implementations. Providers explain findings; they do not decide verdicts.

## Adding an Advisory Source

The core advisory model lives in `src/reachable/advisories.py`. Existing loading
expects OSV-shaped JSON and extracts `vulnerable_symbols` from the affected
package object, `database_specific`, or `ecosystem_specific`.

When adding another source:

- Normalize it into the existing `Advisory` and `AffectedPackage` dataclasses.
- Preserve missing vulnerable symbol metadata as missing. Do not invent symbols
  or turn absent metadata into a non-reachable result.
- Add fixture advisories under `tests/fixtures/advisories` when useful.
- Cover package matching, version range handling, aliases, and symbol extraction
  in `tests/test_advisories.py` or a focused new test.

## Adding a Reachability Rule

Reachability rules belong in `src/reachable/reachability.py`; AST evidence
collection belongs in `src/reachable/callgraph.py`.

Before adding a rule, decide what it can prove:

- If it proves an executable path, return `REACHABLE` with call-path evidence
  when possible.
- If it proves only uncertainty, return `UNKNOWN`.
- Return `NOT_REACHABLE` only when the parsed graph and recorded uncertainty
  support that conclusion.

Keep rule ordering explicit. The current engine intentionally checks the
never-imported package case before missing vulnerable symbol metadata, because
most real OSV advisories do not identify symbols.

Tests for new rules should include both the positive case and the conservative
fallback case. In particular, add coverage showing that dynamic dispatch,
dynamic import, unparsed files, or missing symbol metadata degrade to `UNKNOWN`
when proof is incomplete.

## Code Style

- Use `from __future__ import annotations` in Python modules.
- Keep docstrings and comments focused on why the code exists or why an ordering
  matters. Avoid comments that restate the next line of code.
- Follow Ruff. The configured line length is 90 in `pyproject.toml` under
  `[tool.ruff]`.
- Keep runtime behavior changes small and covered by tests.
- Do not let explanation providers or model text change reachability verdicts.
