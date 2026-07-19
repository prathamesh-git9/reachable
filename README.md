# reachable

`reachable` is a Python CVE reachability triage engine. Given a Python project,
it checks known vulnerabilities in declared dependencies, determines whether
the vulnerable symbols are reachable from application entrypoints, and emits an
OpenVEX document plus a prioritised report.

The problem is volume and precision. More than 48,000 CVEs were published in
2025, about 59,000 are forecast for 2026, and only about 5.5% are ever exploited
in the wild. A mid-sized security team spending five minutes on every CVE would
need more than six hours every working day just to triage, before fixing
anything. Industry analysis names the largest false-positive driver plainly:
teams usually do not know whether the vulnerable code is actually reachable.

## Quickstart

```bash
pip install -e .[dev]
reachable scan tests/fixtures/sample_app --advisories tests/fixtures/advisories
```

JSON and OpenVEX output are available from the same scan:

```bash
reachable scan tests/fixtures/sample_app \
  --advisories tests/fixtures/advisories \
  --format json

reachable scan tests/fixtures/sample_app \
  --advisories tests/fixtures/advisories \
  --format vex
```

Run the local demo with no credentials:

```bash
python examples/demo.py
```

## How It Works

The verdict is produced by static analysis, not by a model.

```text
Dependency files
      |
      v
Declared dependencies ---- OSV advisories
      |                         |
      v                         v
Python AST call graph ---- Vulnerable symbols
      |                         |
      +-----------+-------------+
                  v
        Reachability verdict
                  |
                  v
      OpenVEX + prioritised report
```

The scanner reads `requirements*.txt` and `pyproject.toml`, loads OSV-shaped
advisories, builds an AST call graph, records dynamic constructs as explicit
uncertainty, evaluates reachability, then emits both human and machine-readable
output.

## The Three-Verdict Design

There is no honest binary answer for static reachability.

`REACHABLE` means static analysis found a concrete path from an entrypoint to a
vulnerable symbol. The finding includes call-path evidence.

`NOT_REACHABLE` means the package or vulnerable symbol is not reachable in the
parsed static graph, and the engine has enough evidence to issue a non-reachable
triage result.

`UNKNOWN` means static analysis cannot support either conclusion. Python code
can invoke behavior without an explicit static edge through computed `getattr`,
`importlib`, `eval`, monkeypatching, plugin registries, decorator registration,
framework auto-discovery, and similar patterns. Any uncertainty degrades to
`UNKNOWN`, never `NOT_REACHABLE`, because telling a security team to ignore a
live vulnerability is far worse than making them inspect one they did not need
to.

## Why Rule Ordering Matters

A package that is never imported is `NOT_REACHABLE` even when the advisory names
no vulnerable symbol, because absence from the import graph settles whether that
package can execute.

That rule must run before the missing-symbol rule. Most real OSV advisories do
not carry vulnerable symbol data. If missing symbol metadata were evaluated
first, the tool would answer `UNKNOWN` for almost everything and return the
triage burden to the security team. Evaluating the never-imported rule first
keeps the tool useful while preserving conservative behavior when dynamic
importers or unparsed files could hide execution.

## CLI Reference

```text
reachable scan PATH --advisories PATH [--format table|json|markdown|vex]
                    [--entrypoint SYMBOL] [--no-explain]
                    [--fail-on reachable|unknown|never]
                    [--output PATH]

reachable explain PATH ADVISORY_ID --advisories PATH [--entrypoint SYMBOL]

reachable vex PATH --author AUTHOR --product PRODUCT --advisories PATH
              [--entrypoint SYMBOL]
```

`--advisories` is required and must point to an OSV JSON file or a directory of
OSV JSON documents. The CLI fails clearly if no advisory source is provided.

`--fail-on reachable` exits non-zero when at least one finding is reachable.
`--fail-on unknown` exits non-zero for reachable or unknown findings.
`--fail-on never` always exits zero.

## HTTP API

Create an app by injecting an advisory database:

```python
from reachable.advisories import AdvisoryDatabase
from reachable.api import create_app

app = create_app(AdvisoryDatabase())
```

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/healthz` | Health check |
| `POST` | `/scan` | Run a scan for `project_root` |
| `POST` | `/vex` | Emit OpenVEX for `project_root` |
| `GET` | `/advisories` | List loaded advisories |
| `POST` | `/advisories` | Add one OSV advisory |
| `GET` | `/advisories/{advisory_id}` | Fetch by id or alias |

## MCP Integration

`reachable.mcp_server.create_mcp_server(advisory_db, provider)` exposes MCP
tools for scanning, explanation, advisory listing, and OpenVEX emission. The
MCP package is optional:

```bash
pip install -e .[mcp]
```

The MCP tools use the same scanner contracts as the CLI and API.

## OpenVEX Output

A reachable finding maps to `affected`, a not-reachable finding maps to
`not_affected`, and an unknown finding maps to `under_investigation`.

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "urn:uuid:00000000-0000-0000-0000-000000000000",
  "author": "reachable",
  "timestamp": "2026-07-19T00:00:00+00:00",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "name": "OSV-2026-0002",
        "aliases": ["CVE-2026-10002"]
      },
      "timestamp": "2026-07-19T00:00:00+00:00",
      "products": [{"@id": "sample_app"}],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "no static path from entrypoints to vulnerable symbol"
    }
  ]
}
```

## Configuration

Advisories must be OSV-shaped JSON. `vulnerable_symbols` may appear at the
affected-package level, under `database_specific`, or under `ecosystem_specific`.
When symbol metadata is missing, imported packages become `UNKNOWN`.

The default explanation provider is deterministic and local. Live model
providers are optional and require their own extras and credentials.

## Testing

```bash
pip install -e .[dev]
ruff check .
pytest -q
```

CI runs the same commands on Python 3.11 and 3.12 with no API keys set.

## Design Notes

Limitations are explicit:

- The call graph is single-language Python only.
- There is no cross-language or C-extension analysis.
- Conditional imports and framework magic are approximated.
- A dynamic importer anywhere in the codebase means `NOT_REACHABLE` carries a
  caveat rather than a guarantee.
- The tool prioritises triage. It does not decide whether to patch.

AI is used only after verdicts already exist. It explains findings and drafts
VEX justification prose. It never produces or alters a verdict. If model text
contradicts the static-analysis verdict, the contradiction is flagged rather
than accepted.
