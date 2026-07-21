# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-21

### Added

- Static Python AST call-graph analysis for dependency reachability triage.
- Three-verdict reachability engine with `REACHABLE`, `NOT_REACHABLE`, and
  `UNKNOWN`, preserving uncertainty instead of treating it as not reachable.
- Dynamic uncertainty tracking for constructs such as computed `getattr`,
  dynamic imports, `eval`, `exec`, namespace lookups, lookup-based calls, and
  decorator registration.
- Dependency discovery from `requirements*.txt`, PEP 621 `pyproject.toml`, and
  simple lockfile data.
- OSV-shaped advisory ingestion with vulnerable symbol extraction from affected
  package data, `database_specific`, and `ecosystem_specific`.
- Prioritized human reports that rank reachable findings before unknown
  findings, with not-reachable findings last.
- OpenVEX output mapping reachable findings to `affected`, not-reachable
  findings to `not_affected`, and unknown findings to `under_investigation`.
- Typer CLI for scanning, explaining findings, and emitting OpenVEX.
- FastAPI app factory exposing health, scan, VEX, and advisory endpoints.
- Optional MCP server exposing scan, explain, advisory listing, and VEX tools.
- Provider abstraction for optional explanation generation, with deterministic
  fake, OpenAI, and Grok provider implementations.
- Guardrails that keep AI-generated explanations downstream of static verdicts
  and flag contradictory explanation text.
