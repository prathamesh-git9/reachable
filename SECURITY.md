# Security Policy

## Supported Versions

`reachable` is currently pre-1.0. Security fixes target the latest released
minor version and the `main` branch unless a maintainer states otherwise in a
release note.

## Threat Model

`reachable` analyzes Python projects and third-party dependency metadata to
triage whether vulnerable dependency symbols are callable from application
entrypoints. The scanner is expected to inspect source trees that may include
untrusted dependency or application code.

The analyzer must therefore treat source as data. It uses Python's `ast` module
for static parsing and call-graph construction; it must not import, execute, or
evaluate the analyzed project to discover reachability. Bugs that cause
analyzed code to run during parsing, scanning, explanation, CLI use, API use, or
MCP use are security issues.

The verdict model is also safety-critical. `reachable` has exactly three
verdicts:

- `REACHABLE`: static analysis found a concrete path from an entrypoint to a
  vulnerable symbol.
- `NOT_REACHABLE`: the package or vulnerable symbol is not reachable in the
  parsed static graph, and the engine has enough evidence to say so.
- `UNKNOWN`: static analysis cannot support either conclusion.

`UNKNOWN` must never be collapsed into `NOT_REACHABLE`. Doing so could tell a
security team to ignore vulnerable code that may execute through dynamic import,
computed dispatch, framework registration, unparsed files, or missing advisory
symbol metadata. Changes that weaken this property, hide uncertainty, or let AI
provider output alter a static-analysis verdict should be treated as
security-relevant.

## Reporting a Vulnerability

Please report suspected vulnerabilities privately through GitHub's private
security advisory flow for this repository. Do not open a public issue for a
security report.

Useful reports include:

- Affected version or commit.
- Reproduction steps and a minimal fixture if possible.
- Whether the issue executes analyzed code, changes a verdict incorrectly, or
  mishandles untrusted advisory/project input.
- Any observed impact on CLI, HTTP API, MCP, OpenVEX output, or provider-backed
  explanations.

Maintainers aim to acknowledge reports within a few days. Public disclosure and
release timing should be coordinated through the private advisory.
