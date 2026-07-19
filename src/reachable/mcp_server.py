"""Expose reachability triage through MCP clients.

This lets a security engineer run the same scanner from an MCP client such as
Claude Desktop while preserving the contracts used by the CLI and HTTP API. MCP
is imported lazily because many installations only need local CLI triage.
"""

from __future__ import annotations

from typing import Any

from reachable.advisories import AdvisoryDatabase
from reachable.explain import Explainer
from reachable.providers.base import ChatProvider
from reachable.scan import Scanner, to_jsonable


def create_mcp_server(
    advisory_db: AdvisoryDatabase,
    provider: ChatProvider | None = None,
) -> Any:
    """Create an MCP server exposing scan, explain, list, and VEX tools."""

    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError(
            "reachable.mcp_server requires the official mcp package; install "
            "the mcp extra to use MCP integration."
        ) from exc

    server = FastMCP("reachable")

    @server.tool()
    def scan_project(project_root: str) -> dict[str, Any]:
        """Scan a Python project for reachable vulnerable dependency code."""

        result = Scanner(advisory_db, provider).scan(project_root)
        return to_jsonable(result)

    @server.tool()
    def explain_finding(project_root: str, advisory_id: str) -> dict[str, Any]:
        """Explain one finding by advisory id without changing its verdict."""

        result = Scanner(advisory_db, provider, explain=False).scan(project_root)
        for finding in result.findings:
            advisory = finding.advisory
            if advisory.advisory_id == advisory_id or advisory_id in advisory.aliases:
                return to_jsonable(Explainer(provider).explain(finding))
        return {"error": "advisory not found"}

    @server.tool()
    def list_advisories() -> list[dict[str, Any]]:
        """List advisories currently loaded in the scanner database."""

        return [to_jsonable(advisory) for advisory in advisory_db.all()]

    @server.tool()
    def emit_vex(
        project_root: str,
        author: str,
        product_id: str,
    ) -> dict[str, Any]:
        """Emit the OpenVEX document for a project scan."""

        result = Scanner(advisory_db, provider, explain=False).scan(
            project_root,
            author=author,
            product_id=product_id,
        )
        return to_jsonable(result.openvex)

    return server
