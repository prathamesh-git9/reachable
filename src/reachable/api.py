"""HTTP API for the same reachability pipeline used by the CLI.

The service returns raw verdict, confidence, rationale, and call paths with
every finding so callers can audit analysis evidence instead of trusting model
or transport summaries.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel

from reachable.advisories import AdvisoryDatabase, load_osv
from reachable.providers.base import ChatProvider
from reachable.sarif import to_sarif
from reachable.scan import Scanner, to_jsonable


class ScanRequest(BaseModel):
    project_root: str
    entrypoints: list[str] | None = None
    explain: bool = True


class VexRequest(BaseModel):
    project_root: str
    author: str
    product_id: str


def create_app(
    advisory_db: AdvisoryDatabase,
    provider: ChatProvider | None = None,
) -> FastAPI:
    """Create the FastAPI app with caller-supplied advisory storage."""

    app = FastAPI(title="reachable")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/scan")
    def scan_project(request: ScanRequest) -> dict[str, Any]:
        scanner = Scanner(advisory_db, provider, explain=request.explain)
        result = scanner.scan(
            request.project_root,
            entrypoints=request.entrypoints,
        )
        return to_jsonable(result)

    @app.post("/advisories", status_code=status.HTTP_201_CREATED)
    def add_advisory(document: dict[str, Any]) -> dict[str, Any]:
        advisory = load_osv(document)
        advisory_db.add(advisory)
        return to_jsonable(advisory)

    @app.get("/advisories")
    def list_advisories() -> list[dict[str, Any]]:
        return [to_jsonable(advisory) for advisory in advisory_db.all()]

    @app.get("/advisories/{advisory_id}")
    def get_advisory(advisory_id: str) -> dict[str, Any]:
        for advisory in advisory_db.all():
            if advisory.advisory_id == advisory_id or advisory_id in advisory.aliases:
                return to_jsonable(advisory)
        raise HTTPException(status_code=404, detail="advisory not found")

    @app.post("/vex")
    def emit_vex(request: VexRequest) -> dict[str, Any]:
        scanner = Scanner(advisory_db, provider, explain=False)
        result = scanner.scan(
            request.project_root,
            author=request.author,
            product_id=request.product_id,
        )
        return to_jsonable(result.openvex)

    @app.post("/sarif")
    def emit_sarif(request: ScanRequest) -> dict[str, Any]:
        scanner = Scanner(advisory_db, provider, explain=False)
        result = scanner.scan(
            request.project_root,
            entrypoints=request.entrypoints,
        )
        return to_sarif(result.findings)

    return app
