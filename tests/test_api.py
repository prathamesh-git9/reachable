from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from reachable.advisories import AdvisoryDatabase
from reachable.api import create_app
from reachable.providers.fake import FakeProvider


def test_healthz(advisory_db: AdvisoryDatabase) -> None:
    client = TestClient(create_app(advisory_db, FakeProvider()))

    response = client.get("/healthz")

    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_scan_endpoint_returns_fixture_result(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    client = TestClient(create_app(advisory_db, FakeProvider()))

    response = client.post("/scan", json={"project_root": str(sample_app_path)})

    assert response.status_code == 200
    data = response.json()
    assert len(data["findings"]) == 4
    assert data["call_graph_stats"]["edges"] > 0


def test_advisory_endpoints_include_list_get_create_and_404(
    advisory_db: AdvisoryDatabase,
) -> None:
    client = TestClient(create_app(advisory_db, FakeProvider()))

    list_response = client.get("/advisories")
    get_response = client.get("/advisories/OSV-2026-0001")
    alias_response = client.get("/advisories/CVE-2026-10001")
    missing_response = client.get("/advisories/OSV-MISSING")
    create_response = client.post(
        "/advisories",
        json={
            "id": "OSV-NEW",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "newlib"},
                    "ranges": [{"events": [{"introduced": "0"}]}],
                }
            ],
        },
    )

    assert list_response.status_code == 200
    assert get_response.status_code == 200
    assert alias_response.status_code == 200
    assert missing_response.status_code == 404
    assert create_response.status_code == 201
    assert create_response.json()["advisory_id"] == "OSV-NEW"


def test_vex_endpoint_returns_openvex_document(
    sample_app_path: Path,
    advisory_db: AdvisoryDatabase,
) -> None:
    client = TestClient(create_app(advisory_db, FakeProvider()))

    response = client.post(
        "/vex",
        json={
            "project_root": str(sample_app_path),
            "author": "me",
            "product_id": "pkg:example/sample",
        },
    )

    assert response.status_code == 200
    assert response.json()["statements"]


def test_unknown_route_returns_404(advisory_db: AdvisoryDatabase) -> None:
    client = TestClient(create_app(advisory_db, FakeProvider()))

    response = client.get("/missing")

    assert response.status_code == 404
