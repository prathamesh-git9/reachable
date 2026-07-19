from __future__ import annotations

import shutil
from collections.abc import Callable
from pathlib import Path

import pytest

from reachable.advisories import AdvisoryDatabase, load_osv
from reachable.callgraph import CallGraph, build_call_graph
from reachable.providers.fake import FakeProvider
from reachable.scan import Scanner


@pytest.fixture
def fixture_root() -> Path:
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def advisory_db(fixture_root: Path) -> AdvisoryDatabase:
    database = AdvisoryDatabase()
    for path in sorted((fixture_root / "advisories").glob("*.json")):
        database.add(load_osv(path))
    return database


@pytest.fixture
def advisory_dir(fixture_root: Path) -> Path:
    return fixture_root / "advisories"


@pytest.fixture
def sample_app_path(fixture_root: Path) -> Path:
    return fixture_root / "sample_app"


@pytest.fixture
def sample_app_copy(
    sample_app_path: Path,
    tmp_path: Path,
) -> Callable[[], Path]:
    def copy() -> Path:
        destination = tmp_path / "sample_app"
        shutil.copytree(sample_app_path, destination)
        return destination

    return copy


@pytest.fixture
def call_graph(sample_app_path: Path) -> CallGraph:
    return build_call_graph(sample_app_path)


@pytest.fixture
def fake_provider() -> FakeProvider:
    return FakeProvider()


@pytest.fixture
def scanner(advisory_db: AdvisoryDatabase, fake_provider: FakeProvider) -> Scanner:
    return Scanner(advisory_db, fake_provider)


@pytest.fixture
def fixture_findings(call_graph, sample_app_path, advisory_db):
    """Findings for the sample app, with its four known ground-truth verdicts."""
    from reachable.dependencies import parse_requirements
    from reachable.reachability import analyse

    deps = parse_requirements(sample_app_path / "requirements.txt")
    return analyse(call_graph, deps, advisory_db, entrypoints=None)
