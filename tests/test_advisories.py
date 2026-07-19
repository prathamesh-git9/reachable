from __future__ import annotations

from pathlib import Path

from reachable.advisories import AdvisoryDatabase, load_osv, parse_version


def test_osv_loading_round_trip(fixture_root: Path) -> None:
    advisory = load_osv(fixture_root / "advisories" / "dangerlib.json")

    assert advisory.advisory_id == "OSV-2026-0001"
    assert advisory.aliases == ["CVE-2026-10001"]
    assert advisory.affected[0].package_name == "dangerlib"
    assert advisory.affected[0].vulnerable_symbols == ["dangerlib.vuln.dangerous_call"]


def test_aliases_are_preserved(advisory_db: AdvisoryDatabase) -> None:
    advisory = advisory_db.for_package("dangerlib", "1.0.0")[0]

    assert "CVE-2026-10001" in advisory.aliases


def test_version_range_matching_introduced_fixed_and_open_upper_bound() -> None:
    database = AdvisoryDatabase()
    database.add(
        load_osv(
            {
                "id": "OSV-RANGE",
                "affected": [
                    {
                        "package": {"ecosystem": "PyPI", "name": "range-lib"},
                        "ranges": [
                            {
                                "events": [
                                    {"introduced": "1.0.0"},
                                    {"fixed": "2.0.0"},
                                    {"introduced": "3.0.0"},
                                ]
                            }
                        ],
                    }
                ],
            }
        )
    )

    assert database.for_package("range-lib", "1.5.0")
    assert not database.for_package("range-lib", "2.0.0")
    assert database.for_package("range-lib", "3.1.0")


def test_pep_440_style_versions_compare_correctly() -> None:
    assert parse_version("1.2.3rc1") < parse_version("1.2.3")
    assert parse_version("1.2.3") < parse_version("2.0.0.post1")
    assert parse_version("2.0.0") < parse_version("2.0.0.post1")


def test_for_package_returns_nothing_for_unaffected_version(
    advisory_db: AdvisoryDatabase,
) -> None:
    assert advisory_db.for_package("dangerlib", "1.1.0") == []


def test_count_and_all(advisory_db: AdvisoryDatabase) -> None:
    assert advisory_db.count() == 4
    assert len(advisory_db.all()) == 4
