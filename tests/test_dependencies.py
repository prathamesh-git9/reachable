from __future__ import annotations

from pathlib import Path

from reachable.dependencies import normalize_name, parse_pyproject, parse_requirements


def test_requirements_parses_common_specifiers_markers_and_comments(
    tmp_path: Path,
) -> None:
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "\n".join(
            [
                "plain==1.0.0",
                "minimum>=2.0 ; python_version >= '3.11'",
                "compatible~=3.4  # keep within compatible release",
                "with-extra[security]==4.5.6",
                "",
                "# comment only",
            ]
        ),
        encoding="utf-8",
    )

    dependencies = parse_requirements(requirements)

    assert [(item.name, item.version) for item in dependencies] == [
        ("plain", "1.0.0"),
        ("minimum", "2.0"),
        ("compatible", "3.4"),
        ("with-extra", "4.5.6"),
    ]


def test_pyproject_project_and_optional_dependencies(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
dependencies = [
  "core==1.2.3",
  "marked>=2.0 ; python_version >= '3.11'",
]

[project.optional-dependencies]
dev = ["pytest==8.0.0"]
docs = ["mkdocs>=1.6"]
""",
        encoding="utf-8",
    )

    dependencies = parse_pyproject(pyproject)

    assert [(item.name, item.version) for item in dependencies] == [
        ("core", "1.2.3"),
        ("marked", "2.0"),
        ("pytest", "8.0.0"),
        ("mkdocs", "1.6"),
    ]


def test_pep_503_normalisation_equates_common_spellings() -> None:
    assert normalize_name("Flask_Login") == "flask-login"
    assert normalize_name("flask-login") == "flask-login"
    assert normalize_name("FLASK.LOGIN") == "flask-login"


def test_missing_dependency_files_do_not_raise(tmp_path: Path) -> None:
    assert parse_requirements(tmp_path / "missing.txt") == []
    assert parse_pyproject(tmp_path / "pyproject.toml") == []
