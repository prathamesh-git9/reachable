from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from reachable.callgraph import CallGraph, build_call_graph


def test_import_from_call_resolves_to_fully_qualified_symbol(
    call_graph: CallGraph,
) -> None:
    assert (
        "dangerlib.vuln.dangerous_call"
        in call_graph.edges["sample_app.direct.handle_direct"]
    )
    assert "dangerous_call" not in call_graph.edges["sample_app.direct.handle_direct"]


def test_import_alias_attribute_call_resolves_to_original_module(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "mod.py").write_text(
        "import x.y as z\n\n\ndef run() -> None:\n    z.f()\n",
        encoding="utf-8",
    )

    graph = build_call_graph(tmp_path)

    assert "x.y.f" in graph.edges["pkg.mod.run"]


def test_relative_import_resolves_against_package(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "helper.py").write_text("def f() -> None:\n    pass\n", encoding="utf-8")
    (package / "mod.py").write_text(
        "from .helper import f\n\n\ndef run() -> None:\n    f()\n",
        encoding="utf-8",
    )

    graph = build_call_graph(tmp_path)

    assert "pkg.helper.f" in graph.edges["pkg.mod.run"]


def test_main_guard_registers_module_entrypoint(call_graph: CallGraph) -> None:
    assert "sample_app.main" in call_graph.entrypoints


def test_reachable_from_includes_transitive_symbol_and_excludes_uncalled(
    call_graph: CallGraph,
) -> None:
    reachable = call_graph.reachable_from(call_graph.entrypoints)

    assert "dangerlib.vuln.dangerous_call" in reachable
    assert "unusedlib.risky" not in reachable


def test_paths_to_returns_verifiable_connected_evidence(call_graph: CallGraph) -> None:
    paths = call_graph.paths_to(
        "dangerlib.vuln.dangerous_call",
        call_graph.entrypoints,
    )

    assert paths
    for path in paths:
        assert path[-1] == "dangerlib.vuln.dangerous_call"
        for caller, callee in zip(path, path[1:], strict=False):
            assert callee in call_graph.edges[caller]


def test_computed_getattr_records_dynamic_site(
    call_graph: CallGraph, sample_app_path: Path
) -> None:
    sites = [site for site in call_graph.dynamic_sites if site.kind == "computed_getattr"]

    assert len(sites) == 1
    assert sites[0].module == "sample_app.dynamic"

    # Verify the recorded line against the fixture rather than hardcoding a
    # number: a hardcoded line drifts silently the moment the fixture is
    # edited, and a dynamic site pointing at the wrong line is useless as
    # evidence for the engineer who has to check the claim.
    source = (
        (sample_app_path / "sample_app" / "dynamic.py")
        .read_text(encoding="utf-8")
        .splitlines()
    )
    assert "getattr(" in source[sites[0].lineno - 1]


def test_importlib_import_module_records_dynamic_import(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(
        "import importlib\n\n\ndef run(name: str) -> None:\n"
        "    importlib.import_module(name)\n",
        encoding="utf-8",
    )

    graph = build_call_graph(tmp_path)

    assert any(site.kind == "dynamic_import" for site in graph.dynamic_sites)


def test_syntax_error_is_recorded_without_aborting_build(
    sample_app_copy: Callable[[], Path],
) -> None:
    project = sample_app_copy()
    bad_file = project / "sample_app" / "bad.py"
    bad_file.write_text("def broken(:\n", encoding="utf-8")

    graph = build_call_graph(project)

    assert str(bad_file) in graph.unparsed_files
    assert "dangerlib.vuln.dangerous_call" in graph.reachable_from(graph.entrypoints)
