"""Static call graph construction with uncertainty recorded as data.

The analyser deliberately uses Python's ``ast`` module instead of import-time
introspection. Importing an arbitrary target project during security triage can
run application code and change the result. Static analysis is safer, but it is
incomplete: dynamic dispatch, plugin registration, importlib, monkeypatching,
and decorator registries can all hide real call edges. This module therefore
records those constructs as first-class ``DynamicSite`` evidence instead of
pretending the graph is complete.
"""

from __future__ import annotations

import ast
import tomllib
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class DynamicSite:
    kind: str
    module: str
    lineno: int
    snippet: str


@dataclass
class CallGraph:
    edges: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))
    entrypoints: set[str] = field(default_factory=set)
    dynamic_sites: list[DynamicSite] = field(default_factory=list)
    unparsed_files: list[str] = field(default_factory=list)
    imports: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    def add_edge(self, caller: str, callee: str) -> None:
        self.edges[caller].add(callee)

    def reachable_from(self, roots: Iterable[str]) -> set[str]:
        seen: set[str] = set()
        queue: deque[str] = deque(roots)
        while queue:
            node = queue.popleft()
            if node in seen:
                continue
            seen.add(node)
            queue.extend(self.edges.get(node, set()) - seen)
        return seen

    def paths_to(
        self,
        target: str,
        roots: Iterable[str],
        max_paths: int = 3,
    ) -> list[list[str]]:
        paths: list[list[str]] = []
        queue: deque[list[str]] = deque([[root] for root in roots])
        while queue and len(paths) < max_paths:
            path = queue.popleft()
            node = path[-1]
            if node == target:
                paths.append(path)
                continue
            for child in sorted(self.edges.get(node, set())):
                if child not in path:
                    queue.append([*path, child])
        return paths


def build_call_graph(
    project_root: str | Path,
    include: Iterable[str] | None = None,
    exclude: Iterable[str] | None = None,
) -> CallGraph:
    root = Path(project_root)
    graph = CallGraph()
    include_parts = tuple(include or ())
    exclude_parts = tuple(exclude or ())
    for file_path in root.rglob("*.py"):
        relative = file_path.relative_to(root)
        relative_text = str(relative)
        if include_parts and not any(part in relative_text for part in include_parts):
            continue
        if exclude_parts and any(part in relative_text for part in exclude_parts):
            continue
        module = _module_name(relative)
        try:
            tree = ast.parse(file_path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            graph.unparsed_files.append(str(file_path))
            continue
        Analyzer(graph, module, root, file_path, tree).visit(tree)
    graph.entrypoints.update(_console_scripts(root))
    return graph


class Analyzer(ast.NodeVisitor):
    def __init__(
        self,
        graph: CallGraph,
        module: str,
        root: Path,
        file_path: Path,
        tree: ast.Module,
    ) -> None:
        self.graph = graph
        self.module = module
        self.root = root
        self.file_path = file_path
        self.aliases: dict[str, str] = {}
        self.scope: list[str] = [module]
        self.class_stack: list[str] = []
        self.module_defs = _module_definitions(module, tree)
        self.lookup_values: set[str] = set()

    @property
    def current_symbol(self) -> str:
        return ".".join(self.scope)

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name.split(".", 1)[0]
            self.aliases[local] = alias.name
            self.graph.imports[self.module].add(alias.name.split(".", 1)[0])

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.module is None:
            return
        base = self._resolve_import_base(node.module, node.level)
        self.graph.imports[self.module].add(base.split(".", 1)[0])
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = f"{base}.{alias.name}"

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        class_name = f"{self.current_symbol}.{node.name}"
        self.class_stack.append(class_name)
        self.scope.append(node.name)
        self._record_registration_decorators(node.decorator_list)
        for child in node.body:
            self.visit(child)
        self.scope.pop()
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def visit_If(self, node: ast.If) -> None:
        if _is_main_guard(node.test):
            self.graph.entrypoints.add(self.current_symbol)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        callee = self._resolve_expr(node.func)
        if callee:
            self.graph.add_edge(self.current_symbol, callee)
        self._record_dynamic_call(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Subscript):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.lookup_values.add(target.id)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        if isinstance(node.value, ast.Call):
            call_name = self._resolve_expr(node.value.func)
            if call_name in {"globals", "locals"}:
                self._dynamic("namespace_subscript", node)
        self.generic_visit(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self._record_registration_decorators(node.decorator_list)
        if _has_route_decorator(node.decorator_list):
            self.graph.entrypoints.add(f"{self.current_symbol}.{node.name}")
        self.scope.append(node.name)
        for child in node.body:
            self.visit(child)
        self.scope.pop()

    def _resolve_import_base(self, module: str, level: int) -> str:
        if level == 0:
            return module
        parts = self.module.split(".")
        prefix = parts[: max(0, len(parts) - level)]
        return ".".join([*prefix, module]) if module else ".".join(prefix)

    def _resolve_expr(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            if node.id in self.aliases:
                return self.aliases[node.id]
            if node.id in self.module_defs:
                return self.module_defs[node.id]
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._resolve_expr(node.value)
            if base in {"self", "cls"} and self.class_stack:
                return f"{self.class_stack[-1]}.{node.attr}"
            return f"{base}.{node.attr}" if base else node.attr
        if isinstance(node, ast.Call):
            return self._resolve_expr(node.func)
        return None

    def _record_dynamic_call(self, node: ast.Call) -> None:
        name = self._resolve_expr(node.func)
        computed_getattr = (
            name == "getattr"
            and len(node.args) >= 2
            and not _literal_string(node.args[1])
        )
        if computed_getattr:
            self._dynamic("computed_getattr", node)
        elif name == "setattr":
            self._dynamic("setattr", node)
        elif name in {"importlib.import_module", "__import__"}:
            self._dynamic("dynamic_import", node)
        elif name in {"eval", "exec"}:
            self._dynamic(name, node)
        elif isinstance(node.func, ast.Subscript):
            self._dynamic("lookup_call", node)
        elif isinstance(node.func, ast.Attribute) and isinstance(
            node.func.value, ast.Subscript
        ):
            self._dynamic("lookup_method_call", node)
        elif isinstance(node.func, ast.Name) and node.func.id in self.lookup_values:
            self._dynamic("lookup_value_call", node)

    def _record_registration_decorators(self, decorators: list[ast.expr]) -> None:
        for decorator in decorators:
            if _is_registration_decorator(decorator):
                self._dynamic("decorator_registration", decorator)

    def _dynamic(self, kind: str, node: ast.AST) -> None:
        snippet = ast.get_source_segment(
            self.file_path.read_text(encoding="utf-8"),
            node,
        )
        self.graph.dynamic_sites.append(
            DynamicSite(kind, self.module, getattr(node, "lineno", 0), snippet or kind)
        )


def _module_name(path: Path) -> str:
    parts = list(path.with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _module_definitions(module: str, tree: ast.Module) -> dict[str, str]:
    definitions: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            definitions[node.name] = f"{module}.{node.name}"
    return definitions


def _literal_string(node: ast.AST) -> bool:
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_main_guard(node: ast.AST) -> bool:
    left_name = (
        isinstance(node, ast.Compare)
        and isinstance(node.left, ast.Name)
        and node.left.id == "__name__"
    )
    return (
        left_name
        and len(node.ops) == 1
        and isinstance(node.ops[0], ast.Eq)
        and len(node.comparators) == 1
        and isinstance(node.comparators[0], ast.Constant)
        and node.comparators[0].value == "__main__"
    )


def _has_route_decorator(decorators: list[ast.expr]) -> bool:
    return any(
        _decorator_name(decorator).split(".")[-1] in _ROUTE_NAMES
        for decorator in decorators
    )


def _is_registration_decorator(decorator: ast.expr) -> bool:
    name = _decorator_name(decorator)
    parts = name.split(".")
    return len(parts) >= 2 and parts[-1] in _ROUTE_NAMES


def _decorator_name(decorator: ast.expr) -> str:
    target = decorator.func if isinstance(decorator, ast.Call) else decorator
    if isinstance(target, ast.Name):
        return target.id
    if isinstance(target, ast.Attribute):
        names: list[str] = [target.attr]
        value = target.value
        while isinstance(value, ast.Attribute):
            names.append(value.attr)
            value = value.value
        if isinstance(value, ast.Name):
            names.append(value.id)
        return ".".join(reversed(names))
    return ""


def _console_scripts(root: Path) -> set[str]:
    pyproject = root / "pyproject.toml"
    if not pyproject.exists():
        return set()
    try:
        data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError:
        return set()
    scripts = ((data.get("project") or {}).get("scripts") or {}).values()
    return {str(script).replace(":", ".") for script in scripts}


_ROUTE_NAMES = {"route", "get", "post", "put", "delete", "patch", "websocket"}
