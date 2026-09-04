from __future__ import annotations

import ast
from pathlib import Path

import pytest

from analyzer.analysis.call_graph import CallGraph, build_call_graph
from analyzer.analysis.imports import build_import_table
from analyzer.analysis.models import (
    AnalysisModule,
    CallGraphEdge,
    CallSite,
    ResolutionStatus,
    Symbol,
)
from analyzer.analysis.resolver import CallResolver
from analyzer.analysis.symbols import build_symbol_table


def make_module(
    tmp_path: Path,
    filename: str,
    source: str,
    module_name: str,
) -> AnalysisModule:
    """Create an AnalysisModule from test source."""

    file_path = tmp_path / filename
    file_path.write_text(source, encoding="utf-8")

    return AnalysisModule(
        file_path=file_path,
        module_name=module_name,
        tree=ast.parse(source),
    )


def build_graph(
    modules: list[AnalysisModule],
) -> CallGraph:
    """Build a complete graph for the supplied modules."""

    symbol_table = build_symbol_table(modules)
    import_table = build_import_table(modules)

    module_map = {
        module.module_name: module
        for module in modules
    }  # Resolver expects modules indexed by module name.

    resolver = CallResolver(
        symbol_table,
        import_table,
        module_map,  # Pass the dictionary expected by CallResolver.
    )

    return build_call_graph(modules, symbol_table, resolver)


def test_local_function_edge(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "app.py",
        """
def process():
    validate()


def validate():
    pass
""",
        "app",
    )

    graph = build_graph([module])

    assert graph.has_node("app.process")
    assert graph.has_node("app.validate")

    assert graph.has_edge(
        "app.process",
        "app.validate",
    )

    assert graph.callees("app.process") == (
        "app.validate",
    )

    assert graph.callers("app.validate") == (
        "app.process",
    )


def test_multiple_calls_to_same_function_preserve_call_sites(
    tmp_path: Path,
) -> None:
    module = make_module(
        tmp_path,
        "app.py",
        """
def process():
    validate()
    validate()


def validate():
    pass
""",
        "app",
    )

    graph = build_graph([module])

    edges = graph.edges_from("app.process")

    assert len(edges) == 2

    assert all(
        edge.callee == "app.validate"
        for edge in edges
    )

    assert edges[0].call_site.line != edges[1].call_site.line


def test_imported_function_edge(tmp_path: Path) -> None:
    payments = make_module(
        tmp_path,
        "payments.py",
        """
def charge():
    pass
""",
        "payments",
    )

    app = make_module(
        tmp_path,
        "app.py",
        """
from payments import charge


def process():
    charge()
""",
        "app",
    )

    graph = build_graph([payments, app])

    assert graph.has_edge(
        "app.process",
        "payments.charge",
    )


def test_aliased_import_edge(tmp_path: Path) -> None:
    payments = make_module(
        tmp_path,
        "payments.py",
        """
def charge():
    pass
""",
        "payments",
    )

    app = make_module(
        tmp_path,
        "app.py",
        """
from payments import charge as pay


def process():
    pay()
""",
        "app",
    )

    graph = build_graph([payments, app])

    assert graph.has_edge(
        "app.process",
        "payments.charge",
    )


def test_module_qualified_edge(tmp_path: Path) -> None:
    payments = make_module(
        tmp_path,
        "payments.py",
        """
def charge():
    pass
""",
        "payments",
    )

    app = make_module(
        tmp_path,
        "app.py",
        """
import payments


def process():
    payments.charge()
""",
        "app",
    )

    graph = build_graph([payments, app])

    assert graph.has_edge(
        "app.process",
        "payments.charge",
    )


def test_relative_import_edge(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()

    first = package / "__init__.py"
    first.write_text("", encoding="utf-8")

    payments = package / "payments.py"
    payments.write_text(
        """
def charge():
    pass
""",
        encoding="utf-8",
    )

    app = package / "app.py"
    app.write_text(
        """
from .payments import charge


def process():
    charge()
""",
        encoding="utf-8",
    )

    modules = [
        AnalysisModule(
            file_path=payments,
            module_name="pkg.payments",
            tree=ast.parse(
                payments.read_text(encoding="utf-8")
            ),
        ),
        AnalysisModule(
            file_path=app,
            module_name="pkg.app",
            tree=ast.parse(
                app.read_text(encoding="utf-8")
            ),
        ),
    ]

    graph = build_graph(modules)

    assert graph.has_edge(
        "pkg.app.process",
        "pkg.payments.charge",
    )


def test_self_method_edge(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "service.py",
        """
class Service:

    def process(self):
        self.validate()

    def validate(self):
        pass
""",
        "service",
    )

    graph = build_graph([module])

    assert graph.has_edge(
        "service.Service.process",
        "service.Service.validate",
    )


def test_cls_method_edge(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "service.py",
        """
class Service:

    @classmethod
    def create(cls):
        cls.validate()

    @classmethod
    def validate(cls):
        pass
""",
        "service",
    )

    graph = build_graph([module])

    assert graph.has_edge(
        "service.Service.create",
        "service.Service.validate",
    )


def test_recursive_edge(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "recursive.py",
        """
def walk():
    walk()
""",
        "recursive",
    )

    graph = build_graph([module])

    assert graph.has_edge(
        "recursive.walk",
        "recursive.walk",
    )

    assert len(graph.recursive_edges()) == 1


def test_mutual_recursion_does_not_break_path_search(
    tmp_path: Path,
) -> None:
    module = make_module(
        tmp_path,
        "recursive.py",
        """
def first():
    second()


def second():
    first()
    sink()


def sink():
    pass
""",
        "recursive",
    )

    graph = build_graph([module])

    assert graph.find_paths(
        "recursive.first",
        "recursive.sink",
    ) == (
        (
            "recursive.first",
            "recursive.second",
            "recursive.sink",
        ),
    )


def test_external_call_is_not_graph_edge(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "app.py",
        """
import requests


def fetch():
    requests.get("https://example.com")
""",
        "app",
    )

    graph = build_graph([module])

    assert graph.has_node("app.fetch")

    assert not any(
        edge.caller == "app.fetch"
        and edge.callee == "requests.get"
        for edge in graph.edges()
    )


def test_unresolved_dynamic_call_is_not_graph_edge(
    tmp_path: Path,
) -> None:
    module = make_module(
        tmp_path,
        "dynamic.py",
        """
def process(func):
    func()
""",
        "dynamic",
    )

    graph = build_graph([module])

    assert graph.has_node("dynamic.process")

    assert graph.edges_from("dynamic.process") == ()


def test_unresolved_dotted_call_is_not_graph_edge(
    tmp_path: Path,
) -> None:
    module = make_module(
        tmp_path,
        "dynamic.py",
        """
def process(obj):
    obj.execute()
""",
        "dynamic",
    )

    graph = build_graph([module])

    assert graph.edges_from("dynamic.process") == ()


def test_isolated_symbol_remains_node(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "app.py",
        """
def unused():
    pass
""",
        "app",
    )

    graph = build_graph([module])

    assert graph.has_node("app.unused")
    assert graph.edges_from("app.unused") == ()
    assert graph.edges_to("app.unused") == ()


def test_multiple_callers_are_indexed(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "app.py",
        """
def first():
    shared()


def second():
    shared()


def shared():
    pass
""",
        "app",
    )

    graph = build_graph([module])

    assert graph.callers("app.shared") == (
        "app.first",
        "app.second",
    )


def test_find_paths_returns_all_simple_paths(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "graph.py",
        """
def start():
    first()
    second()


def first():
    sink()


def second():
    sink()


def sink():
    pass
""",
        "graph",
    )

    graph = build_graph([module])

    paths = graph.find_paths(
        "graph.start",
        "graph.sink",
    )

    assert paths == (
        (
            "graph.start",
            "graph.first",
            "graph.sink",
        ),
        (
            "graph.start",
            "graph.second",
            "graph.sink",
        ),
    )


def test_find_paths_respects_max_depth(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "graph.py",
        """
def first():
    second()


def second():
    third()


def third():
    sink()


def sink():
    pass
""",
        "graph",
    )

    graph = build_graph([module])

    assert graph.find_paths(
        "graph.first",
        "graph.sink",
        max_depth=2,
    ) == ()

    assert graph.find_paths(
        "graph.first",
        "graph.sink",
        max_depth=3,
    ) == (
        (
            "graph.first",
            "graph.second",
            "graph.third",
            "graph.sink",
        ),
    )


def test_find_paths_respects_max_paths(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "graph.py",
        """
def start():
    one()
    two()
    three()


def one():
    sink()


def two():
    sink()


def three():
    sink()


def sink():
    pass
""",
        "graph",
    )

    graph = build_graph([module])

    paths = graph.find_paths(
        "graph.start",
        "graph.sink",
        max_paths=2,
    )

    assert len(paths) == 2


def test_find_paths_source_equals_sink(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "app.py",
        """
def process():
    pass
""",
        "app",
    )

    graph = build_graph([module])

    assert graph.find_paths(
        "app.process",
        "app.process",
    ) == (
        ("app.process",),
    )


def test_find_paths_unknown_source_returns_empty(
    tmp_path: Path,
) -> None:
    module = make_module(
        tmp_path,
        "app.py",
        """
def process():
    pass
""",
        "app",
    )

    graph = build_graph([module])

    assert graph.find_paths(
        "missing.source",
        "app.process",
    ) == ()


def test_find_paths_unknown_sink_returns_empty(
    tmp_path: Path,
) -> None:
    module = make_module(
        tmp_path,
        "app.py",
        """
def process():
    pass
""",
        "app",
    )

    graph = build_graph([module])

    assert graph.find_paths(
        "app.process",
        "missing.sink",
    ) == ()


def test_invalid_path_limits_are_rejected(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "app.py",
        """
def process():
    pass
""",
        "app",
    )

    graph = build_graph([module])

    with pytest.raises(ValueError):
        graph.find_paths(
            "app.process",
            "app.process",
            max_depth=-1,
        )

    with pytest.raises(ValueError):
        graph.find_paths(
            "app.process",
            "app.process",
            max_paths=0,
        )


def test_duplicate_edge_is_ignored(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "app.py",
        """
def process():
    validate()


def validate():
    pass
""",
        "app",
    )

    graph = build_graph([module])

    edge = graph.edges_from("app.process")[0]

    assert graph.add_edge(edge) is False
    assert len(graph.edges()) == 1


def test_unknown_edge_endpoint_is_rejected(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "app.py",
        """
def process():
    pass
""",
        "app",
    )

    graph = build_graph([module])

    call_site = CallSite(
        caller="app.process",
        expression="missing",
        file_path=module.file_path,
        line=2,
        column=4,
    )

    edge = CallGraphEdge(
        caller="app.process",
        callee="missing.function",
        call_site=call_site,
    )

    with pytest.raises(ValueError):
        graph.add_edge(edge)


def test_graph_stats(tmp_path: Path) -> None:
    module = make_module(
        tmp_path,
        "app.py",
        """
def process():
    validate()


def validate():
    pass


def unused():
    pass
""",
        "app",
    )

    graph = build_graph([module])

    stats = graph.stats()

    assert stats.node_count == 4
    assert stats.edge_count == 1
    assert stats.recursive_edge_count == 0
