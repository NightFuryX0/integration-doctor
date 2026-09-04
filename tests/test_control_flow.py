from pathlib import Path

import pytest

from analyzer.analysis.call_graph import build_call_graph
from analyzer.analysis.control_flow import (
    ControlFlowKind,
    build_control_flow,
)
from analyzer.analysis.imports import build_import_table
from analyzer.analysis.parser import parse_file
from analyzer.analysis.resolver import CallResolver
from analyzer.analysis.symbols import build_symbol_table


def make_analysis(tmp_path: Path, source: str):
    path = tmp_path / "app.py"
    path.write_text(source, encoding="utf-8")

    module = parse_file(path, tmp_path)

    modules = [module]

    symbol_table = build_symbol_table(modules)
    import_table = build_import_table(modules)

    module_map = {
        item.module_name: item
        for item in modules
    }

    resolver = CallResolver(
        symbol_table,
        import_table,
        module_map,
    )

    graph = build_call_graph(
        modules,
        symbol_table,
        resolver,
    )

    return module, symbol_table, resolver, graph


def test_sequential_calls_preserve_execution_order(
    tmp_path: Path,
) -> None:
    module, symbols, resolver, _ = make_analysis(
        tmp_path,
        """
def webhook():
    verify_signature()
    charge()


def verify_signature():
    pass


def charge():
    pass
""",
    )

    report = build_control_flow(
        module,
        symbols,
        resolver,
    )

    function = report.get("app.webhook")

    assert function is not None

    nodes = function.graph.nodes

    call_nodes = [
        node
        for node in nodes
        if node.kind == ControlFlowKind.CALL
    ]

    assert [node.calls[0].expression for node in call_nodes] == [
        "verify_signature",
        "charge",
    ]

    assert function.graph.edges_from(call_nodes[0].node_id)[0].target == (
        call_nodes[1].node_id
    )


def test_call_targets_are_resolved(
    tmp_path: Path,
) -> None:
    module, symbols, resolver, _ = make_analysis(
        tmp_path,
        """
def webhook():
    charge()


def charge():
    pass
""",
    )

    report = build_control_flow(
        module,
        symbols,
        resolver,
    )

    function = report.get("app.webhook")

    assert function is not None

    call_nodes = function.graph.call_nodes()

    assert len(call_nodes) == 1
    assert call_nodes[0].calls[0].targets == (
        "app.charge",
    )


def test_if_creates_two_possible_paths(
    tmp_path: Path,
) -> None:
    module, symbols, resolver, _ = make_analysis(
        tmp_path,
        """
def webhook():
    if valid:
        verify_signature()

    charge()


def verify_signature():
    pass


def charge():
    pass
""",
    )

    report = build_control_flow(
        module,
        symbols,
        resolver,
    )

    graph = report.get("app.webhook").graph

    condition = next(
        node
        for node in graph.nodes
        if node.kind == ControlFlowKind.CONDITION
    )

    assert len(graph.outgoing(condition.node_id)) == 2


def test_if_else_has_both_branches(
    tmp_path: Path,
) -> None:
    module, symbols, resolver, _ = make_analysis(
        tmp_path,
        """
def webhook():
    if valid:
        verify_signature()
    else:
        reject()

    charge()


def verify_signature():
    pass


def reject():
    pass


def charge():
    pass
""",
    )

    report = build_control_flow(
        module,
        symbols,
        resolver,
    )

    graph = report.get("app.webhook").graph

    condition = next(
        node
        for node in graph.nodes
        if node.kind == ControlFlowKind.CONDITION
    )

    outgoing = graph.outgoing(condition.node_id)

    assert len(outgoing) == 2


def test_return_terminates_normal_flow(
    tmp_path: Path,
) -> None:
    module, symbols, resolver, _ = make_analysis(
        tmp_path,
        """
def webhook():
    verify_signature()
    return
    charge()


def verify_signature():
    pass


def charge():
    pass
""",
    )

    report = build_control_flow(
        module,
        symbols,
        resolver,
    )

    graph = report.get("app.webhook").graph

    charge_nodes = [
        node
        for node in graph.nodes
        if node.calls
        and node.calls[0].expression == "charge"
    ]

    assert len(charge_nodes) == 1
    assert not graph.incoming(charge_nodes[0].node_id)


def test_loop_has_back_edge(
    tmp_path: Path,
) -> None:
    module, symbols, resolver, _ = make_analysis(
        tmp_path,
        """
def process():
    while condition:
        charge()


def charge():
    pass
""",
    )

    report = build_control_flow(
        module,
        symbols,
        resolver,
    )

    graph = report.get("app.process").graph

    condition = next(
        node
        for node in graph.nodes
        if node.kind == ControlFlowKind.CONDITION
    )

    assert any(
        edge.source != condition.node_id
        and edge.target == condition.node_id
        for edge in graph.edges
    )


def test_return_is_explicitly_typed(
    tmp_path: Path,
) -> None:
    module, symbols, resolver, _ = make_analysis(
        tmp_path,
        """
def process():
    return
""",
    )

    report = build_control_flow(
        module,
        symbols,
        resolver,
    )

    graph = report.get("app.process").graph

    assert any(
        node.kind == ControlFlowKind.RETURN
        for node in graph.nodes
    )


def test_raise_is_explicitly_typed(
    tmp_path: Path,
) -> None:
    module, symbols, resolver, _ = make_analysis(
        tmp_path,
        """
def process():
    raise RuntimeError()
""",
    )

    report = build_control_flow(
        module,
        symbols,
        resolver,
    )

    graph = report.get("app.process").graph

    assert any(
        node.kind == ControlFlowKind.RAISE
        for node in graph.nodes
    )


def test_nested_function_uses_symbol_table_name(
    tmp_path: Path,
) -> None:
    module, symbols, resolver, _ = make_analysis(
        tmp_path,
        """
def outer():
    def inner():
        pass

    inner()
""",
    )

    report = build_control_flow(
        module,
        symbols,
        resolver,
    )

    assert report.get("app.outer") is not None
    assert report.get("app.outer.inner") is not None


def test_async_function_is_supported(
    tmp_path: Path,
) -> None:
    module, symbols, resolver, _ = make_analysis(
        tmp_path,
        """
async def webhook():
    charge()


def charge():
    pass
""",
    )

    report = build_control_flow(
        module,
        symbols,
        resolver,
    )

    function = report.get("app.webhook")

    assert function is not None

    call_nodes = function.graph.call_nodes()

    assert len(call_nodes) == 1
    assert call_nodes[0].calls[0].targets == (
        "app.charge",
    )


def test_max_nodes_is_enforced(
    tmp_path: Path,
) -> None:
    module, symbols, resolver, _ = make_analysis(
        tmp_path,
        """
def process():
    first()
    second()


def first():
    pass


def second():
    pass
""",
    )

    with pytest.raises(ValueError, match="maximum node count"):
        build_control_flow(
            module,
            symbols,
            resolver,
            max_nodes=2,
        )


def test_invalid_max_nodes_is_rejected(
    tmp_path: Path,
) -> None:
    module, symbols, resolver, _ = make_analysis(
        tmp_path,
        """
def process():
    pass
""",
    )

    with pytest.raises(ValueError):
        build_control_flow(
            module,
            symbols,
            resolver,
            max_nodes=0,
        )
