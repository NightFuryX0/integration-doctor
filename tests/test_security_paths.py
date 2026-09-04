from pathlib import Path

import pytest

from analyzer.analysis.call_graph import CallGraph, build_call_graph
from analyzer.analysis.control_flow import (
    ControlFlowGraph,
    build_control_flow,
)
from analyzer.analysis.imports import build_import_table
from analyzer.analysis.resolver import CallResolver
from analyzer.analysis.symbols import build_symbol_table
from analyzer.analysis.parser import parse_file
from analyzer.analysis.security_paths import (
    SecurityPathAnalyzer,
    analyze_security_paths,
)


def make_graph(
    tmp_path: Path,
    files: dict[str, str],
) -> tuple[CallGraph, dict[str, ControlFlowGraph]]:
    modules = []

    for relative_path, source in files.items():
        path = tmp_path / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")

        modules.append(
            parse_file(
                path,
                tmp_path,
            )
        )

    symbol_table = build_symbol_table(modules)
    import_table = build_import_table(modules)

    module_map = {
        module.module_name: module
        for module in modules
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

    control_flow: dict[str, ControlFlowGraph] = {}

    for module in modules:
        report = build_control_flow(
            module,
            symbol_table,
            resolver,
        )

        for function in report.functions:
            control_flow[function.function] = function.graph

    return graph, control_flow


def test_direct_protected_path(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def webhook():
    verify_signature()
    charge()


def verify_signature():
    pass


def charge():
    pass
"""
        },
    )

    report = SecurityPathAnalyzer(
        graph,
        control_flow,
    ).analyze(
        entry_points={"app.webhook"},
        sinks={"app.charge"},
        guards={"app.verify_signature"},
    )

    assert report.complete
    assert not report.vulnerable
    assert len(report.results) == 1

    result = report.results[0]

    assert result.protected
    assert not result.unprotected_paths
    assert result.paths[0].nodes == (
        "app.webhook",
        "app.verify_signature",
        "app.charge",
    )


def test_direct_unprotected_path(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def webhook():
    charge()


def verify_signature():
    pass


def charge():
    pass
"""
        },
    )

    report = SecurityPathAnalyzer(
        graph,
        control_flow,
    ).analyze(
        entry_points={"app.webhook"},
        sinks={"app.charge"},
        guards={"app.verify_signature"},
    )

    assert report.complete
    assert report.vulnerable
    assert len(report.unprotected_paths) == 1

    assert report.unprotected_paths[0].nodes == (
        "app.webhook",
        "app.charge",
    )


def test_one_unprotected_branch_is_a_vulnerability(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def webhook():
    verify_signature()
    charge()
    bypass()


def verify_signature():
    pass


def charge():
    pass


def bypass():
    charge()
"""
        },
    )

    report = SecurityPathAnalyzer(
        graph,
        control_flow,
    ).analyze(
        entry_points={"app.webhook"},
        sinks={"app.charge"},
        guards={"app.verify_signature"},
    )

    assert report.complete
    assert report.vulnerable

    paths = {
        path.nodes
        for path in report.unprotected_paths
    }

    assert (
        "app.webhook",
        "app.bypass",
        "app.charge",
    ) in paths


def test_all_paths_must_be_protected(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def webhook():
    verified()
    unverified()


def verified():
    verify_signature()
    charge()


def unverified():
    charge()


def verify_signature():
    pass


def charge():
    pass
"""
        },
    )

    report = SecurityPathAnalyzer(
        graph,
        control_flow,
    ).analyze(
        entry_points={"app.webhook"},
        sinks={"app.charge"},
        guards={"app.verify_signature"},
    )

    assert report.complete
    assert report.vulnerable

    assert len(report.results[0].paths) == 2
    assert len(report.unprotected_paths) == 1


def test_guard_on_path_marks_path_protected(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def webhook():
    process()


def process():
    verify_signature()
    charge()


def verify_signature():
    pass


def charge():
    pass
"""
        },
    )

    report = SecurityPathAnalyzer(
        graph,
        control_flow,
    ).analyze(
        entry_points={"app.webhook"},
        sinks={"app.charge"},
        guards={"app.verify_signature"},
    )

    result = report.results[0]

    assert result.complete
    assert result.protected
    assert not result.unprotected_paths

    assert result.paths[0].guard_nodes == (
        "app.verify_signature",
    )


def test_guard_after_sink_does_not_protect_path(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def webhook():
    charge()
    verify_signature()


def verify_signature():
    pass


def charge():
    pass
"""
        },
    )

    report = SecurityPathAnalyzer(
        graph,
        control_flow,
    ).analyze(
        entry_points={"app.webhook"},
        sinks={"app.charge"},
        guards={"app.verify_signature"},
    )

    assert report.vulnerable
    assert report.unprotected_paths[0].nodes == (
        "app.webhook",
        "app.charge",
    )


def test_multiple_guards_are_supported(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def webhook():
    first_guard()
    second_guard()
    charge()


def first_guard():
    pass


def second_guard():
    pass


def charge():
    pass
"""
        },
    )

    report = SecurityPathAnalyzer(
        graph,
        control_flow,
    ).analyze(
        entry_points={"app.webhook"},
        sinks={"app.charge"},
        guards={
            "app.first_guard",
            "app.second_guard",
        },
    )

    result = report.results[0]

    assert result.protected
    assert result.paths[0].guard_nodes == (
        "app.first_guard",
        "app.second_guard",
    )


def test_cycles_do_not_cause_infinite_traversal(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def webhook():
    first()


def first():
    second()


def second():
    first()
    charge()


def charge():
    pass
"""
        },
    )

    report = SecurityPathAnalyzer(
        graph,
        control_flow,
    ).analyze(
        entry_points={"app.webhook"},
        sinks={"app.charge"},
        guards=set(),
    )

    assert report.complete
    assert report.vulnerable
    assert len(report.unprotected_paths) == 1

    assert report.unprotected_paths[0].nodes == (
        "app.webhook",
        "app.first",
        "app.second",
        "app.charge",
    )


def test_source_equals_sink(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def charge():
    pass
"""
        },
    )

    report = SecurityPathAnalyzer(
        graph,
        control_flow,
    ).analyze(
        entry_points={"app.charge"},
        sinks={"app.charge"},
        guards=set(),
    )

    assert report.complete
    assert report.vulnerable
    assert report.unprotected_paths[0].nodes == ("app.charge",)


def test_source_equals_sink_is_protected_when_source_is_guard(
    tmp_path: Path,
) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def verify():
    pass
"""
        },
    )

    report = SecurityPathAnalyzer(
        graph,
        control_flow,
    ).analyze(
        entry_points={"app.verify"},
        sinks={"app.verify"},
        guards={"app.verify"},
    )

    assert report.complete
    assert not report.vulnerable
    assert report.results[0].protected


def test_unreachable_sink_has_no_paths(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def webhook():
    pass


def charge():
    pass
"""
        },
    )

    report = SecurityPathAnalyzer(
        graph,
        control_flow,
    ).analyze(
        entry_points={"app.webhook"},
        sinks={"app.charge"},
        guards=set(),
    )

    result = report.results[0]

    assert result.complete
    assert not result.vulnerable
    assert not result.paths
    assert not result.protected


def test_depth_limit_marks_analysis_incomplete(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def start():
    first()


def first():
    second()


def second():
    charge()


def charge():
    pass
"""
        },
    )

    report = SecurityPathAnalyzer(
        graph,
        control_flow,
    ).analyze(
        entry_points={"app.start"},
        sinks={"app.charge"},
        guards=set(),
        max_depth=1,
    )

    result = report.results[0]

    assert not result.complete
    assert not result.paths


def test_path_limit_marks_analysis_incomplete(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def start():
    one()
    two()
    three()


def one():
    charge()


def two():
    charge()


def three():
    charge()


def charge():
    pass
"""
        },
    )

    report = SecurityPathAnalyzer(
        graph,
        control_flow,
    ).analyze(
        entry_points={"app.start"},
        sinks={"app.charge"},
        guards=set(),
        max_paths=2,
    )

    result = report.results[0]

    assert not result.complete
    assert len(result.paths) == 2


def test_unknown_entry_point_is_rejected(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def charge():
    pass
"""
        },
    )

    with pytest.raises(ValueError, match="Unknown entry point"):
        SecurityPathAnalyzer(
            graph,
            control_flow,
        ).analyze(
            entry_points={"app.webhook"},
            sinks={"app.charge"},
            guards=set(),
        )


def test_unknown_sink_is_rejected(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def webhook():
    pass
"""
        },
    )

    with pytest.raises(ValueError, match="Unknown sink"):
        SecurityPathAnalyzer(
            graph,
            control_flow,
        ).analyze(
            entry_points={"app.webhook"},
            sinks={"app.charge"},
            guards=set(),
        )


def test_unknown_guard_is_rejected(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def webhook():
    charge()


def charge():
    pass
"""
        },
    )

    with pytest.raises(ValueError, match="Unknown guard"):
        SecurityPathAnalyzer(
            graph,
            control_flow,
        ).analyze(
            entry_points={"app.webhook"},
            sinks={"app.charge"},
            guards={"app.verify"},
        )


def test_invalid_depth_is_rejected(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def webhook():
    pass
"""
        },
    )

    with pytest.raises(ValueError):
        SecurityPathAnalyzer(
            graph,
            control_flow,
        ).analyze(
            entry_points={"app.webhook"},
            sinks={"app.webhook"},
            guards=set(),
            max_depth=-1,
        )


def test_invalid_path_limit_is_rejected(tmp_path: Path) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def webhook():
    pass
"""
        },
    )

    with pytest.raises(ValueError):
        SecurityPathAnalyzer(
            graph,
            control_flow,
        ).analyze(
            entry_points={"app.webhook"},
            sinks={"app.webhook"},
            guards=set(),
            max_paths=0,
        )


def test_convenience_function_matches_analyzer(
    tmp_path: Path,
) -> None:
    graph, control_flow = make_graph(
        tmp_path,
        {
            "app.py": """
def webhook():
    charge()


def charge():
    pass
"""
        },
    )

    report = analyze_security_paths(
        graph,
        control_flow,
        entry_points={"app.webhook"},
        sinks={"app.charge"},
        guards=set(),
    )

    analyzer_paths = SecurityPathAnalyzer(
        graph,
        control_flow,
    ).find_unprotected_paths(
        entry_points={"app.webhook"},
        sinks={"app.charge"},
        guards=set(),
    )

    assert report.unprotected_paths == analyzer_paths
