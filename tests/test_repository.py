from pathlib import Path

import pytest

from analyzer.analysis.repository import (
    IGNORED_DIRECTORIES,
    RepositoryAnalysis,
    build_repository_analysis,
    find_python_files,
)


def write_file(
    root: Path,
    relative_path: str,
    content: str,
) -> Path:
    """Create a UTF-8 source file under the temporary repository."""
    path = root / relative_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def test_find_python_files_returns_python_files_in_deterministic_order(
    tmp_path: Path,
) -> None:
    write_file(tmp_path, "z.py", "z = 1\n")
    write_file(tmp_path, "a.py", "a = 1\n")
    write_file(tmp_path, "pkg/m.py", "m = 1\n")
    write_file(tmp_path, "pkg/a.py", "a = 2\n")

    files = find_python_files(tmp_path)

    assert files == tuple(sorted(files))
    assert [path.relative_to(tmp_path) for path in files] == [
        Path("a.py"),
        Path("pkg/a.py"),
        Path("pkg/m.py"),
        Path("z.py"),
    ]


def test_find_python_files_ignores_all_configured_directories(
    tmp_path: Path,
) -> None:
    write_file(tmp_path, "main.py", "x = 1\n")

    for directory in IGNORED_DIRECTORIES:
        write_file(
            tmp_path,
            f"{directory}/ignored.py",
            "x = 1\n",
        )

    files = find_python_files(tmp_path)

    assert files == (tmp_path / "main.py",)


def test_find_python_files_ignores_nested_ignored_directories(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "src/.venv/nested/ignored.py",
        "x = 1\n",
    )
    write_file(
        tmp_path,
        "src/pkg/valid.py",
        "x = 1\n",
    )

    files = find_python_files(tmp_path)

    assert files == (tmp_path / "src/pkg/valid.py",)


def test_find_python_files_ignores_non_python_files(
    tmp_path: Path,
) -> None:
    write_file(tmp_path, "README.md", "# test\n")
    write_file(tmp_path, "config.json", "{}\n")
    write_file(tmp_path, "main.py", "x = 1\n")

    files = find_python_files(tmp_path)

    assert files == (tmp_path / "main.py",)


def test_find_python_files_requires_existing_root(
    tmp_path: Path,
) -> None:
    missing = tmp_path / "does_not_exist"

    with pytest.raises(FileNotFoundError):
        find_python_files(missing)


def test_find_python_files_requires_directory(
    tmp_path: Path,
) -> None:
    file_path = write_file(
        tmp_path,
        "not_a_directory.py",
        "x = 1\n",
    )

    with pytest.raises(NotADirectoryError):
        find_python_files(file_path)


# ---------------------------------------------------------------------------
# Repository construction
# ---------------------------------------------------------------------------


def test_build_repository_analysis_returns_expected_type(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "payments.py",
        """
def charge():
    pass
""",
    )

    analysis = build_repository_analysis(tmp_path)

    assert isinstance(analysis, RepositoryAnalysis)


def test_build_repository_analysis_normalizes_root(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "payments.py",
        """
def charge():
    pass
""",
    )

    analysis = build_repository_analysis(tmp_path / ".")

    assert analysis.root == tmp_path.resolve()


def test_build_repository_analysis_parses_valid_modules(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "payments.py",
        """
def charge():
    pass


def process_payment():
    charge()
""",
    )

    analysis = build_repository_analysis(tmp_path)

    assert len(analysis.modules) == 1

    module = analysis.module("payments")

    assert module is not None
    assert module.module_name == "payments"
    assert module.file_path == (tmp_path / "payments.py").resolve()


def test_build_repository_analysis_builds_symbol_table(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "payments.py",
        """
def charge():
    pass


def process_payment():
    charge()


class PaymentService:
    def capture(self):
        pass
""",
    )

    analysis = build_repository_analysis(tmp_path)

    assert analysis.symbol_table.get("payments") is not None
    assert analysis.symbol_table.get("payments.charge") is not None
    assert analysis.symbol_table.get("payments.process_payment") is not None
    assert analysis.symbol_table.get(
        "payments.PaymentService"
    ) is not None
    assert analysis.symbol_table.get(
        "payments.PaymentService.capture"
    ) is not None


def test_build_repository_analysis_builds_import_table(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "payments.py",
        """
from helpers import charge
""",
    )

    write_file(
        tmp_path,
        "helpers.py",
        """
def charge():
    pass
""",
    )

    analysis = build_repository_analysis(tmp_path)

    binding = analysis.import_table.resolve(
        "payments",
        "charge",
    )

    assert binding == "helpers.charge"


def test_build_repository_analysis_builds_resolver(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "payments.py",
        """
from helpers import charge


def process_payment():
    charge()
""",
    )

    write_file(
        tmp_path,
        "helpers.py",
        """
def charge():
    pass
""",
    )

    analysis = build_repository_analysis(tmp_path)

    assert analysis.resolver is not None


def test_build_repository_analysis_builds_call_graph(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "payments.py",
        """
from helpers import charge


def process_payment():
    charge()
""",
    )

    write_file(
        tmp_path,
        "helpers.py",
        """
def charge():
    pass
""",
    )

    analysis = build_repository_analysis(tmp_path)

    assert analysis.call_graph.has_node(
        "payments.process_payment"
    )
    assert analysis.call_graph.has_node(
        "helpers.charge"
    )

    assert "helpers.charge" in analysis.call_graph.callees(
        "payments.process_payment"
    )


def test_build_repository_analysis_builds_control_flow(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "payments.py",
        """
def process_payment():
    charge()


def charge():
    pass
""",
    )

    analysis = build_repository_analysis(tmp_path)

    graph = analysis.control_flow_for(
        "payments.process_payment",
    )

    assert graph is not None
    assert graph.function == "payments.process_payment"
    assert graph.entry_node in {
        node.node_id for node in graph.nodes
    }
    assert graph.exit_node in {
        node.node_id for node in graph.nodes
    }


# ---------------------------------------------------------------------------
# Failure isolation
# ---------------------------------------------------------------------------


def test_invalid_python_does_not_discard_valid_modules(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "valid.py",
        """
def valid():
    pass
""",
    )

    write_file(
        tmp_path,
        "broken.py",
        """
def broken(
""",
    )

    analysis = build_repository_analysis(tmp_path)

    assert analysis.module("valid") is not None
    assert analysis.module("broken") is None

    assert len(analysis.parse_errors) == 1

    error_path, error_message = analysis.parse_errors[0]

    assert error_path == (tmp_path / "broken.py").resolve()
    assert "Unable to parse" in error_message


def test_parse_errors_are_deterministic(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "z_broken.py",
        """
def broken(
""",
    )

    write_file(
        tmp_path,
        "a_broken.py",
        """
def broken(
""",
    )

    analysis = build_repository_analysis(tmp_path)

    error_paths = [
        path
        for path, _ in analysis.parse_errors
    ]

    assert error_paths == sorted(error_paths)


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


def test_module_returns_module_by_name(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "payments.py",
        "x = 1\n",
    )

    analysis = build_repository_analysis(tmp_path)

    module = analysis.module("payments")

    assert module is not None
    assert module.module_name == "payments"


def test_module_returns_none_for_unknown_module(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "payments.py",
        "x = 1\n",
    )

    analysis = build_repository_analysis(tmp_path)

    assert analysis.module("unknown") is None


def test_module_for_path_returns_matching_module(
    tmp_path: Path,
) -> None:
    file_path = write_file(
        tmp_path,
        "payments.py",
        "x = 1\n",
    )

    analysis = build_repository_analysis(tmp_path)

    module = analysis.module_for_path(file_path)

    assert module is not None
    assert module.module_name == "payments"


def test_module_for_path_returns_none_for_unknown_file(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "payments.py",
        "x = 1\n",
    )

    analysis = build_repository_analysis(tmp_path)

    assert analysis.module_for_path(
        tmp_path / "unknown.py"
    ) is None


def test_control_flow_for_returns_graph(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "payments.py",
        """
def charge():
    pass
""",
    )

    analysis = build_repository_analysis(tmp_path)

    graph = analysis.control_flow_for("payments.charge")

    assert graph is not None
    assert graph.function == "payments.charge"


def test_control_flow_for_returns_none_for_unknown_function(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "payments.py",
        """
def charge():
    pass
""",
    )

    analysis = build_repository_analysis(tmp_path)

    assert analysis.control_flow_for(
        "payments.does_not_exist"
    ) is None


# ---------------------------------------------------------------------------
# Repository-level analysis consistency
# ---------------------------------------------------------------------------


def test_ignored_files_do_not_appear_in_analysis(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "payments.py",
        """
def charge():
    pass
""",
    )

    write_file(
        tmp_path,
        ".venv/fake.py",
        """
def fake():
    pass
""",
    )

    analysis = build_repository_analysis(tmp_path)

    assert analysis.module("payments") is not None
    assert analysis.module(".venv.fake") is None
    assert all(
        ".venv" not in module.file_path.parts
        for module in analysis.modules
    )


def test_repository_analysis_is_deterministic(
    tmp_path: Path,
) -> None:
    write_file(
        tmp_path,
        "z.py",
        """
def z():
    pass
""",
    )

    write_file(
        tmp_path,
        "a.py",
        """
def a():
    pass
""",
    )

    first = build_repository_analysis(tmp_path)
    second = build_repository_analysis(tmp_path)

    assert [
        module.module_name
        for module in first.modules
    ] == [
        module.module_name
        for module in second.modules
    ]

    assert [
        symbol.qualified_name
        for symbol in first.symbol_table.all_symbols()
    ] == [
        symbol.qualified_name
        for symbol in second.symbol_table.all_symbols()
    ]

    assert first.parse_errors == second.parse_errors
