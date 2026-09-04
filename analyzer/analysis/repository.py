"""Shared repository-wide static-analysis context.

This module builds the expensive analysis structures once and makes them
available to repository-level detectors.

The dependency order is:

    Python files
        ↓
    parsed modules
        ↓
    symbol table + import table
        ↓
    call resolver
        ↓
    call graph + control-flow graphs

Repository-level detectors should consume RepositoryAnalysis rather than
rebuilding these structures themselves.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from analyzer.analysis.call_graph import CallGraph, build_call_graph
from analyzer.analysis.control_flow import (
    ControlFlowGraph,
    build_control_flow,
)
from analyzer.analysis.imports import ImportTable, build_import_table
from analyzer.analysis.models import AnalysisModule
from analyzer.analysis.parser import ParseError, parse_file
from analyzer.analysis.resolver import CallResolver
from analyzer.analysis.symbols import SymbolTable, build_symbol_table

logger = logging.getLogger(__name__)


# Directories that should never be included in repository analysis.
#
# Keep this policy here rather than duplicating it in every repository-level
# analysis pass. New analysis features can therefore share the same file
# discovery behavior.
IGNORED_DIRECTORIES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        ".tox",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "build",
        "dist",
        ".eggs",
    }
)


@dataclass(slots=True)
class RepositoryAnalysis:
    """Complete shared analysis context for one repository."""

    root: Path
    modules: tuple[AnalysisModule, ...]
    symbol_table: SymbolTable
    import_table: ImportTable
    resolver: CallResolver
    call_graph: CallGraph
    control_flow: dict[str, ControlFlowGraph]
    parse_errors: tuple[tuple[Path, str], ...] = ()

    _modules_by_name: dict[str, AnalysisModule] = field(
        init=False,
        repr=False,
    )
    _modules_by_path: dict[Path, AnalysisModule] = field(
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        """Build constant-time module lookup indexes."""

        self._modules_by_name = {
            module.module_name: module
            for module in self.modules
        }

        self._modules_by_path = {
            module.file_path: module
            for module in self.modules
        }

    def module(self, module_name: str) -> AnalysisModule | None:
        """Return a parsed module by qualified module name."""
        return self._modules_by_name.get(module_name)

    def module_for_path(
        self,
        file_path: Path,
    ) -> AnalysisModule | None:
        """Return the parsed module associated with a canonical file path."""
        return self._modules_by_path.get(file_path.resolve())

    def control_flow_for(
        self,
        function: str,
    ) -> ControlFlowGraph | None:
        """Return a function's control-flow graph, if available."""
        return self.control_flow.get(function)


def find_python_files(root: Path) -> tuple[Path, ...]:
    """Return Python source files under ``root`` in deterministic order.

    Files inside generated environments, caches, build artifacts, and other
    non-source directories are excluded.

    Symlinked files/directories are not followed outside the repository root.
    This matters because the scanner may be pointed at untrusted source
    trees.
    """

    root = root.resolve()

    if not root.exists():
        raise FileNotFoundError(f"Repository does not exist: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Repository is not a directory: {root}")

    files: list[Path] = []

    for path in root.rglob("*.py"):
        # Skip anything beneath an ignored directory.
        try:
            relative = path.relative_to(root)
        except ValueError:
            # Defensive guard. rglob() should only return descendants.
            continue

        if any(
            directory in IGNORED_DIRECTORIES
            for directory in relative.parts
        ):
            continue

        # Resolve the path before analysis so a symlink cannot silently make
        # us analyze a file outside the requested repository.
        try:
            resolved = path.resolve()
            resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError):
            logger.warning(
                "Skipping Python file outside repository: %s",
                path,
            )
            continue

        if not resolved.is_file():
            continue

        files.append(resolved)

    return tuple(sorted(set(files)))


def _parse_modules(
    files: tuple[Path, ...],
    root: Path,
) -> tuple[
    tuple[AnalysisModule, ...],
    tuple[tuple[Path, str], ...],
]:
    """Parse all repository Python files.

    One malformed file must not prevent analysis of the rest of the
    repository. Successfully parsed modules continue through later passes;
    parse failures are retained so callers can report them consistently.
    """

    modules: list[AnalysisModule] = []
    errors: list[tuple[Path, str]] = []

    for file_path in files:
        try:
            modules.append(parse_file(file_path, root))
        except ParseError as exc:
            message = str(exc)
            errors.append((file_path, message))
            logger.error("Skipping %s: %s", file_path, message)

    return tuple(modules), tuple(errors)


def _build_control_flow(
    modules: tuple[AnalysisModule, ...],
    symbol_table: SymbolTable,
    resolver: CallResolver,
) -> dict[str, ControlFlowGraph]:
    """Build control-flow graphs for all parsed modules.

    Control-flow construction is module-scoped, so this helper combines
    the individual reports into one repository-level mapping keyed by
    function qualified name.
    """

    graphs: dict[str, ControlFlowGraph] = {}

    for module in modules:
        try:
            report = build_control_flow(
                module,
                symbol_table,
                resolver,
            )
        except (TypeError, ValueError, RecursionError) as exc:
            logger.error(
                "Skipping control-flow analysis for %s: %s",
                module.file_path,
                exc,
            )
            continue

        for function_result in report.functions:
            graphs[function_result.function] = function_result.graph

    return graphs


def build_repository_analysis(root: Path) -> RepositoryAnalysis:
    """Build the complete shared analysis context for a repository.

    The analysis pipeline is intentionally centralized here so expensive
    repository-wide structures are constructed exactly once per scan.

    A malformed Python file is isolated from the rest of the repository.
    Later analysis stages are also defensive: a failure in one module's
    control-flow construction does not discard the successfully analyzed
    modules.
    """

    root = root.resolve()

    files = find_python_files(root)

    modules, parse_errors = _parse_modules(
        files,
        root,
    )

    # Build the repository indexes from the successfully parsed modules.
    symbol_table = build_symbol_table(list(modules))
    import_table = build_import_table(list(modules))

    # CallResolver needs the complete module mapping so it can resolve a
    # call site's file path to its owning module in O(1).
    modules_by_name = {
        module.module_name: module
        for module in modules
    }

    resolver = CallResolver(
        symbol_table,
        import_table,
        modules_by_name,
    )

    call_graph = build_call_graph(
        list(modules),
        symbol_table,
        resolver,
    )

    control_flow = _build_control_flow(
        modules,
        symbol_table,
        resolver,
    )

    return RepositoryAnalysis(
        root=root,
        modules=modules,
        symbol_table=symbol_table,
        import_table=import_table,
        resolver=resolver,
        call_graph=call_graph,
        control_flow=control_flow,
        parse_errors=parse_errors,
    )
