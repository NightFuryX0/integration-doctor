"""Control-flow analysis for repository functions.

The call graph answers:

    "What can call what?"

This module answers:

    "In what possible execution order can statements and calls occur?"

Security analysis needs both pieces of information.

For example:

    def webhook():
        verify_signature()
        charge()

The call graph contains:

    webhook -> verify_signature
    webhook -> charge

The control-flow graph additionally preserves:

    verify_signature -> charge

as an execution-order relationship.

This module is intentionally conservative. It models possible execution
rather than attempting symbolic execution or proving runtime conditions.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from enum import Enum

from analyzer.analysis.models import (
    AnalysisModule,
    CallSite,
    ResolutionStatus,
)
from analyzer.analysis.resolver import (
    CallResolver,
    collect_call_sites,
)
from analyzer.analysis.symbols import SymbolTable


_DEFAULT_MAX_NODES = 100_000


class ControlFlowKind(str, Enum):
    """Type of node in a control-flow graph."""

    ENTRY = "entry"
    EXIT = "exit"
    STATEMENT = "statement"
    CALL = "call"
    CONDITION = "condition"
    RETURN = "return"
    RAISE = "raise"


@dataclass(frozen=True, slots=True)
class ControlFlowCall:
    """Resolved call information attached to a CFG node."""

    expression: str
    line: int
    column: int
    status: ResolutionStatus
    targets: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ControlFlowNode:
    """One node in a function's control-flow graph."""

    node_id: int
    function: str
    kind: ControlFlowKind
    line: int
    column: int
    ast_type: str
    calls: tuple[ControlFlowCall, ...] = ()


@dataclass(frozen=True, slots=True)
class ControlFlowEdge:
    """A directed execution-flow relationship."""

    source: int
    target: int


@dataclass(frozen=True, slots=True)
class ControlFlowGraph:
    """Control-flow graph for one repository function."""

    function: str
    nodes: tuple[ControlFlowNode, ...]
    edges: tuple[ControlFlowEdge, ...]
    entry_node: int
    exit_node: int

    def __post_init__(self) -> None:
        node_ids = {node.node_id for node in self.nodes}

        if self.entry_node not in node_ids:
            raise ValueError(
                f"entry node {self.entry_node} does not exist"
            )

        if self.exit_node not in node_ids:
            raise ValueError(
                f"exit node {self.exit_node} does not exist"
            )

        seen_edges: set[tuple[int, int]] = set()

        for edge in self.edges:
            if edge.source not in node_ids:
                raise ValueError(
                    f"edge source {edge.source} does not exist"
                )

            if edge.target not in node_ids:
                raise ValueError(
                    f"edge target {edge.target} does not exist"
                )

            key = (edge.source, edge.target)

            if key in seen_edges:
                raise ValueError(
                    f"duplicate control-flow edge: {key}"
                )

            seen_edges.add(key)

    def get_node(self, node_id: int) -> ControlFlowNode | None:
        """Return a node by ID."""
        for node in self.nodes:
            if node.node_id == node_id:
                return node

        return None

    def outgoing(
        self,
        node_id: int,
    ) -> tuple[ControlFlowEdge, ...]:
        """Return execution edges leaving a node."""

        return tuple(
            edge
            for edge in self.edges
            if edge.source == node_id
        )

    def incoming(
        self,
        node_id: int,
    ) -> tuple[ControlFlowEdge, ...]:
        """Return execution edges entering a node."""

        return tuple(
            edge
            for edge in self.edges
            if edge.target == node_id
        )

    def edges_from(
        self,
        node_id: int,
    ) -> tuple[ControlFlowEdge, ...]:
        """Alias matching the existing CallGraph API."""

        return self.outgoing(node_id)

    def edges_to(
        self,
        node_id: int,
    ) -> tuple[ControlFlowEdge, ...]:
        """Alias matching the existing CallGraph API."""

        return self.incoming(node_id)

    def call_nodes(self) -> tuple[ControlFlowNode, ...]:
        """Return call nodes in source order."""

        return tuple(
            node
            for node in self.nodes
            if node.kind == ControlFlowKind.CALL
        )


@dataclass(frozen=True, slots=True)
class FunctionControlFlow:
    """Control-flow information for one repository function."""

    function: str
    graph: ControlFlowGraph


@dataclass(frozen=True, slots=True)
class ControlFlowReport:
    """Control-flow graphs for an analyzed module."""

    module_name: str
    functions: tuple[FunctionControlFlow, ...]

    def get(
        self,
        function: str,
    ) -> FunctionControlFlow | None:
        """Return the CFG for a function."""

        for item in self.functions:
            if item.function == function:
                return item

        return None


class _Builder:
    """Mutable implementation detail used while constructing one CFG."""

    def __init__(
        self,
        function: str,
        max_nodes: int,
    ) -> None:
        self.function = function
        self.max_nodes = max_nodes

        self.nodes: list[ControlFlowNode] = []
        self.edges: list[ControlFlowEdge] = []

        self._next_node_id = 0
        self._edge_keys: set[tuple[int, int]] = set()

    def add_node(
        self,
        *,
        kind: ControlFlowKind,
        line: int,
        column: int,
        ast_type: str,
        calls: tuple[ControlFlowCall, ...] = (),
    ) -> int:
        """Create one CFG node."""

        if len(self.nodes) >= self.max_nodes:
            raise ValueError(
                f"control-flow graph for {self.function!r} exceeded "
                f"maximum node count ({self.max_nodes})"
            )

        node_id = self._next_node_id
        self._next_node_id += 1

        self.nodes.append(
            ControlFlowNode(
                node_id=node_id,
                function=self.function,
                kind=kind,
                line=max(line, 1),
                column=max(column, 0),
                ast_type=ast_type,
                calls=calls,
            )
        )

        return node_id

    def add_edge(
        self,
        source: int,
        target: int,
    ) -> None:
        """Add an execution edge exactly once."""

        key = (source, target)

        if key in self._edge_keys:
            return

        self._edge_keys.add(key)

        self.edges.append(
            ControlFlowEdge(
                source=source,
                target=target,
            )
        )


class ControlFlowBuilder:
    """Build conservative CFGs using the existing resolver."""

    def __init__(
        self,
        symbol_table: SymbolTable,
        resolver: CallResolver,
        *,
        max_nodes: int = _DEFAULT_MAX_NODES,
    ) -> None:
        if isinstance(max_nodes, bool) or not isinstance(max_nodes, int):
            raise TypeError("max_nodes must be an integer")

        if max_nodes < 1:
            raise ValueError("max_nodes must be >= 1")

        self.symbol_table = symbol_table
        self.resolver = resolver
        self.max_nodes = max_nodes

    def build_module(
        self,
        module: AnalysisModule,
    ) -> ControlFlowReport:
        """Build CFGs for every repository function in a module."""

        call_sites = self._collect_resolved_calls(module)

        functions: list[FunctionControlFlow] = []

        for node in ast.walk(module.tree):
            if not isinstance(
                node,
                (ast.FunctionDef, ast.AsyncFunctionDef),
            ):
                continue

            function = self._find_symbol_name(
                module,
                node,
            )

            if function is None:
                # A function without a corresponding symbol is not safe to
                # invent a qualified name for. Skip it rather than creating
                # inconsistent analysis data.
                continue

            functions.append(
                self.build_function(
                    function=function,
                    node=node,
                    call_sites=call_sites,
                )
            )

        return ControlFlowReport(
            module_name=module.module_name,
            functions=tuple(functions),
        )

    def build_function(
        self,
        *,
        function: str,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        call_sites: tuple[CallSite, ...] = (),
    ) -> FunctionControlFlow:
        """Build a CFG for one function."""

        builder = _Builder(
            function=function,
            max_nodes=self.max_nodes,
        )

        calls_by_position = self._calls_by_position(
            call_sites,
            function,
        )

        entry = builder.add_node(
            kind=ControlFlowKind.ENTRY,
            line=node.lineno,
            column=node.col_offset,
            ast_type=type(node).__name__,
        )

        exit_node = builder.add_node(
            kind=ControlFlowKind.EXIT,
            line=getattr(node, "end_lineno", node.lineno),
            column=getattr(
                node,
                "end_col_offset",
                node.col_offset,
            ),
            ast_type="FunctionExit",
        )

        continuations, breaks, continues = self._build_statements(
            builder=builder,
            statements=node.body,
            predecessors={entry},
            exit_node=exit_node,
            calls_by_position=calls_by_position,
            break_target=None,
            continue_target=None,
        )

        # Normal fall-through reaches the function exit.
        for predecessor in continuations:
            builder.add_edge(
                predecessor,
                exit_node,
            )

        # A top-level break/continue should not normally be possible because
        # Python syntax requires them inside a loop. Keep the defensive check
        # rather than silently creating malformed edges.
        if breaks or continues:
            raise ValueError(
                f"invalid break/continue state while building {function!r}"
            )

        graph = ControlFlowGraph(
            function=function,
            nodes=tuple(builder.nodes),
            edges=tuple(builder.edges),
            entry_node=entry,
            exit_node=exit_node,
        )

        return FunctionControlFlow(
            function=function,
            graph=graph,
        )

    def _build_statements(
        self,
        *,
        builder: _Builder,
        statements: list[ast.stmt],
        predecessors: set[int],
        exit_node: int,
        calls_by_position: dict[
            tuple[str, int, int],
            tuple[ControlFlowCall, ...],
        ],
        break_target: int | None,
        continue_target: int | None,
    ) -> tuple[set[int], set[int], set[int]]:
        """Build a sequence of statements.

        Returns:

            normal continuations
            break exits
            continue exits
        """

        current = set(predecessors)
        breaks: set[int] = set()
        continues: set[int] = set()

        for statement in statements:

            current, statement_breaks, statement_continues = (
                self._build_statement(
                    builder=builder,
                    statement=statement,
                    predecessors=current,
                    exit_node=exit_node,
                    calls_by_position=calls_by_position,
                    break_target=break_target,
                    continue_target=continue_target,
                )
            )

            breaks.update(statement_breaks)
            continues.update(statement_continues)

        return current, breaks, continues

    def _build_statement(
        self,
        *,
        builder: _Builder,
        statement: ast.stmt,
        predecessors: set[int],
        exit_node: int,
        calls_by_position: dict[
            tuple[str, int, int],
            tuple[ControlFlowCall, ...],
        ],
        break_target: int | None,
        continue_target: int | None,
    ) -> tuple[set[int], set[int], set[int]]:
        """Build one statement."""

        if isinstance(
            statement,
            (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef),
        ):
            # Definitions create objects but do not execute their bodies as
            # part of the surrounding function's normal flow.
            return predecessors, set(), set()

        if isinstance(statement, ast.If):
            return self._build_if(
                builder=builder,
                statement=statement,
                predecessors=predecessors,
                exit_node=exit_node,
                calls_by_position=calls_by_position,
                break_target=break_target,
                continue_target=continue_target,
            )

        if isinstance(
            statement,
            (ast.For, ast.AsyncFor, ast.While),
        ):
            return self._build_loop(
                builder=builder,
                statement=statement,
                predecessors=predecessors,
                exit_node=exit_node,
                calls_by_position=calls_by_position,
            )

        if isinstance(statement, ast.Try):
            return self._build_try(
                builder=builder,
                statement=statement,
                predecessors=predecessors,
                exit_node=exit_node,
                calls_by_position=calls_by_position,
                break_target=break_target,
                continue_target=continue_target,
            )

        if isinstance(statement, ast.Break):
            node_id = self._add_statement_node(
                builder,
                statement,
                calls_by_position,
            )

            for predecessor in predecessors:
                builder.add_edge(predecessor, node_id)

            if break_target is not None:
                builder.add_edge(node_id, break_target)

            return set(), {node_id}, set()

        if isinstance(statement, ast.Continue):
            node_id = self._add_statement_node(
                builder,
                statement,
                calls_by_position,
            )

            for predecessor in predecessors:
                builder.add_edge(predecessor, node_id)

            if continue_target is not None:
                builder.add_edge(node_id, continue_target)

            return set(), set(), {node_id}

        node_id = self._add_statement_node(
            builder,
            statement,
            calls_by_position,
        )

        for predecessor in predecessors:
            builder.add_edge(
                predecessor,
                node_id,
            )

        if isinstance(statement, (ast.Return, ast.Raise)):
            builder.add_edge(
                node_id,
                exit_node,
            )

            return set(), set(), set()

        return {node_id}, set(), set()

    def _build_if(
        self,
        *,
        builder: _Builder,
        statement: ast.If,
        predecessors: set[int],
        exit_node: int,
        calls_by_position: dict[
            tuple[str, int, int],
            tuple[ControlFlowCall, ...],
        ],
        break_target: int | None,
        continue_target: int | None,
    ) -> tuple[set[int], set[int], set[int]]:
        """Build an if/elif/else branch."""

        condition_calls = self._calls_for_statement_expression(
            statement.test,
            calls_by_position,
        )

        condition = builder.add_node(
            kind=ControlFlowKind.CONDITION,
            line=statement.test.lineno,
            column=statement.test.col_offset,
            ast_type=type(statement.test).__name__,
            calls=condition_calls,
        )

        for predecessor in predecessors:
            builder.add_edge(
                predecessor,
                condition,
            )

        true_end, true_breaks, true_continues = (
            self._build_statements(
                builder=builder,
                statements=statement.body,
                predecessors={condition},
                exit_node=exit_node,
                calls_by_position=calls_by_position,
                break_target=break_target,
                continue_target=continue_target,
            )
        )

        if statement.orelse:
            false_end, false_breaks, false_continues = (
                self._build_statements(
                    builder=builder,
                    statements=statement.orelse,
                    predecessors={condition},
                    exit_node=exit_node,
                    calls_by_position=calls_by_position,
                    break_target=break_target,
                    continue_target=continue_target,
                )
            )
        else:
            # If there is no else, the false branch falls through directly
            # after the if.
            false_end = {condition}
            false_breaks = set()
            false_continues = set()

        return (
            true_end | false_end,
            true_breaks | false_breaks,
            true_continues | false_continues,
        )

    def _build_loop(
        self,
        *,
        builder: _Builder,
        statement: ast.For | ast.AsyncFor | ast.While,
        predecessors: set[int],
        exit_node: int,
        calls_by_position: dict[
            tuple[str, int, int],
            tuple[ControlFlowCall, ...],
        ],
    ) -> tuple[set[int], set[int], set[int]]:
        """Build a conservative loop.

        Both zero iterations and repeated iterations are possible.

        `break` exits the loop.
        `continue` returns to the loop condition.
        """

        if isinstance(statement, ast.While):
            condition_expression = statement.test
        else:
            condition_expression = statement.iter

        condition_calls = self._calls_for_statement_expression(
            condition_expression,
            calls_by_position,
        )

        condition = builder.add_node(
            kind=ControlFlowKind.CONDITION,
            line=condition_expression.lineno,
            column=condition_expression.col_offset,
            ast_type=type(condition_expression).__name__,
            calls=condition_calls,
        )

        for predecessor in predecessors:
            builder.add_edge(
                predecessor,
                condition,
            )

        body_end, break_nodes, continue_nodes = (
            self._build_statements(
                builder=builder,
                statements=statement.body,
                predecessors={condition},
                exit_node=exit_node,
                calls_by_position=calls_by_position,
                break_target=None,
                continue_target=condition,
            )
        )

        # A normal body completion repeats the loop.
        for node_id in body_end:
            builder.add_edge(
                node_id,
                condition,
            )

        for node_id in continue_nodes:
            builder.add_edge(
                node_id,
                condition,
            )

            # The condition can evaluate false immediately, so execution can
        # leave the loop. A `break` also leaves the loop and resumes at the
        # same point normal loop exit does, so break nodes belong in the
        # continuation set — not passed upward as unresolved "breaks".
        return (
            {condition} | set(break_nodes),
            set(),
            set(),
        )

    def _build_try(
        self,
        *,
        builder: _Builder,
        statement: ast.Try,
        predecessors: set[int],
        exit_node: int,
        calls_by_position: dict[
            tuple[str, int, int],
            tuple[ControlFlowCall, ...],
        ],
        break_target: int | None,
        continue_target: int | None,
    ) -> tuple[set[int], set[int], set[int]]:
        """Build conservative try/except/else/finally flow.

        Exception dispatch is represented conservatively: handlers may be
        entered from the try region. We intentionally avoid pretending that
        static analysis can determine the exact exception type.
        """

        try_end, try_breaks, try_continues = self._build_statements(
            builder=builder,
            statements=statement.body,
            predecessors=predecessors,
            exit_node=exit_node,
            calls_by_position=calls_by_position,
            break_target=break_target,
            continue_target=continue_target,
        )

        handler_end: set[int] = set()
        handler_breaks: set[int] = set()
        handler_continues: set[int] = set()

        for handler in statement.handlers:
            handler_node = builder.add_node(
                kind=ControlFlowKind.CONDITION,
                line=handler.lineno,
                column=handler.col_offset,
                ast_type=type(handler).__name__,
            )

            # Any statement in the try body may potentially raise. Since we
            # don't perform exception-effect analysis, conservatively allow
            # entry to the handler from every current try predecessor.
            for predecessor in predecessors | try_end:
                builder.add_edge(
                    predecessor,
                    handler_node,
                )

            branch_end, branch_breaks, branch_continues = (
                self._build_statements(
                    builder=builder,
                    statements=handler.body,
                    predecessors={handler_node},
                    exit_node=exit_node,
                    calls_by_position=calls_by_position,
                    break_target=break_target,
                    continue_target=continue_target,
                )
            )

            handler_end.update(branch_end)
            handler_breaks.update(branch_breaks)
            handler_continues.update(branch_continues)

        continuation = try_end | handler_end

        if statement.orelse:
            continuation, else_breaks, else_continues = (
                self._build_statements(
                    builder=builder,
                    statements=statement.orelse,
                    predecessors=continuation,
                    exit_node=exit_node,
                    calls_by_position=calls_by_position,
                    break_target=break_target,
                    continue_target=continue_target,
                )
            )

            try_breaks.update(else_breaks)
            try_continues.update(else_continues)

        if statement.finalbody:
            continuation, final_breaks, final_continues = (
                self._build_statements(
                    builder=builder,
                    statements=statement.finalbody,
                    predecessors=continuation,
                    exit_node=exit_node,
                    calls_by_position=calls_by_position,
                    break_target=break_target,
                    continue_target=continue_target,
                )
            )

            try_breaks.update(final_breaks)
            try_continues.update(final_continues)

        return (
            continuation,
            try_breaks | handler_breaks,
            try_continues | handler_continues,
        )

    def _add_statement_node(
        self,
        builder: _Builder,
        statement: ast.stmt,
        calls_by_position: dict[
            tuple[str, int, int],
            tuple[ControlFlowCall, ...],
        ],
    ) -> int:
        """Create a node for a normal statement."""

        # A call may be nested inside the statement, for example:
        # ``await charge(request)``. Match both the statement position and
        # nested call positions so async calls are represented in the CFG.
        calls: list[ControlFlowCall] = list(
            calls_by_position.get(
                (
                    builder.function,
                    statement.lineno,
                    statement.col_offset,
                ),
                (),
            )
        )

        seen = {
            (call.line, call.column, call.expression)
            for call in calls
        }

        for node in ast.walk(statement):
            if not isinstance(node, ast.Call):
                continue

            line = getattr(node, "lineno", None)
            column = getattr(node, "col_offset", None)

            if line is None or column is None:
                continue

            for call in calls_by_position.get(
                (builder.function, line, column),
                (),
            ):
                key = (call.line, call.column, call.expression)

                if key in seen:
                    continue

                calls.append(call)
                seen.add(key)

        ordered_calls = tuple(
            sorted(
                calls,
                key=lambda call: (
                    call.line,
                    call.column,
                    call.expression,
                ),
            )
        )

        # Return and raise statements keep their explicit control-flow
        # meaning even when their expression contains a call, such as
        # ``raise RuntimeError()`` or ``return process()``.
        if isinstance(statement, ast.Return):
            kind = ControlFlowKind.RETURN
        elif isinstance(statement, ast.Raise):
            kind = ControlFlowKind.RAISE
        elif ordered_calls:
            kind = ControlFlowKind.CALL
        else:
            kind = ControlFlowKind.STATEMENT

        return builder.add_node(
            kind=kind,
            line=statement.lineno,
            column=statement.col_offset,
            ast_type=type(statement).__name__,
            calls=ordered_calls,
        )

    def _collect_resolved_calls(
        self,
        module: AnalysisModule,
    ) -> tuple[CallSite, ...]:
        """Collect calls using the existing resolver API.

        The resolver remains the single source of truth for call resolution.
        This layer only attaches those results to execution-flow nodes.
        """

        try:
            call_sites = collect_call_sites(module)
        except (TypeError, ValueError, RecursionError):
            return ()

        resolved_sites: list[CallSite] = []

        for call_site in call_sites:
            try:
                self.resolver.resolve(call_site)
            except (TypeError, ValueError, RecursionError):
                continue

            resolved_sites.append(call_site)

        return tuple(resolved_sites)

    def _calls_by_position(
        self,
        call_sites: tuple[CallSite, ...],
        function: str,
    ) -> dict[
        tuple[str, int, int],
        tuple[ControlFlowCall, ...],
    ]:
        """Resolve call sites and group them by source statement."""

        result: dict[
            tuple[str, int, int],
            list[ControlFlowCall],
        ] = {}

        for call_site in call_sites:
            if call_site.caller != function:
                continue

            try:
                resolution = self.resolver.resolve(call_site)
            except (TypeError, ValueError, RecursionError):
                continue

            call = ControlFlowCall(
                expression=call_site.expression,
                line=call_site.line,
                column=call_site.column,
                status=resolution.status,
                targets=resolution.targets,
            )

            key = (
                function,
                call_site.line,
                call_site.column,
            )

            result.setdefault(key, []).append(call)

        return {
            key: tuple(
                sorted(
                    calls,
                    key=lambda item: (
                        item.line,
                        item.column,
                        item.expression,
                    ),
                )
            )
            for key, calls in result.items()
        }

    @staticmethod
    def _calls_for_statement_expression(
        expression: ast.expr,
        calls_by_position: dict[
            tuple[str, int, int],
            tuple[ControlFlowCall, ...],
        ],
    ) -> tuple[ControlFlowCall, ...]:
        """Return calls contained in a condition expression.

        Condition calls can be nested inside expressions, so position-based
        lookup is not sufficient by itself. This helper intentionally matches
        by source location.
        """

        calls: list[ControlFlowCall] = []

        for node in ast.walk(expression):
            if not isinstance(node, ast.Call):
                continue

            line = getattr(node, "lineno", None)
            column = getattr(node, "col_offset", None)

            if line is None or column is None:
                continue

            for grouped in calls_by_position.values():
                for call in grouped:
                    if call.line == line and call.column == column:
                        calls.append(call)

        return tuple(
            sorted(
                calls,
                key=lambda item: (
                    item.line,
                    item.column,
                    item.expression,
                ),
            )
        )

    def _find_symbol_name(
        self,
        module: AnalysisModule,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> str | None:
        """Find the exact symbol-table name for an AST function node.

        Matching by file, line, and function name avoids independently
        reconstructing qualified names for nested functions and methods.
        """

        candidates = [
            symbol
            for symbol in self.symbol_table.all_symbols()
            if symbol.file_path == module.file_path
            and symbol.line == node.lineno
            and symbol.name == node.name
        ]

        if not candidates:
            return None

        if len(candidates) == 1:
            return candidates[0].qualified_name

        # Multiple symbols at the same location should never normally occur,
        # but deterministic selection is safer than depending on dictionary
        # insertion order.
        candidates.sort(
            key=lambda symbol: (
                symbol.qualified_name,
                symbol.kind.value,
            )
        )

        return candidates[0].qualified_name


def build_control_flow(
    module: AnalysisModule,
    symbol_table: SymbolTable,
    resolver: CallResolver,
    *,
    max_nodes: int = _DEFAULT_MAX_NODES,
) -> ControlFlowReport:
    """Build control-flow graphs for all functions in a module."""

    return ControlFlowBuilder(
        symbol_table=symbol_table,
        resolver=resolver,
        max_nodes=max_nodes,
    ).build_module(module)
