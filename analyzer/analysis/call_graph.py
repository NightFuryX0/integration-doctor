from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from analyzer.analysis.models import (
    AnalysisModule,
    CallGraphEdge,
    CallGraphNode,
    CallResolution,
    ResolutionStatus,
    Symbol,
)
from analyzer.analysis.resolver import (
    CallResolver,
    collect_call_sites,
)
from analyzer.analysis.symbols import SymbolTable


# Prevent an accidentally huge traversal from consuming unbounded memory.
_DEFAULT_MAX_PATHS = 10_000
_DEFAULT_MAX_DEPTH = 20


@dataclass(frozen=True, slots=True)
class GraphStats:
    """Basic structural statistics for a call graph."""

    node_count: int
    edge_count: int
    root_count: int
    leaf_count: int
    recursive_edge_count: int


class CallGraph:
    """Directed graph representing calls between repository symbols.

    Nodes represent discovered repository symbols.

    Edges represent calls that the resolver confidently resolved to another
    repository symbol.

    External and unresolved calls deliberately do not become graph edges.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, CallGraphNode] = {}

        # caller -> outgoing edges
        self._outgoing: dict[str, list[CallGraphEdge]] = defaultdict(list)

        # callee -> incoming edges
        self._incoming: dict[str, list[CallGraphEdge]] = defaultdict(list)

        # Fast duplicate detection. The source location is part of the key
        # because one caller can legitimately call the same callee multiple
        # times at different source locations.
        self._edge_keys: set[tuple[str, str, int, int]] = set()

    def add_node(self, symbol: Symbol) -> None:
        """Add or replace a graph node.

        Qualified names are the graph identity. Re-adding the exact same
        symbol is harmless. Replacing a symbol with a different definition
        keeps the graph indexes consistent by rebuilding affected edges.
        """

        qualified_name = symbol.qualified_name
        existing = self._nodes.get(qualified_name)

        if existing is not None:
            if existing.symbol == symbol:
                return

            self._remove_node(qualified_name)

        self._nodes[qualified_name] = CallGraphNode(
            qualified_name=qualified_name,
            symbol=symbol,
        )

    def _remove_node(self, qualified_name: str) -> None:
        """Remove a node and every edge connected to it."""

        for edge in tuple(self._outgoing.get(qualified_name, ())):
            self._remove_edge(edge)

        for edge in tuple(self._incoming.get(qualified_name, ())):
            self._remove_edge(edge)

        self._outgoing.pop(qualified_name, None)
        self._incoming.pop(qualified_name, None)
        self._nodes.pop(qualified_name, None)

    def _remove_edge(self, edge: CallGraphEdge) -> None:
        """Remove one edge from both graph indexes."""

        key = self._edge_key(edge)

        self._edge_keys.discard(key)

        outgoing = self._outgoing.get(edge.caller)
        if outgoing is not None:
            try:
                outgoing.remove(edge)
            except ValueError:
                pass

            if not outgoing:
                self._outgoing.pop(edge.caller, None)

        incoming = self._incoming.get(edge.callee)
        if incoming is not None:
            try:
                incoming.remove(edge)
            except ValueError:
                pass

            if not incoming:
                self._incoming.pop(edge.callee, None)

    @staticmethod
    def _edge_key(
        edge: CallGraphEdge,
    ) -> tuple[str, str, int, int]:
        """Return the unique identity of a source-level graph edge."""

        return (
            edge.caller,
            edge.callee,
            edge.call_site.line,
            edge.call_site.column,
        )

    def add_edge(self, edge: CallGraphEdge) -> bool:
        """Add an edge and return whether it was newly inserted.

        Both endpoints must already exist. This invariant prevents accidental
        creation of phantom nodes from unresolved/external calls.
        """

        if not self.has_node(edge.caller):
            raise ValueError(
                f"Cannot add edge with unknown caller: {edge.caller!r}"
            )

        if not self.has_node(edge.callee):
            raise ValueError(
                f"Cannot add edge with unknown callee: {edge.callee!r}"
            )

        key = self._edge_key(edge)

        if key in self._edge_keys:
            return False

        self._edge_keys.add(key)
        self._outgoing[edge.caller].append(edge)
        self._incoming[edge.callee].append(edge)

        return True

    def get_node(self, qualified_name: str) -> CallGraphNode | None:
        """Return a graph node by qualified name."""
        return self._nodes.get(qualified_name)

    def has_node(self, qualified_name: str) -> bool:
        """Return whether a node exists."""
        return qualified_name in self._nodes

    def nodes(self) -> tuple[CallGraphNode, ...]:
        """Return all graph nodes in insertion order."""
        return tuple(self._nodes.values())

    def edges(self) -> tuple[CallGraphEdge, ...]:
        """Return all graph edges in deterministic insertion order."""

        result: list[CallGraphEdge] = []

        for edges in self._outgoing.values():
            result.extend(edges)

        return tuple(result)

    def callees(self, caller: str) -> tuple[str, ...]:
        """Return direct callees of a caller."""

        return tuple(
            edge.callee
            for edge in self._outgoing.get(caller, ())
        )

    def callers(self, callee: str) -> tuple[str, ...]:
        """Return direct callers of a callee."""

        return tuple(
            edge.caller
            for edge in self._incoming.get(callee, ())
        )

    def edges_from(self, caller: str) -> tuple[CallGraphEdge, ...]:
        """Return outgoing edges from a caller."""
        return tuple(self._outgoing.get(caller, ()))

    def edges_to(self, callee: str) -> tuple[CallGraphEdge, ...]:
        """Return incoming edges to a callee."""
        return tuple(self._incoming.get(callee, ()))

    def has_edge(
        self,
        caller: str,
        callee: str,
        line: int | None = None,
        column: int | None = None,
    ) -> bool:
        """Check whether a caller -> callee edge exists.

        Supplying line/column narrows the lookup to a specific call site.
        """

        for edge in self._outgoing.get(caller, ()):
            if edge.callee != callee:
                continue

            if line is not None and edge.call_site.line != line:
                continue

            if column is not None and edge.call_site.column != column:
                continue

            return True

        return False

    def roots(self) -> tuple[str, ...]:
        """Return nodes with no incoming calls."""

        return tuple(
            name
            for name in self._nodes
            if not self._incoming.get(name)
        )

    def leaves(self) -> tuple[str, ...]:
        """Return nodes that call nothing."""

        return tuple(
            name
            for name in self._nodes
            if not self._outgoing.get(name)
        )

    def recursive_edges(self) -> tuple[CallGraphEdge, ...]:
        """Return direct recursive edges such as foo -> foo."""

        return tuple(
            edge
            for edge in self.edges()
            if edge.caller == edge.callee
        )

    def stats(self) -> GraphStats:
        """Return basic graph statistics."""

        return GraphStats(
            node_count=len(self._nodes),
            edge_count=len(self._edge_keys),
            root_count=len(self.roots()),
            leaf_count=len(self.leaves()),
            recursive_edge_count=len(self.recursive_edges()),
        )

    def find_paths(
        self,
        source: str,
        sink: str,
        max_depth: int = _DEFAULT_MAX_DEPTH,
        max_paths: int = _DEFAULT_MAX_PATHS,
    ) -> tuple[tuple[str, ...], ...]:
        """Find bounded directed paths from source to sink.

        This is deliberately a simple DFS rather than an unrestricted graph
        traversal. Security analysis must remain safe on recursive or highly
        connected repositories.

        `max_depth` is the maximum number of edges in a path.

        `max_paths` prevents path explosion from consuming unbounded memory.

        Nodes already present in the current path are not revisited, so
        cycles cannot cause infinite recursion.
        """

        if max_depth < 0:
            raise ValueError("max_depth must be >= 0")

        if max_paths < 1:
            raise ValueError("max_paths must be >= 1")

        if not self.has_node(source):
            return ()

        if not self.has_node(sink):
            return ()

        if source == sink:
            return ((source,),)

        paths: list[tuple[str, ...]] = []

        def visit(
            current: str,
            path: tuple[str, ...],
        ) -> None:
            if len(paths) >= max_paths:
                return

            depth = len(path) - 1

            if depth >= max_depth:
                return

            for edge in self._outgoing.get(current, ()):
                if len(paths) >= max_paths:
                    return

                target = edge.callee

                # Prevent cycles such as:
                # A -> B -> A -> B -> ...
                if target in path:
                    continue

                next_path = (*path, target)

                if target == sink:
                    paths.append(next_path)
                    continue

                visit(target, next_path)

        visit(source, (source,))

        return tuple(paths)


class CallGraphBuilder:
    """Build a repository call graph from analysis results."""

    def __init__(
        self,
        symbol_table: SymbolTable,
        resolver: CallResolver,
    ) -> None:
        self.symbol_table = symbol_table
        self.resolver = resolver

    def build(
        self,
        modules: list[AnalysisModule],
    ) -> CallGraph:
        """Build a graph containing all known repository symbols."""

        graph = CallGraph()

        # Add every symbol first. This ensures isolated functions/classes
        # remain visible and lets edge insertion enforce endpoint integrity.
        for symbol in self.symbol_table.all_symbols():
            graph.add_node(symbol)

        for module in modules:
            self._process_module(graph, module)

        return graph

    def _process_module(
        self,
        graph: CallGraph,
        module: AnalysisModule,
    ) -> None:
        """Process every call site in one module."""

        try:
            # Collector is a module-level function.
            call_sites = collect_call_sites(module)
        except (TypeError, ValueError, RecursionError):
            # A malformed AST/resolver result should not destroy an otherwise
            # useful repository-wide graph.
            return

        for call_site in call_sites:
            try:
                resolution = self.resolver.resolve(
                    call_site,
                )  # CallResolver.resolve() accepts the CallSite only.
            except (TypeError, ValueError, RecursionError):
                # Treat a failed resolution as unknown rather than inventing an edge.
                continue

            self._add_resolution(graph, resolution)

    def _add_resolution(
        self,
        graph: CallGraph,
        resolution: CallResolution,
    ) -> None:
        """Convert a resolved call into one or more graph edges."""

        if resolution.status != ResolutionStatus.RESOLVED:
            return

        caller = resolution.call.caller

        if not graph.has_node(caller):
            return

        for target in resolution.targets:
            # Only repository symbols are allowed to become graph targets.
            if not graph.has_node(target):
                continue

            try:
                graph.add_edge(
                    CallGraphEdge(
                        caller=caller,
                        callee=target,
                        call_site=resolution.call,
                    )
                )
            except ValueError:
                # Defensive boundary: a bad upstream resolution should not
                # corrupt or abort construction of the remaining graph.
                continue


def build_call_graph(
    modules: list[AnalysisModule],
    symbol_table: SymbolTable,
    resolver: CallResolver,
) -> CallGraph:
    """Build a repository call graph."""

    return CallGraphBuilder(
        symbol_table=symbol_table,
        resolver=resolver,
    ).build(modules)
