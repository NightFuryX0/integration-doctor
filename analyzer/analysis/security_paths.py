"""Security-sensitive path analysis over the repository call graph.

This module answers questions of the form:

    "Can an entry point reach a sensitive operation without
     passing through an approved security guard?"

The analysis deliberately works on the already-built CallGraph rather than
re-parsing source code. That keeps security-flow reasoning separate from
parsing, symbol discovery, import resolution, and call resolution.

Important limitation
--------------------
A call graph represents possible call relationships, not full runtime control
flow. Therefore this module reports *possible* paths. It does not claim that
a path is executed for every request.

Security principle
------------------
For a security requirement to be considered satisfied, every discovered
entry -> sink path must contain an approved guard.

If traversal is truncated because of max_depth or max_paths, the analysis is
marked incomplete. An incomplete analysis must never be interpreted as proof
that the flow is protected.
"""
from __future__ import annotations

from dataclasses import dataclass

from analyzer.analysis.call_graph import CallGraph
from analyzer.analysis.control_flow import (
    ControlFlowGraph,
    ControlFlowKind,
)


# Keep traversal bounded. These are deliberately conservative defaults:
# security analysis should not accidentally consume unbounded memory/time.
_DEFAULT_MAX_DEPTH = 20
_DEFAULT_MAX_PATHS = 10_000


@dataclass(frozen=True, slots=True)
class SecurityPath:
    """One possible path from a security entry point to a sensitive sink."""

    entry_point: str
    sink: str
    nodes: tuple[str, ...]
    guard_nodes: tuple[str, ...]

    @property
    def protected(self) -> bool:
        """Whether this path passes through at least one approved guard."""
        return bool(self.guard_nodes)


@dataclass(frozen=True, slots=True)
class SecurityPathResult:
    """Analysis result for one entry-point -> sink pair."""

    entry_point: str
    sink: str
    paths: tuple[SecurityPath, ...]
    unprotected_paths: tuple[SecurityPath, ...]
    complete: bool

    @property
    def vulnerable(self) -> bool:
        """Whether an unprotected path was found."""
        return bool(self.unprotected_paths)

    @property
    def protected(self) -> bool:
        """Whether all discovered paths are protected.

        An empty path set is not considered protected. There is no evidence
        that the sink is reachable from the entry point in that case.
        """
        return bool(self.paths) and not self.unprotected_paths and self.complete


@dataclass(frozen=True, slots=True)
class SecurityPathReport:
    """Repository-wide security path analysis report."""

    results: tuple[SecurityPathResult, ...]

    @property
    def unprotected_paths(self) -> tuple[SecurityPath, ...]:
        """Return every discovered unprotected path."""
        return tuple(
            path
            for result in self.results
            for path in result.unprotected_paths
        )

    @property
    def vulnerable(self) -> bool:
        """Whether at least one unprotected path was discovered."""
        return bool(self.unprotected_paths)

    @property
    def complete(self) -> bool:
        """Whether every requested entry/sink pair was fully explored."""
        return all(result.complete for result in self.results)

    @property
    def incomplete_results(self) -> tuple[SecurityPathResult, ...]:
        """Return entry/sink analyses that were truncated."""
        return tuple(
            result
            for result in self.results
            if not result.complete
        )


@dataclass(frozen=True, slots=True)
class _TraversalState:
    """One point in the interprocedural control-flow traversal."""

    function: str
    node_id: str
    path: tuple[str, ...]
    guard_nodes: tuple[str, ...]
    depth: int


class SecurityPathAnalyzer:
    """Find security-sensitive paths through a repository call graph.

    The analyzer treats:

    * entry points as externally reachable starting functions,
    * sinks as security-sensitive operations,
    * guards as functions that must appear on the path before the sink.

    Example:

        webhook -> verify_signature -> process_payment

    is protected when ``verify_signature`` is an approved guard.

        webhook -> process_payment

    is unprotected.
    """

    def __init__(
        self,
        graph: CallGraph,
        control_flow: dict[str, ControlFlowGraph],
    ) -> None:
        self.graph = graph
        self.control_flow = control_flow

    def analyze(
        self,
        entry_points: set[str] | frozenset[str],
        sinks: set[str] | frozenset[str],
        guards: set[str] | frozenset[str],
        *,
        max_depth: int = _DEFAULT_MAX_DEPTH,
        max_paths: int = _DEFAULT_MAX_PATHS,
    ) -> SecurityPathReport:
        """Analyze every requested entry-point -> sink combination.

        Args:
            entry_points: Repository symbols where traversal begins.
            sinks: Repository symbols representing sensitive operations.
            guards: Repository symbols that satisfy the security requirement.
            max_depth: Maximum number of graph edges explored per path.
            max_paths: Maximum number of complete paths retained per
                entry/sink pair.

        Returns:
            A report containing discovered paths, bypass paths, and whether
            traversal completed without hitting configured limits.

        Raises:
            ValueError: If a supplied symbol does not exist in the graph or
                traversal limits are invalid.
        """
        self._validate_limits(max_depth, max_paths)

        entry_points = self._normalize_symbols(entry_points, "entry_points")
        sinks = self._normalize_symbols(sinks, "sinks")
        guards = self._normalize_symbols(guards, "guards")

        self._validate_symbols(entry_points, "entry point")
        self._validate_symbols(sinks, "sink")
        self._validate_symbols(guards, "guard")

        results: list[SecurityPathResult] = []

        for entry_point in sorted(entry_points):
            for sink in sorted(sinks):
                results.append(
                    self._analyze_pair(
                        entry_point=entry_point,
                        sink=sink,
                        guards=guards,
                        max_depth=max_depth,
                        max_paths=max_paths,
                    )
                )

        return SecurityPathReport(results=tuple(results))

    def find_unprotected_paths(
        self,
        entry_points: set[str] | frozenset[str],
        sinks: set[str] | frozenset[str],
        guards: set[str] | frozenset[str],
        *,
        max_depth: int = _DEFAULT_MAX_DEPTH,
        max_paths: int = _DEFAULT_MAX_PATHS,
    ) -> tuple[SecurityPath, ...]:
        """Convenience API returning only discovered bypass paths.

        Note that an empty tuple does NOT prove the system is safe if the
        corresponding analysis was incomplete. Use ``analyze()`` when the
        caller needs completeness information.
        """
        report = self.analyze(
            entry_points,
            sinks,
            guards,
            max_depth=max_depth,
            max_paths=max_paths,
        )
        return report.unprotected_paths

    def _analyze_pair(
        self,
        *,
        entry_point: str,
        sink: str,
        guards: frozenset[str],
        max_depth: int,
        max_paths: int,
    ) -> SecurityPathResult:
        """Enumerate security-sensitive paths using control flow."""

        if entry_point == sink:
            path = SecurityPath(
                entry_point=entry_point,
                sink=sink,
                nodes=(entry_point,),
                guard_nodes=(
                    (entry_point,)
                    if entry_point in guards
                    else ()
                ),
            )

            return SecurityPathResult(
                entry_point=entry_point,
                sink=sink,
                paths=(path,),
                unprotected_paths=()
                if path.protected
                else (path,),
                complete=True,
            )

        entry_cfg = self.control_flow.get(entry_point)

        if entry_cfg is None:
            return SecurityPathResult(
                entry_point=entry_point,
                sink=sink,
                paths=(),
                unprotected_paths=(),
                complete=True,
            )

        paths: list[SecurityPath] = []
        unprotected_paths: list[SecurityPath] = []
        complete = True

        # Each state represents one possible execution path through the
        # repository. The return stack remembers where a called function
        # should continue after it finishes.
        stack: list[
            tuple[
                str,
                int,
                tuple[str, ...],
                tuple[str, ...],
                tuple[tuple[str, tuple[int, ...]], ...],
                int,
            ]
        ] = [
            (
                entry_point,
                entry_cfg.entry_node,
                (entry_point,),
                (entry_point,) if entry_point in guards else (),
                (),
                0,
            )
        ]

        visited: set[
            tuple[
                str,
                int,
                tuple[str, ...],
                tuple[str, ...],
                tuple[tuple[str, tuple[int, ...]], ...],
                int,
            ]
        ] = set()

        while stack:
            (
                function,
                node_id,
                path,
                path_guards,
                return_stack,
                depth,
            ) = stack.pop()

            state = (
                function,
                node_id,
                path,
                path_guards,
                return_stack,
                depth,
            )

            if state in visited:
                continue

            visited.add(state)

            cfg = self.control_flow.get(function)

            if cfg is None:
                complete = False
                continue

            node = cfg.get_node(node_id)

            if node is None:
                complete = False
                continue

            # When a function finishes, return to the call site's
            # continuation in its caller.
            if node.node_id == cfg.exit_node:
                if not return_stack:
                    continue

                caller_function, continuation_nodes = return_stack[-1]
                remaining_return_stack = return_stack[:-1]

                for continuation_node in continuation_nodes:
                    stack.append(
                        (
                            caller_function,
                            continuation_node,
                            path,
                            path_guards,
                            remaining_return_stack,
                            depth,
                        )
                    )

                continue

            successors = tuple(
                edge.target
                for edge in cfg.outgoing(node.node_id)
            )

            if node.kind == ControlFlowKind.CALL and node.calls:
                for call in node.calls:
                    if not call.targets:
                        # Unknown/external calls cannot be followed, so
                        # conservatively continue with the local CFG.
                        for successor in successors:
                            stack.append(
                                (
                                    function,
                                    successor,
                                    path,
                                    path_guards,
                                    return_stack,
                                    depth,
                                )
                            )
                        continue

                    for target in call.targets:
                        next_depth = depth + 1

                        if next_depth > max_depth:
                            complete = False
                            continue

                        # Guards belong to this call path.
                        next_path = (
                            path
                            if target in path
                            else (*path, target)
                        )

                        next_guards = path_guards

                        if target in guards and target not in path_guards:
                            next_guards = (*path_guards, target)

                        # A sink is a complete security path, but it does
                        # NOT mean execution analysis should stop. There may
                        # be another sink later in the caller.
                        if target == sink:
                            security_path = SecurityPath(
                                entry_point=entry_point,
                                sink=sink,
                                nodes=next_path,
                                guard_nodes=next_guards,
                            )

                            if len(paths) >= max_paths:
                                complete = False
                            else:
                                paths.append(security_path)

                                if not security_path.protected:
                                    unprotected_paths.append(
                                        security_path
                                    )

                            # The sink ends this security path. We still
                            # continue through the caller so later sibling
                            # calls can produce separate paths.
                            #
                            # Reset the path here so a guard used for one
                            # sink cannot incorrectly protect a later,
                            # independent sink path.
                            reset_path = (entry_point,)
                            reset_guards = (
                                (entry_point,)
                                if entry_point in guards
                                else ()
                            )

                            for successor in successors:
                                stack.append(
                                    (
                                        function,
                                        successor,
                                        reset_path,
                                        reset_guards,
                                        return_stack,
                                        depth,
                                    )
                                )

                            continue

                        # Recursive call: don't descend into a function
                        # already present on this path. We still continue
                        # execution after the call.
                        if target in path:
                            for successor in successors:
                                stack.append(
                                    (
                                        function,
                                        successor,
                                        next_path,
                                        next_guards,
                                        return_stack,
                                        depth,
                                    )
                                )
                            continue

                        target_cfg = self.control_flow.get(target)

                        if target_cfg is None:
                            complete = False

                            for successor in successors:
                                stack.append(
                                    (
                                        function,
                                        successor,
                                        next_path,
                                        next_guards,
                                        return_stack,
                                        next_depth,
                                    )
                                )

                            continue

                        next_return_stack = (
                            *return_stack,
                            (function, successors),
                        )

                        stack.append(
                            (
                                target,
                                target_cfg.entry_node,
                                next_path,
                                next_guards,
                                next_return_stack,
                                next_depth,
                            )
                        )

                continue

            # Non-call nodes simply follow their CFG edges.
            for successor in successors:
                stack.append(
                    (
                        function,
                        successor,
                        path,
                        path_guards,
                        return_stack,
                        depth,
                    )
                )

        return SecurityPathResult(
            entry_point=entry_point,
            sink=sink,
            paths=tuple(paths),
            unprotected_paths=tuple(unprotected_paths),
            complete=complete,
        )

    def _validate_symbols(
        self,
        symbols: frozenset[str],
        label: str,
    ) -> None:
        """Reject configuration typos instead of silently ignoring them."""
        unknown = sorted(
            symbol
            for symbol in symbols
            if not self.graph.has_node(symbol)
        )

        if unknown:
            formatted = ", ".join(repr(symbol) for symbol in unknown)
            raise ValueError(
                f"Unknown {label} symbol(s): {formatted}"
            )

    @staticmethod
    def _normalize_symbols(
        symbols: set[str] | frozenset[str],
        label: str,
    ) -> frozenset[str]:
        """Normalize and validate a symbol collection."""

        if not isinstance(symbols, (set, frozenset)):
            raise TypeError(
                f"{label} must be a set or frozenset"
            )

        normalized: set[str] = set()

        for symbol in symbols:
            if not isinstance(symbol, str):
                raise TypeError(
                    f"{label} must contain only strings; "
                    f"got {type(symbol).__name__}"
                )

            value = symbol.strip()

            if not value:
                raise ValueError(
                    f"{label} cannot contain an empty symbol"
                )

            if not all(part.isidentifier() for part in value.split(".")):
                raise ValueError(
                    f"Invalid qualified symbol in {label}: {symbol!r}"
                )

            normalized.add(value)

        return frozenset(normalized)

    @staticmethod
    def _validate_limits(
        max_depth: int,
        max_paths: int,
    ) -> None:
        """Reject dangerous or nonsensical traversal configuration."""

        if isinstance(max_depth, bool) or not isinstance(max_depth, int):
            raise TypeError("max_depth must be an integer")

        if isinstance(max_paths, bool) or not isinstance(max_paths, int):
            raise TypeError("max_paths must be an integer")

        if max_depth < 0:
            raise ValueError("max_depth must be >= 0")

        if max_paths <= 0:
            raise ValueError("max_paths must be > 0")


def analyze_security_paths(
    graph: CallGraph,
    control_flow: dict[str, ControlFlowGraph],
    entry_points: set[str] | frozenset[str],
    sinks: set[str] | frozenset[str],
    guards: set[str] | frozenset[str],
    *,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_paths: int = _DEFAULT_MAX_PATHS,
) -> SecurityPathReport:
    """Convenience wrapper around :class:`SecurityPathAnalyzer`."""
    return SecurityPathAnalyzer(
        graph,
        control_flow,
    ).analyze(
        entry_points,
        sinks,
        guards,
        max_depth=max_depth,
        max_paths=max_paths,
    )
