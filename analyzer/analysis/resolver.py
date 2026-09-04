import ast
import logging
from pathlib import Path

from analyzer.analysis.imports import ImportTable
from analyzer.analysis.models import (
    AnalysisModule,
    CallResolution,
    CallSite,
    ResolutionStatus,
)
from analyzer.analysis.symbols import SymbolTable

logger = logging.getLogger(__name__)

_SELF_LIKE = ("self", "cls")


class CallResolver:
    """Resolve Python call expressions using repository symbols and imports."""

    def __init__(
        self,
        symbol_table: SymbolTable,
        import_table: ImportTable,
        modules: dict[str, AnalysisModule],
    ) -> None:
        self.symbol_table = symbol_table
        self.import_table = import_table
        self.modules = modules

        # Resolving a call's file to its module name is on the hot path
        # (once per call site); do it in O(1) instead of scanning every
        # module for every call.
        self._path_to_module: dict[Path, str] = {
            module.file_path: name for name, module in modules.items()
        }

        # Root package of every internal module -- used to tell a
        # genuinely external import ("requests") apart from an internal
        # one that just failed to resolve to a specific symbol.
        self._internal_roots = {name.split(".")[0] for name in modules}

    def resolve(self, call: CallSite) -> CallResolution:
        """Resolve one call site."""
        expression = call.expression.strip()

        if not expression:
            return CallResolution(
                call=call,
                status=ResolutionStatus.UNRESOLVED,
                reason="Empty call expression",
            )

        parts = expression.split(".")

        if not all(part.isidentifier() for part in parts):
            return CallResolution(
                call=call,
                status=ResolutionStatus.UNRESOLVED,
                reason="Call expression is dynamic or contains non-name syntax",
            )

        module_name = self._path_to_module.get(call.file_path)

        if module_name is None:
            return CallResolution(
                call=call,
                status=ResolutionStatus.UNRESOLVED,
                reason=f"No indexed module for {call.file_path}",
            )

        resolved = self._resolve_self_call(call, parts)
        if resolved is None:
            resolved = self._resolve_name(module_name, parts)

        if resolved is not None:
            return CallResolution(
                call=call,
                status=ResolutionStatus.RESOLVED,
                targets=(resolved,),
            )

        if self._looks_like_external_call(module_name, parts):
            return CallResolution(
                call=call,
                status=ResolutionStatus.EXTERNAL,
                reason="Call target belongs to an external import",
            )

        return CallResolution(
            call=call,
            status=ResolutionStatus.UNRESOLVED,
            reason="Could not resolve call against repository symbols",
        )

    def _resolve_self_call(
        self,
        call: CallSite,
        parts: list[str],
    ) -> str | None:
        """Resolve `self.method(...)` / `cls.method(...)` calls.

        The target class is already known from the call site's enclosing
        scope, so this gets dedicated handling instead of falling through
        to generic import/name resolution, which has no notion of "self".
        """
        if len(parts) < 2 or parts[0] not in _SELF_LIKE:
            return None

        enclosing_class = call.enclosing_class
        if not enclosing_class:
            return None

        candidate = ".".join([enclosing_class, *parts[1:]])
        if self.symbol_table.get(candidate):
            return candidate

        # Could be inherited from a base class. Without full MRO
        # resolution we can't trace it further, so this stays
        # unresolved rather than guessing at a base class.
        return None

    def _resolve_name(self, module_name: str, parts: list[str]) -> str | None:
        """Resolve a dotted call expression that is not a self/cls call."""
        if len(parts) == 1:
            return self._resolve_local_name(module_name, parts[0])

        first, rest = parts[0], parts[1:]
        imported = self.import_table.resolve(module_name, first)

        if imported:
            candidate = ".".join([imported, *rest])
            if self.symbol_table.get(candidate):
                return candidate
            # Imported name may itself be the callable, with remaining
            # parts being attribute access on its result -- not
            # statically resolvable further.
            return None

        # No import binding for the first component: it may already be a
        # fully-qualified in-repo path, or a local variable/parameter we
        # can't resolve without type inference.
        candidate = ".".join(parts)
        if self.symbol_table.get(candidate):
            return candidate

        return None

    def _resolve_local_name(self, module_name: str, name: str) -> str | None:
        """Resolve a simple (single-token) name within a module."""
        imported = self.import_table.resolve(module_name, name)
        if imported and self.symbol_table.get(imported):
            return imported

        local = f"{module_name}.{name}"
        if self.symbol_table.get(local):
            return local

        # Last-resort heuristic: a unique repo-wide match by bare name.
        # Skipped when this module has a wildcard import in scope, since
        # the name could plausibly come from there instead and a
        # cross-repo guess would be even less trustworthy.
        if self.import_table.has_wildcard_import(module_name):
            return None

        matches = self.symbol_table.find_by_name(name)
        if len(matches) == 1:
            return matches[0].qualified_name

        return None

    def _looks_like_external_call(
        self,
        module_name: str,
        parts: list[str],
    ) -> bool:
        """Determine whether a call likely belongs to an external dependency.

        Only a multi-part expression whose first component is imported
        from outside the repository counts as external. self/cls calls
        never reach here as external (handled earlier). A single-name
        call is never external -- an unresolved bare name is almost
        always a local variable/parameter, not an external reference.
        """
        if not parts or parts[0] in _SELF_LIKE or len(parts) == 1:
            return False

        imported = self.import_table.resolve(module_name, parts[0])
        if imported is None:
            return False

        root = imported.split(".")[0]
        return root not in self._internal_roots


def collect_call_sites(analysis_module: AnalysisModule) -> list[CallSite]:
    """Collect statically representable call sites from one module.

    Every call is attributed to its enclosing scope: a function/method
    (qualified to match SymbolTable entries), a class body (executed at
    class-definition time), or the module itself (executed at import
    time) -- none are dropped, unlike a scheme that only tracks calls
    made from inside a `def`.
    """

    calls: list[CallSite] = []
    module_name = analysis_module.module_name

    class CallVisitor(ast.NodeVisitor):
        """Collect calls while tracking qualified caller scope."""

        def __init__(self) -> None:
            self._scope: list[str] = []
            self._class_stack: list[str] = []

        def _qualified_scope(self) -> str:
            parts = [module_name, *self._scope]
            return ".".join(part for part in parts if part)

        def _enclosing_class(self) -> str | None:
            if not self._class_stack:
                return None
            return ".".join([module_name, *self._class_stack])

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            self._scope.append(node.name)
            self._class_stack.append(node.name)
            self.generic_visit(node)
            self._class_stack.pop()
            self._scope.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            self._visit_function(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self._visit_function(node)

        def _visit_function(
            self, node: ast.FunctionDef | ast.AsyncFunctionDef
        ) -> None:
            self._scope.append(node.name)
            self.generic_visit(node)
            self._scope.pop()

        def visit_Call(self, node: ast.Call) -> None:
            expression = _call_expression(node)

            if expression is not None:
                calls.append(
                    CallSite(
                        caller=self._qualified_scope(),
                        expression=expression,
                        file_path=analysis_module.file_path,
                        line=node.lineno,
                        column=node.col_offset,
                        enclosing_class=self._enclosing_class(),
                    )
                )

            self.generic_visit(node)

    CallVisitor().visit(analysis_module.tree)
    return calls


def _call_expression(node: ast.Call) -> str | None:
    """Return a dotted name for a statically representable call target."""
    expression = node.func
    parts: list[str] = []

    while isinstance(expression, ast.Attribute):
        parts.append(expression.attr)
        expression = expression.value

    if isinstance(expression, ast.Name):
        parts.append(expression.id)
        parts.reverse()
        return ".".join(parts)

    return None
