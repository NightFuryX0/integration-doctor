import ast
import logging

from analyzer.analysis.models import AnalysisModule, Symbol, SymbolKind

logger = logging.getLogger(__name__)


class SymbolTable:
    """Repository-wide index of discovered Python symbols."""

    def __init__(self) -> None:
        self._symbols: dict[str, Symbol] = {}
        self._by_name: dict[str, list[Symbol]] = {}

    def add(self, symbol: Symbol) -> None:
        """Add one symbol to the table.

        Symbols are keyed by qualified name. If the same qualified name is
        encountered again, the newer definition replaces the old one and the
        secondary name index is kept in sync.
        """

        existing = self._symbols.get(symbol.qualified_name)

        if existing is not None:
            if existing == symbol:
                return  # Avoid inserting the exact same symbol twice.

            logger.warning(
                "Duplicate symbol %r: replacing definition at %s:%d "
                "with %s:%d",
                symbol.qualified_name,
                existing.file_path,
                existing.line,
                symbol.file_path,
                symbol.line,
            )

            existing_symbols = self._by_name.get(existing.name, [])

            if existing in existing_symbols:
                existing_symbols.remove(existing)

        self._symbols[symbol.qualified_name] = symbol
        self._by_name.setdefault(symbol.name, []).append(symbol)

    def get(self, qualified_name: str) -> Symbol | None:
        """Return a symbol by its fully-qualified name."""
        return self._symbols.get(qualified_name)

    def all_symbols(self) -> tuple[Symbol, ...]:
        """Return all discovered symbols."""
        return tuple(self._symbols.values())

    def find_by_name(self, name: str) -> tuple[Symbol, ...]:
        """Find symbols matching a local name using the secondary index."""
        return tuple(self._by_name.get(name, ()))


class SymbolIndexer(ast.NodeVisitor):
    """Extract symbols from one parsed Python module."""

    def __init__(self, analysis_module: AnalysisModule) -> None:
        self.analysis_module = analysis_module
        self.symbols: list[Symbol] = []

        # Names of currently enclosing definitions.
        self._scope: list[str] = []

        # Tracks the kind of every enclosing definition.
        #
        # Example:
        #   module -> class -> method -> nested function
        #
        # becomes:
        #   ["class", "function", "function"]
        #
        # Looking at the nearest enclosing definition lets us correctly
        # distinguish a method from a function nested inside a method.
        self._scope_kinds: list[str] = []

    def index(self) -> list[Symbol]:
        """Index all symbols in the module."""

        # Reset state so the same indexer can safely be reused.
        self.symbols = []
        self._scope = []
        self._scope_kinds = []

        tree = self.analysis_module.tree

        if not isinstance(tree, ast.Module):
            raise TypeError(
                f"Expected ast.Module for {self.analysis_module.file_path}, "
                f"got {type(tree).__name__}"
            )

        # Every module is itself represented as a graph node.
        self.symbols.append(
            Symbol(
                qualified_name=self.analysis_module.module_name,
                name=self.analysis_module.module_name.rsplit(".", 1)[-1],
                kind=SymbolKind.MODULE,
                file_path=self.analysis_module.file_path,
                line=1,
                parent=None,
            )
        )

        try:
            self.visit(tree)
        except RecursionError as exc:
            raise RecursionError(
                f"AST for {self.analysis_module.file_path} is too deeply "
                "nested to index"
            ) from exc

        return self.symbols

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Record a class and recursively index its contents."""

        qualified_name = self._qualified_name(node.name)

        self.symbols.append(
            Symbol(
                qualified_name=qualified_name,
                name=node.name,
                kind=SymbolKind.CLASS,
                file_path=self.analysis_module.file_path,
                line=node.lineno,
                parent=self._current_scope(),
            )
        )

        self._scope.append(node.name)
        self._scope_kinds.append("class")

        # generic_visit handles classes/functions nested inside control-flow
        # blocks as well as normal class members.
        self.generic_visit(node)

        self._scope_kinds.pop()
        self._scope.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Record a normal function or method."""
        self._index_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Record an async function or method.

        Async is a property of the Python function syntax, not a separate
        SymbolKind. An async class member is still a method.
        """
        self._index_function(node)

    def _index_function(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        """Create a function/method symbol and recurse into its body."""

        kind = self._function_kind(node)
        qualified_name = self._qualified_name(node.name)

        self.symbols.append(
            Symbol(
                qualified_name=qualified_name,
                name=node.name,
                kind=kind,
                file_path=self.analysis_module.file_path,
                line=node.lineno,
                parent=self._current_scope(),
            )
        )

        self._scope.append(node.name)
        self._scope_kinds.append("function")

        # This deliberately uses generic_visit rather than manually walking
        # only definitions, so nested classes/functions inside if/try/with/
        # for blocks are discovered too.
        self.generic_visit(node)

        self._scope_kinds.pop()
        self._scope.pop()

    def _function_kind(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> SymbolKind:
        """Determine the semantic SymbolKind for a function definition."""

        # A function whose nearest enclosing definition is a class is a
        # method. This avoids misclassifying a function nested inside a
        # method as a method.
        if self._nearest_definition_kind() != "class":
            return SymbolKind.FUNCTION

        if self._has_decorator(node, "staticmethod"):
            return SymbolKind.STATICMETHOD

        if self._has_decorator(node, "classmethod"):
            return SymbolKind.CLASSMETHOD

        return SymbolKind.METHOD

    def _nearest_definition_kind(self) -> str | None:
        """Return the kind of the nearest enclosing definition."""

        if not self._scope_kinds:
            return None

        return self._scope_kinds[-1]

    @staticmethod
    def _has_decorator(
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        decorator_name: str,
    ) -> bool:
        """Return whether a function has a named decorator."""

        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id == decorator_name:
                    return True

            elif isinstance(decorator, ast.Attribute):
                if decorator.attr == decorator_name:
                    return True

            # Handle calls such as @decorator(...).
            elif isinstance(decorator, ast.Call):
                target = decorator.func

                if isinstance(target, ast.Name):
                    if target.id == decorator_name:
                        return True

                elif isinstance(target, ast.Attribute):
                    if target.attr == decorator_name:
                        return True

        return False

    def _qualified_name(self, name: str) -> str:
        """Build a module-qualified symbol name."""

        parts = [
            self.analysis_module.module_name,
            *self._scope,
            name,
        ]

        return ".".join(part for part in parts if part)

    def _current_scope(self) -> str:
        """Return the fully-qualified containing symbol."""

        if not self._scope:
            return self.analysis_module.module_name

        return ".".join(
            [
                self.analysis_module.module_name,
                *self._scope,
            ]
        )


def index_module(analysis_module: AnalysisModule) -> list[Symbol]:
    """Index symbols from one parsed Python module."""
    return SymbolIndexer(analysis_module).index()


def build_symbol_table(
    modules: list[AnalysisModule],
) -> SymbolTable:
    """Build one symbol table for an entire repository.

    A failure indexing one module is logged and skipped so the repository
    can still produce a partial call graph.
    """

    table = SymbolTable()

    for module in modules:
        try:
            symbols = index_module(module)
        except (TypeError, RecursionError) as exc:
            logger.error(
                "Skipping %s: failed to index symbols (%s)",
                module.file_path,
                exc,
            )
            continue

        for symbol in symbols:
            table.add(symbol)

    return table
