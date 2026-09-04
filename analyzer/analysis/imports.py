import ast
import logging
from dataclasses import dataclass
from pathlib import Path

from analyzer.analysis.models import AnalysisModule

logger = logging.getLogger(__name__)

INIT_FILE = "__init__.py"


@dataclass(frozen=True)
class ImportBinding:
    """Describes one name introduced into a module by an import."""

    local_name: str
    target: str
    kind: str  # "import" | "from" | "wildcard"
    line: int


class ImportTable:
    """Repository-wide collection of import bindings."""

    def __init__(self) -> None:
        self._bindings: dict[str, list[ImportBinding]] = {}
        self._wildcard_modules: dict[str, list[str]] = {}

    def add(self, module_name: str, binding: ImportBinding) -> None:
        """Add an import binding to a module."""
        self._bindings.setdefault(module_name, []).append(binding)

        if binding.kind == "wildcard":
            self._wildcard_modules.setdefault(module_name, []).append(
                binding.target
            )

    def get(self, module_name: str) -> tuple[ImportBinding, ...]:
        """Return all imports belonging to a module, in source order."""
        return tuple(self._bindings.get(module_name, ()))

    def resolve(self, module_name: str, local_name: str) -> str | None:
        """Resolve a locally imported name to its target.

        If the same local name is imported more than once (e.g. reassigned
        conditionally in a try/except ImportError fallback), the
        lexically-last binding wins, matching normal Python name-binding
        semantics for the common straight-line case. Truly branch-dependent
        bindings can't be resolved with certainty from static analysis
        alone; callers who care can inspect `get()` directly.
        """
        for binding in reversed(self.get(module_name)):
            if binding.local_name == local_name:
                return binding.target

        return None

    def has_wildcard_import(self, module_name: str) -> bool:
        """Return whether a module has any `from x import *` statements.

        Names that can't be resolved via `resolve()` may still be bound
        via one of these — useful for call-graph code to know when
        "unresolved" doesn't mean "undefined".
        """
        return module_name in self._wildcard_modules

    def wildcard_sources(self, module_name: str) -> tuple[str, ...]:
        """Return the modules a given module wildcard-imports from."""
        return tuple(self._wildcard_modules.get(module_name, ()))

    def all_bindings(self) -> tuple[tuple[str, ImportBinding], ...]:
        """Return every (module_name, binding) pair in the repository."""
        return tuple(
            (module_name, binding)
            for module_name, bindings in self._bindings.items()
            for binding in bindings
        )


class ImportIndexer(ast.NodeVisitor):
    """Extract import bindings from one Python module."""

    def __init__(self, analysis_module: AnalysisModule) -> None:
        self.analysis_module = analysis_module
        self.bindings: list[ImportBinding] = []
        self._is_package_init = (
            Path(analysis_module.file_path).name == INIT_FILE
        )

    def index(self) -> list[ImportBinding]:
        """Index imports from the module."""
        self.bindings = []  # reset so index() is safe to call more than once
        self.visit(self.analysis_module.tree)
        return self.bindings

    def visit_Import(self, node: ast.Import) -> None:
        """Index regular `import x` statements."""
        for alias in node.names:
            local_name = alias.asname or alias.name.split(".")[0]

            self.bindings.append(
                ImportBinding(
                    local_name=local_name,
                    target=alias.name,
                    kind="import",
                    line=node.lineno,
                )
            )

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Index `from x import y` statements."""
        module_name = self._resolve_relative_module(node)

        for alias in node.names:
            if alias.name == "*":
                # Wildcard imports cannot be resolved reliably without
                # evaluating the imported module, but we still record
                # that the module happened, so consumers can tell
                # "unresolved name" apart from "possibly star-imported".
                self.bindings.append(
                    ImportBinding(
                        local_name="*",
                        target=module_name,
                        kind="wildcard",
                        line=node.lineno,
                    )
                )
                continue

            local_name = alias.asname or alias.name
            target = (
                f"{module_name}.{alias.name}" if module_name else alias.name
            )

            self.bindings.append(
                ImportBinding(
                    local_name=local_name,
                    target=target,
                    kind="from",
                    line=node.lineno,
                )
            )

    def _resolve_relative_module(self, node: ast.ImportFrom) -> str:
        """Resolve a relative import against the current module's package.

        Follows Python's actual relative-import algorithm, which resolves
        against __package__, not __name__:
          - For a regular module `pkg.sub.mod`, __package__ is `pkg.sub`.
          - For a package's __init__.py, whose module_name already *is*
            `pkg.sub`, __package__ is `pkg.sub` too (itself, not its parent).
        A single level-1 import ('from . import x') therefore lands in
        different places depending on whether the current file is a
        package init or a plain module — this must be accounted for
        explicitly rather than always popping one component.
        """
        module_name = self.analysis_module.module_name

        if node.level == 0:
            return node.module or ""

        parts = module_name.split(".") if module_name else []

        if self._is_package_init:
            # __package__ == module_name itself; level 1 pops nothing.
            pops = node.level - 1
        else:
            # __package__ == module_name minus its last component;
            # level 1 pops exactly that one component.
            pops = node.level

        for _ in range(pops):
            if not parts:
                logger.warning(
                    "Relative import level %d in %s exceeds package depth; "
                    "import cannot be resolved statically",
                    node.level,
                    self.analysis_module.file_path,
                )
                break
            parts.pop()

        if node.module:
            parts.extend(node.module.split("."))

        return ".".join(parts)


def index_module(analysis_module: AnalysisModule) -> list[ImportBinding]:
    """Index imports from one module."""
    return ImportIndexer(analysis_module).index()


def build_import_table(modules: list[AnalysisModule]) -> ImportTable:
    """Build an import table for the entire repository.

    A failure indexing one module's imports is logged and skipped rather
    than aborting the whole build — a partial import table is more useful
    to a call-graph pass than none.
    """
    table = ImportTable()

    for module in modules:
        try:
            bindings = index_module(module)
        except RecursionError as exc:
            logger.error(
                "Skipping imports for %s: %s", module.file_path, exc
            )
            continue

        for binding in bindings:
            table.add(module.module_name, binding)

    return table
