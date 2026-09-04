"""Core data model for call-graph construction.

Design notes:
- All record types are frozen + slotted: hashable, immutable, low memory
  overhead when a large repo produces tens of thousands of symbols/call
  sites.
- __post_init__ validation exists because this model ingests data derived
  from arbitrary (and potentially adversarial) source repositories, not
  just trusted internal callers. A malformed or maliciously crafted file
  should fail fast with a clear error, not silently produce a corrupt
  call graph or blow up memory downstream.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType

# Defensive bound: nothing in real Python source produces identifiers or
# call expressions anywhere near this long. A huge value here is either a
# bug upstream or crafted adversarial input; cap it so one file can't
# balloon memory or downstream string operations (repr, hashing, AI
# context serialization, etc.).
_MAX_IDENTIFIER_LENGTH = 4096


class ResolutionStatus(str, Enum):
    """Describes how confidently a call was resolved."""

    RESOLVED = "resolved"
    AMBIGUOUS = "ambiguous"
    EXTERNAL = "external"
    UNRESOLVED = "unresolved"


class SymbolKind(str, Enum):
    """What kind of callable/definition a Symbol represents.

    An Enum instead of a raw str closes off an entire class of bugs:
    typos like "Function" vs "function" silently producing an
    unresolvable symbol kind, with no error until something downstream
    fails to match on it.
    """

    MODULE = "module"
    CLASS = "class"
    FUNCTION = "function"
    METHOD = "method"
    STATICMETHOD = "staticmethod"
    CLASSMETHOD = "classmethod"


def _validate_identifier(value: str, field_name: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    if len(value) > _MAX_IDENTIFIER_LENGTH:
        raise ValueError(
            f"{field_name} exceeds max length "
            f"({len(value)} > {_MAX_IDENTIFIER_LENGTH}); refusing to "
            f"process, likely malformed or adversarial input"
        )


def _validate_position(line: int, column: int | None = None) -> None:
    if line < 1:
        raise ValueError(f"line must be >= 1, got {line}")
    if column is not None and column < 0:
        raise ValueError(f"column must be >= 0, got {column}")


def _normalize_path(file_path: Path) -> Path:
    """Resolve to an absolute, symlink-free path.

    This model is used by a security scanner that may walk untrusted
    repositories. Resolving symlinks here, once, at construction time,
    means every downstream consumer (AI context builder, SARIF writer,
    report renderer) works with a canonical path rather than each having
    to re-derive one -- and it prevents a crafted symlink inside a
    scanned repo from causing a file to be read from, or a finding to be
    reported against, a location outside the intended scan root.
    strict=False so we don't hard-fail on paths that don't exist on disk
    at construction time (e.g. paths built in tests).
    """
    return file_path.resolve(strict=False)


@dataclass(frozen=True, slots=True)
class Symbol:
    """A Python symbol discovered during repository analysis."""

    qualified_name: str
    name: str
    kind: SymbolKind
    file_path: Path
    line: int
    parent: str | None = None

    def __post_init__(self) -> None:
        _validate_identifier(self.qualified_name, "qualified_name")
        _validate_identifier(self.name, "name")
        _validate_position(self.line)
        # frozen=True blocks normal attribute assignment, including from
        # our own __post_init__ -- object.__setattr__ is the documented
        # escape hatch for validating/normalizing fields at construction.
        object.__setattr__(self, "file_path", _normalize_path(self.file_path))

    @property
    def module_name(self) -> str:
        """Return the module portion of the qualified name.

        Returns "" for a top-level symbol with no enclosing module,
        rather than (incorrectly) returning the symbol's own full
        qualified name.
        """
        if "." not in self.qualified_name:
            return ""
        return self.qualified_name.rsplit(".", 1)[0]


@dataclass(frozen=True, slots=True)
class CallSite:
    """A function or method call found in source code."""

    caller: str
    expression: str
    file_path: Path
    line: int
    column: int
    # Needed to resolve self/cls method calls.
    enclosing_class: str | None = None

    def __post_init__(self) -> None:
        _validate_identifier(self.caller, "caller")
        _validate_identifier(self.expression, "expression")
        _validate_position(self.line, self.column)

        if self.enclosing_class is not None:  # Validate optional class context.
            _validate_identifier(self.enclosing_class, "enclosing_class")

        object.__setattr__(
            self,
            "file_path",
            _normalize_path(self.file_path),
        )


@dataclass(frozen=True, slots=True)
class CallResolution:
    """Result of attempting to resolve a call site."""

    call: CallSite
    status: ResolutionStatus
    targets: tuple[str, ...] = ()
    reason: str | None = None

    def __post_init__(self) -> None:
        # Enforce the invariant the Enum values imply. Without this,
        # a resolver bug could silently produce e.g. RESOLVED with zero
        # targets, and every downstream consumer would need its own
        # defensive check instead of being able to trust the type.
        if self.status == ResolutionStatus.RESOLVED and not self.targets:
            raise ValueError(
                "RESOLVED resolution must include at least one target")
        if self.status == ResolutionStatus.AMBIGUOUS and len(self.targets) < 2:
            raise ValueError(
                "AMBIGUOUS resolution requires 2+ candidate targets")
        if self.status in (ResolutionStatus.UNRESOLVED, ResolutionStatus.EXTERNAL) and self.targets:
            raise ValueError(
                f"{self.status.value} resolution should not carry targets")


@dataclass(frozen=True, slots=True)
class CallGraphNode:
    """A node representing a callable symbol in the call graph."""

    qualified_name: str
    symbol: Symbol

    def __post_init__(self) -> None:
        _validate_identifier(self.qualified_name, "qualified_name")
        if self.qualified_name != self.symbol.qualified_name:
            raise ValueError(
                "CallGraphNode.qualified_name must match symbol.qualified_name "
                f"({self.qualified_name!r} != {self.symbol.qualified_name!r})"
            )


@dataclass(frozen=True, slots=True)
class CallGraphEdge:
    """A directed caller -> callee relationship."""

    caller: str
    callee: str
    call_site: CallSite

    def __post_init__(self) -> None:
        _validate_identifier(self.caller, "caller")
        _validate_identifier(self.callee, "callee")


@dataclass(slots=True)
class AnalysisModule:
    """Parsed representation of one Python source file.

    Not frozen: the AST tree and import map are naturally populated
    incrementally during parsing. imports is exposed as a read-only
    MappingProxyType view so external code can't mutate a module's
    import table after the fact and silently desync it from the
    tree it was derived from.
    """

    file_path: Path
    module_name: str
    tree: ast.Module
    imports: MappingProxyType[str, str] = field(
        default_factory=lambda: MappingProxyType({})
    )

    def __post_init__(self) -> None:
        _validate_identifier(self.module_name, "module_name")
        if not isinstance(self.tree, ast.Module):
            raise TypeError(
                f"tree must be an ast.Module, got {type(self.tree).__name__}"
            )
        self.file_path = _normalize_path(self.file_path)
        if not isinstance(self.imports, MappingProxyType):
            self.imports = MappingProxyType(dict(self.imports))
