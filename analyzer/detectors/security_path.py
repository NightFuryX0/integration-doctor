"""Repository-level detector for unprotected security-sensitive paths.

SECURITY-001 reports possible paths from security-sensitive entry points to
payment-sensitive operations when those paths do not pass through an
approved security guard.

This detector consumes the shared RepositoryAnalysis produced by the
repository analysis layer. It does not parse files or rebuild the call graph.

The rule configuration is separated from the detection machinery so future
security-path rules can reuse the same implementation without duplicating
the traversal and finding-generation logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from analyzer.analysis.repository import RepositoryAnalysis
from analyzer.analysis.security_paths import (
    SecurityPath,
    SecurityPathAnalyzer,
)


# ---------------------------------------------------------------------------
# Rule configuration
# ---------------------------------------------------------------------------

RULE_UNPROTECTED_PATH = "SECURITY-001"
FINDING_TYPE = "UNPROTECTED_PAYMENT_PATH"
SEVERITY_CRITICAL = "CRITICAL"

_DEFAULT_MAX_DEPTH = 20
_DEFAULT_MAX_PATHS = 10_000


@dataclass(frozen=True, slots=True)
class SecurityPathRule:
    """Configuration for one security-sensitive path rule.

    A rule defines:

    * entry-point name patterns,
    * approved security guards,
    * sensitive sink names,
    * finding metadata.

    Keeping these values together means the detection engine does not need
    to change when additional security-sensitive operations are introduced.
    """

    rule_id: str
    finding_type: str
    severity: str
    entry_name_patterns: tuple[str, ...]
    guard_names: frozenset[str]
    sink_names: frozenset[str]
    description: str

    def __post_init__(self) -> None:
        """Validate rule configuration when the rule is created."""

        if not isinstance(self.rule_id, str) or not self.rule_id.strip():
            raise ValueError("rule_id must be a non-empty string")

        if not isinstance(self.finding_type, str) or not self.finding_type.strip():
            raise ValueError(
                "finding_type must be a non-empty string"
            )

        if not isinstance(self.severity, str) or not self.severity.strip():
            raise ValueError(
                "severity must be a non-empty string"
            )

        if not self.entry_name_patterns:
            raise ValueError(
                "entry_name_patterns cannot be empty"
            )

        if not self.sink_names:
            raise ValueError(
                "sink_names cannot be empty"
            )

        if not isinstance(self.guard_names, frozenset):
            raise TypeError(
                "guard_names must be a frozenset"
            )

        if not isinstance(self.sink_names, frozenset):
            raise TypeError(
                "sink_names must be a frozenset"
            )

        for pattern in self.entry_name_patterns:
            if not isinstance(pattern, str) or not pattern.strip():
                raise ValueError(
                    "entry_name_patterns must contain "
                    "non-empty strings"
                )

        for name in self.guard_names:
            if not isinstance(name, str) or not name.strip():
                raise ValueError(
                    "guard_names must contain non-empty strings"
                )

        for name in self.sink_names:
            if not isinstance(name, str) or not name.strip():
                raise ValueError(
                    "sink_names must contain non-empty strings"
                )

        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError(
                "description must be a non-empty string"
            )


# Default SECURITY-001 configuration.

SECURITY_RULE = SecurityPathRule(
    rule_id=RULE_UNPROTECTED_PATH,
    finding_type=FINDING_TYPE,
    severity=SEVERITY_CRITICAL,
    entry_name_patterns=(
        "webhook",
    ),
    guard_names=frozenset(
        {
            "verify_signature",
            "verify_webhook",
            "verify_payload",
            "validate_webhook",
            "verify_header",
            "validate_signature",
            "check_signature",
        }
    ),
    sink_names=frozenset(
        {
            "charge",
            "create_charge",
            "capture_payment",
            "create_payment",
        }
    ),
    description=(
        "Webhook endpoint can reach a payment-sensitive operation "
        "without passing through an approved security guard."
    ),
)


# ---------------------------------------------------------------------------
# Public detector API
# ---------------------------------------------------------------------------


def analyze_repository(
    analysis: RepositoryAnalysis,
    *,
    rule: SecurityPathRule = SECURITY_RULE,
    max_depth: int = _DEFAULT_MAX_DEPTH,
    max_paths: int = _DEFAULT_MAX_PATHS,
) -> list[dict]:
    """Analyze one repository for unprotected security-sensitive paths.

    The expensive repository-wide structures are supplied by
    ``RepositoryAnalysis`` and therefore are not rebuilt here.

    Args:
        analysis: Shared repository analysis context.
        rule: Security-path rule configuration.
        max_depth: Maximum interprocedural traversal depth.
        max_paths: Maximum paths retained for each entry/sink pair.

    Returns:
        Scanner-compatible finding dictionaries.

    Raises:
        TypeError: If ``analysis`` or ``rule`` has the wrong type.
        ValueError: If traversal limits are invalid.
    """

    if not isinstance(analysis, RepositoryAnalysis):
        raise TypeError(
            "analysis must be a RepositoryAnalysis instance"
        )

    if not isinstance(rule, SecurityPathRule):
        raise TypeError(
            "rule must be a SecurityPathRule"
        )

    _validate_limits(max_depth, max_paths)

    entry_points = _find_entry_points(
        analysis,
        rule,
    )
    guards = _find_guards(
        analysis,
        rule,
    )
    sinks = _find_sinks(
        analysis,
        rule,
    )

    # No complete flow exists when one side of the relationship is absent.
    # In particular, do not produce findings merely because a guard or sink
    # exists somewhere in the repository.
    if not entry_points or not sinks:
        return []

    analyzer = SecurityPathAnalyzer(
        analysis.call_graph,
        analysis.control_flow,
    )

    report = analyzer.analyze(
        entry_points,
        sinks,
        guards,
        max_depth=max_depth,
        max_paths=max_paths,
    )

    return [
        _finding_for_path(
            analysis,
            path,
            rule,
        )
        for path in report.unprotected_paths
    ]


# ---------------------------------------------------------------------------
# Symbol discovery
# ---------------------------------------------------------------------------


def _iter_function_symbols(
    analysis: RepositoryAnalysis,
) -> Iterable[str]:
    """Yield qualified names of callable symbols in the call graph.

    The call graph contains CallGraphNode objects rather than raw strings.
    This helper keeps that implementation detail isolated from the rest of
    the detector.

    Keeping symbol iteration in one place also makes future filtering easier
    if we later need to distinguish functions, methods, or other callables.
    """

    for node in analysis.call_graph.nodes():
        if node.symbol.kind.value in {
            "function",
            "method",
            "staticmethod",
            "classmethod",
        }:
            yield node.qualified_name


def _find_entry_points(
    analysis: RepositoryAnalysis,
    rule: SecurityPathRule,
) -> set[str]:
    """Find callable symbols matching configured entry-point patterns."""

    return {
        symbol_name
        for symbol_name in _iter_function_symbols(analysis)
        if _matches_any_pattern(
            _short_name(symbol_name),
            rule.entry_name_patterns,
        )
    }


def _find_guards(
    analysis: RepositoryAnalysis,
    rule: SecurityPathRule,
) -> set[str]:
    """Find callable symbols recognized as approved security guards."""

    return {
        symbol_name
        for symbol_name in _iter_function_symbols(analysis)
        if _short_name(symbol_name).lower() in rule.guard_names
    }


def _find_sinks(
    analysis: RepositoryAnalysis,
    rule: SecurityPathRule,
) -> set[str]:
    """Find callable symbols recognized as sensitive operations."""

    return {
        symbol_name
        for symbol_name in _iter_function_symbols(analysis)
        if _short_name(symbol_name).lower() in rule.sink_names
    }


def _short_name(symbol_name: str) -> str:
    """Return the final component of a qualified symbol name."""

    return symbol_name.rsplit(".", 1)[-1]


def _matches_any_pattern(
    name: str,
    patterns: Iterable[str],
) -> bool:
    """Return whether a function name matches any configured pattern."""

    lowered_name = name.lower()

    return any(
        pattern.lower() in lowered_name
        for pattern in patterns
    )


# ---------------------------------------------------------------------------
# Finding generation
# ---------------------------------------------------------------------------


def _finding_for_path(
    analysis: RepositoryAnalysis,
    path: SecurityPath,
    rule: SecurityPathRule,
) -> dict:
    """Convert one unprotected path into a scanner-compatible finding."""

    entry_node = analysis.call_graph.get_node(
        path.entry_point
    )

    if entry_node is None:
        raise ValueError(
            "Security path entry point disappeared from the call graph: "
            f"{path.entry_point!r}"
        )

    symbol = entry_node.symbol

    return {
        "rule_id": rule.rule_id,
        "type": rule.finding_type,
        "severity": rule.severity,
        "file": str(symbol.file_path),
        "line": symbol.line,
        "message": (
            f"{rule.description} "
            f"Path: {' -> '.join(path.nodes)}"
        ),
    }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_limits(
    max_depth: int,
    max_paths: int,
) -> None:
    """Validate traversal limits before starting analysis."""

    if isinstance(max_depth, bool) or not isinstance(max_depth, int):
        raise TypeError("max_depth must be an integer")

    if isinstance(max_paths, bool) or not isinstance(max_paths, int):
        raise TypeError("max_paths must be an integer")

    if max_depth < 0:
        raise ValueError("max_depth must be >= 0")

    if max_paths <= 0:
        raise ValueError("max_paths must be > 0")
