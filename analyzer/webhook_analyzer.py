"""Backward-compatible entry point for the webhook signature detector.

The real implementation lives in :mod:`analyzer.detectors.webhook`. This
module exists only so that code written against the old flat import path
keeps working, e.g.::

    import webhook_analyzer
    webhook_analyzer.analyze_file("some_handler.py")

    from webhook_analyzer import analyze_file, WebhookDetector

New code should import directly from ``analyzer.detectors.webhook`` — this
module intentionally contains no detection logic of its own, so there is
only ever one implementation to keep correct.

This shim also remains runnable as a script for old callers that used to
invoke it directly::

    python webhook_analyzer.py [path/to/file.py]

Importing this module emits a :class:`DeprecationWarning` pointing callers
at the canonical location. That warning does not change behavior; it is
purely informational and is filtered out by default in most test runners.
"""

from __future__ import annotations

import sys
import warnings
from pathlib import Path

# --- locate and import the real implementation --------------------------
#
# `analyzer.detectors.webhook` must be importable as a package (i.e. an
# `analyzer/` directory containing `__init__.py` and `detectors/__init__.py`
# must be on sys.path). When this shim is imported normally that's already
# the case. When it's *run directly* as a script from a different working
# directory, Python only puts this file's own directory on sys.path, which
# may not be where the `analyzer` package lives relative to the caller — so
# we make one bounded, explicit attempt to add likely candidate directories
# before giving up with a clear, actionable error rather than a bare
# ModuleNotFoundError.


def _import_real_module():
    try:
        import analyzer.detectors.webhook as _impl  # noqa: WPS433 (intentional local import)

        return _impl
    except ModuleNotFoundError:
        pass

    # Fallback: this file may be sitting next to (or inside) the project
    # root that contains the `analyzer` package but wasn't added to
    # sys.path because the shim was executed as a standalone script.
    candidate_roots = {
        Path(__file__).resolve().parent,
        Path(__file__).resolve().parent.parent,
        Path.cwd(),
    }
    for root in candidate_roots:
        root_str = str(root)
        if root_str not in sys.path:
            sys.path.insert(0, root_str)
        try:
            import analyzer.detectors.webhook as _impl  # noqa: WPS433

            return _impl
        except ModuleNotFoundError:
            continue

    raise ImportError(
        "webhook_analyzer is a compatibility shim and could not locate its "
        "real implementation at 'analyzer.detectors.webhook'. Make sure an "
        "'analyzer' package (with 'analyzer/__init__.py' and "
        "'analyzer/detectors/__init__.py') is present on sys.path, "
        "typically alongside this file or at your project root."
    )


_impl = _import_real_module()

analyze_file = _impl.analyze_file
WebhookDetector = _impl.WebhookDetector
RULE_MISSING_SIGNATURE = _impl.RULE_MISSING_SIGNATURE
RULE_WEAK_SIGNATURE = _impl.RULE_WEAK_SIGNATURE
SEVERITY_CRITICAL = _impl.SEVERITY_CRITICAL
SEVERITY_HIGH = _impl.SEVERITY_HIGH
main = _impl.main

del _import_real_module  # keep this module's public surface clean

warnings.warn(
    "webhook_analyzer is a deprecated compatibility shim; import from "
    "'analyzer.detectors.webhook' instead.",
    DeprecationWarning,
    stacklevel=2,
)

__all__ = [
    "analyze_file",
    "WebhookDetector",
    "RULE_MISSING_SIGNATURE",
    "RULE_WEAK_SIGNATURE",
    "SEVERITY_CRITICAL",
    "SEVERITY_HIGH",
    "main",
]


if __name__ == "__main__":
    raise SystemExit(main())
