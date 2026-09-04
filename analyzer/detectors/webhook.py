"""Static-analysis detector for webhook signature verification issues.

This module implements a lightweight, AST-based scanner that flags webhook
handlers which either:

* Never verify the authenticity of an incoming payload at all
  (``WEBHOOK-001`` / ``MISSING_WEBHOOK_SIGNATURE``), or
* Read a signature header but only perform a superficial check on it (e.g.
  a truthiness test or a non-constant-time ``==`` comparison) instead of a
  real cryptographic verification (``WEBHOOK-003`` /
  ``WEAK_WEBHOOK_SIGNATURE_VERIFICATION``).

Design notes / known limitations
---------------------------------
This is a heuristic textual/AST pattern matcher, not a data-flow analyzer.
It cannot follow a signature value across variable reassignment chains,
through helper modules, or across function boundaries. Treat findings as
leads for review, not as ground truth, and expect some false negatives on
unusual code shapes.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Iterable, Iterator

# --- Rule identifiers ----------------------------------------------------

RULE_MISSING_SIGNATURE = "WEBHOOK-001"
RULE_WEAK_SIGNATURE = "WEBHOOK-003"

SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"

# Substrings (already lower-cased) that indicate code is reading a webhook
# signature value. Kept broad to cover common providers and frameworks.
_SIGNATURE_INDICATORS = (
    "x-signature",
    "x-webhook-signature",
    "x-hub-signature",
    "stripe-signature",
    "razorpay-signature",
    "svix-signature",
    "http_x_signature",
    "http_x_webhook_signature",
    "signature",
)

# Substrings indicating the value is being pulled out of request
# headers/metadata (as opposed to, say, a signature computed locally).
_HEADER_ACCESS_INDICATORS = ("headers", "meta", "header")

# Calls that represent an actual constant-time / cryptographic comparison.
_CRYPTOGRAPHIC_VERIFICATION_INDICATORS = (
    "hmac.compare_digest",
    "compare_digest",
    "secrets.compare_digest",
)

# SDK/helper call names that are trusted to perform full verification
# themselves (they raise/return falsy on an invalid signature), even
# without an explicit local crypto comparison visible in this function.
_TRUSTED_VERIFICATION_HELPERS = (
    "construct_event",  # e.g. stripe.Webhook.construct_event(...)
    "verify_webhook",
    "verify_payload",
    "validate_webhook",
    "verify_signature",
    "verify_header",
    # NEW: a couple more common naming conventions for the same concept,
    # in the same spirit as the SDK/provider coverage already listed above.
    "validate_signature",
    "check_signature",
)

_WEBHOOK_NAME_INDICATOR = "webhook"


def _safe_unparse(node: ast.AST) -> str:
    """``ast.unparse`` lower-cased, tolerant of exotic/unsupported nodes."""
    try:
        return ast.unparse(node).lower()
    except Exception:
        return ""


def _contains_identifier(text: str, name: str) -> bool:
    """Whole-word (identifier) match, so 'sig' doesn't match 'signature_ok'."""
    return re.search(rf"\b{re.escape(name.lower())}\b", text) is not None


class WebhookDetector(ast.NodeVisitor):
    """Walks a module's AST looking for weak/missing webhook verification."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: list[dict] = []

    # -- visitor entry points ---------------------------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    # -- core decision logic ------------------------------------------------

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if not self._is_webhook_endpoint(node):
            return

        signature_vars = self._find_signature_variable_names(node)
        has_header_read = self._has_signature_header_read(node, signature_vars)
        has_crypto_verification = self._has_cryptographic_verification(
            node, signature_vars
        )

        # NEW: also treat a bare (no-parentheses) verification decorator,
        # e.g. `@verify_webhook_signature` applied directly to the handler,
        # as satisfying verification. Such a decorator is an ast.Name in
        # decorator_list rather than an ast.Call, so it was previously
        # invisible to _has_cryptographic_verification (which only looks
        # at ast.Call nodes) -- a handler protected entirely by a bare
        # decorator would have been flagged as MISSING_WEBHOOK_SIGNATURE.
        if has_crypto_verification or self._has_verification_decorator(node):
            return  # properly verified: no finding

        if has_header_read and self._has_weak_signature_usage(node, signature_vars):
            self._add_finding(
                rule_id=RULE_WEAK_SIGNATURE,
                finding_type="WEAK_WEBHOOK_SIGNATURE_VERIFICATION",
                severity=SEVERITY_HIGH,
                line=node.lineno,
                message=(
                    "Webhook endpoint reads a signature but does not appear "
                    "to perform cryptographic signature verification."
                ),
            )
            return

        self._add_finding(
            rule_id=RULE_MISSING_SIGNATURE,
            finding_type="MISSING_WEBHOOK_SIGNATURE",
            severity=SEVERITY_CRITICAL,
            line=node.lineno,
            message=(
                "Webhook endpoint processes incoming payment events without "
                "apparent signature verification."
            ),
        )

    def _add_finding(
        self, *, rule_id: str, finding_type: str, severity: str, line: int, message: str
    ) -> None:
        self.findings.append(
            {
                "rule_id": rule_id,
                "type": finding_type,
                "severity": severity,
                "file": self.file_path,
                "line": line,
                "message": message,
            }
        )

    # -- endpoint identification --------------------------------------------

    def _is_webhook_endpoint(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        if _WEBHOOK_NAME_INDICATOR in node.name.lower():
            return True

        for decorator in node.decorator_list:
            if _WEBHOOK_NAME_INDICATOR in _safe_unparse(decorator):
                return True

        return False

    def _has_verification_decorator(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> bool:
        """True if the function is itself wrapped by something that looks
        like a trusted verification decorator, used bare (no parentheses)
        so it never appears as an ast.Call -- e.g. ``@verify_webhook``
        rather than ``@verify_webhook()``.
        """
        for decorator in node.decorator_list:
            decorator_text = _safe_unparse(decorator)
            if not decorator_text:
                continue
            if any(ind in decorator_text for ind in _TRUSTED_VERIFICATION_HELPERS):
                return True

        return False

    # -- call/assignment scanning helpers -----------------------------------

    def _iter_calls(self, node: ast.AST) -> Iterator[ast.Call]:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                yield child

    def _looks_like_signature_header_read(self, call: ast.Call) -> bool:
        """True for a call that is *itself* a header lookup carrying a
        signature, e.g. ``request.headers.get("X-Signature")``.

        Only the call's own callee and arguments are inspected (not the
        full recursively-unparsed subtree), so a call that merely *contains*
        a header lookup as one argument among others — e.g.
        ``stripe.Webhook.construct_event(body, request.headers.get(...), secret)``
        — is correctly NOT treated as itself being a header read.
        """
        func_source = _safe_unparse(call.func)
        if not func_source or not any(
            indicator in func_source for indicator in _HEADER_ACCESS_INDICATORS
        ):
            return False

        arg_sources = [_safe_unparse(a) for a in call.args]
        arg_sources.extend(_safe_unparse(kw.value) for kw in call.keywords)
        args_text = " ".join(arg_sources)
        return any(indicator in args_text for indicator in _SIGNATURE_INDICATORS)

    def _find_signature_variable_names(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> set[str]:
        """Collect names of local variables assigned from a header read that
        looks like a webhook signature, e.g. ``sig = request.headers.get(...)``.
        """
        names: set[str] = set()
        for child in ast.walk(node):
            value = None
            targets: Iterable[ast.expr] = ()

            if isinstance(child, ast.Assign):
                value = child.value
                targets = child.targets
            elif isinstance(child, (ast.AnnAssign, ast.NamedExpr)):
                value = child.value
                targets = [child.target]

            if not isinstance(value, ast.Call):
                continue
            if not self._looks_like_signature_header_read(value):
                continue

            for target in targets:
                if isinstance(target, ast.Name):
                    names.add(target.id)

        return names

    def _has_signature_header_read(
        self, node: ast.AST, signature_vars: set[str]
    ) -> bool:
        if signature_vars:
            return True
        return any(self._looks_like_signature_header_read(c) for c in self._iter_calls(node))

    def _has_cryptographic_verification(
        self, node: ast.AST, signature_vars: set[str]
    ) -> bool:
        """True only if a real verification call is found, and — when we
        know the signature's variable name — that call actually references
        it. This prevents an unrelated ``compare_digest`` call elsewhere in
        the function from masking a genuinely unverified signature.
        """
        for call in self._iter_calls(node):
            # NEW: identify "is this a verification call?" using ONLY the
            # callee (call.func), not the full unparsed call including its
            # arguments. Under the old logic, matching against the full
            # call text meant something like
            # `log.info("did not verify_signature for this request")`
            # was indistinguishable from an actual verify_signature(...)
            # call -- a log message could make the detector believe a
            # completely unprotected webhook was verified.
            func_source = _safe_unparse(call.func)
            if not func_source:
                continue

            is_crypto_call = any(
                ind in func_source for ind in _CRYPTOGRAPHIC_VERIFICATION_INDICATORS
            )
            is_trusted_helper = any(
                ind in func_source for ind in _TRUSTED_VERIFICATION_HELPERS
            )
            if not (is_crypto_call or is_trusted_helper):
                continue

            if not signature_vars:
                return True

            # For the "does this call actually use our signature variable?"
            # check, the full call text (including arguments) is exactly
            # what we want to search, since the variable appears as an
            # argument, not as part of the callee.
            full_source = _safe_unparse(call)
            if any(_contains_identifier(full_source, var) for var in signature_vars):
                return True

        return False

    def _has_weak_signature_usage(
        self, node: ast.AST, signature_vars: set[str]
    ) -> bool:
        """True if the signature is referenced in a conditional/boolean/
        comparison context without ever going through real verification
        (covers both truthiness checks like ``if signature:`` and
        timing-unsafe checks like ``signature == expected``).
        """
        candidates: list[ast.AST] = []
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.IfExp)):
                candidates.append(child.test)
            elif isinstance(child, ast.Assert):
                candidates.append(child.test)
            elif isinstance(child, ast.BoolOp):
                candidates.append(child)
            elif isinstance(child, ast.Compare):
                candidates.append(child)
            elif isinstance(child, ast.UnaryOp) and isinstance(child.op, ast.Not):
                candidates.append(child)

        for candidate in candidates:
            text = _safe_unparse(candidate)
            if not text:
                continue

            if signature_vars and any(
                _contains_identifier(text, var) for var in signature_vars
            ):
                return True

            if not signature_vars and any(
                ind in text for ind in _SIGNATURE_INDICATORS
            ) and any(ind in text for ind in _HEADER_ACCESS_INDICATORS):
                return True

        return False


def analyze_file(file_path: str) -> list[dict]:
    """Parse ``file_path`` and return a list of webhook-signature findings.

    Raises:
        FileNotFoundError: if ``file_path`` does not exist.
        SyntaxError: if the file is not valid Python source.
        UnicodeDecodeError: if the file cannot be decoded as UTF-8.
    """
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(f"No such file: {file_path!r}")

    try:
        source = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise UnicodeDecodeError(
            exc.encoding,
            exc.object,
            exc.start,
            exc.end,
            f"{file_path}: {exc.reason} (file must be UTF-8 encoded)",
        ) from exc

    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as exc:
        raise SyntaxError(
            f"{file_path}: {exc.msg} (line {exc.lineno})") from exc

    analyzer = WebhookDetector(str(path))
    analyzer.visit(tree)
    return analyzer.findings


def _format_finding(finding: dict) -> str:
    return (
        f"[{finding['severity']}] {finding['rule_id']} {finding['type']}\n"
        f"  {finding['file']}:{finding['line']}\n"
        f"  {finding['message']}"
    )


def _main() -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Scan a Python file for missing/weak webhook signature verification."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="integrations/broken_webhook/app.py",
        help="Path to the Python file to analyze.",
    )
    args = parser.parse_args()

    try:
        findings = analyze_file(args.target)
    except (FileNotFoundError, SyntaxError, UnicodeDecodeError) as exc:
        print(f"Error: {exc}")
        return 2

    if not findings:
        print("No findings.")
        return 0

    for finding in findings:
        print(_format_finding(finding))

    return 1 if any(f["severity"] == SEVERITY_CRITICAL for f in findings) else 0


# Public alias: backward-compatible entry points (e.g. webhook_analyzer.py)
# should call `main()` rather than reaching into the private `_main`.
main = _main


if __name__ == "__main__":
    raise SystemExit(main())
