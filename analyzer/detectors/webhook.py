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
# FIX: Update the documented limitation because the detector now follows
# simple local signature aliases, while still not performing full data-flow.
This is a heuristic textual/AST pattern matcher, not a full data-flow analyzer.
It can follow simple local signature variable reassignments, but it cannot
follow values through helper modules or across function boundaries. Treat
findings as leads for review, not as ground truth, and expect some false
negatives on unusual code shapes.,
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
        # NEW: keep the module AST available so webhook decorators can be
        # resolved to their local implementations.
        self._module_tree: ast.Module | None = None

    # -- visitor entry points ---------------------------------------------

    def visit_Module(self, node: ast.Module) -> None:
        # NEW: save the complete module tree before inspecting functions,
        # so decorator implementations can be resolved locally.
        self._module_tree = node
        self.generic_visit(node)

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
        signature_vars = self._expand_signature_variable_names(
            node,
            signature_vars,
        )
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
        if (
            has_crypto_verification
            or self._has_verification_decorator(node)
            or self._has_verified_local_decorator(node)
        ):
            return  # properly verified: no finding

        # FIX: A standalone cryptographic comparison whose result is ignored
        # does not verify the webhook, so report it as missing verification.
        if self._has_unenforced_crypto_verification(node, signature_vars):
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
            return

        if has_header_read and self._has_weak_signature_usage(
            node, signature_vars
        ):
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

    def _has_verified_local_decorator(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> bool:
        """Return True when a locally defined decorator performs real
        signature verification and only calls the wrapped handler after
        successful verification.
        """
        if self._module_tree is None:
            return False

        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Name):
                continue

            decorator_definition = None

            for definition in self._module_tree.body:
                if (
                    isinstance(
                        definition, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and definition.name == decorator.id
                ):
                    decorator_definition = definition
                    break

            if decorator_definition is None:
                continue

            # A real decorator must perform cryptographic verification.
            if not self._has_cryptographic_verification(
                decorator_definition, set()
            ):
                continue

            # The decorator must also call the wrapped function. Otherwise
            # the verification code may be unrelated to the actual handler.
            if not self._decorator_calls_wrapped_function(decorator_definition):
                continue

            # The wrapped function call must be reachable only after a
            # verification failure has already been rejected. This keeps a
            # crypto call by itself from being treated as an effective guard.
            if self._decorator_call_is_after_rejection(
                decorator_definition
            ):
                return True

        return False

    def _decorator_calls_wrapped_function(
        self, decorator: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> bool:
        """Return True when the decorator eventually calls its wrapped input."""
        parameter_names = {argument.arg for argument in decorator.args.args}
        if not parameter_names:
            return False

        for call in self._iter_calls(decorator):
            call_source = _safe_unparse(call.func)
            if any(
                _contains_identifier(call_source, name)
                for name in parameter_names
            ):
                return True

        return False

    def _decorator_call_is_after_rejection(
        self, decorator: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> bool:
        """Return True when a wrapped-function call follows a rejecting guard."""
        wrapped_names = {argument.arg for argument in decorator.args.args}
        if not wrapped_names:
            return False

        for child in ast.walk(decorator):
            if not isinstance(child, ast.If):
                continue

            if not self._has_cryptographic_verification(child.test, set()):
                continue

            # A guard such as `if not compare_digest(...): return ...` is a
            # strong signal that failed verification stops the request.
            if not self._contains_termination(child.body):
                continue

            for call in self._iter_calls(decorator):
                if not self._call_is_wrapped_function(call, wrapped_names):
                    continue

                if getattr(call, "lineno", 0) > getattr(child, "lineno", 0):
                    return True

        return False

    def _call_is_wrapped_function(
        self, call: ast.Call, wrapped_names: set[str]
    ) -> bool:
        return any(
            isinstance(call.func, ast.Name) and call.func.id == name
            for name in wrapped_names
        )

    def _contains_termination(self, statements: list[ast.stmt]) -> bool:
        """Return True when a statement block contains request termination."""
        for statement in statements:
            if isinstance(statement, (ast.Return, ast.Raise)):
                return True

            # Common nested termination forms, while keeping this heuristic
            # deliberately small and readable.
            if isinstance(statement, ast.If):
                if self._contains_termination(statement.body) or self._contains_termination(
                    statement.orelse
                ):
                    return True

        return False

    # -- call/assignment scanning helpers -----------------------------------

    def _iter_calls(self, node: ast.AST) -> Iterator[ast.Call]:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                yield child

    def _has_crypto_call_in_condition(
        self, condition: ast.AST, signature_vars: set[str]
    ) -> bool:
        """Return True when a crypto/helper call is used inside a condition."""
        for call in self._iter_calls(condition):
            func_source = _safe_unparse(call.func)

            if not func_source:
                continue

            is_crypto_call = any(
                ind in func_source
                for ind in _CRYPTOGRAPHIC_VERIFICATION_INDICATORS
            )
            is_trusted_helper = any(
                ind in func_source
                for ind in _TRUSTED_VERIFICATION_HELPERS
            )

            if not (is_crypto_call or is_trusted_helper):
                continue

            if not signature_vars:
                return True

            full_source = _safe_unparse(call)

            if any(
                _contains_identifier(full_source, var)
                for var in signature_vars
            ):
                return True

        return False

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

    # FIX: Follow simple local assignments so a signature alias is treated
    # as the same signature value during verification checks.
    def _expand_signature_variable_names(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        signature_vars: set[str],
    ) -> set[str]:
        """Follow simple local assignments derived from known signature variables."""
        expanded = set(signature_vars)

        changed = True
        while changed:
            changed = False

            for child in ast.walk(node):
                if not isinstance(child, ast.Assign):
                    continue

                if not isinstance(child.value, ast.Name):
                    continue

                if child.value.id not in expanded:
                    continue

                for target in child.targets:
                    if not isinstance(target, ast.Name):
                        continue

                    if target.id not in expanded:
                        expanded.add(target.id)
                        changed = True

        return expanded

    def _has_signature_header_read(
        self, node: ast.AST, signature_vars: set[str]
    ) -> bool:
        if signature_vars:
            return True
        return any(self._looks_like_signature_header_read(c) for c in self._iter_calls(node))

    def _has_cryptographic_verification(
        self, node: ast.AST, signature_vars: set[str]
    ) -> bool:
        """True when a real verification operation is found."""

        # FIX: Trusted SDK/helper calls can perform verification internally,
        # so they remain valid even when they are standalone calls.
        for call in self._iter_calls(node):
            func_source = _safe_unparse(call.func)
            if not func_source:
                continue

            is_crypto_call = any(
                ind in func_source
                for ind in _CRYPTOGRAPHIC_VERIFICATION_INDICATORS
            )
            is_trusted_helper = any(
                ind in func_source
                for ind in _TRUSTED_VERIFICATION_HELPERS
            )

            # FIX: Trusted SDK/helper calls can perform verification on their
            # own, so a standalone trusted helper is valid verification.
            if is_trusted_helper:
                if not signature_vars:
                    return True

                full_source = _safe_unparse(call)

                if any(
                    _contains_identifier(full_source, var)
                    for var in signature_vars
                ):
                    return True

                continue

            # FIX: A raw crypto comparison only counts as verification when
            # its result is actually used as a condition. A standalone
            # compare_digest() call has its result ignored and must not
            # suppress WEBHOOK-001.
            if is_crypto_call:
                if self._is_call_inside_verification_condition(node, call):
                    if not signature_vars:
                        return True

                    full_source = _safe_unparse(call)

                    if any(
                        _contains_identifier(full_source, var)
                        for var in signature_vars
                    ):
                        return True

                continue

        # FIX: A condition expression can be passed directly here by the
        # decorator checks, so inspect that expression as a real condition.
        if isinstance(node, ast.expr):
            return self._has_crypto_call_in_condition(
                node,
                signature_vars,
            )

        # FIX: When given a whole function or decorator definition, inspect
        # only actual condition expressions. Standalone crypto calls elsewhere
        # in the function do not count as effective verification.
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.IfExp, ast.Assert)):
                if self._has_crypto_call_in_condition(
                    child.test,
                    signature_vars,
                ):
                    return True

        return False

    def _has_unenforced_crypto_verification(
        self, node: ast.AST, signature_vars: set[str]
    ) -> bool:
        """Return True when a crypto comparison is made but its result is ignored."""

        for call in self._iter_calls(node):
            func_source = _safe_unparse(call.func)
            if not func_source:
                continue

            # FIX: Only raw cryptographic comparisons need this check.
            # Trusted SDK/helper calls are handled separately because they
            # perform verification internally.
            if not any(
                ind in func_source
                for ind in _CRYPTOGRAPHIC_VERIFICATION_INDICATORS
            ):
                continue

            if signature_vars:
                full_source = _safe_unparse(call)

                if not any(
                    _contains_identifier(full_source, var)
                    for var in signature_vars
                ):
                    continue

            # FIX: If the comparison is not inside a condition, its result
            # is being ignored and therefore cannot protect the webhook.
            if not self._is_call_inside_verification_condition(node, call):
                return True

        return False

    def _is_call_inside_verification_condition(
        self, node: ast.AST, target_call: ast.Call
    ) -> bool:
        """Return True when a call appears inside an execution condition."""

        for child in ast.walk(node):
            if not isinstance(child, (ast.If, ast.IfExp, ast.Assert)):
                continue

            if any(
                candidate is target_call
                for candidate in self._iter_calls(child.test)
            ):
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
        # FIX: Track conditions that already contain real cryptographic
        # verification so they are not also classified as weak usage.
        verified_conditions: set[int] = set()

        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.IfExp, ast.Assert)):
                if self._has_crypto_call_in_condition(
                    child.test,
                    signature_vars,
                ):
                    verified_conditions.add(id(child.test))
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
            # FIX: Skip conditions that contain a real cryptographic
            # verification call.
            if id(candidate) in verified_conditions:
                continue
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
