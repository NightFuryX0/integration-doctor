"""Static-analysis detector for missing payment-webhook idempotency checks.

Flags webhook handlers that appear to mutate payment/order state (charge,
capture, refund, etc.) without any visible guard against processing the
same event twice -- a common source of double-charges when a payment
provider retries a webhook delivery (which most providers do, on purpose,
whenever they don't get a fast 2xx response).

Design notes / known limitations
---------------------------------
Like the webhook signature detector, this is a heuristic AST pattern
matcher, not a data-flow analyzer. It cannot follow values across
variable reassignment chains, through helper modules, or across function
boundaries, and it does not distinguish a loop/helper defined *inside*
the handler from the handler's own top-level logic. Treat findings as
leads for review, not as ground truth.
"""

from __future__ import annotations

import ast
from pathlib import Path

# --- Rule identifiers ----------------------------------------------------

RULE_MISSING_IDEMPOTENCY_CHECK = "WEBHOOK-002"
SEVERITY_HIGH = "HIGH"

# Substrings indicating the code is mutating payment/order state.
_PAYMENT_STATE_WORDS = (
    "payment",
    "order",
    "paid",
    "capture",
    "refund",
    "charge",
)

# Substrings indicating some form of duplicate-event guard is present.
# Deliberately checked against the FULL unparsed source (not just
# identifiers): in real integrations these markers are extremely often
# read as string literals -- e.g. `data.get("event_id")` or
# `if "webhook_id" in seen:` -- so restricting this to identifier nodes
# would create false positives on correctly-guarded code.
_DUPLICATE_CHECK_WORDS = (
    "idempotency",
    "already_processed",
    "processed",
    "event_id",
    "webhook_id",
)


def _safe_unparse(node: ast.AST) -> str:
    """``ast.unparse`` lower-cased, tolerant of exotic/unsupported nodes."""
    try:
        return ast.unparse(node).lower()
    except Exception:
        return ""


class IdempotencyDetector(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings: list[dict] = []

    # -- visitor entry points ---------------------------------------------
    # NEW: async def handlers (FastAPI, aiohttp, Sanic, ...) are extremely
    # common for webhook receivers and were previously invisible to this
    # detector -- ast.NodeVisitor only calls visit_FunctionDef for `def`,
    # never for `async def` (ast.AsyncFunctionDef), so an async webhook
    # handler with no idempotency guard silently produced zero findings.

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    # -- core decision logic ------------------------------------------------

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if not self._is_webhook(node):
            return

        if self._changes_payment_state(node) and not self._checks_duplicate(node):
            self.findings.append(
                {
                    "rule_id": RULE_MISSING_IDEMPOTENCY_CHECK,
                    "type": "MISSING_IDEMPOTENCY_CHECK",
                    "severity": SEVERITY_HIGH,
                    "file": self.file_path,
                    "line": node.lineno,
                    "message": (
                        "Webhook handler appears to change payment or "
                        "order state without an obvious duplicate-event check."
                    ),
                }
            )

    # -- endpoint identification --------------------------------------------

    def _is_webhook(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        # NEW: also check decorators (e.g. @app.route("/webhook", ...)),
        # matching webhook.py's detection so a handler named something
        # other than "webhook" but routed to a webhook path isn't skipped.
        if "webhook" in node.name.lower():
            return True

        for decorator in node.decorator_list:
            if "webhook" in _safe_unparse(decorator):
                return True

        return False

    # -- call/text scanning helpers ------------------------------------------

    def _changes_payment_state(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        # NEW: only the call's callee (e.g. "order.capture") is checked,
        # not its full unparsed text including string arguments. Under the
        # old logic, `logger.info("refund may be needed for this order")`
        # was itself indistinguishable from an actual `order.refund()`
        # call -- a log message could trigger a false "payment operation"
        # match purely from its wording.
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue

            call_text = _safe_unparse(child.func)
            if any(word in call_text for word in _PAYMENT_STATE_WORDS):
                return True

        return False

    def _checks_duplicate(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        # Full-text match is intentional here -- see _DUPLICATE_CHECK_WORDS.
        source = _safe_unparse(node)
        return any(word in source for word in _DUPLICATE_CHECK_WORDS)


def analyze_file(file_path: str) -> list[dict]:
    """Parse ``file_path`` and return a list of missing-idempotency findings.

    Raises:
        FileNotFoundError: if ``file_path`` does not exist.
        SyntaxError: if the file is not valid Python source.
        UnicodeDecodeError: if the file cannot be decoded as UTF-8.
    """
    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Could not analyze '{file_path}' because the file does not exist."
        )

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

    detector = IdempotencyDetector(str(path))
    detector.visit(tree)

    return detector.findings
