import ast
from pathlib import Path


class RetryDetector(ast.NodeVisitor):
    """Find potentially unsafe retry patterns around payment operations."""

    PAYMENT_OPERATIONS = (
        "payment",
        "capture",
        "refund",
        "order",
        "razorpay",
    )

    RETRY_INDICATORS = (
        "retry",
        "retries",
        "attempt",
        "attempts",
    )

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        if self._contains_payment_operation(node) and self._contains_retry_logic(node):
            if not self._has_obvious_retry_protection(node):
                self.findings.append(
                    {
                        "rule_id": "PAYMENT-003",
                        "type": "POTENTIALLY_UNSAFE_RETRY",
                        "severity": "HIGH",
                        "file": self.file_path,
                        "line": node.lineno,
                        "message": (
                            "This function appears to retry a payment-related "
                            "operation without an obvious retry-safety mechanism."
                        ),
                    }
                )

        self.generic_visit(node)

    def _contains_payment_operation(self, node: ast.FunctionDef) -> bool:
        """Check whether the function appears to call a payment-related operation."""

        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue

            call_text = ast.unparse(child).lower()

            if any(
                operation in call_text
                for operation in self.PAYMENT_OPERATIONS
            ):
                return True

        return False

    def _contains_retry_logic(self, node: ast.FunctionDef) -> bool:
        """Check whether the function appears to contain retry behavior."""

        source = ast.unparse(node).lower()

        return any(
            indicator in source
            for indicator in self.RETRY_INDICATORS
        ) or self._contains_loop(node)

    def _contains_loop(self, node: ast.FunctionDef) -> bool:
        """Check for loops that could be used to repeat an operation."""

        return any(
            isinstance(child, (ast.For, ast.While))
            for child in ast.walk(node)
        )

    def _has_obvious_retry_protection(self, node: ast.FunctionDef) -> bool:
        """Look for common signs that retry behavior is deliberately controlled."""

        source = ast.unparse(node).lower()

        protection_indicators = (
            "idempotency",
            "idempotency_key",
            "idempotent",
            "backoff",
            "exponential_backoff",
            "max_retries",
            "retry_after",
        )

        return any(
            indicator in source
            for indicator in protection_indicators
        )


def analyze_file(file_path: str) -> list[dict]:
    """Analyze one Python file for potentially unsafe payment retries."""

    path = Path(file_path)

    if not path.is_file():
        raise FileNotFoundError(
            f"Could not analyze '{file_path}' because the file does not exist."
        )

    source = path.read_text(encoding="utf-8")

    tree = ast.parse(
        source,
        filename=str(path),
    )

    detector = RetryDetector(str(path))
    detector.visit(tree)

    return detector.findings
