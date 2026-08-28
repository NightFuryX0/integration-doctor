import ast
from pathlib import Path


class IdempotencyDetector(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        if self._is_webhook(node):
            if self._changes_payment_state(node) and not self._checks_duplicate(node):
                self.findings.append(
                    {
                        "rule_id": "WEBHOOK-002",
                        "type": "MISSING_IDEMPOTENCY_CHECK",
                        "severity": "HIGH",
                        "file": self.file_path,
                        "line": node.lineno,
                        "message": (
                            "Webhook handler appears to change payment or "
                            "order state without an obvious duplicate-event check."
                        ),
                    }
                )

        self.generic_visit(node)

    def _is_webhook(self, node: ast.FunctionDef) -> bool:
        return "webhook" in node.name.lower()

    def _changes_payment_state(self, node: ast.FunctionDef) -> bool:
        payment_words = (
            "payment",
            "order",
            "paid",
            "capture",
            "refund",
        )

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_text = ast.unparse(child).lower()

                if any(word in call_text for word in payment_words):
                    return True

        return False

    def _checks_duplicate(self, node: ast.FunctionDef) -> bool:
        duplicate_words = (
            "idempotency",
            "already_processed",
            "processed",
            "event_id",
            "webhook_id",
        )

        source = ast.unparse(node).lower()

        return any(
            word in source
            for word in duplicate_words
        )


def analyze_file(file_path: str) -> list[dict]:
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

    detector = IdempotencyDetector(str(path))
    detector.visit(tree)

    return detector.findings
