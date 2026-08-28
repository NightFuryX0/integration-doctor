import ast
from pathlib import Path


class WebhookDetector(ast.NodeVisitor):
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.findings = []

    def visit_FunctionDef(self, node: ast.FunctionDef):
        if self._is_webhook_endpoint(node):
            if not self._has_signature_verification(node):
                self.findings.append(
                    {
                        "rule_id": "WEBHOOK-001",
                        "type": "MISSING_WEBHOOK_SIGNATURE",
                        "severity": "CRITICAL",
                        "file": self.file_path,
                        "line": node.lineno,
                        "message": (
                            "Webhook endpoint processes incoming payment "
                            "events without apparent signature verification."
                        ),
                    }
                )

        self.generic_visit(node)

    def _is_webhook_endpoint(self, node: ast.FunctionDef) -> bool:
        if "webhook" in node.name.lower():
            return True

        for decorator in node.decorator_list:
            decorator_source = ast.unparse(decorator).lower()

            if "webhook" in decorator_source:
                return True

        return False

    def _has_signature_verification(self, node: ast.FunctionDef) -> bool:
        verification_indicators = (
            "verify_signature",
            "verify_webhook",
            "signature",
            "hmac",
            "compare_digest",
        )

        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_source = ast.unparse(child).lower()

                if any(
                    indicator in call_source
                    for indicator in verification_indicators
                ):
                    return True

        return False


def analyze_file(file_path: str) -> list[dict]:
    path = Path(file_path)

    source = path.read_text(encoding="utf-8")

    tree = ast.parse(source, filename=str(path))

    analyzer = WebhookDetector(str(path))
    analyzer.visit(tree)

    return analyzer.findings


if __name__ == "__main__":
    target = "integrations/broken_webhook/app.py"

    findings = analyze_file(target)

    if not findings:
        print("No findings.")

    for finding in findings:
        print(
            f"[{finding['severity']}] "
            f"{finding['rule_id']} "
            f"{finding['type']}"
        )
        print(
            f"  {finding['file']}:{finding['line']}"
        )
        print(f"  {finding['message']}")
