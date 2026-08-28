from analyzer.detectors.webhook import analyze_file


def test_webhook_with_middleware_is_flagged_for_ai_review():
    findings = analyze_file(
        "integrations/safe_webhook/middleware_verified.py"
    )
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "WEBHOOK-001"
