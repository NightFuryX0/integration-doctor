from analyzer.webhook_analyzer import analyze_file


def test_detects_missing_signature():
    findings = analyze_file(
        "integrations/broken_webhook/app.py"
    )

    assert any(
        finding["type"] == "MISSING_WEBHOOK_SIGNATURE"
        for finding in findings
    )
