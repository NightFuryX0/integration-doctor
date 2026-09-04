from analyzer.detectors.webhook import analyze_file


def test_webhook_with_verified_middleware_is_not_flagged():
    findings = analyze_file(
        "integrations/safe_webhook/middleware_verified.py"
    )

    assert not findings
