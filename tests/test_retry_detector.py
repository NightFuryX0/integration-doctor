from analyzer.detectors.retry import analyze_file


def test_detects_unsafe_payment_retry():
    findings = analyze_file(
        "integrations/broken_webhook/unsafe_retry.py"
    )

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "PAYMENT-003"
    assert findings[0]["type"] == "POTENTIALLY_UNSAFE_RETRY"


def test_does_not_flag_safe_payment_retry():
    findings = analyze_file(
        "integrations/broken_webhook/safe_retry.py"
    )

    assert findings == []
