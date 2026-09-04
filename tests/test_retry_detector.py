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


def test_does_not_flag_payment_loop_without_retry_behavior(tmp_path):
    payment_file = tmp_path / "payments.py"
    payment_file.write_text(
        """
def process_payments(payments):
    for payment in payments:
        capture_payment(payment)
"""
    )

    findings = analyze_file(str(payment_file))

    assert findings == []


def test_does_not_flag_retry_word_in_comment_or_message(tmp_path):
    payment_file = tmp_path / "payments.py"
    payment_file.write_text(
        """
def process_payment(payment_id):
    message = "Retry this request later"
    capture_payment(payment_id)
"""
    )

    findings = analyze_file(str(payment_file))

    assert findings == []
