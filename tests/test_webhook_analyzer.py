from analyzer.detectors.webhook import analyze_file
import pytest


def test_detects_missing_signature():
    findings = analyze_file("integrations/broken_webhook/app.py")
    assert any(
        finding["type"] == "MISSING_WEBHOOK_SIGNATURE" for finding in findings
    )


def test_signature_header_alone_is_not_treated_as_verification(tmp_path):
    webhook_file = tmp_path / "webhook.py"
    webhook_file.write_text(
        """
def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    process_event(request)
"""
    )
    findings = analyze_file(str(webhook_file))
    assert any(finding["rule_id"] == "WEBHOOK-001" for finding in findings)


def test_detects_weak_signature_verification(tmp_path):
    webhook_file = tmp_path / "webhook.py"
    webhook_file.write_text(
        """
def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    if signature:
        process_event(request)
"""
    )
    findings = analyze_file(str(webhook_file))
    assert any(finding["rule_id"] == "WEBHOOK-003" for finding in findings)
    # Regression: this must NOT also be reported as fully missing.
    assert not any(finding["rule_id"] == "WEBHOOK-001" for finding in findings)


def test_accepts_hmac_compare_digest_as_signature_verification(tmp_path):
    webhook_file = tmp_path / "webhook.py"
    webhook_file.write_text(
        """
import hmac
def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    expected = "expected-signature"
    if hmac.compare_digest(signature, expected):
        process_event(request)
"""
    )
    findings = analyze_file(str(webhook_file))
    assert not any(finding["rule_id"] == "WEBHOOK-001" for finding in findings)
    assert not any(finding["rule_id"] == "WEBHOOK-003" for finding in findings)


def test_accepts_explicit_signature_verification_helper(tmp_path):
    webhook_file = tmp_path / "webhook.py"
    webhook_file.write_text(
        """
def verify_signature(signature, body):
    return True
def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    if verify_signature(signature, request.body):
        process_event(request)
"""
    )
    findings = analyze_file(str(webhook_file))
    assert not any(finding["rule_id"] == "WEBHOOK-001" for finding in findings)
    assert not any(finding["rule_id"] == "WEBHOOK-003" for finding in findings)


def test_accepts_razorpay_hmac_verification_decorator(tmp_path):
    webhook_file = tmp_path / "webhook.py"
    webhook_file.write_text(
        """
import hashlib
import hmac
from functools import wraps

WEBHOOK_SECRET = "secret"


def verify_razorpay_signature(function):
    @wraps(function)
    def wrapper(request):
        signature = request.headers.get("X-Razorpay-Signature")
        if not signature:
            return {"error": "Missing signature"}, 401

        raw_body = request.get_data()

        expected_signature = hmac.new(
            key=WEBHOOK_SECRET.encode("utf-8"),
            msg=raw_body,
            digestmod=hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected_signature, signature):
            return {"error": "Invalid signature"}, 401

        return function(request)

    return wrapper


@verify_razorpay_signature
def payment_webhook(request):
    process_payment(request)
"""
    )

    findings = analyze_file(str(webhook_file))

    assert not any(
        finding["rule_id"] == "WEBHOOK-001" for finding in findings
    )
    assert not any(
        finding["rule_id"] == "WEBHOOK-003" for finding in findings
    )


def test_accepts_verified_webhook_decorator(tmp_path):
    webhook_file = tmp_path / "webhook.py"
    webhook_file.write_text(
        """
import hashlib
import hmac
from functools import wraps

WEBHOOK_SECRET = "secret"


def verify_webhook_signature(function):
    @wraps(function)
    def wrapper(request):
        signature = request.headers.get("X-Webhook-Signature")
        if not signature:
            return {"error": "Missing signature"}, 401

        expected = hmac.new(
            WEBHOOK_SECRET.encode("utf-8"),
            request.get_data(),
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(expected, signature):
            return {"error": "Invalid signature"}, 401

        return function(request)

    return wrapper


@verify_webhook_signature
def webhook_handler(request):
    process_event(request)
"""
    )

    findings = analyze_file(str(webhook_file))

    assert not any(
        finding["rule_id"] == "WEBHOOK-001" for finding in findings
    )
    assert not any(
        finding["rule_id"] == "WEBHOOK-003" for finding in findings
    )
# --- Regression / hardening tests for the fixes made to the detector -----


def test_insecure_equality_comparison_is_flagged_as_weak(tmp_path):
    """`signature == expected` is a timing-unsafe comparison, not real
    verification, and should be flagged the same as a truthiness check."""
    webhook_file = tmp_path / "webhook.py"
    webhook_file.write_text(
        """
def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    expected = compute_expected_signature(request.body)
    if signature == expected:
        process_event(request)
"""
    )
    findings = analyze_file(str(webhook_file))
    assert any(finding["rule_id"] == "WEBHOOK-003" for finding in findings)


def test_unrelated_compare_digest_call_does_not_mask_missing_verification(tmp_path):
    """A `hmac.compare_digest` call on data unrelated to the actual webhook
    signature must not be treated as verifying that signature."""
    webhook_file = tmp_path / "webhook.py"
    webhook_file.write_text(
        """
import hmac
def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    hmac.compare_digest("unrelated-a", "unrelated-b")
    process_event(request)
"""
    )
    findings = analyze_file(str(webhook_file))
    assert any(finding["rule_id"] == "WEBHOOK-001" for finding in findings)
    assert not any(finding["rule_id"] == "WEBHOOK-003" for finding in findings)


def test_trusted_sdk_helper_verifies_even_without_local_variable(tmp_path):
    """SDK helpers like stripe's construct_event() perform verification
    internally (and raise on failure), so no local signature variable is
    required for the detector to trust them."""
    webhook_file = tmp_path / "webhook.py"
    webhook_file.write_text(
        """
def webhook_handler(request):
    event = stripe.Webhook.construct_event(
        request.body, request.headers.get("Stripe-Signature"), endpoint_secret
    )
    process_event(event)
"""
    )
    findings = analyze_file(str(webhook_file))
    assert findings == []


def test_async_webhook_handlers_are_analyzed(tmp_path):
    webhook_file = tmp_path / "webhook.py"
    webhook_file.write_text(
        """
async def webhook_handler(request):
    await process_event(request)
"""
    )
    findings = analyze_file(str(webhook_file))
    assert any(finding["rule_id"] == "WEBHOOK-001" for finding in findings)


def test_non_webhook_functions_are_ignored(tmp_path):
    webhook_file = tmp_path / "webhook.py"
    webhook_file.write_text(
        """
def homepage(request):
    return render(request, "index.html")
"""
    )
    findings = analyze_file(str(webhook_file))
    assert findings == []


def test_missing_file_raises_file_not_found_error(tmp_path):
    import pytest

    with pytest.raises(FileNotFoundError):
        analyze_file(str(tmp_path / "does_not_exist.py"))


def test_invalid_syntax_raises_syntax_error(tmp_path):
    import pytest

    webhook_file = tmp_path / "webhook.py"
    webhook_file.write_text("def webhook_handler(request:\n    pass")

    with pytest.raises(SyntaxError):
        analyze_file(str(webhook_file))


def test_legacy_webhook_analyzer_import_delegates_to_canonical_detector():
    with pytest.warns(
        DeprecationWarning,
        match="webhook_analyzer is a deprecated compatibility shim",
    ):
        from analyzer import webhook_analyzer

    from analyzer.detectors import webhook

    assert webhook_analyzer.analyze_file is webhook.analyze_file
    assert webhook_analyzer.WebhookDetector is webhook.WebhookDetector


def test_legacy_webhook_analyzer_exports_public_constants():
    from analyzer import webhook_analyzer
    from analyzer.detectors import webhook

    assert (
        webhook_analyzer.RULE_MISSING_SIGNATURE
        == webhook.RULE_MISSING_SIGNATURE
    )
    assert webhook_analyzer.RULE_WEAK_SIGNATURE == webhook.RULE_WEAK_SIGNATURE
    assert webhook_analyzer.SEVERITY_CRITICAL == webhook.SEVERITY_CRITICAL
    assert webhook_analyzer.SEVERITY_HIGH == webhook.SEVERITY_HIGH
    assert webhook_analyzer.main is webhook.main


def test_legacy_webhook_analyzer_import_produces_same_findings():
    from analyzer import webhook_analyzer
    from analyzer.detectors import webhook

    target = "integrations/broken_webhook/app.py"

    legacy_findings = webhook_analyzer.analyze_file(target)
    canonical_findings = webhook.analyze_file(target)

    assert legacy_findings == canonical_findings


def test_crypto_comparison_without_enforcement_is_not_trusted(tmp_path):
    webhook_file = tmp_path / "webhook.py"
    webhook_file.write_text(
        """
import hmac

def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    expected = "expected-signature"

    hmac.compare_digest(signature, expected)

    process_event(request)
"""
    )

    findings = analyze_file(str(webhook_file))

    assert any(
        finding["rule_id"] == "WEBHOOK-001"
        for finding in findings
    )


def test_accepts_signature_after_simple_reassignment(tmp_path):
    webhook_file = tmp_path / "webhook.py"
    webhook_file.write_text(
        """
import hmac

def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    sig = signature
    expected = "expected-signature"

    if hmac.compare_digest(sig, expected):
        process_event(request)
"""
    )

    findings = analyze_file(str(webhook_file))

    assert not any(
        finding["rule_id"] == "WEBHOOK-001" for finding in findings
    )
    assert not any(
        finding["rule_id"] == "WEBHOOK-003" for finding in findings
    )
