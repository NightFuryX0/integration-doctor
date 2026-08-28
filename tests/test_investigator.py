
from unittest.mock import MagicMock
from analyzer.ai.investigator import (
    GeminiInvestigator,
    InvestigatorAPIError,
    InvestigatorParseError,
)
from google.genai.errors import APIError
from analyzer.ai.investigator import GeminiInvestigator
import logging
import time
from google.genai import types
logger = logging.getLogger(__name__)


def test_investigator_returns_true_positive_from_mocked_gemini(
    monkeypatch,
):
    # Provide a fake API key so the real Gemini configuration check passes.
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    # Replace the real Gemini client constructor with a mock.
    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.genai.Client",
        lambda api_key: mock_client,
    )

    # Simulate the structured response Gemini would normally return.
    mock_response = MagicMock()
    mock_response.parsed = {
        "verdict": "TRUE_POSITIVE",
        "confidence": "HIGH",
        "explanation": (
            "The webhook processes the request without verifying "
            "the provider signature."
        ),
        "evidence": [
            "The endpoint directly processes the webhook request.",
            "No cryptographic signature verification is performed.",
        ],
        "files_examined": [
            "integrations/broken_webhook/app.py",
        ],
    }

    # Make the mocked Gemini API return our fake response.
    mock_client.models.generate_content.return_value = mock_response

    investigator = GeminiInvestigator(
        max_retries=0,
    )

    result = investigator.investigate(
        finding={
            "rule_id": "WEBHOOK-001",
            "type": "MISSING_WEBHOOK_SIGNATURE",
            "severity": "CRITICAL",
            "file": "integrations/broken_webhook/app.py",
            "line": 10,
            "message": "Webhook signature verification is missing.",
        },
        source_code="""
@app.route("/webhook", methods=["POST"])
def webhook():
    data = request.get_json()
    process_payment(data)
""",
        file_path="integrations/broken_webhook/app.py",
    )

    assert result.verdict == "TRUE_POSITIVE"
    assert result.confidence == "HIGH"
    assert "signature" in result.explanation.lower()
    assert len(result.evidence) == 2
    assert result.files_examined == [
        "integrations/broken_webhook/app.py",
    ]

    # Verify that our test used the mocked Gemini client instead of
    # making a real API request.
    mock_client.models.generate_content.assert_called_once()


def test_investigator_returns_false_positive_from_mocked_gemini(
    monkeypatch,
):
    # Provide a fake API key so the real Gemini configuration check passes.
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    # Replace the real Gemini client with a mock.
    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.genai.Client",
        lambda api_key: mock_client,
    )

    # Simulate Gemini determining that the detector was mistaken.
    mock_response = MagicMock()
    mock_response.parsed = {
        "verdict": "FALSE_POSITIVE",
        "confidence": "HIGH",
        "explanation": (
            "The webhook is protected by middleware that performs "
            "signature verification before the handler runs."
        ),
        "evidence": [
            "The route uses signature-verification middleware.",
        ],
        "files_examined": [
            "middleware.py",
        ],
    }

    mock_client.models.generate_content.return_value = mock_response

    investigator = GeminiInvestigator(max_retries=0)

    result = investigator.investigate(
        finding={
            "rule_id": "WEBHOOK-001",
            "type": "MISSING_WEBHOOK_SIGNATURE",
            "severity": "CRITICAL",
            "file": "webhook.py",
            "line": 10,
            "message": "Webhook signature verification is missing.",
        },
        source_code="def webhook():\n    process_webhook()",
        file_path="webhook.py",
    )

    assert result.verdict == "FALSE_POSITIVE"
    assert result.confidence == "HIGH"
    assert "middleware" in result.explanation.lower()
    assert result.files_examined == ["middleware.py"]


def test_investigator_returns_uncertain_from_mocked_gemini(
    monkeypatch,
):
    # Provide a fake API key so the real Gemini configuration check passes.
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    # Replace the real Gemini client with a mock.
    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.genai.Client",
        lambda api_key: mock_client,
    )

    # Simulate Gemini deciding that the supplied evidence is insufficient.
    mock_response = MagicMock()
    mock_response.parsed = {
        "verdict": "UNCERTAIN",
        "confidence": "LOW",
        "explanation": (
            "The supplied source does not contain enough information "
            "to determine whether signature verification occurs elsewhere."
        ),
        "evidence": [
            "The webhook handler is shown, but related middleware "
            "implementation is unavailable."
        ],
        "files_examined": [
            "webhook.py",
        ],
    }

    mock_client.models.generate_content.return_value = mock_response

    investigator = GeminiInvestigator(max_retries=0)

    result = investigator.investigate(
        finding={
            "rule_id": "WEBHOOK-001",
            "type": "MISSING_WEBHOOK_SIGNATURE",
            "severity": "CRITICAL",
            "file": "webhook.py",
            "line": 10,
            "message": "Webhook signature verification is missing.",
        },
        source_code="def webhook():\n    process_webhook()",
        file_path="webhook.py",
    )

    assert result.verdict == "UNCERTAIN"
    assert result.confidence == "LOW"
    assert "enough information" in result.explanation.lower()
    assert result.files_examined == ["webhook.py"]


def test_investigator_rejects_empty_gemini_response(
    monkeypatch,
):
    # Provide a fake API key so the real Gemini configuration check passes.
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    # Replace the real Gemini client with a mock.
    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.genai.Client",
        lambda api_key: mock_client,
    )

    # Simulate Gemini returning no parsed structured response.
    mock_response = MagicMock()
    mock_response.parsed = None
    mock_response.text = ""

    mock_client.models.generate_content.return_value = mock_response

    investigator = GeminiInvestigator(max_retries=0)

    try:
        investigator.investigate(
            finding={
                "rule_id": "WEBHOOK-001",
                "type": "MISSING_WEBHOOK_SIGNATURE",
                "severity": "CRITICAL",
                "file": "webhook.py",
                "line": 10,
                "message": "Webhook signature verification is missing.",
            },
            source_code="def webhook():\n    process_webhook()",
            file_path="webhook.py",
        )

        assert False, "Expected InvestigatorParseError"
    except InvestigatorParseError as error:
        assert "could not be parsed" in str(error)


def test_investigator_rejects_malformed_structured_response(
    monkeypatch,
):
    # Provide a fake API key so the real Gemini configuration check passes.
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    # Replace the real Gemini client with a mock.
    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.genai.Client",
        lambda api_key: mock_client,
    )

    # Simulate Gemini returning data that violates the expected schema.
    mock_response = MagicMock()
    mock_response.parsed = {
        "verdict": "NOT_A_VALID_VERDICT",
        "confidence": "HIGH",
        "explanation": "Malformed response.",
        "evidence": [],
        "files_examined": [],
    }

    mock_client.models.generate_content.return_value = mock_response

    investigator = GeminiInvestigator(max_retries=0)

    try:
        investigator.investigate(
            finding={
                "rule_id": "WEBHOOK-001",
                "type": "MISSING_WEBHOOK_SIGNATURE",
                "severity": "CRITICAL",
                "file": "webhook.py",
                "line": 10,
                "message": "Webhook signature verification is missing.",
            },
            source_code="def webhook():\n    process_webhook()",
            file_path="webhook.py",
        )

        assert False, "Expected InvestigatorParseError"
    except InvestigatorParseError as error:
        assert "expected investigation schema" in str(error)


def test_investigator_retries_after_temporary_api_failure(
    monkeypatch,
):
    # Provide a fake API key so the real Gemini configuration check passes.
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    # Replace the real Gemini client with a mock.
    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.genai.Client",
        lambda api_key: mock_client,
    )

    # Avoid actually waiting during the retry backoff.
    monkeypatch.setattr(
        "analyzer.ai.investigator.time.sleep",
        lambda seconds: None,
    )

    # First request fails, second request succeeds.
    mock_response = MagicMock()
    mock_response.parsed = {
        "verdict": "TRUE_POSITIVE",
        "confidence": "MEDIUM",
        "explanation": "The payment operation is not protected.",
        "evidence": ["The payment operation can be retried directly."],
        "files_examined": ["payment.py"],
    }

    mock_client.models.generate_content.side_effect = [
        RuntimeError("temporary Gemini failure"),
        mock_response,
    ]

    investigator = GeminiInvestigator(
        max_retries=1,
        retry_backoff_seconds=0,
    )

    result = investigator.investigate(
        finding={
            "rule_id": "PAYMENT-003",
            "type": "POTENTIALLY_UNSAFE_RETRY",
            "severity": "HIGH",
            "file": "payment.py",
            "line": 20,
            "message": "Payment operation may be retried unsafely.",
        },
        source_code="charge_payment()",
        file_path="payment.py",
    )

    assert result.verdict == "TRUE_POSITIVE"
    assert result.confidence == "MEDIUM"

    # The API should have been called twice:
    # once for the failed attempt and once for the successful retry.
    assert mock_client.models.generate_content.call_count == 2


def test_investigator_raises_api_error_after_all_retries_fail(
    monkeypatch,
):
    # Provide a fake API key so the real Gemini configuration check passes.
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    # Replace the real Gemini client with a mock.
    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.genai.Client",
        lambda api_key: mock_client,
    )

    # Avoid real retry delays.
    monkeypatch.setattr(
        "analyzer.ai.investigator.time.sleep",
        lambda seconds: None,
    )

    # Simulate Gemini failing every time.
    mock_client.models.generate_content.side_effect = RuntimeError(
        "Gemini service unavailable"
    )

    investigator = GeminiInvestigator(
        max_retries=2,
        retry_backoff_seconds=0,
    )

    try:
        investigator.investigate(
            finding={
                "rule_id": "WEBHOOK-001",
                "type": "MISSING_WEBHOOK_SIGNATURE",
                "severity": "CRITICAL",
                "file": "webhook.py",
                "line": 10,
                "message": "Webhook signature verification is missing.",
            },
            source_code="def webhook():\n    process_webhook()",
            file_path="webhook.py",
        )

        assert False, "Expected InvestigatorAPIError"
    except InvestigatorAPIError as error:
        assert "failed after 3 attempts" in str(error)
        assert "Gemini service unavailable" in str(error)

    # max_retries=2 means:
    # initial attempt + 2 retries = 3 total API calls.
    assert mock_client.models.generate_content.call_count == 3


def test_investigator_retries_network_disconnect(
    monkeypatch,
):
    # Provide a fake API key so the real Gemini configuration check passes.
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    # Replace the real Gemini client with a mock.
    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.genai.Client",
        lambda api_key: mock_client,
    )

    # Avoid real retry delays.
    monkeypatch.setattr(
        "analyzer.ai.investigator.time.sleep",
        lambda seconds: None,
    )

    # Simulate the type of transport failure encountered with Gemini.
    mock_response = MagicMock()
    mock_response.parsed = {
        "verdict": "UNCERTAIN",
        "confidence": "LOW",
        "explanation": "The request succeeded after a network failure.",
        "evidence": ["The supplied source is incomplete."],
        "files_examined": ["webhook.py"],
    }

    mock_client.models.generate_content.side_effect = [
        ConnectionError("Server disconnected without sending a response"),
        mock_response,
    ]

    investigator = GeminiInvestigator(
        max_retries=1,
        retry_backoff_seconds=0,
    )

    result = investigator.investigate(
        finding={
            "rule_id": "WEBHOOK-001",
            "type": "MISSING_WEBHOOK_SIGNATURE",
            "severity": "CRITICAL",
            "file": "webhook.py",
            "line": 10,
            "message": "Webhook signature verification is missing.",
        },
        source_code="def webhook():\n    process_webhook()",
        file_path="webhook.py",
    )

    assert result.verdict == "UNCERTAIN"
    assert result.confidence == "LOW"
    assert mock_client.models.generate_content.call_count == 2


def test_investigator_retries_on_gemini_503(
    monkeypatch,
):
    # Provide a fake API key so the real Gemini configuration check passes.
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    # Replace the real Gemini client with a mock.
    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.genai.Client",
        lambda api_key: mock_client,
    )

    # Avoid real retry delays.
    monkeypatch.setattr(
        "analyzer.ai.investigator.time.sleep",
        lambda seconds: None,
    )

    # Simulate the 503 error previously encountered with Gemini.
    api_error = APIError(
        code=503,
        response_json={
            "error": {
                "status": "UNAVAILABLE",
                "message": "This model is currently experiencing high demand.",
            }
        },
    )

    # The first request gets a 503.
    # The retry then succeeds.
    mock_response = MagicMock()
    mock_response.parsed = {
        "verdict": "TRUE_POSITIVE",
        "confidence": "HIGH",
        "explanation": "The finding is valid.",
        "evidence": ["The payment operation is unsafe."],
        "files_examined": ["payment.py"],
    }

    mock_client.models.generate_content.side_effect = [
        api_error,
        mock_response,
    ]

    investigator = GeminiInvestigator(
        max_retries=1,
        retry_backoff_seconds=0,
    )

    result = investigator.investigate(
        finding={
            "rule_id": "PAYMENT-003",
            "type": "POTENTIALLY_UNSAFE_RETRY",
            "severity": "HIGH",
            "file": "payment.py",
            "line": 20,
            "message": "Payment operation may be retried unsafely.",
        },
        source_code="charge_payment()",
        file_path="payment.py",
    )

    assert result.verdict == "TRUE_POSITIVE"
    assert result.confidence == "HIGH"

    # 503 should result in one retry.
    assert mock_client.models.generate_content.call_count == 2


def test_investigator_does_not_retry_permanent_api_error(
    monkeypatch,
):
    # Provide a fake API key so the real Gemini configuration check passes.
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    # Replace the real Gemini client with a mock.
    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.genai.Client",
        lambda api_key: mock_client,
    )

    # Avoid real retry delays.
    monkeypatch.setattr(
        "analyzer.ai.investigator.time.sleep",
        lambda seconds: None,
    )

    # Simulate a permanent 400 Bad Request from Gemini.
    api_error = APIError(
        code=400,
        response_json={
            "error": {
                "status": "INVALID_ARGUMENT",
                "message": "The request is invalid.",
            }
        },
    )

    mock_client.models.generate_content.side_effect = api_error

    investigator = GeminiInvestigator(
        max_retries=2,
        retry_backoff_seconds=0,
    )

    try:
        investigator.investigate(
            finding={
                "rule_id": "WEBHOOK-001",
                "type": "MISSING_WEBHOOK_SIGNATURE",
                "severity": "CRITICAL",
                "file": "webhook.py",
                "line": 10,
                "message": "Webhook signature verification is missing.",
            },
            source_code="def webhook():\n    process_webhook()",
            file_path="webhook.py",
        )

        assert False, "Expected InvestigatorAPIError"
    except InvestigatorAPIError as error:
        assert "400" in str(error)

    # A permanent 400 error should not be retried.
    assert mock_client.models.generate_content.call_count == 1


def test_investigator_retries_on_rate_limit(
    monkeypatch,
):
    # Provide a fake API key so the real Gemini configuration check passes.
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    # Replace the real Gemini client with a mock.
    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.genai.Client",
        lambda api_key: mock_client,
    )

    # Avoid real retry delays.
    monkeypatch.setattr(
        "analyzer.ai.investigator.time.sleep",
        lambda seconds: None,
    )

    # Simulate Gemini rate limiting the first request.
    rate_limit_error = APIError(
        code=429,
        response_json={
            "error": {
                "status": "RESOURCE_EXHAUSTED",
                "message": "Too many requests.",
            }
        },
    )

    # The retry succeeds.
    mock_response = MagicMock()
    mock_response.parsed = {
        "verdict": "TRUE_POSITIVE",
        "confidence": "MEDIUM",
        "explanation": "The finding is valid.",
        "evidence": ["The payment operation is unsafe."],
        "files_examined": ["payment.py"],
    }

    mock_client.models.generate_content.side_effect = [
        rate_limit_error,
        mock_response,
    ]

    investigator = GeminiInvestigator(
        max_retries=1,
        retry_backoff_seconds=0,
    )

    result = investigator.investigate(
        finding={
            "rule_id": "PAYMENT-003",
            "type": "POTENTIALLY_UNSAFE_RETRY",
            "severity": "HIGH",
            "file": "payment.py",
            "line": 20,
            "message": "Payment operation may be retried unsafely.",
        },
        source_code="charge_payment()",
        file_path="payment.py",
    )

    assert result.verdict == "TRUE_POSITIVE"
    assert result.confidence == "MEDIUM"

    # 429 should result in one bounded retry.
    assert mock_client.models.generate_content.call_count == 2


def test_investigator_stops_after_repeated_rate_limits(
    monkeypatch,
):
    # Provide a fake API key so the real Gemini configuration check passes.
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    # Replace the real Gemini client with a mock.
    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.genai.Client",
        lambda api_key: mock_client,
    )

    # Avoid real retry delays.
    monkeypatch.setattr(
        "analyzer.ai.investigator.time.sleep",
        lambda seconds: None,
    )

    # Simulate Gemini remaining rate-limited on every attempt.
    rate_limit_error = APIError(
        code=429,
        response_json={
            "error": {
                "status": "RESOURCE_EXHAUSTED",
                "message": "Too many requests.",
            }
        },
    )

    mock_client.models.generate_content.side_effect = rate_limit_error

    investigator = GeminiInvestigator(
        max_retries=2,
        retry_backoff_seconds=0,
    )

    try:
        investigator.investigate(
            finding={
                "rule_id": "WEBHOOK-001",
                "type": "MISSING_WEBHOOK_SIGNATURE",
                "severity": "CRITICAL",
                "file": "webhook.py",
                "line": 10,
                "message": "Webhook signature verification is missing.",
            },
            source_code="def webhook():\n    process_webhook()",
            file_path="webhook.py",
        )

        assert False, "Expected InvestigatorAPIError"

    except InvestigatorAPIError as error:
        assert "failed after 3 attempts" in str(error)

    # max_retries=2 means:
    # initial attempt + 2 retries = 3 total attempts.
    assert mock_client.models.generate_content.call_count == 3
