"""Tests for analyzer.ai.investigator: Gemini and NVIDIA providers,
plus AI_PROVIDER selection logic.

Both providers are mocked at their client-construction boundary
(genai.Client for Gemini, OpenAI for NVIDIA) so no real network calls
or API keys are used.
"""

import json
import logging
from unittest.mock import MagicMock

import openai
import pytest
from google.genai.errors import APIError

from analyzer.ai.investigator import (
    GeminiInvestigator,
    InvestigatorAPIError,
    InvestigatorConfigError,
    InvestigatorParseError,
    NvidiaInvestigator,
    _build_investigator,
)

logger = logging.getLogger(__name__)
"""Tests for the NVIDIA provider and AI_PROVIDER selection logic.

These mock the `openai` client boundary the same way test_investigator.py
mocks the Gemini client boundary: no real network calls are made. NVIDIA's
API cannot be reached from this test environment regardless (and never
should be, from unit tests -- see the docstring in investigator.py).
"""


logger = logging.getLogger(__name__)


def _mock_openai_response(payload: dict) -> MagicMock:
    """Build a mock matching the shape of an OpenAI/NVIDIA chat completion."""

    response = MagicMock()
    response.choices = [MagicMock()]
    response.choices[0].message.content = json.dumps(payload)
    return response


def test_nvidia_investigator_requires_api_key(monkeypatch):
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)

    with pytest.raises(InvestigatorConfigError):
        NvidiaInvestigator()


def test_nvidia_investigator_rejects_empty_model(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")
    monkeypatch.setenv("NVIDIA_MODEL", "   ")

    with pytest.raises(InvestigatorConfigError):
        NvidiaInvestigator()


def test_nvidia_investigator_returns_true_positive(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")

    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.OpenAI",
        lambda api_key, base_url: mock_client,
    )

    mock_client.chat.completions.create.return_value = _mock_openai_response(
        {
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
    )

    investigator = NvidiaInvestigator(max_retries=0)

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
    assert len(result.evidence) == 2

    # Confirm the JSON-schema-constrained request shape was used, and that
    # thinking is disabled so message.content is pure JSON.
    _, kwargs = mock_client.chat.completions.create.call_args
    assert kwargs["response_format"]["type"] == "json_schema"
    assert kwargs["extra_body"]["chat_template_kwargs"]["enable_thinking"] is False

    mock_client.chat.completions.create.assert_called_once()


def test_nvidia_investigator_rejects_empty_response(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")

    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.OpenAI",
        lambda api_key, base_url: mock_client,
    )

    empty_response = MagicMock()
    empty_response.choices = [MagicMock()]
    empty_response.choices[0].message.content = ""
    mock_client.chat.completions.create.return_value = empty_response

    investigator = NvidiaInvestigator(max_retries=0)

    with pytest.raises(InvestigatorParseError, match="no investigation data"):
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


def test_nvidia_investigator_rejects_malformed_json(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")

    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.OpenAI",
        lambda api_key, base_url: mock_client,
    )

    bad_response = MagicMock()
    bad_response.choices = [MagicMock()]
    bad_response.choices[0].message.content = "not valid json {"
    mock_client.chat.completions.create.return_value = bad_response

    investigator = NvidiaInvestigator(max_retries=0)

    with pytest.raises(InvestigatorParseError, match="expected investigation schema"):
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


def test_nvidia_investigator_rejects_invalid_schema(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")

    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.OpenAI",
        lambda api_key, base_url: mock_client,
    )

    bad_response = MagicMock()
    bad_response.choices = [MagicMock()]
    bad_response.choices[0].message.content = json.dumps(
        {
            "verdict": "TRUE_POSITIVE",
        }
    )

    mock_client.chat.completions.create.return_value = bad_response

    investigator = NvidiaInvestigator(max_retries=0)

    with pytest.raises(
        InvestigatorParseError,
        match="expected investigation schema",
    ):
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


def test_nvidia_investigator_retries_on_503(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")

    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.OpenAI",
        lambda api_key, base_url: mock_client,
    )
    monkeypatch.setattr(
        "analyzer.ai.investigator.time.sleep",
        lambda seconds: None,
    )

    # Build a real InternalServerError (5xx) the way the openai SDK does,
    # rather than guessing its constructor signature.
    mock_request = MagicMock()
    server_error = openai.InternalServerError(
        message="Service unavailable",
        response=MagicMock(status_code=503, headers={}),
        body=None,
    )

    success_response = _mock_openai_response(
        {
            "verdict": "TRUE_POSITIVE",
            "confidence": "HIGH",
            "explanation": "The finding is valid.",
            "evidence": ["The payment operation is unsafe."],
            "files_examined": ["payment.py"],
        }
    )

    mock_client.chat.completions.create.side_effect = [
        server_error,
        success_response,
    ]

    investigator = NvidiaInvestigator(max_retries=1, retry_backoff_seconds=0)

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
    assert mock_client.chat.completions.create.call_count == 2


def test_nvidia_investigator_does_not_retry_permanent_400(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")

    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.OpenAI",
        lambda api_key, base_url: mock_client,
    )
    monkeypatch.setattr(
        "analyzer.ai.investigator.time.sleep",
        lambda seconds: None,
    )

    bad_request_error = openai.BadRequestError(
        message="The request is invalid.",
        response=MagicMock(status_code=400, headers={}),
        body=None,
    )

    mock_client.chat.completions.create.side_effect = bad_request_error

    investigator = NvidiaInvestigator(max_retries=2, retry_backoff_seconds=0)

    with pytest.raises(InvestigatorAPIError, match="400"):
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

    # A permanent 400 must not be retried.
    assert mock_client.chat.completions.create.call_count == 1


def test_nvidia_investigator_retries_on_rate_limit(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")

    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.OpenAI",
        lambda api_key, base_url: mock_client,
    )
    monkeypatch.setattr(
        "analyzer.ai.investigator.time.sleep",
        lambda seconds: None,
    )

    rate_limit_error = openai.RateLimitError(
        message="Too many requests.",
        response=MagicMock(status_code=429, headers={}),
        body=None,
    )

    success_response = _mock_openai_response(
        {
            "verdict": "TRUE_POSITIVE",
            "confidence": "MEDIUM",
            "explanation": "The finding is valid.",
            "evidence": ["The payment operation is unsafe."],
            "files_examined": ["payment.py"],
        }
    )

    mock_client.chat.completions.create.side_effect = [
        rate_limit_error,
        success_response,
    ]

    investigator = NvidiaInvestigator(max_retries=1, retry_backoff_seconds=0)

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
    assert mock_client.chat.completions.create.call_count == 2


def test_nvidia_investigator_retries_network_disconnect(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")

    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.OpenAI",
        lambda api_key, base_url: mock_client,
    )
    monkeypatch.setattr(
        "analyzer.ai.investigator.time.sleep",
        lambda seconds: None,
    )

    connection_error = openai.APIConnectionError(
        message="Server disconnected without sending a response",
        request=MagicMock(),
    )

    success_response = _mock_openai_response(
        {
            "verdict": "UNCERTAIN",
            "confidence": "LOW",
            "explanation": "The request succeeded after a network failure.",
            "evidence": ["The supplied source is incomplete."],
            "files_examined": ["webhook.py"],
        }
    )

    mock_client.chat.completions.create.side_effect = [
        connection_error,
        success_response,
    ]

    investigator = NvidiaInvestigator(max_retries=1, retry_backoff_seconds=0)

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
    assert mock_client.chat.completions.create.call_count == 2


def test_nvidia_investigator_stops_after_repeated_failures(monkeypatch):
    monkeypatch.setenv("NVIDIA_API_KEY", "test-key")

    mock_client = MagicMock()
    monkeypatch.setattr(
        "analyzer.ai.investigator.OpenAI",
        lambda api_key, base_url: mock_client,
    )
    monkeypatch.setattr(
        "analyzer.ai.investigator.time.sleep",
        lambda seconds: None,
    )

    mock_client.chat.completions.create.side_effect = RuntimeError(
        "NVIDIA service unavailable"
    )

    investigator = NvidiaInvestigator(max_retries=2, retry_backoff_seconds=0)

    with pytest.raises(InvestigatorAPIError, match="failed after 3 attempts"):
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

    assert mock_client.chat.completions.create.call_count == 3


# --- Provider selection ---------------------------------------------------


def test_build_investigator_defaults_to_nvidia_when_both_keys_present(monkeypatch):
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.setenv("NVIDIA_API_KEY", "nvidia-key")
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")

    monkeypatch.setattr(
        "analyzer.ai.investigator.OpenAI",
        lambda api_key, base_url: MagicMock(),
    )

    investigator = _build_investigator()
    assert isinstance(investigator, NvidiaInvestigator)


def test_build_investigator_uses_gemini_when_only_gemini_key_present(monkeypatch):
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")

    monkeypatch.setattr(
        "analyzer.ai.investigator.genai.Client",
        lambda api_key: MagicMock(),
    )

    investigator = _build_investigator()
    assert isinstance(investigator, GeminiInvestigator)


def test_build_investigator_falls_back_to_gemini_if_nvidia_misconfigured(monkeypatch):
    # AI_PROVIDER explicitly asks for nvidia, but no NVIDIA key is set --
    # should fall back to Gemini rather than hard failing, since a Gemini
    # key is available.
    monkeypatch.setenv("AI_PROVIDER", "nvidia")
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")

    monkeypatch.setattr(
        "analyzer.ai.investigator.genai.Client",
        lambda api_key: MagicMock(),
    )

    investigator = _build_investigator()
    assert isinstance(investigator, GeminiInvestigator)


def test_build_investigator_raises_when_nothing_configured(monkeypatch):
    monkeypatch.delenv("AI_PROVIDER", raising=False)
    monkeypatch.delenv("NVIDIA_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    with pytest.raises(InvestigatorConfigError, match="No AI provider"):
        _build_investigator()


def test_build_investigator_rejects_unknown_provider(monkeypatch):
    monkeypatch.setenv("AI_PROVIDER", "openai-direct")

    with pytest.raises(InvestigatorConfigError, match="not recognized"):
        _build_investigator()


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


def test_build_prompt_explains_valid_security_guard():
    investigator = NvidiaInvestigator.__new__(NvidiaInvestigator)

    prompt = investigator._build_prompt(
        finding={
            "rule_id": "WEBHOOK-001",
            "type": "MISSING_WEBHOOK_SIGNATURE",
            "severity": "CRITICAL",
            "file": "webhook.py",
            "line": 10,
            "message": "Webhook signature verification is missing.",
        },
        source_code="""
def webhook():
    if not verify_signature(payload, signature, secret):
        return "Invalid signature", 401

    process_payment(data)
""",
        file_path="webhook.py",
    )

    assert "valid security gate" in prompt
    assert "Continuing to the sensitive operation" in prompt
    assert "invalid or unverified request" in prompt


def test_build_prompt_includes_known_rule_guidance():
    investigator = GeminiInvestigator.__new__(
        GeminiInvestigator)  # skip __init__/config

    prompt = investigator._build_prompt(
        finding={
            "rule_id": "WEBHOOK-001",
            "type": "MISSING_WEBHOOK_SIGNATURE",
            "severity": "CRITICAL",
            "file": "webhook.py",
            "line": 10,
            "message": "Webhook signature verification is missing.",
        },
        source_code="def webhook(): pass",
        file_path="webhook.py",
    )

    assert "WHY THIS RULE EXISTS" in prompt
    assert "reachable by anyone on the internet" in prompt


def test_build_prompt_falls_back_for_unknown_rule():
    investigator = GeminiInvestigator.__new__(GeminiInvestigator)

    prompt = investigator._build_prompt(
        finding={
            "rule_id": "UNKNOWN-999",
            "type": "SOMETHING_ELSE",
            "severity": "LOW",
            "file": "x.py",
            "line": 1,
            "message": "n/a",
        },
        source_code="pass",
        file_path="x.py",
    )

    assert "No additional rule-specific context is available" in prompt


def test_build_prompt_requires_control_flow_analysis_for_webhooks():
    investigator = NvidiaInvestigator.__new__(NvidiaInvestigator)

    prompt = investigator._build_prompt(
        finding={
            "rule_id": "WEBHOOK-001",
            "type": "MISSING_WEBHOOK_SIGNATURE",
            "severity": "CRITICAL",
            "file": "webhook.py",
            "line": 10,
            "message": "Webhook signature verification is missing.",
        },
        source_code="def webhook(): pass",
        file_path="webhook.py",
    )

    assert "trace the actual control flow" in prompt
    assert "invalid or unverified request" in prompt
    assert "sensitive operation" in prompt
