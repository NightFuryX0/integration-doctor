from analyzer import scanner
from analyzer.ai.investigator import InvestigatorAPIError


def test_ai_failure_does_not_crash_scanner(monkeypatch):
    # Create a static finding that would normally be sent to the AI investigator.
    findings = [
        {
            "rule_id": "WEBHOOK-001",
            "type": "MISSING_WEBHOOK_SIGNATURE",
            "severity": "CRITICAL",
            "file": "webhook.py",
            "line": 10,
            "message": "Webhook signature verification is missing.",
        }
    ]

    # Replace the AI investigation function with a fake failure.
    def fake_investigate_file(finding):
        raise InvestigatorAPIError(  # Fixed: use the exception imported from its actual module.
            "Gemini service unavailable"
        )

    # Patch the function used by investigate_findings().
    monkeypatch.setattr(
        "analyzer.ai.investigator.investigate_file",
        fake_investigate_file,
    )

    # Run AI investigation.
    results = scanner.investigate_findings(findings)

    # The AI failure should not crash the scanner.
    assert results == []


def test_ai_failure_does_not_prevent_remaining_findings(
    monkeypatch,
):
    # Create multiple static findings.
    findings = [
        {
            "rule_id": "WEBHOOK-001",
            "type": "MISSING_WEBHOOK_SIGNATURE",
            "severity": "CRITICAL",
            "file": "webhook.py",
            "line": 10,
            "message": "Webhook signature verification is missing.",
        },
        {
            "rule_id": "PAYMENT-003",
            "type": "POTENTIALLY_UNSAFE_RETRY",
            "severity": "HIGH",
            "file": "payment.py",
            "line": 20,
            "message": "Payment operation may be retried unsafely.",
        },
    ]

    # Track which findings reached the AI investigator.
    calls = []

    def fake_investigate_file(finding):
        calls.append(finding["rule_id"])

        # Simulate Gemini failing for the first finding.
        if finding["rule_id"] == "WEBHOOK-001":
            raise InvestigatorAPIError(
                "Gemini service unavailable"
            )

        # Simulate a successful investigation for the second finding.
        return type(
            "FakeResult",
            (),
            {
                "verdict": "TRUE_POSITIVE",
                "confidence": "HIGH",
            },
        )()

    # Patch the investigator used by the scanner.
    monkeypatch.setattr(
        "analyzer.ai.investigator.investigate_file",
        fake_investigate_file,
    )

    # Prevent display formatting from becoming part of this test.
    monkeypatch.setattr(
        "analyzer.ai.display.print_investigation",
        lambda result: None,
    )

    results = scanner.investigate_findings(findings)

    # Both findings should have reached the investigator.
    assert calls == [
        "WEBHOOK-001",
        "PAYMENT-003",
    ]

    # The failed first investigation should not prevent
    # the second investigation from succeeding.
    assert len(results) == 1
    assert results[0]["finding"]["rule_id"] == "PAYMENT-003"
    assert results[0]["investigation"].verdict == "TRUE_POSITIVE"


def test_scanner_attaches_ai_investigation_to_finding(
    monkeypatch,
):
    # Create a static finding that should be investigated by the AI.
    findings = [
        {
            "rule_id": "WEBHOOK-001",
            "type": "MISSING_WEBHOOK_SIGNATURE",
            "severity": "CRITICAL",
            "file": "webhook.py",
            "line": 10,
            "message": "Webhook signature verification is missing.",
        }
    ]

    # Create a fake AI investigation result.
    fake_result = type(
        "FakeResult",
        (),
        {
            "verdict": "TRUE_POSITIVE",
            "confidence": "HIGH",
            "explanation": "The webhook has no signature verification.",
            "evidence": [
                "The webhook directly processes the request."
            ],
            "files_examined": [
                "webhook.py"
            ],
        },
    )()

    # Track the finding passed into the AI investigator.
    investigated_findings = []

    def fake_investigate_file(finding):
        investigated_findings.append(finding)
        return fake_result

    # Patch the investigator used by the scanner.
    monkeypatch.setattr(
        "analyzer.ai.investigator.investigate_file",
        fake_investigate_file,
    )

    # Prevent display output from becoming part of this test.
    monkeypatch.setattr(
        "analyzer.ai.display.print_investigation",
        lambda result: None,
    )

    results = scanner.investigate_findings(findings)

    # The scanner should have sent the static finding to the AI.
    assert investigated_findings == [findings[0]]

    # The scanner should return one enriched result.
    assert len(results) == 1

    # The original finding should still be attached.
    assert results[0]["finding"] == findings[0]

    # The AI investigation should be attached to that finding.
    assert results[0]["investigation"] is fake_result

    # Verify the AI result survived the scanner unchanged.
    assert results[0]["investigation"].verdict == "TRUE_POSITIVE"
    assert results[0]["investigation"].confidence == "HIGH"
    assert (
        results[0]["investigation"].explanation
        == "The webhook has no signature verification."
    )
