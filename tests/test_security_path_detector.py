"""Tests for the SECURITY-001 repository-level detector."""

from __future__ import annotations

from pathlib import Path

import pytest

from analyzer.analysis.repository import build_repository_analysis
from analyzer.detectors.security_path import (
    SECURITY_RULE,
    SecurityPathRule,
    analyze_repository,
)


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def write_file(
    root: Path,
    relative_path: str,
    content: str,
) -> Path:
    """Create a source file inside a temporary repository."""

    file_path = root / relative_path
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(content, encoding="utf-8")

    return file_path


def build_analysis(
    root: Path,
):
    """Build the shared repository analysis used by detector tests."""

    return build_repository_analysis(root)


def run_detector(
    root: Path,
    *,
    rule: SecurityPathRule = SECURITY_RULE,
    max_depth: int = 20,
    max_paths: int = 10_000,
) -> list[dict]:
    """Build repository analysis and execute the detector."""

    analysis = build_analysis(root)

    return analyze_repository(
        analysis,
        rule=rule,
        max_depth=max_depth,
        max_paths=max_paths,
    )


def assert_no_findings(
    findings: list[dict],
) -> None:
    """Assert that the detector considers the repository clean."""

    assert findings == []


def assert_single_finding(
    findings: list[dict],
    *,
    rule_id: str = "SECURITY-001",
    finding_type: str = "UNPROTECTED_PAYMENT_PATH",
    severity: str = "CRITICAL",
) -> dict:
    """Assert and return the only finding."""

    assert len(findings) == 1

    finding = findings[0]

    assert finding["rule_id"] == rule_id
    assert finding["type"] == finding_type
    assert finding["severity"] == severity

    return finding


# ---------------------------------------------------------------------------
# Basic security paths
# ---------------------------------------------------------------------------


def test_reports_unprotected_webhook_to_charge(
    tmp_path: Path,
) -> None:
    """A webhook reaching a payment sink without a guard is vulnerable."""

    file_path = write_file(
        tmp_path,
        "payments.py",
        """
def webhook(request):
    charge(request)


def charge(request):
    pass
""",
    )

    findings = run_detector(tmp_path)

    finding = assert_single_finding(findings)

    assert finding["file"] == str(file_path.resolve())
    assert finding["line"] == 2
    assert "webhook" in finding["message"]
    assert "charge" in finding["message"]


def test_does_not_report_protected_webhook_to_charge(
    tmp_path: Path,
) -> None:
    """A guard between the webhook and sink protects the path."""

    write_file(
        tmp_path,
        "payments.py",
        """
def webhook(request):
    verify_signature(request)
    charge(request)


def verify_signature(request):
    pass


def charge(request):
    pass
""",
    )

    findings = run_detector(tmp_path)

    assert_no_findings(findings)


def test_detects_cross_file_unprotected_path(
    tmp_path: Path,
) -> None:
    """Security paths can cross module boundaries."""

    write_file(
        tmp_path,
        "webhooks.py",
        """
def webhook(request):
    process_payment(request)
""",
    )

    write_file(
        tmp_path,
        "payments.py",
        """
def process_payment(request):
    charge(request)


def charge(request):
    pass
""",
    )

    findings = run_detector(tmp_path)

    assert_single_finding(findings)


def test_cross_file_guard_protects_path(
    tmp_path: Path,
) -> None:
    """A guard in another module still protects the path."""

    write_file(
        tmp_path,
        "webhooks.py",
        """
from security import verify_signature
from payments import process_payment


def webhook(request):
    verify_signature(request)
    process_payment(request)
""",
    )

    write_file(
        tmp_path,
        "security.py",
        """
def verify_signature(request):
    pass
""",
    )

    write_file(
        tmp_path,
        "payments.py",
        """
def process_payment(request):
    charge(request)


def charge(request):
    pass
""",
    )

    findings = run_detector(tmp_path)

    assert_no_findings(findings)


# ---------------------------------------------------------------------------
# Multiple paths
# ---------------------------------------------------------------------------


def test_reports_unprotected_branch_even_when_another_branch_is_protected(
    tmp_path: Path,
) -> None:
    """Every possible entry-to-sink path must be protected."""

    write_file(
        tmp_path,
        "payments.py",
        """
def webhook(request):
    safe_payment(request)
    unsafe_payment(request)


def safe_payment(request):
    verify_signature(request)
    charge(request)


def unsafe_payment(request):
    charge(request)


def verify_signature(request):
    pass


def charge(request):
    pass
""",
    )

    findings = run_detector(tmp_path)

    finding = assert_single_finding(findings)

    assert "unsafe_payment" in finding["message"]


def test_reports_multiple_unprotected_sinks(
    tmp_path: Path,
) -> None:
    """Independent vulnerable sinks should produce separate findings."""

    write_file(
        tmp_path,
        "payments.py",
        """
def webhook(request):
    charge(request)
    create_payment(request)


def charge(request):
    pass


def create_payment(request):
    pass
""",
    )

    findings = run_detector(tmp_path)

    assert len(findings) == 2
    assert all(
        finding["rule_id"] == "SECURITY-001"
        for finding in findings
    )


# ---------------------------------------------------------------------------
# Negative cases
# ---------------------------------------------------------------------------


def test_normal_function_reaching_payment_is_not_a_webhook_finding(
    tmp_path: Path,
) -> None:
    """SECURITY-001 only concerns configured security entry points."""

    write_file(
        tmp_path,
        "payments.py",
        """
def normal_request(request):
    charge(request)


def charge(request):
    pass
""",
    )

    findings = run_detector(tmp_path)

    assert_no_findings(findings)


def test_webhook_without_payment_sink_is_clean(
    tmp_path: Path,
) -> None:
    """A webhook alone is not enough to trigger SECURITY-001."""

    write_file(
        tmp_path,
        "webhook.py",
        """
def webhook(request):
    process_event(request)


def process_event(request):
    print(request)
""",
    )

    findings = run_detector(tmp_path)

    assert_no_findings(findings)


def test_guard_without_security_flow_is_clean(
    tmp_path: Path,
) -> None:
    """A guard existing somewhere in the repository proves nothing."""

    write_file(
        tmp_path,
        "payments.py",
        """
def verify_signature(request):
    pass


def charge(request):
    pass
""",
    )

    findings = run_detector(tmp_path)

    assert_no_findings(findings)


# ---------------------------------------------------------------------------
# Configured guards
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "guard_name",
    sorted(SECURITY_RULE.guard_names),
)
def test_every_configured_guard_can_protect_a_path(
    tmp_path: Path,
    guard_name: str,
) -> None:
    """Every guard in the rule configuration should actually work."""

    write_file(
        tmp_path,
        "payments.py",
        f"""
def webhook(request):
    {guard_name}(request)
    charge(request)


def {guard_name}(request):
    pass


def charge(request):
    pass
""",
    )

    findings = run_detector(tmp_path)

    assert_no_findings(findings)


# ---------------------------------------------------------------------------
# Configured sinks
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "sink_name",
    sorted(SECURITY_RULE.sink_names),
)
def test_every_configured_sink_can_trigger_security_001(
    tmp_path: Path,
    sink_name: str,
) -> None:
    """Every configured sink should participate in security-flow analysis."""

    write_file(
        tmp_path,
        "payments.py",
        f"""
def webhook(request):
    {sink_name}(request)


def {sink_name}(request):
    pass
""",
    )

    findings = run_detector(tmp_path)

    assert_single_finding(findings)


# ---------------------------------------------------------------------------
# Async support
# ---------------------------------------------------------------------------


def test_async_webhook_path_is_detected(
    tmp_path: Path,
) -> None:
    """Async functions participate in the same security-flow analysis."""

    write_file(
        tmp_path,
        "payments.py",
        """
async def webhook(request):
    await charge(request)


async def charge(request):
    pass
""",
    )

    findings = run_detector(tmp_path)

    assert_single_finding(findings)


# ---------------------------------------------------------------------------
# Cycles and traversal limits
# ---------------------------------------------------------------------------


def test_recursive_call_cycle_does_not_hang(
    tmp_path: Path,
) -> None:
    """Recursive call graphs must remain bounded."""

    write_file(
        tmp_path,
        "payments.py",
        """
def webhook(request):
    process(request)


def process(request):
    process(request)
    charge(request)


def charge(request):
    pass
""",
    )

    findings = run_detector(tmp_path)

    assert_single_finding(findings)


def test_traversal_depth_can_be_configured(
    tmp_path: Path,
) -> None:
    """The detector exposes traversal limits without changing its rule."""

    write_file(
        tmp_path,
        "payments.py",
        """
def webhook(request):
    first(request)


def first(request):
    second(request)


def second(request):
    charge(request)


def charge(request):
    pass
""",
    )

    findings = run_detector(
        tmp_path,
        max_depth=1,
    )

    # A deliberately shallow analysis may be incomplete, but it must not
    # invent a vulnerability when the sink cannot actually be reached.
    assert findings == []


# ---------------------------------------------------------------------------
# Custom rules
# ---------------------------------------------------------------------------


def make_custom_rule(
    *,
    entry_names: tuple[str, ...] = ("incoming_event",),
    guard_names: frozenset[str] = frozenset({"authenticate"}),
    sink_names: frozenset[str] = frozenset({"execute_payment"}),
) -> SecurityPathRule:
    """Create a small custom rule for configuration tests."""

    return SecurityPathRule(
        rule_id="TEST-SECURITY-001",
        finding_type="TEST_UNPROTECTED_PATH",
        severity="HIGH",
        entry_name_patterns=entry_names,
        guard_names=guard_names,
        sink_names=sink_names,
        description="Custom security path was not protected.",
    )


def test_custom_rule_can_protect_a_path(
    tmp_path: Path,
) -> None:
    """Rule behavior should be driven by configuration."""

    write_file(
        tmp_path,
        "payments.py",
        """
def incoming_event(request):
    authenticate(request)
    execute_payment(request)


def authenticate(request):
    pass


def execute_payment(request):
    pass
""",
    )

    findings = run_detector(
        tmp_path,
        rule=make_custom_rule(),
    )

    assert_no_findings(findings)


def test_custom_rule_can_report_a_path(
    tmp_path: Path,
) -> None:
    """Custom entry, guard and sink names should work without code changes."""

    write_file(
        tmp_path,
        "payments.py",
        """
def incoming_event(request):
    execute_payment(request)


def execute_payment(request):
    pass
""",
    )

    findings = run_detector(
        tmp_path,
        rule=make_custom_rule(),
    )

    finding = assert_single_finding(
        findings,
        rule_id="TEST-SECURITY-001",
        finding_type="TEST_UNPROTECTED_PATH",
        severity="HIGH",
    )

    assert "incoming_event" in finding["message"]
    assert "execute_payment" in finding["message"]


# ---------------------------------------------------------------------------
# Configuration validation
# ---------------------------------------------------------------------------


def test_detector_rejects_invalid_rule_type(
    tmp_path: Path,
) -> None:
    """Invalid detector configuration should fail explicitly."""

    analysis = build_analysis(tmp_path)

    with pytest.raises(
        TypeError,
        match="SecurityPathRule",
    ):
        analyze_repository(
            analysis,
            rule="invalid",  # type: ignore[arg-type]
        )


def test_rule_rejects_empty_entry_patterns() -> None:
    """A rule without entry points cannot perform useful flow analysis."""

    with pytest.raises(
        ValueError,
        match="entry_name_patterns cannot be empty",
    ):
        SecurityPathRule(
            rule_id="TEST",
            finding_type="TEST",
            severity="HIGH",
            entry_name_patterns=(),
            guard_names=frozenset({"verify"}),
            sink_names=frozenset({"charge"}),
            description="test",
        )


def test_rule_rejects_empty_sink_names() -> None:
    """A rule without sinks cannot define a security-sensitive flow."""

    with pytest.raises(
        ValueError,
        match="sink_names cannot be empty",
    ):
        SecurityPathRule(
            rule_id="TEST",
            finding_type="TEST",
            severity="HIGH",
            entry_name_patterns=("webhook",),
            guard_names=frozenset({"verify"}),
            sink_names=frozenset(),
            description="test",
        )


# ---------------------------------------------------------------------------
# Finding metadata
# ---------------------------------------------------------------------------


def test_finding_points_to_entry_point(
    tmp_path: Path,
) -> None:
    """Findings should point users to the source entry point."""

    file_path = write_file(
        tmp_path,
        "handlers.py",
        """
def unrelated():
    pass


def webhook(request):
    charge(request)


def charge(request):
    pass
""",
    )

    findings = run_detector(tmp_path)

    finding = assert_single_finding(findings)

    assert finding["file"] == str(file_path.resolve())
    assert finding["line"] == 6


def test_does_not_report_unrelated_function_with_webhook_in_name(
    tmp_path: Path,
) -> None:
    """A helper containing 'webhook' in its name is not necessarily an entry point."""

    write_file(
        tmp_path,
        "payments.py",
        """
def webhook_documentation():
    charge()


def charge():
    pass
""",
    )

    findings = run_detector(tmp_path)

    assert_no_findings(findings)
