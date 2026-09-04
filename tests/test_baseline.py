from pathlib import Path

import pytest

from analyzer.baseline import (
    BASELINE_VERSION,
    create_baseline,
    filter_new_findings,
    fingerprint_finding,
    load_baseline,
    save_baseline,
)


def finding(
    rule_id="WEBHOOK-001",
    file="webhook.py",
    line=10,
):
    """Create a small finding for baseline tests."""

    return {
        "rule_id": rule_id,
        "type": "TEST_FINDING",
        "severity": "HIGH",
        "file": file,
        "line": line,
        "message": "Test finding.",
    }


def test_fingerprint_is_stable():
    first = fingerprint_finding(finding())
    second = fingerprint_finding(finding())

    assert first == second
    assert len(first) == 64


def test_fingerprint_changes_for_different_rule():
    first = fingerprint_finding(
        finding("WEBHOOK-001")
    )
    second = fingerprint_finding(
        finding("WEBHOOK-002")
    )

    assert first != second


def test_fingerprint_changes_for_different_file():
    first = fingerprint_finding(
        finding(file="one.py")
    )
    second = fingerprint_finding(
        finding(file="two.py")
    )

    assert first != second


def test_fingerprint_changes_for_different_line():
    first = fingerprint_finding(
        finding(line=10)
    )
    second = fingerprint_finding(
        finding(line=11)
    )

    assert first != second


def test_fingerprint_supports_missing_line():
    result = fingerprint_finding(
        finding(line=None)
    )

    assert isinstance(result, str)
    assert len(result) == 64


def test_create_baseline_is_versioned_and_sorted():
    findings = [
        finding("WEBHOOK-002", line=20),
        finding("WEBHOOK-001", line=10),
        finding("WEBHOOK-002", line=20),
    ]

    baseline = create_baseline(findings)

    assert baseline["version"] == BASELINE_VERSION
    assert baseline["findings"] == sorted(
        set(baseline["findings"])
    )
    assert len(baseline["findings"]) == 2


def test_save_and_load_baseline(tmp_path: Path):
    path = tmp_path / "baseline.json"
    findings = [finding()]

    save_baseline(findings, path)

    loaded = load_baseline(path)

    assert loaded == {
        fingerprint_finding(findings[0])
    }


def test_save_baseline_creates_parent_directory(
    tmp_path: Path,
):
    path = tmp_path / "nested" / "baseline.json"

    save_baseline([finding()], path)

    assert path.exists()


def test_load_baseline_rejects_missing_file(
    tmp_path: Path,
):
    with pytest.raises(
        ValueError,
        match="does not exist",
    ):
        load_baseline(
            tmp_path / "missing.json"
        )


def test_load_baseline_rejects_invalid_json(
    tmp_path: Path,
):
    path = tmp_path / "baseline.json"

    path.write_text(
        "{broken",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Invalid baseline JSON",
    ):
        load_baseline(path)


def test_load_baseline_rejects_non_object(
    tmp_path: Path,
):
    path = tmp_path / "baseline.json"

    path.write_text(
        "[]",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="JSON object",
    ):
        load_baseline(path)


def test_load_baseline_rejects_wrong_version(
    tmp_path: Path,
):
    path = tmp_path / "baseline.json"

    path.write_text(
        '{"version": 999, "findings": []}',
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Unsupported baseline version",
    ):
        load_baseline(path)


def test_load_baseline_rejects_invalid_findings_type(
    tmp_path: Path,
):
    path = tmp_path / "baseline.json"

    path.write_text(
        '{"version": 1, "findings": "not-a-list"}',
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="must be a list",
    ):
        load_baseline(path)


def test_load_baseline_rejects_non_string_fingerprints(
    tmp_path: Path,
):
    path = tmp_path / "baseline.json"

    path.write_text(
        '{"version": 1, "findings": [123]}',
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="only strings",
    ):
        load_baseline(path)


def test_filter_new_findings():
    old_finding = finding(
        "WEBHOOK-001",
        line=10,
    )
    new_finding = finding(
        "WEBHOOK-002",
        line=20,
    )

    baseline = {
        fingerprint_finding(old_finding)
    }

    result = filter_new_findings(
        [old_finding, new_finding],
        baseline,
    )

    assert result == [new_finding]


def test_filter_new_findings_keeps_all_when_baseline_is_empty():
    findings = [
        finding("WEBHOOK-001"),
        finding("WEBHOOK-002"),
    ]

    assert filter_new_findings(
        findings,
        set(),
    ) == findings
