from analyzer.suppression import (
    Suppression,
    filter_suppressed_findings,
    parse_suppressions,
)


def test_parse_suppression_without_reason(tmp_path):
    source = tmp_path / "example.py"
    source.write_text(
        "# integration-doctor-ignore: WEBHOOK-001\n"
        "def webhook():\n"
        "    pass\n",
        encoding="utf-8",
    )

    suppressions = parse_suppressions(source)

    assert suppressions == [
        Suppression(
            rule_id="WEBHOOK-001",
            line=1,
            reason=None,
        )
    ]


def test_parse_suppression_with_reason(tmp_path):
    source = tmp_path / "example.py"
    source.write_text(
        "# integration-doctor-ignore: WEBHOOK-001 -- legacy endpoint\n"
        "def webhook():\n"
        "    pass\n",
        encoding="utf-8",
    )

    suppressions = parse_suppressions(source)

    assert suppressions == [
        Suppression(
            rule_id="WEBHOOK-001",
            line=1,
            reason="legacy endpoint",
        )
    ]


def test_parse_multiple_suppressions(tmp_path):
    source = tmp_path / "example.py"
    source.write_text(
        "# integration-doctor-ignore: WEBHOOK-001\n"
        "webhook()\n"
        "# integration-doctor-ignore: RETRY-001 -- accepted risk\n"
        "retry()\n",
        encoding="utf-8",
    )

    suppressions = parse_suppressions(source)

    assert suppressions == [
        Suppression(
            rule_id="WEBHOOK-001",
            line=1,
            reason=None,
        ),
        Suppression(
            rule_id="RETRY-001",
            line=3,
            reason="accepted risk",
        ),
    ]


def test_filter_suppresses_matching_rule_on_next_line():
    findings = [
        {
            "rule_id": "WEBHOOK-001",
            "file": "example.py",
            "line": 2,
        },
        {
            "rule_id": "RETRY-001",
            "file": "example.py",
            "line": 2,
        },
    ]

    result = filter_suppressed_findings(
        findings,
        file_suppressions={
            "example.py": [
                Suppression("WEBHOOK-001", line=1),
            ]
        },
    )

    assert result == [findings[1]]


def test_filter_suppresses_matching_rule_on_same_line():
    finding = {
        "rule_id": "WEBHOOK-001",
        "file": "example.py",
        "line": 10,
    }

    result = filter_suppressed_findings(
        [finding],
        file_suppressions={
            "example.py": [
                Suppression("WEBHOOK-001", line=10),
            ]
        },
    )

    assert result == []


def test_filter_does_not_suppress_different_rule():
    finding = {
        "rule_id": "RETRY-001",
        "file": "example.py",
        "line": 10,
    }

    result = filter_suppressed_findings(
        [finding],
        file_suppressions={
            "example.py": [
                Suppression("WEBHOOK-001", line=9),
            ]
        },
    )

    assert result == [finding]


def test_filter_does_not_suppress_different_line():
    finding = {
        "rule_id": "WEBHOOK-001",
        "file": "example.py",
        "line": 10,
    }

    result = filter_suppressed_findings(
        [finding],
        file_suppressions={
            "example.py": [
                Suppression("WEBHOOK-001", line=5),
            ]
        },
    )

    assert result == [finding]


def test_parse_invalid_file_returns_no_suppressions(tmp_path):
    source = tmp_path / "broken.py"
    source.write_text(
        "def broken(:\n",
        encoding="utf-8",
    )

    assert parse_suppressions(source) == []
