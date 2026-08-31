import json

import pytest

from analyzer import scanner


# ---------------------------------------------------------------------------
# find_python_files
# ---------------------------------------------------------------------------


def test_find_python_files_ignores_directories(tmp_path):
    # A real source file that should be found.
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    # Files sitting inside directories that should be ignored entirely.
    for ignored_dir in (".git", "venv", "__pycache__", "node_modules", "build"):
        nested = tmp_path / ignored_dir / "sub"
        nested.mkdir(parents=True)
        (nested / "ignored.py").write_text("y = 2\n", encoding="utf-8")

    found = scanner.find_python_files(str(tmp_path))

    assert [f.name for f in found] == ["app.py"]


def test_find_python_files_missing_target_raises(tmp_path):
    missing = tmp_path / "does-not-exist"

    with pytest.raises(FileNotFoundError):
        scanner.find_python_files(str(missing))


def test_find_python_files_target_is_file_raises(tmp_path):
    not_a_dir = tmp_path / "file.py"
    not_a_dir.write_text("x = 1\n", encoding="utf-8")

    with pytest.raises(NotADirectoryError):
        scanner.find_python_files(str(not_a_dir))


def test_find_python_files_skips_unreadable_directory(tmp_path, monkeypatch):
    # A directory os.walk can't read should be skipped (with a warning)
    # rather than crashing the whole scan.
    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")

    def fake_walk(root, onerror=None):
        if onerror is not None:
            onerror(OSError("permission denied"))
        yield str(root), [], ["app.py"]

    monkeypatch.setattr(scanner.os, "walk", fake_walk)

    found = scanner.find_python_files(str(tmp_path))

    assert [f.name for f in found] == ["app.py"]


# ---------------------------------------------------------------------------
# _run_detectors_on_file: isolation and parser-error handling
# ---------------------------------------------------------------------------


def test_run_detectors_reports_syntax_error_once(tmp_path, monkeypatch):
    bad_file = tmp_path / "broken.py"
    bad_file.write_text("def broken(:\n", encoding="utf-8")

    calls = []

    def tracking_detector(path):
        calls.append(path)
        return []

    monkeypatch.setattr(scanner, "DETECTORS", (tracking_detector,))

    findings = scanner._run_detectors_on_file(bad_file)

    # Syntax errors are caught before any detector runs, so we get exactly
    # one PARSER-001 finding and detectors are never invoked on this file.
    assert len(findings) == 1
    assert findings[0]["rule_id"] == "PARSER-001"
    assert findings[0]["type"] == "SYNTAX_ERROR"
    assert calls == []


def test_run_detectors_reports_encoding_error(tmp_path):
    bad_file = tmp_path / "bad_encoding.py"
    bad_file.write_bytes(b"\xff\xfe\x00invalid")

    findings = scanner._run_detectors_on_file(bad_file)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "PARSER-002"
    assert findings[0]["type"] == "FILE_ENCODING_ERROR"


def test_run_detectors_isolates_a_failing_detector(tmp_path, monkeypatch):
    # One detector raises, one detector returns a real finding. Both should
    # be reflected in the output: the crash must not suppress the other
    # detector's results.
    ok_file = tmp_path / "ok.py"
    ok_file.write_text("x = 1\n", encoding="utf-8")

    def crashing_detector(path):
        raise RuntimeError("boom")

    def working_detector(path):
        return [
            {
                "rule_id": "RETRY-001",
                "type": "UNSAFE_RETRY",
                "severity": "HIGH",
                "file": path,
                "line": 1,
                "message": "found it",
            }
        ]

    monkeypatch.setattr(
        scanner, "DETECTORS", (crashing_detector, working_detector)
    )

    findings = scanner._run_detectors_on_file(ok_file)

    rule_ids = {f["rule_id"] for f in findings}
    assert "PARSER-003" in rule_ids  # the crash was captured...
    assert "RETRY-001" in rule_ids  # ...but didn't block the other detector
    assert len(findings) == 2


# ---------------------------------------------------------------------------
# scan_repository (light integration test)
# ---------------------------------------------------------------------------


def test_scan_repository_returns_findings(tmp_path, monkeypatch):
    source_file = tmp_path / "payment.py"
    source_file.write_text(
        """
def charge():
    payment_api.charge()
    payment_api.charge()
""",
        encoding="utf-8",
    )

    # Use a deterministic fake detector rather than relying on the real
    # detectors' unspecified heuristics, so this test doesn't silently pass
    # or fail based on unrelated detector changes.
    def fake_detector(path):
        return [
            {
                "rule_id": "RETRY-001",
                "type": "UNSAFE_RETRY",
                "severity": "HIGH",
                "file": path,
                "line": 3,
                "message": "duplicate charge call detected",
            }
        ]

    monkeypatch.setattr(scanner, "DETECTORS", (fake_detector,))

    findings = scanner.scan_repository(str(tmp_path))

    assert isinstance(findings, list)
    assert findings
    assert findings[0]["rule_id"] == "RETRY-001"


# ---------------------------------------------------------------------------
# group_findings_by_file
# ---------------------------------------------------------------------------


def test_group_findings_by_file_sorts_by_line_then_severity():
    findings = [
        {"file": "a.py", "line": 10, "severity": "LOW", "rule_id": "L"},
        {"file": "a.py", "line": None, "severity": "ERROR", "rule_id": "E"},
        {"file": "a.py", "line": 5, "severity": "CRITICAL", "rule_id": "C1"},
        {"file": "a.py", "line": 5, "severity": "HIGH", "rule_id": "H"},
    ]

    grouped = scanner.group_findings_by_file(findings)
    ordered_ids = [f["rule_id"] for f in grouped["a.py"]]

    # Lines come before "no line" entries; within the same line, more
    # severe findings sort first.
    assert ordered_ids == ["C1", "H", "L", "E"]


# ---------------------------------------------------------------------------
# investigate_findings
# ---------------------------------------------------------------------------


def _finding(rule_id="RULE-1", file="f.py"):
    return {
        "rule_id": rule_id,
        "type": "SOME_TYPE",
        "severity": "HIGH",
        "file": file,
        "line": 1,
        "message": "msg",
    }


def test_investigate_findings_continues_after_api_error(monkeypatch):
    findings = [_finding("A"), _finding("B"), _finding("C")]

    def fake_investigate(finding):
        if finding["rule_id"] == "B":
            raise scanner.InvestigatorAPIError("rate limited")
        return {"summary": f"ok-{finding['rule_id']}"}

    monkeypatch.setattr(scanner, "investigate_file", fake_investigate)

    results, interrupted = scanner.investigate_findings(
        findings, show_progress=False)

    assert interrupted is False
    assert [r["finding"]["rule_id"] for r in results] == ["A", "C"]


def test_investigate_findings_continues_after_unexpected_error(monkeypatch):
    findings = [_finding("A"), _finding("B")]

    def fake_investigate(finding):
        if finding["rule_id"] == "A":
            raise ValueError("unexpected")
        return {"summary": "ok"}

    monkeypatch.setattr(scanner, "investigate_file", fake_investigate)

    results, interrupted = scanner.investigate_findings(
        findings, show_progress=False)

    assert interrupted is False
    assert [r["finding"]["rule_id"] for r in results] == ["B"]


def test_investigate_findings_preserves_partial_results_on_interrupt(monkeypatch):
    findings = [_finding("A"), _finding("B"), _finding("C")]

    def fake_investigate(finding):
        if finding["rule_id"] == "B":
            raise KeyboardInterrupt()
        return {"summary": f"ok-{finding['rule_id']}"}

    monkeypatch.setattr(scanner, "investigate_file", fake_investigate)

    results, interrupted = scanner.investigate_findings(
        findings, show_progress=False)

    # "A" completed before the interrupt and must not be discarded; "C"
    # was never reached.
    assert interrupted is True
    assert [r["finding"]["rule_id"] for r in results] == ["A"]


# ---------------------------------------------------------------------------
# _build_summary
# ---------------------------------------------------------------------------


def test_build_summary_schema_is_stable_even_when_empty():
    summary = scanner._build_summary([])

    assert summary == {
        "total": 0,
        "files": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "errors": 0,
    }


# ---------------------------------------------------------------------------
# main(): JSON mode
# ---------------------------------------------------------------------------


def _fake_args(**overrides):
    defaults = {"target": ".", "ai": False, "json": True, "verbose": False}
    defaults.update(overrides)
    return type("Args", (), defaults)()


def test_main_json_output_is_valid(monkeypatch, capsys):
    finding = {
        "rule_id": "WEBHOOK-001",
        "type": "MISSING_WEBHOOK_SIGNATURE",
        "severity": "CRITICAL",
        "file": "webhook.py",
        "line": 10,
        "message": "Webhook signature verification is missing.",
    }

    monkeypatch.setattr(scanner, "scan_repository", lambda target: [finding])
    monkeypatch.setattr(scanner, "parse_arguments", lambda: _fake_args())

    exit_code = scanner.main()

    assert exit_code == scanner.EXIT_FINDINGS

    data = json.loads(capsys.readouterr().out)

    assert data["findings"] == [finding]
    assert data["summary"]["total"] == 1
    assert data["summary"]["critical"] == 1
    assert data["summary"]["files"] == 1
    assert data["investigations"] == []
    assert "ai_investigation_interrupted" not in data


def test_main_json_output_includes_full_summary_schema_on_error(monkeypatch, capsys):
    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: (_ for _ in ()).throw(
            FileNotFoundError("Scan target does not exist")
        ),
    )
    monkeypatch.setattr(
        scanner, "parse_arguments", lambda: _fake_args(target="nope")
    )

    exit_code = scanner.main()

    assert exit_code == scanner.EXIT_ERROR

    data = json.loads(capsys.readouterr().out)

    # The summary schema must be identical whether or not the scan
    # succeeded, so downstream JSON consumers don't need special-case
    # handling for the error path.
    assert set(data["summary"].keys()) == {
        "total",
        "files",
        "critical",
        "high",
        "medium",
        "low",
        "errors",
    }
    assert data["error"]


def test_main_with_ai_flag_includes_investigations_in_json(monkeypatch, capsys):
    finding = _finding("RETRY-001")

    monkeypatch.setattr(scanner, "scan_repository", lambda target: [finding])
    monkeypatch.setattr(
        scanner, "investigate_file", lambda f: {"summary": "looks bad"}
    )
    monkeypatch.setattr(
        scanner, "parse_arguments", lambda: _fake_args(ai=True)
    )

    exit_code = scanner.main()

    assert exit_code == scanner.EXIT_FINDINGS

    data = json.loads(capsys.readouterr().out)

    assert len(data["investigations"]) == 1
    assert data["investigations"][0]["finding"] == finding
    assert data["investigations"][0]["investigation"] == {
        "summary": "looks bad"}


# ---------------------------------------------------------------------------
# main(): human-readable mode
# ---------------------------------------------------------------------------


def test_main_returns_clean_for_no_findings(monkeypatch, capsys):
    monkeypatch.setattr(scanner, "scan_repository", lambda target: [])
    monkeypatch.setattr(
        scanner, "parse_arguments", lambda: _fake_args(json=False)
    )

    exit_code = scanner.main()

    assert exit_code == scanner.EXIT_CLEAN
    assert "No findings." in capsys.readouterr().out


def test_main_prints_findings_and_summary_for_human_mode(monkeypatch, capsys):
    finding = _finding("RETRY-001", file="webhook.py")

    monkeypatch.setattr(scanner, "scan_repository", lambda target: [finding])
    monkeypatch.setattr(
        scanner, "parse_arguments", lambda: _fake_args(json=False)
    )

    exit_code = scanner.main()
    output = capsys.readouterr().out

    assert exit_code == scanner.EXIT_FINDINGS
    assert "RETRY-001" in output
    assert "webhook.py" in output
    assert "Summary:" in output


def test_main_returns_error_for_invalid_target(monkeypatch, capsys):
    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: (_ for _ in ()).throw(
            FileNotFoundError("Scan target does not exist")
        ),
    )
    monkeypatch.setattr(
        scanner, "parse_arguments", lambda: _fake_args(
            target="does-not-exist", json=False)
    )

    exit_code = scanner.main()

    assert exit_code == scanner.EXIT_ERROR
    assert "Error:" in capsys.readouterr().out
