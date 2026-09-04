
import argparse
import json
import sys
from pathlib import Path

import pytest

from analyzer import scanner
from analyzer.baseline import save_baseline
from analyzer.ai.investigator import InvestigatorAPIError


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _finding(
    rule_id: str = "WEBHOOK-001",
    *,
    severity: str = "CRITICAL",
    file: str = "webhook.py",
    line: int = 10,
) -> dict:
    """Create a small finding used by scanner tests."""

    return {
        "rule_id": rule_id,
        "type": "TEST_FINDING",
        "severity": severity,
        "file": file,
        "line": line,
        "message": "Test finding.",
    }


def _fake_args(
    *,
    target: str = ".",
    ai: bool = False,
    json: bool = False,
    verbose: bool = False,
    sarif: bool = False,
    baseline: str | None = None,
    generate_baseline: str | None = None,
) -> argparse.Namespace:
    """Create CLI arguments without invoking argparse."""

    return argparse.Namespace(
        target=target,
        ai=ai,
        json=json,
        verbose=verbose,
        sarif=sarif,  # Fixed: main() now supports the --sarif output mode.
        # Fixed: provide the optional baseline path used by main().
        baseline=baseline,
        # Fixed: provide the optional baseline-generation path used by main().
        generate_baseline=generate_baseline,
    )


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------


def test_find_python_files_returns_python_files(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n")
    (tmp_path / "notes.txt").write_text("not python\n")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "worker.py").write_text("print('worker')\n")

    files = scanner.find_python_files(str(tmp_path))

    assert files == [
        tmp_path / "app.py",
        tmp_path / "nested" / "worker.py",
    ]


def test_find_python_files_ignores_default_directories(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("print('hello')\n")

    ignored_directories = (
        ".git",
        ".venv",
        "venv",
        "__pycache__",
        "node_modules",
        ".tox",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "build",
        "dist",
        ".eggs",
    )

    for directory in ignored_directories:
        ignored = tmp_path / directory
        ignored.mkdir()
        (ignored / "ignored.py").write_text("print('ignored')\n")

    files = scanner.find_python_files(str(tmp_path))

    assert files == [tmp_path / "app.py"]


def test_find_python_files_raises_for_missing_target(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist"

    with pytest.raises(FileNotFoundError):
        scanner.find_python_files(str(missing))


def test_find_python_files_raises_for_file_target(tmp_path: Path) -> None:
    file_path = tmp_path / "app.py"
    file_path.write_text("print('hello')\n")

    with pytest.raises(NotADirectoryError):
        scanner.find_python_files(str(file_path))


def test_find_python_files_skips_unreadable_paths(
    tmp_path: Path,
    monkeypatch,
) -> None:
    python_file = tmp_path / "app.py"
    python_file.write_text("print('hello')\n")

    def fake_walk(*args, **kwargs):
        onerror = kwargs["onerror"]
        onerror(OSError("permission denied"))
        yield str(tmp_path), [], ["app.py"]

    monkeypatch.setattr(scanner.os, "walk", fake_walk)

    files = scanner.find_python_files(str(tmp_path))

    assert files == [python_file]


# ---------------------------------------------------------------------------
# Parser-level error handling
# ---------------------------------------------------------------------------


def test_run_detectors_reports_invalid_encoding(tmp_path: Path) -> None:
    file_path = tmp_path / "broken.py"
    file_path.write_bytes(b"\xff\xfe\x00\x00")

    findings = scanner._run_detectors_on_file(file_path)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "PARSER-002"
    assert findings[0]["type"] == "FILE_ENCODING_ERROR"
    assert findings[0]["severity"] == "ERROR"


def test_run_detectors_reports_invalid_syntax(tmp_path: Path) -> None:
    file_path = tmp_path / "broken.py"
    file_path.write_text("def broken(:\n")

    findings = scanner._run_detectors_on_file(file_path)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "PARSER-001"
    assert findings[0]["type"] == "SYNTAX_ERROR"
    assert findings[0]["severity"] == "ERROR"


def test_run_detectors_reports_file_read_error(
    tmp_path: Path,
    monkeypatch,
) -> None:
    file_path = tmp_path / "broken.py"
    file_path.write_text("print('hello')\n")

    def fake_read_text(*args, **kwargs):
        raise OSError("permission denied")

    monkeypatch.setattr(Path, "read_text", fake_read_text)

    findings = scanner._run_detectors_on_file(file_path)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "PARSER-004"
    assert findings[0]["type"] == "FILE_READ_ERROR"
    assert findings[0]["severity"] == "ERROR"


# ---------------------------------------------------------------------------
# Detector isolation
# ---------------------------------------------------------------------------


def test_run_detectors_isolates_a_failing_detector(
    tmp_path: Path,
    monkeypatch,
) -> None:
    file_path = tmp_path / "app.py"
    file_path.write_text("print('hello')\n")

    def working_detector(path: str) -> list[dict]:
        return [_finding("WORKING-001")]

    def failing_detector(path: str) -> list[dict]:
        raise RuntimeError("detector failed")

    monkeypatch.setattr(
        scanner,
        "DETECTORS",
        (
            working_detector,
            failing_detector,
        ),
    )

    findings = scanner._run_detectors_on_file(file_path)

    assert any(f["rule_id"] == "WORKING-001" for f in findings)
    assert any(f["rule_id"] == "PARSER-003" for f in findings)


def test_run_detectors_handles_detector_syntax_error(
    tmp_path: Path,
    monkeypatch,
) -> None:
    file_path = tmp_path / "app.py"
    file_path.write_text("print('hello')\n")

    def failing_detector(path: str) -> list[dict]:
        raise SyntaxError("invalid syntax")

    monkeypatch.setattr(scanner, "DETECTORS", (failing_detector,))

    findings = scanner._run_detectors_on_file(file_path)

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "PARSER-001"
    assert findings[0]["type"] == "SYNTAX_ERROR"


# ---------------------------------------------------------------------------
# Detector naming
# ---------------------------------------------------------------------------


def test_detector_name_returns_module_and_name() -> None:
    def example_detector(path: str) -> list[dict]:
        return []

    name = scanner._detector_name(example_detector)

    assert name.endswith(".example_detector")


def test_detector_name_handles_callable_without_module() -> None:
    class Detector:
        def __call__(self, path: str) -> list[dict]:
            return []

    detector = Detector()

    name = scanner._detector_name(detector)

    assert name.endswith(".detector")


# ---------------------------------------------------------------------------
# Repository scanning
# ---------------------------------------------------------------------------


def test_scan_repository_returns_findings(
    tmp_path: Path,
    monkeypatch,
) -> None:
    python_file = tmp_path / "app.py"
    python_file.write_text("print('hello')\n")

    finding = _finding()

    monkeypatch.setattr(
        scanner,
        "_run_detectors_on_file",
        lambda path: [finding],
    )

    monkeypatch.setattr(
        scanner,
        "build_repository_analysis",
        lambda root: object(),
    )

    monkeypatch.setattr(
        scanner,
        "analyze_security_paths",
        lambda analysis: [],
    )

    findings = scanner.scan_repository(str(tmp_path))

    assert findings == [finding]


def test_scan_repository_respects_configured_exclusions(
    tmp_path: Path,
    monkeypatch,
) -> None:
    included = tmp_path / "included.py"
    excluded_directory = tmp_path / "excluded"
    excluded = excluded_directory / "excluded.py"

    included.write_text("print('included')\n")
    excluded_directory.mkdir()
    excluded.write_text("print('excluded')\n")

    def fake_detector(path: str) -> list[dict]:
        if path.endswith("included.py"):
            return [_finding("WEBHOOK-001", file=path)]
        return [_finding("WEBHOOK-002", file=path)]

    monkeypatch.setattr(scanner, "DETECTORS", (fake_detector,))
    monkeypatch.setattr(
        scanner,
        "build_repository_analysis",
        lambda root: object(),
    )
    monkeypatch.setattr(
        scanner,
        "analyze_security_paths",
        lambda analysis: [],
    )

    config_file = tmp_path / "integration-doctor.toml"
    config_file.write_text(
        """
[tool.integration-doctor]
exclude = ["excluded"]
"""
    )

    findings = scanner.scan_repository(str(tmp_path))

    assert len(findings) == 1
    assert findings[0]["file"].endswith("included.py")


def test_scan_repository_filters_disabled_rules(
    tmp_path: Path,
    monkeypatch,
) -> None:
    python_file = tmp_path / "app.py"
    python_file.write_text("print('hello')\n")

    def fake_detector(path: str) -> list[dict]:
        return [
            _finding("WEBHOOK-001", file=path),
            _finding("RETRY-001", file=path),
        ]

    monkeypatch.setattr(scanner, "DETECTORS", (fake_detector,))
    monkeypatch.setattr(
        scanner,
        "build_repository_analysis",
        lambda root: object(),
    )
    monkeypatch.setattr(
        scanner,
        "analyze_security_paths",
        lambda analysis: [],
    )

    config_file = tmp_path / "integration-doctor.toml"
    config_file.write_text(
        """
[tool.integration-doctor]
disabled_rules = ["WEBHOOK-001"]
"""
    )

    findings = scanner.scan_repository(str(tmp_path))

    assert len(findings) == 1
    assert findings[0]["rule_id"] == "RETRY-001"


def test_find_python_files_keeps_default_ignored_directories(
    tmp_path: Path,
) -> None:
    ignored = tmp_path / ".venv"
    ignored.mkdir()

    (ignored / "ignored.py").write_text("print('ignored')\n")
    (tmp_path / "app.py").write_text("print('app')\n")

    files = scanner.find_python_files(str(tmp_path))

    assert files == [tmp_path / "app.py"]

# ---------------------------------------------------------------------------
# Suppression integration
# ---------------------------------------------------------------------------


def test_scan_repository_respects_inline_suppression(
    tmp_path: Path,
    monkeypatch,
) -> None:
    python_file = tmp_path / "app.py"
    python_file.write_text(
        "# integration-doctor-ignore: WEBHOOK-001 -- verified elsewhere\n"
        "def webhook():\n"
        "    pass\n"
    )

    finding = _finding(
        "WEBHOOK-001",
        file=str(python_file),
        line=2,
    )

    monkeypatch.setattr(
        scanner,
        "_run_detectors_on_file",
        lambda path: [finding],
    )
    monkeypatch.setattr(
        scanner,
        "build_repository_analysis",
        lambda root: object(),
    )
    monkeypatch.setattr(
        scanner,
        "analyze_security_paths",
        lambda analysis: [],
    )

    findings = scanner.scan_repository(str(tmp_path))

    assert findings == []
# ---------------------------------------------------------------------------
# Finding grouping and ordering
# ---------------------------------------------------------------------------


def test_group_findings_by_file_sorts_by_line_then_severity() -> None:
    findings = [
        _finding("LOW-001", severity="LOW", file="app.py", line=20),
        _finding("CRITICAL-001", severity="CRITICAL", file="app.py", line=10),
        _finding("HIGH-001", severity="HIGH", file="app.py", line=10),
        _finding("HIGH-002", severity="HIGH", file="other.py", line=5),
    ]

    grouped = scanner.group_findings_by_file(findings)

    assert list(grouped) == ["app.py", "other.py"]
    assert [f["rule_id"] for f in grouped["app.py"]] == [
        "CRITICAL-001",
        "HIGH-001",
        "LOW-001",
    ]


def test_build_summary_schema_is_stable_even_when_empty() -> None:
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


def test_build_summary_counts_findings() -> None:
    findings = [
        _finding("A", severity="CRITICAL", file="a.py"),
        _finding("B", severity="HIGH", file="b.py"),
        _finding("C", severity="MEDIUM", file="b.py"),
        _finding("D", severity="LOW", file="c.py"),
        _finding("E", severity="ERROR", file="d.py"),
    ]

    summary = scanner._build_summary(findings)

    assert summary == {
        "total": 5,
        "files": 4,
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 1,
        "errors": 1,
    }


# ---------------------------------------------------------------------------
# AI investigation handling
# ---------------------------------------------------------------------------


def test_investigate_findings_continues_after_api_error(
    monkeypatch,
) -> None:
    findings = [
        _finding("A", file="a.py"),
        _finding("B", file="b.py"),
    ]

    def fake_investigate_file(finding, *args, **kwargs):
        if finding["rule_id"] == "A":
            raise InvestigatorAPIError("API unavailable")
        return {"result": "success"}

    monkeypatch.setattr(
        scanner,
        "investigate_file",
        fake_investigate_file,
    )

    results, interrupted = scanner.investigate_findings(
        findings,
        show_progress=False,
    )

    assert interrupted is False
    assert len(results) == 1
    assert results[0]["finding"]["rule_id"] == "B"


def test_investigate_findings_continues_after_unexpected_error(
    monkeypatch,
) -> None:
    findings = [
        _finding("A", file="a.py"),
        _finding("B", file="b.py"),
    ]

    def fake_investigate_file(finding, *args, **kwargs):
        if finding["rule_id"] == "A":
            raise RuntimeError("unexpected failure")
        return {"result": "success"}

    monkeypatch.setattr(
        scanner,
        "investigate_file",
        fake_investigate_file,
    )

    results, interrupted = scanner.investigate_findings(
        findings,
        show_progress=False,
    )

    assert interrupted is False
    assert len(results) == 1
    assert results[0]["finding"]["rule_id"] == "B"


def test_investigate_findings_preserves_partial_results_on_interrupt(
    monkeypatch,
) -> None:
    findings = [
        _finding("A", file="a.py"),
        _finding("B", file="b.py"),
    ]

    calls = iter(
        [
            {"result": "success"},
            KeyboardInterrupt(),
        ]
    )

    def fake_investigate_file(finding, *args, **kwargs):
        result = next(calls)

        if isinstance(result, BaseException):
            raise result

        return result

    monkeypatch.setattr(
        scanner,
        "investigate_file",
        fake_investigate_file,
    )

    results, interrupted = scanner.investigate_findings(
        findings,
        show_progress=False,
    )

    assert interrupted is True
    assert len(results) == 1


def test_serialize_investigation_supports_dict() -> None:
    result = {"answer": "safe"}

    assert scanner._serialize_investigation(result) == {
        "answer": "safe"
    }


def test_serialize_investigation_supports_dict() -> None:
    result = {"answer": "safe"}

    assert scanner._serialize_investigation(result) == {
        "answer": "safe"
    }


def test_serialize_investigation_returns_plain_values() -> None:
    assert scanner._serialize_investigation("safe") == "safe"


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


def test_parse_arguments_defaults(monkeypatch) -> None:
    monkeypatch.setattr(
        scanner,
        "package_version",
        lambda package: "0.1.0",
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["integration-doctor"],
    )

    args = scanner.parse_arguments()

    assert args.target == "integrations/broken_webhook"
    assert args.ai is False
    assert args.json is False
    assert args.sarif is False
    assert args.verbose is False


def test_parse_arguments_accepts_sarif(monkeypatch) -> None:
    monkeypatch.setattr(
        sys,
        "argv",
        ["integration-doctor", ".", "--sarif"],
    )

    args = scanner.parse_arguments()

    assert args.sarif is True


# ---------------------------------------------------------------------------
# SARIF output
# ---------------------------------------------------------------------------


def test_build_sarif_returns_valid_structure() -> None:
    findings = [
        _finding(
            "WEBHOOK-001",
            severity="CRITICAL",
            file="webhook.py",
            line=10,
        )
    ]

    sarif = scanner._build_sarif(findings)

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1

    run = sarif["runs"][0]

    assert run["tool"]["driver"]["name"] == "Integration Doctor"
    assert len(run["results"]) == 1

    result = run["results"][0]

    assert result["ruleId"] == "WEBHOOK-001"
    assert result["level"] == "error"
    assert result["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] == "webhook.py"
    assert result["locations"][0]["physicalLocation"]["region"]["startLine"] == 10


def test_build_sarif_maps_severity_levels() -> None:
    findings = [
        _finding("A", severity="CRITICAL"),
        _finding("B", severity="HIGH"),
        _finding("C", severity="MEDIUM"),
        _finding("D", severity="LOW"),
        _finding("E", severity="ERROR"),
    ]

    sarif = scanner._build_sarif(findings)

    levels = {
        result["ruleId"]: result["level"]
        for result in sarif["runs"][0]["results"]
    }

    assert levels == {
        "A": "error",
        "B": "error",
        "C": "warning",
        "D": "note",
        "E": "error",
    }


def test_build_sarif_deduplicates_rules() -> None:
    findings = [
        _finding("WEBHOOK-001", file="a.py", line=10),
        _finding("WEBHOOK-001", file="b.py", line=20),
    ]

    sarif = scanner._build_sarif(findings)

    rules = sarif["runs"][0]["tool"]["driver"]["rules"]

    assert len(rules) == 1
    assert rules[0]["id"] == "WEBHOOK-001"


def test_build_sarif_handles_missing_line() -> None:
    finding = _finding("TEST-001")
    finding["line"] = None

    sarif = scanner._build_sarif([finding])

    location = sarif["runs"][0]["results"][0]["locations"][0]

    assert "region" not in location["physicalLocation"]


# ---------------------------------------------------------------------------
# Main CLI behavior
# ---------------------------------------------------------------------------


def test_main_json_output_is_valid(
    monkeypatch,
    capsys,
) -> None:
    finding = _finding(
        "WEBHOOK-001",
        file="webhook.py",
        line=10,
    )

    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: [finding],
    )
    monkeypatch.setattr(
        scanner,
        "parse_arguments",
        lambda: _fake_args(json=True),
    )

    exit_code = scanner.main()

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert exit_code == scanner.EXIT_FINDINGS
    assert output["findings"] == [finding]
    assert output["summary"]["total"] == 1


def test_main_json_output_includes_full_summary_schema_on_error(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: (_ for _ in ()).throw(
            FileNotFoundError("target missing")
        ),
    )
    monkeypatch.setattr(
        scanner,
        "parse_arguments",
        lambda: _fake_args(json=True),
    )

    exit_code = scanner.main()

    captured = capsys.readouterr()
    output = json.loads(captured.out)

    assert exit_code == scanner.EXIT_ERROR
    assert output["error"] == "target missing"
    assert output["summary"] == {
        "total": 0,
        "files": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "errors": 0,
    }


def test_main_with_ai_flag_includes_investigations_in_json(
    monkeypatch,
    capsys,
) -> None:
    finding = _finding()

    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: [finding],
    )
    monkeypatch.setattr(
        scanner,
        "investigate_findings",
        lambda findings, show_progress: (
            [
                {
                    "finding": finding,
                    "investigation": {"answer": "safe"},
                }
            ],
            False,
        ),
    )
    monkeypatch.setattr(
        scanner,
        "parse_arguments",
        lambda: _fake_args(
            ai=True,
            json=True,
        ),
    )

    exit_code = scanner.main()

    output = json.loads(capsys.readouterr().out)

    assert exit_code == scanner.EXIT_FINDINGS
    assert output["investigations"][0]["finding"] == finding
    assert output["investigations"][0]["investigation"] == {
        "answer": "safe"
    }


def test_main_returns_clean_for_no_findings(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: [],
    )
    monkeypatch.setattr(
        scanner,
        "parse_arguments",
        lambda: _fake_args(json=False),
    )

    exit_code = scanner.main()

    assert exit_code == scanner.EXIT_CLEAN
    assert "No findings." in capsys.readouterr().out


def test_main_prints_findings_and_summary_for_human_mode(
    monkeypatch,
    capsys,
) -> None:
    finding = _finding(
        "RETRY-001",
        file="webhook.py",
    )

    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: [finding],
    )
    monkeypatch.setattr(
        scanner,
        "parse_arguments",
        lambda: _fake_args(json=False),
    )

    exit_code = scanner.main()

    output = capsys.readouterr().out

    assert exit_code == scanner.EXIT_FINDINGS
    assert "RETRY-001" in output
    assert "webhook.py:10" in output
    assert "1 finding(s)" in output


def test_main_returns_error_for_invalid_target(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: (_ for _ in ()).throw(
            FileNotFoundError("missing target")
        ),
    )
    monkeypatch.setattr(
        scanner,
        "parse_arguments",
        lambda: _fake_args(json=False),
    )

    exit_code = scanner.main()

    assert exit_code == scanner.EXIT_ERROR
    assert "Error: missing target" in capsys.readouterr().out


def test_main_returns_clean_when_baseline_removes_all_findings(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Return exit code 0 when all findings are already in the baseline."""
    finding = _finding("WEBHOOK-001")

    baseline_path = tmp_path / "baseline.json"
    save_baseline([finding], baseline_path)

    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: [finding],
    )
    monkeypatch.setattr(
        scanner,
        "parse_arguments",
        lambda: _fake_args(
            baseline=str(baseline_path),
        ),
    )

    exit_code = scanner.main()

    assert exit_code == scanner.EXIT_CLEAN


def test_main_returns_findings_when_baseline_leaves_new_findings(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Return exit code 1 when a new finding remains after baseline filtering."""
    old_finding = _finding("WEBHOOK-001")
    new_finding = _finding(
        "PAYMENT-003",
        file="payments.py",
        line=20,
    )

    baseline_path = tmp_path / "baseline.json"
    save_baseline([old_finding], baseline_path)

    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: [old_finding, new_finding],
    )
    monkeypatch.setattr(
        scanner,
        "parse_arguments",
        lambda: _fake_args(
            baseline=str(baseline_path),
        ),
    )

    exit_code = scanner.main()

    assert exit_code == scanner.EXIT_FINDINGS


def test_main_returns_error_for_invalid_baseline(
    monkeypatch,
    tmp_path: Path,
) -> None:
    """Return exit code 2 when the baseline cannot be loaded."""
    baseline_path = tmp_path / "missing-baseline.json"

    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: [],
    )
    monkeypatch.setattr(
        scanner,
        "parse_arguments",
        lambda: _fake_args(
            baseline=str(baseline_path),
        ),
    )

    exit_code = scanner.main()

    assert exit_code == scanner.EXIT_ERROR


def test_main_outputs_sarif(
    monkeypatch,
    capsys,
) -> None:
    finding = _finding(
        "WEBHOOK-001",
        severity="CRITICAL",
        file="webhook.py",
        line=10,
    )

    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: [finding],
    )
    monkeypatch.setattr(
        scanner,
        "parse_arguments",
        lambda: _fake_args(sarif=True),
    )

    exit_code = scanner.main()

    output = json.loads(capsys.readouterr().out)

    assert exit_code == scanner.EXIT_FINDINGS
    assert output["version"] == "2.1.0"
    assert output["runs"][0]["results"][0]["ruleId"] == "WEBHOOK-001"


def test_main_outputs_clean_sarif(
    monkeypatch,
    capsys,
) -> None:
    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: [],
    )
    monkeypatch.setattr(
        scanner,
        "parse_arguments",
        lambda: _fake_args(sarif=True),
    )

    exit_code = scanner.main()

    output = json.loads(capsys.readouterr().out)

    assert exit_code == scanner.EXIT_CLEAN
    assert output["version"] == "2.1.0"
    assert output["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# SARIF / JSON stdout isolation
# ---------------------------------------------------------------------------


def test_main_json_does_not_print_human_output(
    monkeypatch,
    capsys,
) -> None:
    finding = _finding()

    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: [finding],
    )
    monkeypatch.setattr(
        scanner,
        "parse_arguments",
        lambda: _fake_args(json=True),
    )

    scanner.main()

    output = capsys.readouterr().out

    json.loads(output)

    assert "STATIC ANALYSIS" not in output
    assert "No findings." not in output


def test_main_sarif_does_not_print_human_output(
    monkeypatch,
    capsys,
) -> None:
    finding = _finding()

    monkeypatch.setattr(
        scanner,
        "scan_repository",
        lambda target: [finding],
    )
    monkeypatch.setattr(
        scanner,
        "parse_arguments",
        lambda: _fake_args(sarif=True),
    )

    scanner.main()

    output = capsys.readouterr().out

    json.loads(output)

    assert "STATIC ANALYSIS" not in output
    assert "[CRITICAL]" not in output
