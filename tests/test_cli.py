import json
import subprocess
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# CLI helper
# ---------------------------------------------------------------------------


def run_cli(*args):
    """Run the CLI in the same Python environment as the test suite."""
    return subprocess.run(
        [sys.executable, "-m", "analyzer.scanner", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def write_file(path: Path, content: str):
    """Write a UTF-8 source file for a CLI integration test."""
    path.write_text(content, encoding="utf-8")


# ---------------------------------------------------------------------------
# --help / --version
# ---------------------------------------------------------------------------


def test_cli_help():
    result = run_cli("--help")

    assert result.returncode == 0
    assert "Scan a repository for payment integration issues." in result.stdout
    assert "--ai" in result.stdout
    assert "--json" in result.stdout
    assert "--sarif" in result.stdout
    assert "--verbose" in result.stdout
    assert "--version" in result.stdout


def test_cli_version():
    result = run_cli("--version")

    assert result.returncode == 0
    assert result.stdout.startswith("integration-doctor ")
    assert result.stderr == ""


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------


def test_cli_json_output_is_valid_for_clean_repository(tmp_path):
    write_file(
        tmp_path / "clean.py",
        "def hello():\n"
        "    return 'hello'\n",
    )

    result = run_cli(str(tmp_path), "--json")

    assert result.returncode == 0
    assert result.stderr == ""

    data = json.loads(result.stdout)

    assert set(data) == {
        "findings",
        "investigations",
        "summary",
    }
    assert data["findings"] == []
    assert data["investigations"] == []
    assert data["summary"] == {
        "total": 0,
        "files": 0,
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "errors": 0,
    }


def test_cli_json_output_contains_findings(tmp_path):
    write_file(
        tmp_path / "unsafe_retry.py",
        """
def process_payment(payment):
    for attempt in range(3):
        payment.charge()
""",
    )

    result = run_cli(str(tmp_path), "--json")

    assert result.returncode == 1

    data = json.loads(result.stdout)

    assert data["findings"]
    assert data["summary"]["total"] == len(data["findings"])

    rule_ids = {finding["rule_id"] for finding in data["findings"]}

    assert rule_ids


# ---------------------------------------------------------------------------
# SARIF output
# ---------------------------------------------------------------------------


def test_cli_sarif_output_is_valid_for_clean_repository(tmp_path):
    write_file(
        tmp_path / "clean.py",
        "def hello():\n"
        "    return 'hello'\n",
    )

    result = run_cli(str(tmp_path), "--sarif")

    assert result.returncode == 0
    assert result.stderr == ""

    data = json.loads(result.stdout)

    assert data["version"] == "2.1.0"
    assert "$schema" in data
    assert len(data["runs"]) == 1

    run = data["runs"][0]

    assert run["tool"]["driver"]["name"] == "Integration Doctor"
    assert run["results"] == []


def test_cli_sarif_output_contains_findings(tmp_path):
    write_file(
        tmp_path / "unsafe_retry.py",
        """
def process_payment(payment):
    for attempt in range(3):
        payment.charge()
""",
    )

    result = run_cli(str(tmp_path), "--sarif")

    assert result.returncode == 1

    data = json.loads(result.stdout)

    assert data["version"] == "2.1.0"

    run = data["runs"][0]
    results = run["results"]

    assert results

    for finding in results:
        assert finding["ruleId"]
        assert finding["level"] in {"error", "warning", "note"}
        assert finding["message"]["text"]

        assert "locations" in finding
        assert finding["locations"]

        physical_location = finding["locations"][0]["physicalLocation"]

        assert physical_location["artifactLocation"]["uri"]


# ---------------------------------------------------------------------------
# Invalid target
# ---------------------------------------------------------------------------


def test_cli_invalid_target_returns_error_in_json_mode(tmp_path):
    missing_target = tmp_path / "does-not-exist"

    result = run_cli(str(missing_target), "--json")

    assert result.returncode == 2

    data = json.loads(result.stdout)

    assert data["findings"] == []
    assert data["investigations"] == []
    assert data["summary"]["total"] == 0
    assert data["error"]


def test_cli_invalid_target_returns_error_in_human_mode(tmp_path):
    missing_target = tmp_path / "does-not-exist"

    result = run_cli(str(missing_target))

    assert result.returncode == 2
    assert "Error:" in result.stdout


# ---------------------------------------------------------------------------
# Machine-readable output integrity
# ---------------------------------------------------------------------------


def test_cli_json_stdout_is_machine_readable(tmp_path):
    write_file(
        tmp_path / "clean.py",
        "x = 1\n",
    )

    result = run_cli(str(tmp_path), "--json")

    assert result.returncode == 0

    # stdout must contain only JSON so CI systems can consume it directly.
    json.loads(result.stdout)


def test_cli_sarif_stdout_is_machine_readable(tmp_path):
    write_file(
        tmp_path / "clean.py",
        "x = 1\n",
    )

    result = run_cli(str(tmp_path), "--sarif")

    assert result.returncode == 0

    # stdout must contain only SARIF JSON so external tooling can consume it.
    sarif = json.loads(result.stdout)

    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
