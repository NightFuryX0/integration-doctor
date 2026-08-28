from __future__ import annotations

import argparse
import json
import logging
import sys
import traceback
from pathlib import Path

from analyzer.detectors.webhook import analyze_file as analyze_webhook
from analyzer.detectors.idempotency import analyze_file as analyze_idempotency
from analyzer.detectors.retry import analyze_file as analyze_retry


IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
}

DETECTORS = (
    analyze_webhook,
    analyze_idempotency,
    analyze_retry,
)

# Exit codes follow the flake8/pylint convention so this can be used in CI.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

logger = logging.getLogger("integration_doctor")


def find_python_files(root: str) -> list[Path]:
    """Find Python files while ignoring generated and dependency directories."""

    root_path = Path(root)

    if not root_path.exists():
        raise FileNotFoundError(f"Scan target does not exist: {root}")

    if not root_path.is_dir():
        raise NotADirectoryError(f"Scan target is not a directory: {root}")

    return sorted(
        path
        for path in root_path.rglob("*.py")
        if not any(ignored in path.parts for ignored in IGNORED_DIRECTORIES)
    )


def _run_detectors_on_file(file_path: Path) -> list[dict]:
    """Run all detectors against a single file, isolating failures per file."""

    findings: list[dict] = []

    try:
        for detector in DETECTORS:
            findings.extend(detector(str(file_path)))

    except SyntaxError as error:
        findings.append(
            {
                "rule_id": "PARSER-001",
                "type": "SYNTAX_ERROR",
                "severity": "ERROR",
                "file": str(file_path),
                "line": error.lineno,
                "message": (
                    "Could not analyze this file because "
                    "it contains invalid Python syntax."
                ),
            }
        )

    except UnicodeDecodeError:
        findings.append(
            {
                "rule_id": "PARSER-002",
                "type": "FILE_ENCODING_ERROR",
                "severity": "ERROR",
                "file": str(file_path),
                "line": None,
                "message": (
                    "Could not analyze this file because "
                    "it could not be decoded as UTF-8."
                ),
            }
        )

    except Exception as error:  # noqa: BLE001 — a scanner must never crash on one bad file
        logger.exception("Detector crashed on %s", file_path)
        findings.append(
            {
                "rule_id": "PARSER-003",
                "type": "DETECTOR_ERROR",
                "severity": "ERROR",
                "file": str(file_path),
                "line": None,
                "message": (
                    "A detector raised an unexpected error while analyzing "
                    f"this file ({type(error).__name__}: {error}). "
                    "Skipping this file; see logs for the full traceback."
                ),
            }
        )

    return findings


def scan_repository(root: str) -> list[dict]:
    """Run all deterministic detectors against a repository."""

    findings: list[dict] = []

    for file_path in find_python_files(root):
        findings.extend(_run_detectors_on_file(file_path))

    return findings


def _severity_rank(finding: dict) -> int:
    order = {"ERROR": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return order.get(finding.get("severity", ""), 99)


def group_findings_by_file(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings by file, each file's findings sorted by line number."""

    grouped: dict[str, list[dict]] = {}
    for finding in findings:
        grouped.setdefault(finding.get(
            "file", "<unknown file>"), []).append(finding)

    for file_findings in grouped.values():
        file_findings.sort(key=lambda f: (
            f.get("line") is None, f.get("line", 0), _severity_rank(f)))

    return grouped


def print_finding(finding: dict) -> None:
    """Print one static-analysis finding."""

    line = finding.get("line")
    location = finding.get("file", "<unknown file>")
    if line:
        location += f":{line}"

    print(
        f"[{finding.get('severity', 'UNKNOWN')}] "
        f"{finding.get('rule_id', '?')} "
        f"{finding.get('type', '?')}"
    )
    print(f"  {location}")
    print(f"  {finding.get('message', '(no message provided)')}")


def print_summary(findings: list[dict]) -> None:
    """Print a one-line-per-severity summary, useful for a quick scan/demo readout."""

    counts: dict[str, int] = {}
    for finding in findings:
        severity = finding.get("severity", "UNKNOWN")
        counts[severity] = counts.get(severity, 0) + 1

    print()
    print("-" * 50)
    total = len(findings)
    breakdown = ", ".join(f"{count} {severity}" for severity, count in sorted(
        counts.items(), key=lambda kv: kv[0]))
    print(
        f"Summary: {total} finding(s) across {len({f.get('file') for f in findings})} file(s) — {breakdown}")


def _print_header(title: str) -> None:
    print()
    print("=" * 50)
    print(title)
    print("=" * 50)


def investigate_findings(findings: list[dict]) -> list[dict]:
    """Send static findings to the AI investigator. Returns investigation results."""

    from analyzer.ai.display import print_investigation
    from analyzer.ai.investigator import (
        InvestigatorAPIError,
        InvestigatorConfigError,
        InvestigatorParseError,
        investigate_file,
    )

    _print_header("AI INVESTIGATION")

    results: list[dict] = []

    for finding in findings:
        print()
        print(
            f"Investigating {finding.get('rule_id', '?')} in {finding.get('file', '?')}...")

        try:
            result = investigate_file(finding)
            print_investigation(result)
            results.append({"finding": finding, "investigation": result})

        except (
            InvestigatorAPIError,
            InvestigatorConfigError,
            InvestigatorParseError,
            FileNotFoundError,
            UnicodeDecodeError,
        ) as error:
            print()
            print("AI investigation failed.")
            print(f"Reason: {error}")
            print("Continuing with the remaining findings.")
            logger.warning("Investigation failed for %s: %s",
                           finding.get("file"), error)

        except KeyboardInterrupt:
            print()
            print("AI investigation interrupted by user. Stopping here.")
            break

    return results


def parse_arguments() -> argparse.Namespace:
    """Parse command-line options."""

    parser = argparse.ArgumentParser(
        description="Scan a repository for payment integration issues."
    )

    parser.add_argument(
        "target",
        nargs="?",
        default="integrations/broken_webhook",
        help="Directory to scan.",
    )

    parser.add_argument(
        "--ai",
        action="store_true",
        help="Run Gemini investigation on detected findings.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit findings as JSON instead of human-readable text (disables --ai output formatting).",
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug logging (detector crashes, retry attempts, etc.).",
    )

    return parser.parse_args()


def main() -> int:
    """Run Integration Doctor. Returns a process exit code."""

    args = parse_arguments()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        findings = scan_repository(args.target)
    except (FileNotFoundError, NotADirectoryError) as error:
        print(f"Error: {error}")
        return EXIT_ERROR

    if not findings:
        if args.json:
            print(json.dumps(
                {"findings": [], "summary": {"total": 0}}, indent=2))
        else:
            print("No findings.")
        return EXIT_CLEAN

    if args.json and not args.ai:
        print(json.dumps({"findings": findings, "summary": {
              "total": len(findings)}}, indent=2, default=str))
        return EXIT_FINDINGS

    _print_header("STATIC ANALYSIS")

    grouped = group_findings_by_file(findings)
    for file_path, file_findings in grouped.items():
        print()
        print(f"{file_path}  ({len(file_findings)} finding(s))")
        print("-" * 50)
        for finding in file_findings:
            print_finding(finding)
            print()

    print_summary(findings)

    investigation_results: list[dict] = []
    if args.ai:
        try:
            investigation_results = investigate_findings(findings)
        except KeyboardInterrupt:
            print()
            print("Interrupted. Exiting.")
            return EXIT_FINDINGS

    if args.json:
        print()
        print(json.dumps(
            {
                "findings": findings,
                "investigations": [
                    {
                        "finding": r["finding"],
                        "investigation": r["investigation"].model_dump()
                        if hasattr(r["investigation"], "model_dump")
                        else r["investigation"],
                    }
                    for r in investigation_results
                ],
                "summary": {"total": len(findings)},
            },
            indent=2,
            default=str,
        ))

    return EXIT_FINDINGS


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        print("Interrupted by user.")
        raise SystemExit(EXIT_ERROR)
