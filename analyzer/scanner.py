from __future__ import annotations
from importlib.metadata import version as package_version
from analyzer.detectors.retry import analyze_file as analyze_retry
from analyzer.detectors.idempotency import analyze_file as analyze_idempotency
from analyzer.detectors.webhook import analyze_file as analyze_webhook
from analyzer.ai.investigator import (
    InvestigatorAPIError,
    investigate_file,
)
from analyzer.ai.display import print_investigation
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import argparse
import ast
import json
import logging
import os

# ANSI escape codes keep terminal colors lightweight without adding a dependency.
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
GRAY = "\033[90m"
CYAN = "\033[36m"
GREEN = "\033[32m"


IGNORED_DIRECTORIES = {
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
}

DETECTORS = (
    analyze_webhook,
    analyze_idempotency,
    analyze_retry,
)

# Exit codes allow Integration Doctor to be used from CI/CD pipelines.
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2

logger = logging.getLogger("integration_doctor")


def find_python_files(root: str) -> list[Path]:
    """Find Python files while ignoring generated and dependency directories.

    Unreadable subdirectories (e.g. due to permissions) are skipped with a
    warning rather than aborting the entire scan.
    """

    root_path = Path(root)

    if not root_path.exists():
        raise FileNotFoundError(f"Scan target does not exist: {root}")

    if not root_path.is_dir():
        raise NotADirectoryError(f"Scan target is not a directory: {root}")

    def _on_walk_error(error: OSError) -> None:
        logger.warning("Skipping unreadable path during scan: %s", error)

    files: list[Path] = []

    for dirpath, dirnames, filenames in os.walk(root_path, onerror=_on_walk_error):
        # Prune ignored directories in-place so os.walk never descends into
        # them at all (faster, and avoids matching filenames that merely
        # happen to sit inside an ignored directory further down the tree).
        dirnames[:] = sorted(
            dirname for dirname in dirnames if dirname not in IGNORED_DIRECTORIES
        )

        for filename in filenames:
            if filename.endswith(".py"):
                files.append(Path(dirpath) / filename)

    return sorted(files)


def _parser_error_finding(rule_id: str, finding_type: str, file_path: Path, line, message: str) -> dict:
    """Build a standard PARSER-* finding dict."""

    return {
        "rule_id": rule_id,
        "type": finding_type,
        "severity": "ERROR",
        "file": str(file_path),
        "line": line,
        "message": message,
    }


def _run_detectors_on_file(file_path: Path) -> list[dict]:
    """Run all detectors against a single file, isolating failures per detector.

    The file is read and syntax-checked once up front: if it can't be read
    as UTF-8 or doesn't parse as valid Python, none of the detectors can
    meaningfully analyze it, so we report a single parser-level finding
    instead of letting every detector independently raise on (and duplicate
    a report for) the same underlying problem.

    If an individual detector then raises an unexpected error, only that
    detector's contribution is skipped — the remaining detectors still run
    against the file, so one buggy or crashing detector can't silently
    suppress findings from the others.
    """

    try:
        source = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return [
            _parser_error_finding(
                "PARSER-002",
                "FILE_ENCODING_ERROR",
                file_path,
                None,
                "Could not analyze this file because it could not be decoded as UTF-8.",
            )
        ]
    except OSError as error:
        return [
            _parser_error_finding(
                "PARSER-004",
                "FILE_READ_ERROR",
                file_path,
                None,
                f"Could not analyze this file because it could not be read ({error}).",
            )
        ]

    try:
        ast.parse(source, filename=str(file_path))
    except SyntaxError as error:
        return [
            _parser_error_finding(
                "PARSER-001",
                "SYNTAX_ERROR",
                file_path,
                error.lineno,
                "Could not analyze this file because it contains invalid Python syntax.",
            )
        ]

    findings: list[dict] = []

    for detector in DETECTORS:
        try:
            findings.extend(detector(str(file_path)))

        except SyntaxError as error:
            # Defensive: a detector may re-parse the file itself and hit a
            # syntax edge case our pre-check didn't catch (e.g. version-
            # specific grammar). Isolate it to this detector only.
            findings.append(
                _parser_error_finding(
                    "PARSER-001",
                    "SYNTAX_ERROR",
                    file_path,
                    error.lineno,
                    (
                        f"Detector '{_detector_name(detector)}' could not analyze "
                        "this file because it contains invalid Python syntax."
                    ),
                )
            )

        except Exception as error:  # noqa: BLE001
            logger.exception(
                "Detector '%s' crashed on %s", _detector_name(
                    detector), file_path
            )
            findings.append(
                {
                    "rule_id": "PARSER-003",
                    "type": "DETECTOR_ERROR",
                    "severity": "ERROR",
                    "file": str(file_path),
                    "line": None,
                    "message": (
                        f"Detector '{_detector_name(detector)}' raised an unexpected "
                        f"error while analyzing this file "
                        f"({type(error).__name__}: {error}). "
                        "Other detectors still ran; see logs for the full traceback."
                    ),
                }
            )

    return findings


def _detector_name(detector) -> str:
    """Best-effort human-readable name for a detector callable, for messages."""

    module = getattr(detector, "__module__", "") or ""
    name = getattr(detector, "__name__", "") or "detector"
    return f"{module}.{name}" if module else name


def scan_repository(root: str) -> list[dict]:
    """Run all deterministic detectors against a repository."""

    findings: list[dict] = []

    for file_path in find_python_files(root):
        findings.extend(_run_detectors_on_file(file_path))

    return findings


def _severity_rank(finding: dict) -> int:
    """Return a stable sorting rank for finding severity."""

    order = {
        "ERROR": 0,
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 3,
        "LOW": 4,
    }

    return order.get(finding.get("severity", ""), 99)


def group_findings_by_file(findings: list[dict]) -> dict[str, list[dict]]:
    """Group findings by file and sort each file's findings."""

    grouped: dict[str, list[dict]] = {}

    for finding in findings:
        grouped.setdefault(
            finding.get("file", "<unknown file>"),
            [],
        ).append(finding)

    for file_findings in grouped.values():
        file_findings.sort(
            key=lambda finding: (
                finding.get("line") is None,
                finding.get("line", 0),
                _severity_rank(finding),
            )
        )

    return grouped


def _severity_color(severity: str) -> str:
    """Return the terminal color for a finding severity."""

    colors = {
        "CRITICAL": RED,
        "HIGH": YELLOW,
        "MEDIUM": BLUE,
        "LOW": GRAY,
        "ERROR": RED,
    }

    return colors.get(severity, RESET)


def print_finding(finding: dict) -> None:
    """Print one static-analysis finding."""

    line = finding.get("line")
    location = finding.get("file", "<unknown file>")
    severity = finding.get("severity", "UNKNOWN")

    if line is not None:
        location += f":{line}"

    # Color the severity so important findings stand out in the terminal.
    severity_text = (
        f"{_severity_color(severity)}"
        f"[{severity}]"
        f"{RESET}"
    )

    print(
        f"{severity_text} "
        f"{finding.get('rule_id', '?')} "
        f"{finding.get('type', '?')}"
    )
    print(f"  {location}")
    print(f"  {finding.get('message', '(no message provided)')}")


def print_summary(findings: list[dict]) -> None:
    """Print a compact severity summary."""

    counts: dict[str, int] = {}

    for finding in findings:
        severity = finding.get("severity", "UNKNOWN")
        counts[severity] = counts.get(severity, 0) + 1

    print()
    print("-" * 50)

    total = len(findings)

    breakdown = ", ".join(
        f"{count} {severity}"
        for severity, count in sorted(
            counts.items(),
            key=lambda item: item[0],
        )
    )

    # Use green when the scan is clean and red when errors were found.
    if not findings:
        summary_color = GREEN
    elif counts.get("ERROR", 0) > 0:
        summary_color = RED
    else:
        summary_color = YELLOW

    print(
        f"{summary_color}{BOLD}"
        f"Summary: {total} finding(s) across "
        f"{len({finding.get('file') for finding in findings})} file(s)"
        f" — {breakdown}"
        f"{RESET}"
    )


def _print_header(title: str) -> None:
    """Print a human-readable section header."""

    # Use cyan and bold to make major CLI sections easy to distinguish.
    print()
    print(f"{BOLD}{CYAN}" + "=" * 50 + f"{RESET}")
    print(f"{BOLD}{CYAN}{title}{RESET}")
    print(f"{BOLD}{CYAN}" + "=" * 50 + f"{RESET}")


def investigate_findings(
    findings: list[dict],
    *,
    show_progress: bool = True,
) -> tuple[list[dict], bool]:
    """Send static findings to the AI investigator concurrently.

    Returns a tuple of (results, interrupted). Failures investigating an
    individual finding are isolated so they don't abort investigation of the
    remaining findings. If the user interrupts (Ctrl+C) partway through,
    any results already gathered are preserved and returned rather than
    discarded, with `interrupted` set to True.
    """

    results: list[dict] = []
    interrupted = False

    if show_progress:
        _print_header("AI INVESTIGATION")

    if not findings:
        return results, interrupted

    # Run the independent API requests concurrently so five findings do not
    # have to wait for five sequential ~10-second NVIDIA responses.
    max_workers = min(5, len(findings))

    # Keep the finding index so completed results can be restored to the
    # original static-analysis order instead of depending on completion order.
    indexed_results: dict[int, dict] = {}

    try:
        # Create a small thread pool because these tasks are network-bound API
        # requests rather than CPU-heavy work.
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(investigate_file, finding): index
                for index, finding in enumerate(findings)
            }

            # Process each investigation as soon as its API request finishes.
            for future in as_completed(futures):
                index = futures[future]
                finding = findings[index]

                if show_progress:
                    print(
                        f"\nInvestigating {finding['rule_id']} "
                        f"in {finding['file']}..."
                    )

                try:
                    result = future.result()

                except InvestigatorAPIError as error:
                    if show_progress:
                        print(f"AI investigation failed: {error}")
                    continue

                except Exception as error:  # noqa: BLE001
                    logger.exception(
                        "Unexpected error investigating %s",
                        finding.get("file"),
                    )
                    if show_progress:
                        print(
                            f"AI investigation failed unexpectedly: {error}"
                        )
                    continue

                indexed_results[index] = {
                    "finding": finding,
                    "investigation": result,
                }

    except KeyboardInterrupt:
        # Preserve investigations that completed before Ctrl+C and report
        # that the AI investigation phase was interrupted.
        interrupted = True

        if show_progress:
            print("\nInterrupted. Keeping investigations completed so far.")

    # Restore the original finding order because futures finish at different
    # times depending on the API response latency.
    results = [
        indexed_results[index]
        for index in sorted(indexed_results)
    ]

    return results, interrupted


def _serialize_investigation(result):
    """Convert an investigation result into JSON-compatible data."""

    if hasattr(result, "model_dump"):
        return result.model_dump()

    if hasattr(result, "__dict__"):
        return result.__dict__

    return result


def _build_summary(findings: list[dict]) -> dict:
    """Build the common scan summary used by human and JSON output.

    Always returns the same set of keys, whether or not there are any
    findings, so downstream consumers (e.g. CI scripts parsing --json
    output) can rely on a stable schema regardless of the scan outcome.
    """

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "ERROR": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "UNKNOWN")

        if severity in severity_counts:
            severity_counts[severity] += 1

    return {
        "total": len(findings),
        "files": len({finding.get("file") for finding in findings}),
        "critical": severity_counts["CRITICAL"],
        "high": severity_counts["HIGH"],
        "medium": severity_counts["MEDIUM"],
        "low": severity_counts["LOW"],
        "errors": severity_counts["ERROR"],
    }


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
        help="Run AI investigation on detected findings.",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output.",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"integration-doctor {package_version('integration-doctor')}",
        help="Show the installed Integration Doctor version.",
    )

    return parser.parse_args()


def main() -> int:
    """Run Integration Doctor and return a process exit code."""

    args = parse_arguments()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        findings = scan_repository(args.target)

    except (FileNotFoundError, NotADirectoryError) as error:
        if args.json:
            print(
                json.dumps(
                    {
                        "findings": [],
                        "investigations": [],
                        "summary": _build_summary([]),
                        "error": str(error),
                    },
                    indent=2,
                )
            )
        else:
            print(f"Error: {error}")

        return EXIT_ERROR

    investigation_results: list[dict] = []
    investigation_interrupted = False

    if args.ai and findings:
        investigation_results, investigation_interrupted = investigate_findings(
            findings,
            show_progress=not args.json,
        )

    # Display completed AI investigations only in human-readable mode.
    if not args.json:
        for result in investigation_results:
            print_investigation(result["investigation"])

    summary = _build_summary(findings)

    if args.json:
        output: dict = {
            "findings": findings,
            "investigations": [
                {
                    "finding": result["finding"],
                    "investigation": _serialize_investigation(
                        result["investigation"]
                    ),
                }
                for result in investigation_results
            ],
            "summary": summary,
        }

        if investigation_interrupted:
            output["ai_investigation_interrupted"] = True

        print(json.dumps(output, indent=2, default=str))

        return EXIT_FINDINGS if findings else EXIT_CLEAN

    if not findings:
        print("No findings.")
        return EXIT_CLEAN

    _print_header("STATIC ANALYSIS")

    grouped = group_findings_by_file(findings)

    for file_path, file_findings in grouped.items():
        print()
        print(f"{file_path}  ({len(file_findings)} finding(s))")
        print("-" * 50)

        for finding in file_findings:
            print_finding(finding)
            print()

    if investigation_interrupted:
        print()
        print(
            "Note: AI investigation was interrupted before all findings "
            "were investigated. Results above reflect only what completed."
        )

    print_summary(findings)

    return EXIT_FINDINGS


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print()
        print("Interrupted by user.")
        raise SystemExit(EXIT_ERROR)
