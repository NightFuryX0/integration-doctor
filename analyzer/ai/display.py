"""Terminal display for AI investigation results.

ANSI escape codes keep terminal colors lightweight without adding a dependency.
Colors are automatically disabled when stdout is not a TTY (e.g. piped to a
file or captured in CI logs) so output stays clean and doesn't clutter logs
with raw escape sequences.
"""

import sys

_USE_COLOR = sys.stdout.isatty()

RESET = "\033[0m" if _USE_COLOR else ""
BOLD = "\033[1m" if _USE_COLOR else ""
RED = "\033[31m" if _USE_COLOR else ""
YELLOW = "\033[33m" if _USE_COLOR else ""
CYAN = "\033[36m" if _USE_COLOR else ""
GREEN = "\033[32m" if _USE_COLOR else ""

_VERDICT_COLORS = {
    "TRUE_POSITIVE": RED,
    "FALSE_POSITIVE": GREEN,
    # Changed from NEEDS_REVIEW to UNCERTAIN to match InvestigationResult.
    "UNCERTAIN": YELLOW,
}

_CONFIDENCE_COLORS = {
    "HIGH": GREEN,
    "MEDIUM": YELLOW,
    "LOW": RED,
}


def _verdict_color(verdict: str) -> str:
    """Return the terminal color for an AI verdict."""
    return _VERDICT_COLORS.get(verdict, RESET)


def _confidence_color(confidence: str) -> str:
    """Return the terminal color for a confidence level.

    Falls back to RESET (not RED) for unrecognized values so a typo or
    unexpected value in the data doesn't silently masquerade as "LOW".
    """
    return _CONFIDENCE_COLORS.get(confidence, RESET)


def _print_bulleted_section(title: str, items) -> None:
    """Print a titled, underlined section of bullet points.

    Prints a placeholder line if `items` is empty so the section isn't
    left looking broken or truncated.
    """
    print(f"{BOLD}{title}{RESET}")
    print("-" * 50)
    if items:
        for item in items:
            print(f"  • {item}")
    else:
        print("  (none)")
    print()


def print_investigation(result) -> None:
    """Display an AI investigation in a readable terminal format.

    Expects `result` to have: verdict, confidence, explanation, evidence
    (iterable), and files_examined (iterable) attributes.
    """
    verdict_raw = getattr(result, "verdict", "") or ""
    verdict_display = verdict_raw.replace("_", " ") or "UNKNOWN"
    verdict_color = _verdict_color(verdict_raw)

    confidence_raw = (getattr(result, "confidence", "") or "").upper()
    confidence_display = confidence_raw or "UNKNOWN"
    confidence_color = _confidence_color(confidence_raw)

    explanation = getattr(result, "explanation",
                          None) or "(no explanation provided)"
    evidence = getattr(result, "evidence", None) or []
    files_examined = getattr(result, "files_examined", None) or []

    print()
    print(f"{BOLD}{CYAN}" + "=" * 50 + f"{RESET}")
    print(f"{BOLD}{CYAN}AI INVESTIGATION{RESET}")
    print(f"{BOLD}{CYAN}" + "=" * 50 + f"{RESET}")
    print()

    # Color the verdict so the AI's conclusion is immediately visible.
    print(f"Verdict      : {verdict_color}{BOLD}{verdict_display}{RESET}")

    # Highlight confidence because it affects how much weight to give the verdict.
    print(
        f"Confidence   : {confidence_color}{BOLD}{confidence_display}{RESET}")
    print()

    print(f"{BOLD}Explanation{RESET}")
    print("-" * 50)
    print(explanation)
    print()

    _print_bulleted_section("Evidence", evidence)
    _print_bulleted_section("Files Examined", files_examined)

    print(f"{BOLD}{CYAN}" + "=" * 50 + f"{RESET}")
