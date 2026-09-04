# ANSI escape codes keep terminal colors lightweight without adding a dependency.
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
GREEN = "\033[32m"


def _verdict_color(verdict: str) -> str:
    """Return the terminal color for an AI verdict."""

    colors = {
        "TRUE_POSITIVE": RED,
        "FALSE_POSITIVE": GREEN,
        "NEEDS_REVIEW": YELLOW,
    }

    return colors.get(verdict, RESET)


def print_investigation(result):
    """Display an AI investigation in a readable terminal format."""

    verdict = result.verdict.replace("_", " ")
    verdict_color = _verdict_color(result.verdict)

    print()
    print(f"{BOLD}{CYAN}" + "=" * 50 + f"{RESET}")
    print(f"{BOLD}{CYAN}AI INVESTIGATION{RESET}")
    print(f"{BOLD}{CYAN}" + "=" * 50 + f"{RESET}")
    print()

    # Color the verdict so the AI's conclusion is immediately visible.
    print(
        f"Verdict      : "
        f"{verdict_color}{BOLD}{verdict}{RESET}"
    )

    # Highlight confidence because it affects how much weight to give the verdict.
    confidence = result.confidence.upper()
    confidence_color = (
        GREEN if confidence == "HIGH"
        else YELLOW if confidence == "MEDIUM"
        else RED
    )

    print(
        f"Confidence   : "
        f"{confidence_color}{BOLD}{confidence}{RESET}"
    )

    print()

    print(f"{BOLD}Explanation{RESET}")
    print("-" * 50)
    print(result.explanation)

    print()

    print(f"{BOLD}Evidence{RESET}")
    print("-" * 50)
    for evidence in result.evidence:
        print(f"  • {evidence}")

    print()

    print(f"{BOLD}Files Examined{RESET}")
    print("-" * 50)
    for file_path in result.files_examined:
        print(f"  • {file_path}")

    print()

    print(f"{BOLD}{CYAN}" + "=" * 50 + f"{RESET}")
