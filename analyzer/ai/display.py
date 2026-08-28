def print_investigation(result):
    """Display an AI investigation in a readable terminal format."""

    print()
    print("=" * 50)
    print("AI INVESTIGATION")
    print("=" * 50)

    print()
    print(f"Verdict      : {result.verdict.replace('_', ' ')}")
    print(f"Confidence   : {result.confidence}")

    print()
    print("Explanation")
    print("-" * 50)
    print(result.explanation)

    print()
    print("Evidence")
    print("-" * 50)

    for evidence in result.evidence:
        print(f"  • {evidence}")

    print()
    print("Files Examined")
    print("-" * 50)

    for file_path in result.files_examined:
        print(f"  • {file_path}")

    print()
    print("=" * 50)
