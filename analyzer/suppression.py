from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tokenize


SUPPRESSION_PREFIX = "integration-doctor-ignore:"


@dataclass(frozen=True)
class Suppression:
    """A rule suppression attached to a specific source line."""

    rule_id: str
    line: int
    reason: str | None = None


def parse_suppressions(file_path: str | Path) -> list[Suppression]:
    """Read Integration Doctor suppression comments from a Python file.

    A suppression applies to the comment's own line or the immediately
    following source line. This keeps suppressions precise instead of
    disabling a rule for an entire file.
    """

    path = Path(file_path)

    try:
        with path.open("rb") as file:
            tokens = tokenize.tokenize(file.readline)

            suppressions: list[Suppression] = []

            for token in tokens:
                if token.type != tokenize.COMMENT:
                    continue

                comment = token.string.lstrip("#").strip()

                if not comment.startswith(SUPPRESSION_PREFIX):
                    continue

                value = comment[len(SUPPRESSION_PREFIX):].strip()

                if not value:
                    continue

                if "--" in value:
                    rule_id, reason = value.split("--", 1)
                    rule_id = rule_id.strip()
                    reason = reason.strip() or None
                else:
                    rule_id = value.strip()
                    reason = None

                if not rule_id:
                    continue

                suppressions.append(
                    Suppression(
                        rule_id=rule_id,
                        line=token.start[0],
                        reason=reason,
                    )
                )

    except (OSError, tokenize.TokenError, IndentationError, SyntaxError):
        # Suppression parsing must never make the scanner fail.
        return []

    return suppressions


def filter_suppressed_findings(
    findings: list[dict],
    *,
    file_suppressions: dict[str, list[Suppression]],
) -> list[dict]:
    """Remove findings covered by precise source-line suppressions."""

    filtered: list[dict] = []

    for finding in findings:
        file_path = str(finding.get("file", ""))
        line = finding.get("line")
        rule_id = finding.get("rule_id")

        suppressed = False

        if isinstance(line, int) and rule_id:
            for suppression in file_suppressions.get(file_path, []):
                if suppression.rule_id != rule_id:
                    continue

                # A suppression can sit on the finding's own line or on the
                # immediately preceding line.
                if suppression.line in {line, line - 1}:
                    suppressed = True
                    break

        if not suppressed:
            filtered.append(finding)

    return filtered
