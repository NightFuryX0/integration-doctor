from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any


# Increment this when the baseline file format changes in a
# way that older versions can no longer understand.
BASELINE_VERSION = 1


@dataclass(frozen=True)
class FindingFingerprint:
    """Stable identity for a static-analysis finding."""

    rule_id: str
    file: str
    line: int | None

    def as_string(self) -> str:
        """Return the canonical data used to create the fingerprint."""

        # Keep the representation deterministic so the same finding
        # always produces the same fingerprint.
        line = "" if self.line is None else str(self.line)

        return f"{self.rule_id}|{self.file}|{line}"


def fingerprint_finding(finding: dict[str, Any]) -> str:
    """Create a stable SHA-256 fingerprint for a finding."""

    identity = FindingFingerprint(
        rule_id=str(finding.get("rule_id", "")),
        file=str(finding.get("file", "")),
        line=finding.get("line"),
    )

    # SHA-256 gives us a compact and stable identifier without storing
    # the entire finding in the baseline.
    return hashlib.sha256(
        identity.as_string().encode("utf-8")
    ).hexdigest()


def create_baseline(
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Create a versioned baseline document from scanner findings."""

    # A set removes duplicate fingerprints. Sorting makes the generated
    # file deterministic, which is useful for version control.
    fingerprints = sorted(
        {
            fingerprint_finding(finding)
            for finding in findings
        }
    )

    return {
        "version": BASELINE_VERSION,
        "findings": fingerprints,
    }


def save_baseline(
    findings: list[dict[str, Any]],
    path: str | Path,
) -> None:
    """Write a baseline document to disk."""

    baseline_path = Path(path)

    # Create the parent directory when a nested baseline path is supplied.
    baseline_path.parent.mkdir(parents=True, exist_ok=True)

    baseline = create_baseline(findings)

    # End with a newline so the generated JSON behaves nicely in
    # version-controlled files and terminal tools.
    baseline_path.write_text(
        json.dumps(baseline, indent=2) + "\n",
        encoding="utf-8",
    )


def load_baseline(path: str | Path) -> set[str]:
    """Load and validate baseline fingerprints from disk."""

    baseline_path = Path(path)

    try:
        data = json.loads(
            baseline_path.read_text(encoding="utf-8")
        )

    except FileNotFoundError as error:
        raise ValueError(
            f"Baseline file does not exist: {baseline_path}"
        ) from error

    except OSError as error:
        raise ValueError(
            f"Could not read baseline file: {error}"
        ) from error

    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid baseline JSON: {error}"
        ) from error

    # The top-level baseline must be a JSON object.
    if not isinstance(data, dict):
        raise ValueError(
            "Baseline must contain a JSON object."
        )

    version = data.get("version")

    # Reject formats that this version of Integration Doctor does not know.
    if version != BASELINE_VERSION:
        raise ValueError(
            f"Unsupported baseline version: {version!r}."
        )

    fingerprints = data.get("findings")

    # The findings collection must always be a list.
    if not isinstance(fingerprints, list):
        raise ValueError(
            "Baseline 'findings' must be a list."
        )

    # Fingerprints must be strings so malformed baseline files cannot
    # silently produce incorrect comparisons.
    if not all(isinstance(item, str) for item in fingerprints):
        raise ValueError(
            "Baseline 'findings' must contain only strings."
        )

    return set(fingerprints)


def filter_new_findings(
    findings: list[dict[str, Any]],
    baseline_fingerprints: set[str],
) -> list[dict[str, Any]]:
    """Return only findings that are not already in the baseline."""

    return [
        finding
        for finding in findings
        if fingerprint_finding(finding) not in baseline_fingerprints
    ]
