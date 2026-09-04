from pathlib import Path

from analyzer.detectors.webhook import analyze_file


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "webhook_eval"
SAFE_DIR = FIXTURE_ROOT / "safe"
UNSAFE_DIR = FIXTURE_ROOT / "unsafe"


def _has_finding(path: Path) -> bool:
    return bool(analyze_file(str(path)))


def test_webhook_evaluation_corpus():
    safe_cases = sorted(SAFE_DIR.glob("*.py"))
    unsafe_cases = sorted(UNSAFE_DIR.glob("*.py"))

    assert safe_cases
    assert unsafe_cases

    true_negatives = sum(not _has_finding(path) for path in safe_cases)
    false_positives = sum(_has_finding(path) for path in safe_cases)

    true_positives = sum(_has_finding(path) for path in unsafe_cases)
    false_negatives = sum(not _has_finding(path) for path in unsafe_cases)

    assert false_positives == 0
    assert false_negatives == 0

    precision = true_positives / (true_positives + false_positives)
    recall = true_positives / (true_positives + false_negatives)

    assert precision == 1.0
    assert recall == 1.0
    assert true_negatives == len(safe_cases)
    assert true_positives == len(unsafe_cases)
