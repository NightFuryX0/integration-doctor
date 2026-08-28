import ast
from pathlib import Path
import re

MAX_FILES = 5
MAX_TOTAL_CHARS = 30_000
MAX_FILE_CHARS = 8_000

IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "tests",
}

IGNORED_FILES = {
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.test",
    "credentials.json",
    "service-account.json",
}

SECRET_PATTERNS = [
    # Fixed: detect common secret/token/password assignments while preserving the variable name.
    re.compile(
        r'(?i)(\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password)\b'
        r'\s*[:=]\s*)["\']([^"\']+)["\']'
    ),

    # Fixed: detect common Stripe secret-key values.
    re.compile(
        r'\bsk_(?:live|test)_[A-Za-z0-9]+\b'
    ),

    # Fixed: detect PEM private-key blocks before they can reach the AI.
    re.compile(
        r'-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----',
        re.DOTALL,
    ),
]


def _is_sensitive_file(path: Path) -> bool:
    """Return True when a file should never be included in AI context."""

    # Fixed: block explicitly known credential/config files.
    if path.name in IGNORED_FILES:
        return True

    # Fixed: block all environment files such as .env.local or .env.production.
    if path.name == ".env" or path.name.startswith(".env."):
        return True

    # Fixed: block common private-key file types, regardless of capitalization.
    if path.suffix.lower() in {".pem", ".key"}:
        return True

    return False


def _redact_secrets(source: str) -> str:
    """Replace likely secrets before source code is sent to the AI."""

    # Fixed: replace assignment-style secrets while preserving the code structure.
    for pattern in SECRET_PATTERNS:
        source = pattern.sub(
            lambda match: (
                f'{match.group(1)}"[REDACTED_SECRET]"'
                if match.lastindex and match.lastindex >= 2
                else "[REDACTED_SECRET]"
            ),
            source,
        )

    return source


def build_repository_context(
    file_path: str,
    repository_root: str,
) -> list[dict]:
    """Find a small amount of relevant local code for the AI investigator.

    Each returned dict has:
        "file": absolute path (str)
        "source": possibly-truncated source text
        "truncated": True if "source" is NOT the full contents of the file,
                     for any reason (per-file cap OR combined-budget cap).
    """

    target = Path(file_path).resolve()
    root = Path(repository_root).resolve()

    if not target.is_file():
        raise FileNotFoundError(
            f"Could not build context because '{file_path}' does not exist."
        )

    if not root.is_dir():
        raise NotADirectoryError(
            f"Repository root '{repository_root}' does not exist."
        )

    files = []

    # Always start with the file that produced the finding.
    files.append(target)

    # Add files imported directly by the target file.
    files.extend(
        _find_imported_local_files(
            target=target,
            repository_root=root,
        )
    )

    # Add nearby Python files because decorators and helpers are often kept
    # beside the webhook handler.
    files.extend(
        sorted(
            path
            for path in target.parent.glob("*.py")
            if path != target
        )
    )

    selected_files = []
    seen_files = set()
    total_chars = 0

    for path in files:
        path = path.resolve()

        if path in seen_files:
            continue

        if not path.is_file():
            continue

        if not _is_inside_repository(path, root):
            continue

        if any(
            ignored in path.parts
            for ignored in IGNORED_DIRECTORIES
        ):
            continue

        # Fixed: use the centralized sensitive-file check.
        if _is_sensitive_file(path):
            continue

        if len(selected_files) >= MAX_FILES:
            break
        try:
            source = path.read_text(encoding="utf-8")
            source = _redact_secrets(source)
        except (UnicodeDecodeError, OSError):
            continue

        remaining_chars = MAX_TOTAL_CHARS - total_chars

        if remaining_chars <= 0:
            break

        full_length = len(source)
        cutoff = min(MAX_FILE_CHARS, remaining_chars)
        truncated = full_length > cutoff
        source = source[:cutoff]

        selected_files.append(
            {
                "file": str(path),
                "source": source,
                "truncated": truncated,
            }
        )

        seen_files.add(path)
        total_chars += len(source)

    return selected_files


def _find_imported_local_files(
    target: Path,
    repository_root: Path,
) -> list[Path]:
    """Resolve simple local imports used by the target file."""

    try:
        source = target.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(target))
    except (OSError, UnicodeDecodeError, SyntaxError):
        return []

    imported_files = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_files.extend(
                    _resolve_import(
                        alias.name,
                        target.parent,
                        repository_root,
                    )
                )

        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_files.extend(
                    _resolve_import(
                        node.module,
                        target.parent,
                        repository_root,
                    )
                )

    return imported_files


def _resolve_import(
    module_name: str,
    current_directory: Path,
    repository_root: Path,
) -> list[Path]:
    """Turn a simple Python import into a local file path when possible."""

    parts = module_name.split(".")

    candidates = [
        current_directory.joinpath(*parts).with_suffix(".py"),
        repository_root.joinpath(*parts).with_suffix(".py"),
        repository_root.joinpath(*parts, "__init__.py"),
    ]

    return [
        path.resolve()
        for path in candidates
        if path.is_file() and _is_inside_repository(path, repository_root)
    ]


def _is_inside_repository(
    path: Path,
    repository_root: Path,
) -> bool:
    """Make sure context collection never escapes the repository."""

    try:
        path.relative_to(repository_root)
        return True
    except ValueError:
        return False
