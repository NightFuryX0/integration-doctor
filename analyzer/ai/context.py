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

    # NEW: Add files imported by the target file, and files imported BY
    # those files, and so on (bounded by MAX_FILES). This is what lets a
    # webhook handler that calls process_payment() (imported from
    # payment.py) also pull in security.py, if payment.py in turn imports
    # verify_signature() from there. Previously this only resolved one
    # level of imports -- the target's own -- so a security control
    # implemented two files away from the finding never reached the AI
    # investigator, and the model had no choice but to guess.
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
    """Resolve local imports used by the target file, transitively.

    NEW: This now does a breadth-first walk of the local import graph
    instead of only looking at the target file's own imports. For each
    file we discover, we also parse *its* imports and queue up whatever
    local modules it pulls in, and so on -- so `webhook.py` importing
    `process_payment` from `payment.py`, which itself imports
    `verify_signature` from `security.py`, now surfaces both files, not
    just the first hop.

    Traversal is bounded by MAX_FILES (matching the cap already enforced
    in build_repository_context) and each file is visited at most once,
    so it terminates even on modules that import each other in a cycle.
    Ordering is deterministic: imports are sorted before being queued, and
    files are discovered in breadth-first (nearest-dependency-first) order.
    """

    discovered: list[Path] = []
    seen = {target}
    queue = [target]

    while queue and len(discovered) < MAX_FILES:
        current = queue.pop(0)

        try:
            source = current.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(current))
        except (OSError, UnicodeDecodeError, SyntaxError):
            continue

        direct_imports = []

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    direct_imports.extend(
                        _resolve_import(
                            alias.name,
                            current.parent,
                            repository_root,
                        )
                    )

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    direct_imports.extend(
                        _resolve_import(
                            node.module,
                            current.parent,
                            repository_root,
                        )
                    )

        # Sorted for deterministic ordering; a set() also collapses any
        # duplicate candidate paths _resolve_import may have produced.
        for imported_path in sorted(set(direct_imports)):
            if imported_path in seen:
                continue

            seen.add(imported_path)
            discovered.append(imported_path)
            queue.append(imported_path)

            if len(discovered) >= MAX_FILES:
                break

    return discovered


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


def test_build_repository_context_includes_transitive_import_chain(tmp_path):
    """webhook.py imports process_payment from payment.py, which imports
    verify_signature from security.py -- both must be pulled in, not just
    the file webhook.py imports directly."""

    (tmp_path / "webhook.py").write_text(
        "from payment import process_payment\n\n"
        "@app.route(\"/webhook\", methods=[\"POST\"])\n"
        "def webhook():\n"
        "    data = request.get_json()\n"
        "    process_payment(data)\n"
    )
    (tmp_path / "payment.py").write_text(
        "from security import verify_signature\n\n"
        "def process_payment(data):\n"
        "    verify_signature(data)\n"
        "    charge(data)\n"
    )
    (tmp_path / "security.py").write_text(
        "def verify_signature(data):\n    return True\n"
    )
    (tmp_path / "unrelated.py").write_text(
        "def unrelated():\n    pass\n"
    )

    context = build_repository_context(
        file_path=str(tmp_path / "webhook.py"),
        repository_root=str(tmp_path),
    )

    files_included = {Path(item["file"]).name for item in context}
    assert "payment.py" in files_included
    assert "security.py" in files_included


def test_build_repository_context_prioritizes_dependency_chain_over_unrelated_sibling(tmp_path):
    (tmp_path / "webhook.py").write_text(
        "from payment import process_payment\n\ndef webhook():\n    process_payment({})\n"
    )
    (tmp_path / "payment.py").write_text(
        "from security import verify_signature\n\ndef process_payment(data):\n    verify_signature(data)\n"
    )
    (tmp_path / "security.py").write_text(
        "def verify_signature(data):\n    return True\n"
    )
    (tmp_path / "unrelated.py").write_text(
        "def unrelated():\n    pass\n"
    )

    context = build_repository_context(
        file_path=str(tmp_path / "webhook.py"),
        repository_root=str(tmp_path),
    )

    names = [Path(item["file"]).name for item in context]
    assert names.index("payment.py") < names.index("unrelated.py")
    assert names.index("security.py") < names.index("unrelated.py")


def test_build_repository_context_avoids_duplicate_entries(tmp_path):
    (tmp_path / "webhook.py").write_text(
        "from payment import process_payment\n\ndef webhook():\n    process_payment({})\n"
    )
    (tmp_path / "payment.py").write_text("def process_payment(data):\n    pass\n")

    context = build_repository_context(
        file_path=str(tmp_path / "webhook.py"),
        repository_root=str(tmp_path),
    )

    files_seen = [item["file"] for item in context]
    assert len(files_seen) == len(set(files_seen))


def test_build_repository_context_handles_missing_import_gracefully(tmp_path):
    (tmp_path / "webhook.py").write_text(
        "from nonexistent_module import something\n\ndef webhook():\n    something()\n"
    )

    # Should not raise even though `nonexistent_module` can't be resolved.
    context = build_repository_context(
        file_path=str(tmp_path / "webhook.py"),
        repository_root=str(tmp_path),
    )

    files_included = {Path(item["file"]).name for item in context}
    assert "webhook.py" in files_included


def test_build_repository_context_handles_circular_imports(tmp_path):
    (tmp_path / "a.py").write_text(
        "from b import helper_b\n\ndef helper_a():\n    return helper_b()\n"
    )
    (tmp_path / "b.py").write_text(
        "from a import helper_a\n\ndef helper_b():\n    return 1\n"
    )

    # Must terminate rather than looping forever on the a <-> b cycle.
    context = build_repository_context(
        file_path=str(tmp_path / "a.py"),
        repository_root=str(tmp_path),
    )

    files_included = {Path(item["file"]).name for item in context}
    assert "a.py" in files_included
    assert "b.py" in files_included


def test_build_repository_context_still_bounded_by_max_files(tmp_path):
    from analyzer.ai.context import MAX_FILES

    (tmp_path / "m0.py").write_text("from m1 import x\ndef f(): x()\n")
    for i in range(1, 8):
        (tmp_path /
         f"m{i}.py").write_text(f"from m{i+1} import x\ndef x(): pass\n")
    (tmp_path / "m8.py").write_text("def x(): pass\n")

    context = build_repository_context(
        file_path=str(tmp_path / "m0.py"),
        repository_root=str(tmp_path),
    )

    assert len(context) <= MAX_FILES
