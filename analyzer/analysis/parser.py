import ast
import logging
from pathlib import Path

from analyzer.analysis.models import AnalysisModule

logger = logging.getLogger(__name__)

INIT_FILE = "__init__.py"


class ParseError(Exception):
    """Raised when a Python file cannot be parsed."""


def module_name_from_path(file_path: Path, repository_root: Path) -> str:
    """Convert a repository-relative Python path into a dotted module name.

    Raises:
        ParseError: if file_path is not inside repository_root.
    """
    try:
        relative_path = file_path.resolve().relative_to(repository_root.resolve())
    except ValueError as exc:
        raise ParseError(
            f"{file_path} is not inside repository root {repository_root}"
        ) from exc

    if relative_path.name == INIT_FILE:
        parts = relative_path.parent.parts
    else:
        parts = relative_path.with_suffix("").parts

    if not parts:
        # repository_root itself, or a top-level __init__.py at the root
        raise ParseError(f"Cannot derive a module name for {file_path}")

    # Guard against non-identifier path segments (e.g. dirs with dashes,
    # dots from version suffixes, etc.) producing an invalid module name.
    for part in parts:
        if not part.isidentifier():
            logger.warning(
                "Path segment %r in %s is not a valid Python identifier; "
                "module name may not be importable",
                part,
                file_path,
            )

    return ".".join(parts)


def parse_file(file_path: Path, repository_root: Path) -> AnalysisModule:
    """Read and parse one Python file into an AnalysisModule.

    Raises:
        ParseError: on any failure to locate, read, decode, or parse the file.
    """
    if not file_path.exists():
        raise ParseError(f"File does not exist: {file_path}")
    if not file_path.is_file():
        raise ParseError(f"Not a regular file: {file_path}")

    try:
        raw = file_path.read_bytes()
    except OSError as exc:
        raise ParseError(f"Unable to read {file_path}: {exc}") from exc

    source = _decode_source(raw, file_path)

    try:
        tree = ast.parse(source, filename=str(file_path))
    except SyntaxError as exc:
        raise ParseError(f"Unable to parse {file_path}: {exc}") from exc
    except (ValueError, RecursionError) as exc:
        # ast.parse can raise ValueError on null bytes / invalid source,
        # and RecursionError on pathologically nested expressions.
        raise ParseError(f"Unable to parse {file_path}: {exc}") from exc

    try:
        module_name = module_name_from_path(file_path, repository_root)
    except ParseError:
        raise
    except Exception as exc:  # defensive: never let an unexpected error escape
        raise ParseError(
            f"Unable to derive module name for {file_path}: {exc}") from exc

    return AnalysisModule(
        file_path=file_path,
        module_name=module_name,
        tree=tree,
    )


def _decode_source(raw: bytes, file_path: Path) -> str:
    """Decode file bytes to text, handling BOM and encoding declarations.

    ast.parse can technically take bytes directly, but decoding ourselves
    gives cleaner error messages and lets us strip a UTF-8 BOM, which
    Python's tokenizer otherwise chokes on in some versions.
    """
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError(
            f"Unable to decode {file_path} as UTF-8: {exc}") from exc
