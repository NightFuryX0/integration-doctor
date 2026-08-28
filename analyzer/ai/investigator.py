"""
Integration Doctor — AI Investigator component.

Given a static-analysis finding, asks Gemini to independently verify
whether the finding is a real bug (TRUE_POSITIVE), a misfire
(FALSE_POSITIVE), or inconclusive (UNCERTAIN).

The investigator uses:
1. The static-analysis finding.
2. The complete (bounded) source of the affected file.
3. Relevant local repository context.
"""

from __future__ import annotations

import json
import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Literal, Optional, Tuple

from dotenv import load_dotenv
from google import genai
from google.genai import types  # FIX: use the SDK's typed generation config
from google.genai.errors import APIError
from pydantic import BaseModel, Field

from analyzer.ai.context import build_repository_context


load_dotenv()

logger = logging.getLogger("integration_doctor.investigator")

# Keep the main source bounded so very large files do not create huge prompts.
MAX_SOURCE_CHARS = 20_000

# Keep all additional repository context bounded as well.
MAX_CONTEXT_CHARS = 30_000


class InvestigatorConfigError(RuntimeError):
    """Raised when the investigator is incorrectly configured."""


class InvestigatorAPIError(RuntimeError):
    """Raised when the Gemini API call fails."""


class InvestigatorParseError(RuntimeError):
    """Raised when Gemini's response cannot be parsed correctly."""


class InvestigationResult(BaseModel):
    """Structured result returned by the AI investigator."""

    verdict: Literal[
        "TRUE_POSITIVE",
        "FALSE_POSITIVE",
        "UNCERTAIN",
    ] = Field(
        description="Whether the static analyzer finding is a real issue."
    )

    confidence: Literal[
        "HIGH",
        "MEDIUM",
        "LOW",
    ] = Field(
        description="Confidence in the investigation result."
    )

    explanation: str = Field(
        description=(
            "Clear explanation of why the finding is or is not "
            "a real issue."
        )
    )

    evidence: List[str] = Field(
        description=(
            "Specific pieces of source code or repository context "
            "supporting the verdict."
        )
    )

    files_examined: List[str] = Field(
        description="Files actually examined while reaching the conclusion."
    )


class GeminiInvestigator:
    """Uses Gemini to independently investigate static-analysis findings."""

    def __init__(
        self,
        max_retries: int = 2,
        retry_backoff_seconds: float = 1.5,
    ):
        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise InvestigatorConfigError(
                "GEMINI_API_KEY is not set. "
                "Add it to the .env file before using the AI investigator."
            )

        model = os.getenv(
            "GEMINI_MODEL",
            "gemini-3-flash-preview",
        ).strip()

        if not model:
            raise InvestigatorConfigError(
                "GEMINI_MODEL is set but empty. "
                "Provide a valid Gemini model name."
            )

        if max_retries < 0:
            raise ValueError("max_retries cannot be negative.")

        if retry_backoff_seconds < 0:
            raise ValueError(
                "retry_backoff_seconds cannot be negative."
            )

        self.client = genai.Client(api_key=api_key)
        self.model = model
        self.max_retries = max_retries
        self.retry_backoff_seconds = retry_backoff_seconds

    def investigate(
        self,
        finding: Dict,
        source_code: str,
        file_path: str,
        repository_context: Optional[List[Dict]] = None,
        source_truncated: bool = False,
    ) -> InvestigationResult:
        """Investigate one static-analysis finding."""

        if not isinstance(finding, dict):
            raise TypeError("finding must be a dictionary.")

        if not isinstance(source_code, str):
            raise TypeError("source_code must be a string.")

        if not isinstance(file_path, str) or not file_path.strip():
            raise ValueError("file_path must be a non-empty string.")

        prompt = self._build_prompt(
            finding=finding,
            source_code=source_code,
            file_path=file_path,
            repository_context=repository_context,
            source_truncated=source_truncated,
        )

        response = self._call_with_retries(prompt)

        if not response.parsed:
            raw_response = getattr(
                response,
                "text",
                "<no response text>",
            )

            logger.error(
                "Gemini response could not be parsed: %s",
                raw_response,
            )

            raise InvestigatorParseError(
                "Gemini returned a response, but it could not be "
                "parsed into the expected investigation format."
            )

        try:
            if isinstance(response.parsed, InvestigationResult):
                result = response.parsed
            else:
                result = InvestigationResult.model_validate(
                    response.parsed
                )

        except Exception as exc:
            raise InvestigatorParseError(
                "Gemini returned data, but it did not match the "
                "expected investigation schema."
            ) from exc

        logger.info(
            "Investigated %s -> verdict=%s confidence=%s",
            file_path,
            result.verdict,
            result.confidence,
        )

        return result

    def _call_with_retries(self, prompt: str):
        """Call Gemini and retry failed requests a limited number of times.

        BUG FIX (#3): the original code only caught `APIError`. Timeouts,
        connection resets, and other transport-layer failures from the SDK
        do not necessarily subclass `APIError`, so they propagated straight
        out of this function and would crash the CLI's scan loop mid-scan.
        We now catch any exception raised by the SDK call, retry it the same
        way, and wrap whatever we last saw in `InvestigatorAPIError`.
        """

        last_error: Optional[BaseException] = None
        total_attempts = self.max_retries + 1

        for attempt in range(1, total_attempts + 1):
            try:
                return self.client.models.generate_content(
                    model=self.model,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        response_schema=InvestigationResult,
                        automatic_function_calling=types.AutomaticFunctionCallingConfig(
                            disable=True,
                        ),
                    ),
                )

            except Exception as exc:
                last_error = exc

                is_api_error = isinstance(exc, APIError)

                logger.warning(
                    "Gemini request failed (attempt %d/%d)%s: %s",
                    attempt,
                    total_attempts,
                    "" if is_api_error else " [non-APIError exception]",
                    exc,
                )

                if attempt < total_attempts:
                    time.sleep(
                        self.retry_backoff_seconds * attempt
                    )

        raise InvestigatorAPIError(
            f"Gemini API call failed after "
            f"{total_attempts} attempts: {last_error}"
        ) from last_error

    def _build_prompt(
        self,
        finding: Dict,
        source_code: str,
        file_path: str,
        repository_context: Optional[List[Dict]] = None,
        source_truncated: bool = False,
    ) -> str:
        """Build the complete prompt sent to Gemini."""

        # BUG FIX (#4): truncation of the main source now happens in
        # investigate_file()/the caller via a bounded read, so by the time
        # source_code gets here it is already <= MAX_SOURCE_CHARS. We still
        # defensively re-slice in case investigate() is called directly with
        # an untruncated string, and we rely on the `source_truncated` flag
        # (rather than re-deriving it from length) so callers that already
        # know the real on-disk truncation status can tell us accurately.
        truncated_here = len(source_code) > MAX_SOURCE_CHARS
        code_for_prompt = source_code[:MAX_SOURCE_CHARS]
        is_truncated = source_truncated or truncated_here

        if is_truncated:
            code_for_prompt += (
                "\n\n# ... [TRUNCATED: file exceeds the analysis limit. "
                "Unexamined sections must not be treated as evidence of safety.] ..."
            )

        finding_json = json.dumps(
            finding,
            indent=2,
            default=str,
        )

        context_text = self._format_repository_context(
            repository_context or [],
            main_file_path=file_path,
        )

        return f"""
You are the investigation component of Integration Doctor.

Integration Doctor is a security and reliability analyzer for
Razorpay payment integrations.

A deterministic static analyzer has reported a potential problem.

Your job is NOT to blindly agree with the detector.

You must independently inspect the supplied source code and
relevant repository context.

Determine whether the finding is:

TRUE_POSITIVE
The reported issue genuinely exists.

FALSE_POSITIVE
The code is actually safe and the detector misunderstood the context.

UNCERTAIN
There is not enough evidence to make a reliable decision.

IMPORTANT RULES:

1. Do not assume the detector is correct.

2. Look for verification, middleware, decorators, helper functions,
   imported functions, wrappers, configuration, and related code.

3. Base your conclusion ONLY on the evidence supplied in this prompt.

4. Do not invent files, functions, configuration, database behavior,
   middleware behavior, or security controls that you cannot see.

5. If the evidence is insufficient, return UNCERTAIN.

6. Explain your conclusion clearly.

7. Provide specific evidence from the supplied code.

8. If source code is marked TRUNCATED (main file or repository context),
   do not treat missing/unexamined code as evidence that the application
   is safe.

9. Do not assume that a function named "verify_signature",
   "check_idempotency", "safe_retry", or similar is actually safe.
   Inspect its implementation.

10. Distinguish between:
    - a security control existing,
    - the control actually being called,
    - and the control actually performing the required security operation.

11. Do not call something a TRUE_POSITIVE merely because the detector
    message or filename suggests that it is vulnerable.

12. Do not call something a FALSE_POSITIVE merely because a function
    or decorator has a security-related name.

13. If you cannot establish the answer from the supplied evidence,
    prefer UNCERTAIN.

14. Only list files in files_examined that were actually provided
    in this prompt.

STATIC ANALYZER FINDING:

{finding_json}

FILE BEING INVESTIGATED:

{file_path}

MAIN SOURCE CODE:

```python
{code_for_prompt}
```

RELEVANT LOCAL REPOSITORY CONTEXT:

{context_text}

Use the repository context to investigate:

- decorators
- middleware
- imported helpers
- signature verification
- idempotency mechanisms
- retry-safety mechanisms
- payment-state handling
- other code directly relevant to the reported finding

Return ONLY the structured investigation result.
"""

    def _format_repository_context(
        self,
        repository_context: List[Dict],
        main_file_path: str,
    ) -> str:
        """Convert repository files into bounded prompt text.

        BUG FIX (#1): build_repository_context() always returns the target
        file itself as its first entry (that's how it seeds the search), so
        without filtering it here the exact same file gets sent to Gemini
        twice: once in full (up to MAX_SOURCE_CHARS) as "MAIN SOURCE CODE",
        and again independently truncated (up to context.MAX_FILE_CHARS)
        inside "repository context". That wastes prompt budget and hands
        the model two differently-truncated copies of one file to reconcile.
        We now skip any context entry whose resolved path matches the main
        file being investigated.

        BUG FIX (#2): context.py truncates each file individually to
        MAX_FILE_CHARS and now reports that via a "truncated" flag on each
        item. Previously this function only appended a [TRUNCATED] marker
        when the *combined* context budget forced further cutting here,
        so a file already cut down in context.py could pass through with
        no truncation marker at all -- silently violating rule 8. We now
        honor the upstream flag in addition to our own combined-budget cut.
        """

        try:
            main_resolved = str(Path(main_file_path).resolve())
        except OSError:
            main_resolved = main_file_path

        if not repository_context:
            return "No additional repository context was available."

        sections = []
        total_chars = 0

        for item in repository_context:
            if not isinstance(item, dict):
                continue

            file_path = (
                item.get("file")
                or item.get("file_path")
                or item.get("path")
            )

            source = (
                item.get("source")
                or item.get("source_code")
                or item.get("content")
            )

            if not file_path or source is None:
                continue

            # Skip the file already shown in full as MAIN SOURCE CODE.
            try:
                resolved = str(Path(file_path).resolve())
            except OSError:
                resolved = file_path

            if resolved == main_resolved:
                continue

            if not isinstance(source, str):
                source = str(source)

            already_truncated_upstream = bool(item.get("truncated"))

            remaining_chars = MAX_CONTEXT_CHARS - total_chars

            if remaining_chars <= 0:
                break

            bounded_source = source[:remaining_chars]
            cut_by_combined_budget = len(bounded_source) < len(source)

            if already_truncated_upstream or cut_by_combined_budget:
                bounded_source += (
                    "\n# ... [TRUNCATED repository context] ..."
                )

            sections.append(
                f"""
--- Repository file: {file_path} ---

```python
{bounded_source}
```
"""
            )

            total_chars += len(bounded_source)

        if not sections:
            return "No usable repository context was available."

        return "\n".join(sections)


def _read_source_bounded(
    path: Path,
    limit: int = MAX_SOURCE_CHARS,
) -> Tuple[str, bool]:
    """Read up to `limit` + 1 characters of a file, never the whole thing.

    BUG FIX (#4): the original code did
    `source_code = file_path.read_text(encoding="utf-8")`, which loads the
    entire file into memory before any truncation happens later in
    `_build_prompt`. For a very large file that is unnecessary I/O and
    memory use for content that will just be discarded. We instead read a
    bounded number of characters directly and report whether the file
    continued past that point, so callers know the truncation status
    without ever materializing the rest of the file.
    """

    try:
        with path.open("r", encoding="utf-8") as handle:
            content = handle.read(limit + 1)
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"Could not investigate '{path}' because it is not valid UTF-8."
        ) from exc

    truncated = len(content) > limit

    return content[:limit], truncated


# BUG FIX (#5): the original investigate_file() called `GeminiInvestigator()`
# on every single finding, which means every finding in a scan re-ran API key
# validation and re-created a `genai.Client`. That's wasteful, and it means a
# transient client-construction problem (e.g. a flaky env read) surfaces on
# every finding instead of once. We now lazily build one shared instance and
# reuse it, while still allowing a caller (or a test) to inject its own via
# the `investigator` parameter.
_shared_investigator: Optional[GeminiInvestigator] = None


def _get_shared_investigator() -> GeminiInvestigator:
    global _shared_investigator

    if _shared_investigator is None:
        _shared_investigator = GeminiInvestigator()

    return _shared_investigator


def investigate_file(
    finding: Dict,
    repository_root: str = ".",
    investigator: Optional[GeminiInvestigator] = None,
) -> InvestigationResult:
    """Investigate a finding using its source file and repository context.

    `investigator` lets a caller (e.g. scanner.py, or a test) supply one
    long-lived `GeminiInvestigator` to reuse across many findings instead of
    paying client-construction cost per finding. If omitted, a shared
    module-level instance is created on first use and reused thereafter.
    """

    if not isinstance(finding, dict):
        raise TypeError("finding must be a dictionary.")

    file_value = finding.get("file")

    if not isinstance(file_value, str) or not file_value.strip():
        raise ValueError(
            "finding must contain a non-empty 'file' field."
        )

    file_path = Path(file_value)

    if not file_path.is_file():
        raise FileNotFoundError(
            f"Could not investigate '{file_path}' because the file does not exist."
        )

    source_code, source_truncated = _read_source_bounded(
        file_path,
        limit=MAX_SOURCE_CHARS,
    )

    # Repository context is supplemental, so a failure to collect it must
    # not prevent investigation of the main source file.
    try:
        repository_context = build_repository_context(
            file_path=str(file_path),
            repository_root=repository_root,
        )
    except Exception as exc:
        logger.warning(
            "Could not collect repository context for %s: %s",
            file_path,
            exc,
        )
        repository_context = []

    active_investigator = investigator or _get_shared_investigator()

    return active_investigator.investigate(
        finding=finding,
        source_code=source_code,
        file_path=str(file_path),
        repository_context=repository_context,
        source_truncated=source_truncated,
    )
