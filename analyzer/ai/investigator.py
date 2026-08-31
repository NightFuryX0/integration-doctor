"""
Integration Doctor — AI Investigator component.

Given a static-analysis finding, asks an AI model to independently verify
whether the finding is a real bug (TRUE_POSITIVE), a misfire
(FALSE_POSITIVE), or inconclusive (UNCERTAIN).

The investigator uses:
1. The static-analysis finding.
2. The complete (bounded) source of the affected file.
3. Relevant local repository context.

Two providers are supported:
- NVIDIA (nemotron-3.5-lightning, via NVIDIA's OpenAI-compatible NIM API).
  Preferred by default during development/testing because it currently
  offers materially higher request limits than Gemini's free tier, which
  matters when iterating on the investigator itself.
- Gemini (the original provider). Still fully supported, and used as an
  automatic fallback if NVIDIA is selected but not usable.

Which provider is used is controlled by the AI_PROVIDER environment
variable ("nvidia" or "gemini"). If unset, the provider is auto-detected
from whichever API key is present, preferring NVIDIA_API_KEY.

The scanner and the rest of the codebase do not need to know which
provider is active: they only ever call investigate_file(), which returns
the same InvestigationResult regardless of provider.
"""

from __future__ import annotations
import re
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

# NEW: NVIDIA's hosted NIM endpoint is OpenAI-compatible, so the `openai`
# package is the client for the NVIDIA provider. It is imported
# defensively (not at hard module scope) so that a Gemini-only install
# that hasn't run `pip install openai` doesn't fail to import this module
# at all -- it will only fail if it actually tries to construct an
# NvidiaInvestigator, with a clear error explaining why.
try:
    from openai import OpenAI
    import openai as openai_sdk

    _OPENAI_SDK_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only when openai isn't installed
    OpenAI = None
    openai_sdk = None
    _OPENAI_SDK_AVAILABLE = False


load_dotenv()

logger = logging.getLogger("integration_doctor.investigator")

# Keep the main source bounded so very large files do not create huge prompts.
MAX_SOURCE_CHARS = 20_000

# Keep all additional repository context bounded as well.
MAX_CONTEXT_CHARS = 30_000

# NEW: Explain why each detector rule fires so the AI does not have to
# decide from scratch whether the security control is required.
RULE_GUIDANCE = {
    "WEBHOOK": (
        "This rule fires when a webhook handler processes an incoming "
        "request without verifying it actually came from the payment "
        "provider (for example, an HMAC or signature check). Webhook "
        "endpoints are reachable by anyone on the internet, so this "
        "integration point requires signature verification. The only "
        "open question is whether verification actually happens "
        "somewhere in the request path, such as inline code, a decorator, "
        "or middleware."
    ),
    "IDEMPOTENCY": (
        "This rule fires when a payment-mutating operation does not "
        "appear to guard against duplicate execution. The open question "
        "is whether an idempotency mechanism actually protects the "
        "operation."
    ),
    "RETRY": (
        "This rule fires when an operation that mutates payment state "
        "may be retried in a way that could cause duplicate side effects. "
        "The open question is whether the retry path is actually "
        "protected against duplicate execution."
    ),
}


def _rule_guidance_for(finding: Dict) -> str:
    """Return rule-specific guidance for a finding."""

    rule_id = str(finding.get("rule_id", ""))
    prefix = rule_id.split("-")[0].upper()

    return RULE_GUIDANCE.get(prefix, "")


class InvestigatorConfigError(RuntimeError):
    """Raised when the investigator is incorrectly configured."""


class InvestigatorAPIError(RuntimeError):
    """Raised when the AI provider's API call fails."""


class InvestigatorParseError(RuntimeError):
    """Raised when the AI provider's response cannot be parsed correctly."""


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


# NEW: shared investigation flow, factored out so NvidiaInvestigator and
# GeminiInvestigator do not each carry their own copy of prompt
# construction and repository-context formatting. Only the actual
# "call the provider and turn its response into an InvestigationResult"
# step differs per provider (`_investigate_prompt`).
#
# This is a straight extraction of logic that previously lived inside
# GeminiInvestigator -- GeminiInvestigator's public behavior (including
# every existing test that constructs it directly and calls
# `.investigate(...)`) is unchanged.
class BaseInvestigator:
    """Shared prompt-building and validation; subclasses call their provider."""

    max_retries: int
    retry_backoff_seconds: float

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

        result = self._investigate_prompt(prompt)

        logger.info(
            "Investigated %s -> verdict=%s confidence=%s",
            file_path,
            result.verdict,
            result.confidence,
        )

        return result

    def _investigate_prompt(self, prompt: str) -> InvestigationResult:
        """Call the provider and return a validated InvestigationResult.

        Implemented by each provider subclass.
        """

        raise NotImplementedError

    def _build_prompt(
        self,
        finding: Dict,
        source_code: str,
        file_path: str,
        repository_context: Optional[List[Dict]] = None,
        source_truncated: bool = False,
    ) -> str:
        """Build the complete prompt sent to the AI provider."""

        truncated_here = len(source_code) > MAX_SOURCE_CHARS
        code_for_prompt = source_code[:MAX_SOURCE_CHARS]
        is_truncated = source_truncated or truncated_here

        if is_truncated:
            code_for_prompt += (
                "\n\n# ... [TRUNCATED: file exceeds the analysis limit. "
                "Unexamined sections must not be treated as evidence of safety.] ..."
            )

        # NEW: Tell the model why this rule exists before asking it to
        # determine whether the finding is actually valid.
        rule_guidance = _rule_guidance_for(finding) or (
            "No additional rule-specific context is available for this "
            "finding; rely on its message and severity."
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

15. Distinguish absence of evidence from evidence of absence.

    The fact that a security control is not visible in the main source
    file does NOT by itself prove that the control is missing.

    Before classifying a finding as TRUE_POSITIVE, inspect all relevant
    evidence supplied in the prompt, including:

    - the main source file,
    - imported local files,
    - helper functions,
    - decorators,
    - middleware,
    - wrappers,
    - configuration,
    - and repository context.

    If the supplied evidence demonstrates that the required control
    exists and protects the sensitive operation, classify the finding
    as FALSE_POSITIVE.

    If the supplied evidence does not contain enough information to
    determine whether the control exists or protects the operation,
    classify the finding as UNCERTAIN.

    If the supplied evidence clearly demonstrates that the sensitive
    operation can execute without the required control, classify the
    finding as TRUE_POSITIVE.

    Do not use "I could not find it" as sufficient evidence for
    TRUE_POSITIVE when relevant repository context is incomplete,
    truncated, or unavailable.


16. Recognize valid guard-clause security checks.

    A security control is valid when successful verification is required
    before a sensitive operation can proceed.

    For example:

        if not verify_signature(payload, signature, secret):
            return "Invalid signature", 401

        process_payment(data)

    The control-flow meaning is:

        verification fails -> invalid or unverified request is rejected
        -> function stops

        verification succeeds -> execution continues
        -> sensitive operation runs

    Therefore, process_payment() is protected by verify_signature() and
    the check is a valid security gate.

    Do NOT classify this as TRUE_POSITIVE merely because the sensitive
    operation appears after the verification call.

    Trace the actual control flow and determine whether an invalid or
    unverified request can reach the sensitive operation.

    The relevant question is not:

        "Does process_payment() appear after verification?"

    The relevant question is:

        "Can process_payment() execute when verification has failed?"

    If the answer is no, the verification is functioning as a valid
    security gate.

    Continuing to the sensitive operation is expected when verification
    succeeds. This is NOT evidence of a vulnerability.

    A TRUE_POSITIVE requires an execution path where the sensitive
    operation can occur without successful verification.


17. Analyze the implementation and the caller separately.

    The existence of a function with a security-related name is not
    sufficient evidence that the required control exists.

    If the implementation of the verification function is supplied,
    inspect it and determine whether it actually performs the required
    security operation.

    Then inspect the caller and determine whether the result of that
    verification actually controls access to the sensitive operation.

    Both conditions matter:

        1. The verification function must perform the required check.
        2. The request must be prevented from reaching the sensitive
           operation when that check fails.

    For example, this is protected:

        valid = verify_signature(payload, signature, secret)

        if not valid:
            return "Invalid signature", 401

        process_payment(data)

    But this is NOT protected:

        valid = verify_signature(payload, signature, secret)

        process_payment(data)

    because the verification result does not affect whether the payment
    operation executes.

    Likewise, this is NOT sufficient:

        def verify_signature(...):
            return True

    if the supplied implementation does not actually perform the
    required verification.


18. Trace actual control flow rather than judging code by textual
    proximity.

    You must trace the actual control flow from the untrusted input
    through the security check to the sensitive operation.

    Determine whether there is an execution path that reaches the
    sensitive operation without successful verification.

    A TRUE_POSITIVE requires evidence of such an execution path.

    A security check located several lines before a sensitive operation
    may still fully protect it.

    Conversely, a security check located immediately before a sensitive
    operation may still be ineffective if:

    - its result is ignored,
    - its failure does not stop execution,
    - the sensitive operation is reachable through another branch,
    - the sensitive operation is called elsewhere without the check,
    - or the check itself does not perform the required security
      operation.

    Do not judge protection based solely on textual proximity.
19. Do not invent bypasses or hypothetical execution paths.

    Base the verdict only on behavior demonstrated by the supplied
    evidence.

    Do NOT assume that a check can be bypassed merely because:

    - an input could theoretically be malformed,
    - a header could theoretically be missing,
    - a framework could theoretically behave differently,
    - an exception could theoretically occur,
    - another file might theoretically contain a bypass,
    - or some undocumented deployment behavior might theoretically
      exist.

    Such possibilities may be mentioned as uncertainty only when the
    supplied code provides concrete evidence supporting them.

    Do not convert hypothetical possibilities into TRUE_POSITIVE.


20. Treat rejection, return, raise, abort, and equivalent termination
    as valid enforcement mechanisms.

    A security check does not need to use one specific coding pattern.

    The control should be considered enforced when a failed check causes
    execution to stop or otherwise prevents the sensitive operation
    from occurring.

    Examples include:

        return response, 401

        raise PermissionError(...)

        abort(401)

        if not authorized:
            return

    The exact mechanism is less important than the resulting control
    flow.

    Determine whether the failure path actually prevents the sensitive
    operation.


21. Do not require redundant checks when the supplied control already
    establishes the required security property.

    If verify_signature() is shown to reject invalid signatures and the
    caller rejects a failed verification result before processing the
    request, do not require an additional explicit check merely for
    missing headers, empty signatures, or other inputs unless the
    supplied implementation demonstrates that those inputs can bypass
    verification.

    Do not invent a vulnerability that is already prevented by the
    supplied verification logic.

    Similarly, do not require a second idempotency check, retry guard,
    authorization check, or equivalent control when the supplied code
    already demonstrates an effective control for the property being
    investigated.


22. Use the strongest conclusion supported by the supplied evidence.

    Use TRUE_POSITIVE when the supplied evidence demonstrates that the
    reported security or reliability issue genuinely exists.

    Use FALSE_POSITIVE when the supplied evidence demonstrates that the
    required control exists and prevents the reported issue.

    Use UNCERTAIN when the supplied evidence leaves a material question
    unresolved.

    Do not choose TRUE_POSITIVE simply because the detector's finding
    sounds plausible.

    Do not choose FALSE_POSITIVE simply because a security-related
    function, variable, decorator, or comment exists.

    The verdict must follow from the actual implementation and control
    flow visible in the supplied evidence.
STATIC ANALYZER FINDING:

{finding_json}

WHY THIS RULE EXISTS:

{rule_guidance}

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
        without filtering it here the exact same file gets sent to the model
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


class GeminiInvestigator(BaseInvestigator):
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
                "Add it to the .env file before using the Gemini investigator."
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

    # NEW: this is the same body that used to live inline inside
    # `investigate()` before prompt-building/validation moved to
    # BaseInvestigator. Behavior is unchanged.
    def _investigate_prompt(self, prompt: str) -> InvestigationResult:
        response = self._call_with_retries(
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=InvestigationResult,
            ),
        )

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
                "Gemini response could not be parsed."
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

        return result

    def _call_with_retries(
        self,
        *,
        contents: str,
        config: types.GenerateContentConfig,
    ) -> types.GenerateContentResponse:
        """Call Gemini with bounded retries for transient failures."""

        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                return self.client.models.generate_content(
                    model=self.model,
                    contents=contents,
                    config=config,
                )

            except APIError as error:
                # Permanent 4xx API errors should not be pointlessly retried.
                if error.code < 500 and error.code != 429:
                    raise InvestigatorAPIError(
                        f"Gemini request failed with "
                        f"{error.code} {error.status}: {error.message}"
                    ) from error

                # 429 and 5xx errors may be temporary, so allow retries.
                last_error = error

            except (
                ConnectionError,
                TimeoutError,
            ) as error:
                # Network and timeout failures are commonly temporary.
                last_error = error

            except Exception as error:
                # Preserve bounded retry behavior for unexpected SDK failures.
                last_error = error

            if attempt < self.max_retries:
                delay = self.retry_backoff_seconds * (2**attempt)

                logger.warning(
                    "Gemini request failed (attempt %s/%s): %s",
                    attempt + 1,
                    self.max_retries + 1,
                    last_error,
                )

                time.sleep(delay)

        raise InvestigatorAPIError(
            f"Gemini request failed after "
            f"{self.max_retries + 1} attempts: {last_error}"
        ) from last_error


class NvidiaInvestigator(BaseInvestigator):
    """Uses NVIDIA-hosted Nemotron to independently investigate findings.

    NVIDIA's endpoint is OpenAI-compatible, so this uses the standard
    OpenAI client pointed at NVIDIA's API rather than a custom HTTP client.
    """

    DEFAULT_MODEL = "nvidia/nemotron-3.5-lightning-30b-a3b"
    BASE_URL = "https://integrate.api.nvidia.com/v1"

    def __init__(
        self,
        max_retries: int = 2,
        retry_backoff_seconds: float = 1.5,
    ):
        if not _OPENAI_SDK_AVAILABLE:
            raise InvestigatorConfigError(
                "The 'openai' package is required to use the NVIDIA "
                "provider (it is NVIDIA's documented OpenAI-compatible "
                "client). Install it with `pip install openai`."
            )

        api_key = os.getenv("NVIDIA_API_KEY")

        if not api_key:
            raise InvestigatorConfigError(
                "NVIDIA_API_KEY is not set. "
                "Add it to the .env file before using the NVIDIA investigator."
            )

        model = os.getenv(
            "NVIDIA_MODEL",
            self.DEFAULT_MODEL,
        ).strip()

        if not model:
            raise InvestigatorConfigError(
                "NVIDIA_MODEL is set but empty. "
                "Provide a valid NVIDIA model name."
            )

        if max_retries < 0:
            raise ValueError("max_retries cannot be negative.")

        if retry_backoff_seconds < 0:
            raise ValueError(
                "retry_backoff_seconds cannot be negative."
            )

        self.client = OpenAI(api_key=api_key, base_url=self.BASE_URL)
        self.model = model
        self.max_retries = max_retries
        self.retry_backoff_seconds = retry_backoff_seconds

        # Built once (schema doesn't change), reused on every request rather
        # than regenerated per call.
        self._response_format = {
            "type": "json_schema",
            "json_schema": {
                "name": "investigation_result",
                "schema": InvestigationResult.model_json_schema(),
            },
        }

    def _investigate_prompt(self, prompt: str) -> InvestigationResult:
        response = self._call_with_retries(prompt)

        raw_content = None
        if response.choices:
            raw_content = response.choices[0].message.content

        if not raw_content:
            logger.error("NVIDIA returned an empty investigation response.")
            raise InvestigatorParseError(
                "NVIDIA returned a response, but it contained no "
                "investigation data."
            )

        try:
            # First, try parsing the response exactly as NVIDIA returned it.
            parsed = json.loads(raw_content)

        except json.JSONDecodeError:
            # NVIDIA may occasionally wrap valid JSON in Markdown fences
            # or include a small amount of text around the JSON object.
            cleaned_content = raw_content.strip()

            # Remove Markdown JSON code fences if the model used them.
            if cleaned_content.startswith("```"):
                cleaned_content = re.sub(
                    r"^```(?:json)?\s*",
                    "",
                    cleaned_content,
                    flags=re.IGNORECASE,
                )
                cleaned_content = re.sub(
                    r"\s*```$",
                    "",
                    cleaned_content,
                ).strip()

            # Try to isolate the outermost JSON object.
            start = cleaned_content.find("{")
            end = cleaned_content.rfind("}")

            if start == -1 or end == -1 or end <= start:
                raise InvestigatorParseError(
                    "NVIDIA returned data, but it did not match the "
                    "expected investigation schema."
                )

            json_content = cleaned_content[start: end + 1]

            try:
                parsed = json.loads(json_content)

            except json.JSONDecodeError as exc:
                logger.error(
                    "NVIDIA returned malformed JSON: %s",
                    raw_content,
                )
                raise InvestigatorParseError(
                    "NVIDIA returned data, but it did not match the "
                    "expected investigation schema."
                ) from exc

        try:
            # Validate the parsed object against our expected schema.
            result = InvestigationResult.model_validate(parsed)

        except ValueError as exc:
            logger.error(
                "NVIDIA investigation response failed schema validation: %s",
                raw_content,
            )
            raise InvestigatorParseError(
                "NVIDIA returned JSON, but it did not match the "
                "expected investigation schema."
            ) from exc

        return result

    def _call_with_retries(self, prompt: str):
        """Call NVIDIA with bounded retries for transient failures.

        Mirrors GeminiInvestigator._call_with_retries: permanent 4xx
        client errors (other than 429) fail immediately; 429 and
        5xx/connection failures are retried with exponential backoff.

        Uses the real `openai` SDK exception hierarchy (verified against
        the installed package): APIStatusError is the base for all 4xx/5xx
        responses and carries `.status_code`; RateLimitError (429) and
        InternalServerError (5xx) are its subclasses; APIConnectionError
        is raised separately for network-level failures and has no
        `.status_code`.
        """

        last_error = None

        for attempt in range(self.max_retries + 1):
            try:
                return self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {
                            "role": "user",
                            "content": prompt,
                        }
                    ],
                    temperature=0.0,
                    max_tokens=4096,
                    response_format=self._response_format,
                    # Disable visible chain-of-thought so message.content
                    # holds only the structured JSON we asked for, per
                    # NVIDIA's guidance for structured-output requests.
                    extra_body={
                        "chat_template_kwargs": {
                            "enable_thinking": False,
                        },
                    },
                )

            except openai_sdk.RateLimitError as error:
                # 429s are always worth a bounded retry.
                last_error = error

            except openai_sdk.APIStatusError as error:
                # Other 4xx (400/401/403/404/422) are permanent -- retrying
                # won't fix a bad request, bad credentials, or a bad model
                # name. 5xx (InternalServerError etc.) is retryable.
                if error.status_code is not None and error.status_code < 500:
                    raise InvestigatorAPIError(
                        f"NVIDIA request failed with "
                        f"{error.status_code}: {error}"
                    ) from error

                last_error = error

            except (
                openai_sdk.APIConnectionError,
                ConnectionError,
                TimeoutError,
            ) as error:
                # Network-level failures (including timeouts) are commonly
                # temporary.
                last_error = error

            except Exception as error:  # noqa: BLE001
                # Preserve bounded retry behavior for unexpected SDK failures.
                last_error = error

            if attempt < self.max_retries:
                delay = self.retry_backoff_seconds * (2**attempt)

                logger.warning(
                    "NVIDIA request failed (attempt %s/%s): %s",
                    attempt + 1,
                    self.max_retries + 1,
                    last_error,
                )

                time.sleep(delay)

        raise InvestigatorAPIError(
            f"NVIDIA request failed after "
            f"{self.max_retries + 1} attempts: {last_error}"
        ) from last_error


def _read_source_bounded(
    path: Path,
    limit: int = MAX_SOURCE_CHARS,
) -> Tuple[str, bool]:
    """Read up to `limit` + 1 characters of a file, never the whole thing."""

    try:
        with path.open("r", encoding="utf-8") as handle:
            content = handle.read(limit + 1)
    except UnicodeDecodeError as exc:
        raise ValueError(
            f"Could not investigate '{path}' because it is not valid UTF-8."
        ) from exc

    truncated = len(content) > limit

    return content[:limit], truncated


# NEW: provider selection. AI_PROVIDER explicitly chooses "nvidia" or
# "gemini". If unset, we auto-detect from whichever API key is present,
# preferring NVIDIA (higher request limits for iterative testing). If
# NVIDIA is selected/detected but not actually usable (missing key,
# missing `openai` package), we fall back to Gemini rather than hard
# failing, as long as a Gemini key is configured -- this is the
# "NVIDIA primary, Gemini fallback" behavior.
def _build_investigator(
    max_retries: int = 2,
    retry_backoff_seconds: float = 1.5,
) -> BaseInvestigator:
    """Construct the configured AI investigator (NVIDIA or Gemini)."""

    provider = os.getenv("AI_PROVIDER", "").strip().lower()

    if provider not in ("", "nvidia", "gemini"):
        raise InvestigatorConfigError(
            f"AI_PROVIDER={provider!r} is not recognized. "
            "Use 'nvidia' or 'gemini', or leave it unset to auto-detect."
        )

    if not provider:
        if os.getenv("NVIDIA_API_KEY"):
            provider = "nvidia"
        elif os.getenv("GEMINI_API_KEY"):
            provider = "gemini"
        else:
            raise InvestigatorConfigError(
                "No AI provider is configured. Set NVIDIA_API_KEY or "
                "GEMINI_API_KEY (and optionally AI_PROVIDER) in .env "
                "before using the AI investigator."
            )

    if provider == "nvidia":
        try:
            return NvidiaInvestigator(
                max_retries=max_retries,
                retry_backoff_seconds=retry_backoff_seconds,
            )
        except InvestigatorConfigError as error:
            if os.getenv("GEMINI_API_KEY"):
                logger.warning(
                    "NVIDIA provider is not usable (%s); falling back "
                    "to Gemini.",
                    error,
                )
                return GeminiInvestigator(
                    max_retries=max_retries,
                    retry_backoff_seconds=retry_backoff_seconds,
                )
            raise

    return GeminiInvestigator(
        max_retries=max_retries,
        retry_backoff_seconds=retry_backoff_seconds,
    )


# The module keeps one shared, lazily-built investigator instance so that
# every finding in a scan doesn't re-validate configuration and
# re-construct a client. A caller (or a test) can still inject its own via
# the `investigator` parameter of investigate_file().
_shared_investigator: Optional[BaseInvestigator] = None


def _get_shared_investigator() -> BaseInvestigator:
    global _shared_investigator

    if _shared_investigator is None:
        _shared_investigator = _build_investigator()

    return _shared_investigator


def investigate_file(
    finding: Dict,
    repository_root: str = ".",
    investigator: Optional[BaseInvestigator] = None,
) -> InvestigationResult:
    """Investigate a finding using its source file and repository context.

    `investigator` lets a caller (e.g. scanner.py, or a test) supply one
    long-lived investigator instance to reuse across many findings instead
    of paying client-construction cost per finding. If omitted, a shared
    module-level instance is created on first use (provider chosen via
    AI_PROVIDER / available API keys) and reused thereafter.
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
