# Integration Doctor

Integration Doctor is a static-analysis tool for catching unsafe patterns in payment and webhook integrations before they turn into an incident.

Payment integrations have a habit of looking fine at a glance while quietly missing something important — a signature check that never actually gets called, a webhook handler that'll happily process the same event twice, a retry loop with no idempotency key in sight. This tool scans your code and flags that stuff for review.

Right now it looks at three things:

- Webhook signature verification
- Duplicate webhook/event handling
- Retry safety around payment operations

There's also an optional AI layer on top. Once a detector flags something, you can have an AI model take a second look at the finding along with the actual source and give its own opinion — including telling you the detector got it wrong.

Integration Doctor isn't a replacement for your payment provider's SDK or docs. It's a second set of eyes on top of them.

---

## What it checks

### Webhook verification

Webhook endpoints should confirm a request is genuinely coming from the provider before doing anything with it. The webhook detector looks at each handler and checks whether it's doing that — cryptographic comparison, a trusted SDK helper (`stripe.Webhook.construct_event`, etc.), that kind of thing.

It's static and heuristic, worth repeating: it doesn't run your code, and it can't prove verification is _correct_ at runtime, only that something that looks like verification is present.

### Webhook idempotency

Providers retry webhook deliveries. That's normal, expected behavior on their end — but it means the same event can hit your handler more than once. The idempotency detector looks for handlers that appear to mutate payment or order state without any visible guard against reprocessing an event it's already seen.

It's looking for things like:

- `event_id`
- `webhook_id`
- `already_processed` / `processed`
- `idempotency`

### Payment retries

Retries are genuinely useful for temporary failures, but retrying a payment operation blindly can double-charge someone. The retry detector looks for functions that call something payment-related, retry it (via a loop or retry-flavored logic), and don't show any obvious protection — an idempotency key, backoff, `max_retries`, that sort of thing.

---

## How it works

Under the hood it's all `ast` — the code is parsed, never executed.

```text
Python project
     |
     v
  Scanner
     |
     v
  Detectors
     |
     v
  Findings
     |
     +-------> Human-readable output
     +-------> JSON output
     +-------> Optional AI investigation
```

The detectors are deterministic — same code in, same findings out, every time. If AI investigation is turned on, each finding gets sent to the investigator along with the relevant source and some bounded repository context, and comes back with an independent read on whether it's actually a problem. The AI layer sits on top of the detectors rather than replacing them, on purpose — you still get repeatable results even without it.

---

## Installation

```bash
git clone <repository-url>
cd integration-doctor
python -m venv .venv
source .venv/bin/activate   # macOS/Linux
pip install -r requirements.txt
```

---

## Usage

```bash
python -m analyzer.scanner
```

With no target given, it scans `integrations/broken_webhook` by default. Point it somewhere else:

```bash
python -m analyzer.scanner path/to/project
```

Full options:

```text
usage: scanner.py [-h] [--ai] [--json] [-v] [target]

Scan a repository for payment integration issues.

positional arguments:
  target         Directory to scan.

options:
  -h, --help     show this help message and exit
  --ai           Run AI investigation on detected findings.
  --json         Emit machine-readable JSON output.
  -v, --verbose  Enable debug logging.
```

---

## AI investigation

Static analysis is good at spotting suspicious shapes in code, but a heuristic detector doesn't understand your architecture. It doesn't know that verification happens in middleware three files away. That's what the AI layer is for.

```bash
python -m analyzer.scanner integrations/broken_webhook --ai
```

The investigator gets the finding, the relevant source file, and bounded repository context, and returns:

- Verdict — `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `UNCERTAIN`
- Confidence
- Explanation
- Evidence
- Files examined

It's specifically instructed not to just rubber-stamp the detector — if the code shows real evidence the control exists and is reachable, it'll call something a false positive.

### Providers

Both Gemini and NVIDIA are supported.

The investigator can be configured through environment variables:

````text
AI_PROVIDER
GEMINI_API_KEY
GEMINI_MODEL
NVIDIA_API_KEY
NVIDIA_MODEL
---

## JSON output

```bash
python -m analyzer.scanner integrations/broken_webhook --json
````

```json
{
  "findings": [],
  "investigations": [],
  "summary": {
    "total": 0,
    "files": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "errors": 0
  }
}
```

Add `--ai` and the `investigations` array gets populated alongside the findings they correspond to. The shape stays the same whether or not anything was found — one less thing for downstream tooling to special-case.

---

## Exit codes

| Code | Meaning                                      |
| ---- | -------------------------------------------- |
| `0`  | Clean scan, nothing found                    |
| `1`  | Scan completed, findings exist               |
| `2`  | Scanner couldn't complete (bad target, etc.) |

A finding isn't a scanner failure — that's what exit code `1` is for. Makes it easy to wire into CI without treating "found something" the same as "broke."

---

## What gets scanned

Python files only, for now. These directories are skipped automatically:

```text
.git .venv venv __pycache__ node_modules
.tox .pytest_cache .mypy_cache .ruff_cache
build dist .eggs
```

Directories it can't read get skipped with a warning rather than killing the whole scan. Files that fail UTF-8 decoding, have invalid syntax, or trip up a detector unexpectedly show up as their own parser/error findings instead of crashing anything.

---

## Findings

```json
{
  "rule_id": "WEBHOOK-001",
  "type": "MISSING_WEBHOOK_SIGNATURE",
  "severity": "CRITICAL",
  "file": "app.py",
  "line": 42,
  "message": "..."
}
```

| Field           | What it is                |
| --------------- | ------------------------- |
| `rule_id`       | which rule fired          |
| `type`          | the specific issue        |
| `severity`      | how bad, roughly          |
| `file` / `line` | where                     |
| `message`       | plain-English explanation |

Rule families right now: `WEBHOOK-*`, `PAYMENT-003`, `PARSER-*`.

One naming quirk worth flagging: `WEBHOOK-002` is the idempotency check, not `IDEMPOTENCY-*`. It got grouped under the `WEBHOOK-*` family early on since it's specifically about webhook duplicate-delivery safety, but it does mean rule-ID prefix matching elsewhere in the codebase needs to account for that if it's trying to route by concern rather than by exact ID.

---

## Example integrations

```text
integrations/
├── broken_webhook/
│   ├── app.py
│   ├── duplicate_webhook.py
│   ├── safe_retry.py
│   └── unsafe_retry.py
└── safe_webhook/
    └── middleware_verified.py
```

Handy for sanity-checking the detectors against both the broken and the fixed versions of the same pattern:

```bash
python -m analyzer.scanner integrations/broken_webhook
```

---

## Project structure

```text
integration-doctor/
│
├── analyzer/
│   ├── ai/
│   │   ├── context.py
│   │   ├── display.py
│   │   └── investigator.py
│   │
│   ├── detectors/
│   │   ├── webhook.py
│   │   ├── idempotency.py
│   │   └── retry.py
│   │
│   ├── scanner.py
│   └── webhook_analyzer.py
│
├── integrations/
│   ├── broken_webhook/
│   └── safe_webhook/
│
├── tests/
│   ├── test_context.py
│   ├── test_false_positive.py
│   ├── test_investigator.py
│   ├── test_retry_detector.py
│   ├── test_scanner.py
│   └── test_webhook_analyzer.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

- **`analyzer/scanner.py`** — the entry point. Finds files, skips what should be skipped, checks for encoding/syntax problems, runs the detectors, optionally kicks off AI investigation, prints output, exits with the right code.
- **`analyzer/detectors/`** — one file per class of problem.
- **`analyzer/ai/`** — the optional layer: repository context, provider clients, structured results, error handling.
- **`integrations/`** — sample apps used to exercise the detectors against.
- **`tests/`** — coverage for all of the above.

---

## Limitations

The detectors are heuristics, not proofs. They read code shapes; they don't run the app or trace real execution.

A detector can miss verification that happens through a helper function, middleware, another module entirely, or some framework-specific abstraction it doesn't recognize. So a finding means "this is worth a look," not "this is definitely broken" — and no findings doesn't mean the integration is airtight, just that nothing obvious jumped out.

That's the actual goal here: catch the obvious stuff early and give you something concrete to go check, not replace a real security review.

---

## Testing

```bash
pytest -q
```

Covers the scanner, all three detectors, false-positive cases, repository context, and the AI investigator (mocked — no real API calls in the test suite).

After making changes:

```bash
pytest -q
git diff --check
python -m analyzer.scanner --help
```

---

## Where things stand

Working today:

- AST-based static analysis for webhook signature, idempotency, and retry safety
- Detector-level failure isolation (one bad detector doesn't take down the scan)
- Parser/file-error handling
- Human-readable and JSON output, with stable exit codes
- Optional AI investigation via Gemini or NVIDIA
- Bounded repository context for the AI layer
- A real test suite

Next up is mostly polish: easier configuration, better detector coverage, cleaner reporting, and more realistic example integrations to test against.

---

## Scope

Integration Doctor doesn't replace your payment provider's SDK, their webhook verification mechanism, their idempotency support, or their docs — those are still the source of truth for how the provider actually expects things to work.

What it does is look at _your_ code and ask a narrower question: does this integration look like it's actually handling those safety concerns, or does it just look like it should?
