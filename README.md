# Integration Doctor

> **Static analysis for payment and webhook integrations.**
> Catch risky integration patterns before they become production incidents.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-279%20passing-brightgreen?logo=pytest)](https://pytest.org/)
[![Ruff](https://img.shields.io/badge/code%20quality-ruff-brightgreen?logo=ruff)](https://docs.astral.sh/ruff/)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-purple)](https://sarifweb.azurewebsites.net/)
[![Version](https://img.shields.io/badge/version-0.1.0-informational)](https://packaging.python.org/)

---

## Why this exists

Payment and webhook code is small, but small mistakes here are expensive: a webhook that never checks its signature, a retry loop that double-charges a card, a duplicate event that gets processed twice. These bugs pass code review easily because the code _looks_ reasonable — the missing piece is invisible unless you're specifically looking for it.

Integration Doctor reads Python source statically (no execution) and combines AST analysis, repository-wide symbol resolution, call-graph reasoning, deterministic detectors, and an optional AI investigation layer to find these patterns before they ship.

A finding means **"this deserves a closer look,"** not **"this is definitely a vulnerability."** No findings does not mean an integration is secure. That distinction matters and is treated as a first-class design constraint, not a disclaimer — see [Limitations](#limitations).

---

## Quick look

```bash
integration-doctor . --sarif
```

```python
# app.py
import hmac

def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    expected = "expected-signature"

    hmac.compare_digest(signature, expected)   # result never checked

    process_event(request)
```

```text
CRITICAL WEBHOOK-001
app.py:4
Webhook handler processes a request without enforced signature verification.
```

The comparison exists — its result is just never used. Integration Doctor is built specifically to catch that gap between "a security check is present" and "a security check is enforced."

---

## What it catches

| Rule              | Area                | What it looks for                                                                           |
| ----------------- | ------------------- | ------------------------------------------------------------------------------------------- |
| `WEBHOOK-001`     | Webhook signatures  | Missing signature verification entirely                                                     |
| `WEBHOOK-003`     | Webhook signatures  | A signature is read but only weakly checked (truthiness, `==`, unenforced `compare_digest`) |
| `PAYMENT-003`     | Payment retries     | Retry/loop behavior around a payment operation with no visible safety mechanism             |
| `PARSER-001..004` | Repository scanning | Files that can't be safely analyzed (syntax errors, encoding issues, detector crashes)      |

> **TODO before publishing:** the idempotency detector's rule ID needs to be confirmed against the actual source (`analyzer/detectors/idempotency.py`) — it is _not_ `WEBHOOK-002` in any code or SARIF output I've seen. Fill in the correct ID here.

---

## How it works

```text
repository
    │
    ▼
source scanner ──► Python AST
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
  symbol table      detectors      repository context
        │               │                │
        ▼               │                │
    resolver            │                │
        │               │                │
        ▼               ▼                ▼
                  call graph
                        │
                        ▼
                 static findings
                        │
        ┌───────────────┼────────────────┐
        ▼               ▼                ▼
  suppressions      baseline      AI investigation (optional)
        │               │                │
        └───────────────┼────────────────┘
                         ▼
                  CLI / JSON / SARIF
                         │
                         ▼
              GitHub Code Scanning
```

**Deterministic static analysis is the foundation. AI is optional and never required to run a scan.**

### Symbol table & resolver

The analyzer builds symbols for functions, methods, classes, and nested functions across the repository, then resolves call sites back to those symbols. Resolution is deliberately conservative: if two modules both define `capture_payment()`, a bare call to it is left **unresolved** rather than guessed. An uncertain answer is safer than a confidently wrong one in a security tool.

### Call graph

Tracks call edges, branches, returns, raises, loops (including back-edges), async functions, and recursive edges, with explicit `max_depth`, `max_paths`, and cycle-prevention bounds on path exploration — because unrestricted traversal on a real repository can blow up fast.

---

## Detectors

**Webhook signature verification** — recognizes HMAC-based checks, `hmac.compare_digest`, trusted SDK helpers (e.g. Stripe-style `construct_event`), and simple local signature-variable reassignment. It also distinguishes "a crypto comparison exists somewhere in this function" from "the result of that comparison actually gates the sensitive operation" — the case shown above.

**Webhook idempotency** — flags handlers that appear to mutate payment/order state with no visible duplicate-event guard (`event_id`, `already_processed`, `idempotency`, etc.). Presence of these words isn't treated as proof of safety, only as recognizable evidence of it.

**Payment retry safety** — looks for the combination of (a) a payment-related call, (b) retry/loop structure, (c) no visible idempotency key, retry limit, or backoff. Explicitly tested _not_ to flag an ordinary `for payment in payments: capture(payment)` loop, and not to fire just because the word "retry" appears inside a log message string.

---

## AI investigation (optional)

```text
deterministic detector → finding → optional AI investigation → additional context
```

Static rules are good at being reproducible; they're not good at judging intent. When `--ai` is passed, a finding plus its relevant source and bounded repository context go to an investigator model, which returns an independent TRUE_POSITIVE / FALSE_POSITIVE / UNCERTAIN verdict with evidence — explicitly instructed to separate "a control exists" from "a control is called" from "a control actually gates the operation." The scanner works fully offline without this layer; AI augments triage, it doesn't replace the rules.

---

## Output formats

**Human-readable** (default), **JSON** (`--json`, stable schema for scripting), and **SARIF 2.1.0** (`--sarif`, with rule IDs, severity mapping, and deduplicated rule metadata — consumable directly by GitHub Code Scanning).

---

## Configuration, suppression, baselines

```toml
# integration-doctor.toml
[tool.integration-doctor]
exclude = ["generated", "vendor"]
disabled_rules = ["WEBHOOK-001"]
```

```python
# integration-doctor-ignore: WEBHOOK-001 -- verified in middleware
def webhook():
    ...
```

Suppressions are line-specific (comment line or the line right after it) so exceptions stay next to the code that caused them instead of silencing a rule repo-wide.

Baselines let you adopt the tool on an existing codebase without fixing every historical finding on day one:

```bash
integration-doctor . --generate-baseline baseline.json   # snapshot current findings
integration-doctor . --baseline baseline.json            # only new findings are reported
```

Fingerprints are SHA-256 over `(rule_id, file, line)`. `--baseline` and `--generate-baseline` are mutually exclusive.

---

## CI/CD

Exit codes are the contract: `0` on a clean scan, `1` when findings exist, `2` on invocation/analysis error. A GitHub Actions workflow runs the test suite, a baseline scan, SARIF generation, and SARIF upload to Code Scanning — the tool is meant to run in CI as a gate, not just locally.

---

## Testing

```text
279 tests passing, 0 warnings (pytest -W default)
ruff check .
git diff --check
```

Beyond per-detector unit tests, the suite includes deliberate false-positive regression cases: an ordinary payment loop that isn't a retry, the word "Retry" inside a message string, a function merely _named_ `webhook_documentation` (not treated as an entry point), and an unenforced `compare_digest()` call.

On a purpose-built evaluation corpus (safe: direct HMAC, trusted SDK, trusted helper, reassigned signature / unsafe: missing signature, header-only, truthiness check, insecure equality, ignored `compare_digest`, unrelated `compare_digest`), the webhook detector currently scores:

```text
Precision: 1.00
Recall:    1.00
```

This means perfect performance **on this corpus** — not a proof of correctness on arbitrary real-world code. The corpus is evidence of detector quality, not a substitute for testing against code the author didn't write.

---

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

```bash
pip install -e ".[dev]"        # development
pip install -e ".[examples]"   # example Flask/Razorpay integrations
```

## Quick start

```bash
integration-doctor integrations/broken_webhook   # intentionally vulnerable fixture
integration-doctor integrations/safe_webhook     # safe fixture
integration-doctor . --json
integration-doctor . --sarif
integration-doctor . --ai
integration-doctor --version
```

---

## Project structure

```text
analyzer/
├── ai/            context.py, display.py, investigator.py
├── analysis/      call_graph.py, models.py, resolver.py, symbols.py
├── detectors/     webhook.py, idempotency.py, retry.py, security_path.py
├── baseline.py    config.py    suppression.py    scanner.py
integrations/      broken_webhook/   safe_webhook/
tests/             detector, analysis, evaluation, integration, E2E
.github/workflows/ tests.yml
```

---

## Design principles

- **Deterministic first** — same source, same findings, every time.
- **Conservative resolution** — an unresolved call beats a confidently wrong one.
- **Useful over clever** — this isn't a Python compiler; it's a tool for catching real integration mistakes developers can understand.
- **AI assists, doesn't replace** — deterministic analysis remains the source of truth.

---

## Limitations

Integration Doctor does not execute code and cannot fully reason about dynamic behavior, arbitrary framework/middleware abstractions, helper-module verification several layers removed from the call site, or general data flow across variables and functions. It can therefore both miss real problems and flag safe code. It is a heuristic AST/pattern matcher, not a data-flow or type-checking engine — treat findings as a prompt for review, not a verdict.

```text
static finding → developer review → fix, suppress, or investigate further
```

---

## Roadmap

`0.1.0` scope is complete. Future directions build on the existing architecture rather than growing it randomly: broader framework recognition, real interprocedural data-flow tracking, more payment providers, larger real-world (not self-authored) evaluation corpora, and richer SARIF metadata.

---

## Contributing

1. Define the unsafe pattern.
2. Add a representative unsafe fixture, then safe cases that should _not_ trigger.
3. Add regression tests for the likely false positives.
4. Implement the detector, run the full suite + Ruff, update the docs.

For security-sensitive rules, document the heuristic's limitation alongside the rule itself.

---

## License

Integration Doctor is released under the **MIT License**.

See the [`LICENSE`](LICENSE) file for the full license text.

---

> Integration Doctor is a static-analysis safety net for payment and webhook integrations. It does not promise your integration is safe — it tries to make the dangerous parts harder to miss.
