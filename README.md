# Integration Doctor

> **Static analysis for payment and webhook integrations.**
>
> Catch risky integration patterns before they become production incidents.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-279%20passing-brightgreen?logo=pytest)](https://pytest.org/)
[![Ruff](https://img.shields.io/badge/code%20quality-ruff-brightgreen?logo=ruff)](https://docs.astral.sh/ruff/)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-purple)](https://sarifweb.azurewebsites.net/)
[![Version](https://img.shields.io/badge/version-0.1.0-informational)](https://packaging.python.org/)

---

## Why Integration Doctor exists

Payment and webhook code is often small, but small mistakes can have expensive consequences.

A webhook may process a request without verifying its signature.  
A provider may deliver the same event more than once.  
A retry loop may repeat a payment operation without a safe idempotency mechanism.

These problems are easy to miss in a normal code review because the code can look completely reasonable at first glance.

**Integration Doctor looks for those patterns statically, before the code reaches production.**

It reads Python source code without executing it and combines AST analysis, repository-level context, symbol resolution, call-graph analysis, deterministic detectors, and optional AI investigation.

The goal is deliberately practical:

> **Find suspicious integration patterns early, explain why they matter, and fit the result into the tools developers already use.**

---

## What it catches

| Rule | Area | What it looks for |
|---|---|---|
| `WEBHOOK-*` | Webhooks | Missing or ineffective signature verification |
| `WEBHOOK-002` | Webhook idempotency | Payment or order state changes without an obvious duplicate-event guard |
| `PAYMENT-003` | Payment retries | Retry behavior around payment operations without an obvious safety mechanism |
| `PARSER-*` | Repository scanning | Source files that cannot be safely analyzed |

The rules are intentionally heuristic.

A finding means:

> **"This deserves a closer look."**

It does not mean:

> **"The application is definitely vulnerable."**

Likewise, no findings does not prove an integration is completely secure.

---

# The interesting part: it understands code structure

Integration Doctor started as AST-based detector logic, but the analysis pipeline grew beyond simply looking at one file at a time.

```text
                         Python Repository
                                │
                                ▼
                       ┌─────────────────┐
                       │  Source Scanner │
                       └────────┬────────┘
                                │
                                ▼
                         ┌─────────────┐
                         │ Python AST  │
                         └──────┬──────┘
                                │
                 ┌──────────────┼──────────────┐
                 ▼              ▼              ▼
          Symbol Table      Detectors      Repository
                 │              │             Context
                 ▼              │              │
             Resolver           │              │
                 │              │              │
                 ▼              ▼              ▼
                         ┌─────────────────┐
                         │   Call Graph    │
                         └────────┬────────┘
                                  │
                                  ▼
                           Static Findings
                                  │
                     ┌────────────┼────────────┐
                     ▼            ▼            ▼
                 Suppressions   Baseline      AI
                     │            │        Investigation
                     └────────────┼────────────┘
                                  ▼
                         ┌─────────────────┐
                         │  CLI / Outputs  │
                         └────────┬────────┘
                                  │
                         ┌────────┴────────┐
                         ▼                 ▼
                       JSON              SARIF
                                           │
                                           ▼
                                  GitHub Code Scanning
```

The important design choice is that **deterministic static analysis remains the foundation**.

AI is optional. It does not replace the detectors.

---

# Detection in more detail

## 1. Webhook signature verification

Webhook authenticity matters because the application should not blindly trust data coming from an HTTP request.

The webhook detector recognizes several forms of verification, including:

- HMAC-based verification
- `hmac.compare_digest`
- recognizable trusted SDK verification
- trusted verification helpers
- simple local reassignment of signature variables
- actual enforcement of a verification result

It also tries not to confuse "a crypto comparison exists somewhere" with "the webhook actually enforces the result."

For example, this is suspicious:

```python
import hmac

def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    expected = "expected-signature"

    hmac.compare_digest(signature, expected)

    process_event(request)
```

The comparison exists, but its result is ignored.

That is different from:

```python
import hmac

def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    sig = signature
    expected = "expected-signature"

    if hmac.compare_digest(sig, expected):
        process_event(request)
```

The detector also follows the simple local reassignment from `signature` to `sig`.

### Important limitation

This is not a complete data-flow engine.

It can recognize patterns within the analysis it understands, but it cannot prove that verification performed through an arbitrary helper module, middleware layer, framework abstraction, or dynamic runtime behavior is correct.

That limitation is intentional and documented.

---

## 2. Webhook idempotency

Payment providers can retry webhook deliveries.

A handler therefore needs to consider what happens if the same event arrives again.

The idempotency detector looks for webhook handlers that appear to change payment or order state without an obvious duplicate-processing guard.

Recognizable concepts include:

```text
event_id
webhook_id
already_processed
processed
idempotency
```

The detector is not claiming that the presence of one of these words automatically makes an application safe. It is looking for recognizable evidence of duplicate-event protection.

---

## 3. Payment retry safety

Retries are useful when failures are temporary.

They can also be dangerous when the operation being retried changes payment state.

Integration Doctor looks for combinations of:

1. A payment-related operation
2. Retry or loop behavior
3. An absence of an obvious safety mechanism

Recognizable safety mechanisms include things such as:

- idempotency keys
- explicit retry limits
- backoff behavior

The detector also has regression coverage to ensure that an ordinary payment loop is not automatically treated as a retry mechanism and that the word `"Retry"` inside a message does not trigger a finding by itself.

---

# Repository-level analysis

One of the biggest differences between Integration Doctor and a simple AST script is that it can reason across a repository.

### Symbol table

The analyzer builds symbols for relevant Python definitions, including functions, methods, classes, and nested functions.

Symbols carry information such as:

- qualified name
- source file
- line number
- symbol kind

### Call resolution

The resolver attempts to connect a call site to the appropriate repository symbol.

It is deliberately conservative when names are ambiguous.

If two modules both define:

```python
def capture_payment():
    ...
```

a bare reference to `capture_payment()` is not arbitrarily assigned to one of them.

**Uncertainty is safer than a confident wrong answer.**

### Call graph

The call graph tracks:

- nodes
- call edges
- call sites
- sequential calls
- branches
- returns
- raises
- loops
- loop back-edges
- nested functions
- async functions
- recursive edges

Path exploration has explicit safeguards:

- `max_depth`
- `max_paths`
- cycle prevention

This matters because unrestricted path exploration can grow very quickly in real repositories.

---

# AI investigation

Static analysis is good at being deterministic.

It is not always good at understanding intent.

Integration Doctor therefore has an optional AI investigation layer.

When enabled, the investigator receives a finding together with relevant source code and bounded repository context. It can provide an independent assessment of the finding.

The architecture is intentionally:

```text
Deterministic detector
        │
        ▼
     Finding
        │
        ▼
 Optional AI investigation
        │
        ▼
 Additional context / assessment
```

The AI layer is **not required to run the scanner**.

That means the core tool remains:

- deterministic
- locally runnable
- usable without an AI provider
- testable independently

This separation is important because AI can make mistakes. The project treats AI as an investigation layer, not as the source of truth for the static-analysis rules.

---

# Developer-friendly output

## Human-readable output

```text
CRITICAL WEBHOOK-001
app.py:42

Webhook handler appears to process a request without
recognizable signature verification.
```

## JSON

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

Structured output makes it possible to consume findings from scripts and other tooling.

## SARIF

Integration Doctor can also emit **SARIF 2.1.0**, including:

- rule IDs
- messages
- severity mapping
- file locations
- line numbers
- deduplicated rule metadata

That makes the findings suitable for security-result workflows such as GitHub Code Scanning.

```bash
integration-doctor . --sarif
```

---

# Configuration

Integration Doctor supports an optional `integration-doctor.toml`.

```toml
[tool.integration-doctor]

exclude = [
    "generated",
    "vendor",
]

disabled_rules = [
    "WEBHOOK-001",
]
```

You can:

- exclude directories
- disable individual rules
- keep project-specific configuration in version control

The project supports Python 3.10+ and uses `tomllib` where available, with a `tomli` fallback for older supported Python versions.

---

# Suppressions

Not every finding is a bug.

Sometimes the code is intentionally structured in a way the analyzer cannot understand.

A finding can be suppressed close to the code:

```python
# integration-doctor-ignore: WEBHOOK-001 -- verified in middleware
def webhook():
    ...
```

The suppression is line-specific and applies to the comment's line or the immediately following source line.

This keeps the decision close to the code that caused the finding instead of disabling an entire rule across a repository.

---

# Baselines

Introducing static analysis into an existing project should not require fixing every historical finding on day one.

Integration Doctor supports baselines for exactly that reason.

Create one:

```bash
integration-doctor . --generate-baseline baseline.json
```

Then scan against it:

```bash
integration-doctor . --baseline baseline.json
```

Existing findings are filtered out.

New findings are still reported.

The baseline uses SHA-256 fingerprints derived from finding identity information such as:

- rule ID
- file
- line

This makes the baseline useful as a practical "new problems must not increase" mechanism.

`--baseline` and `--generate-baseline` cannot be used together.

---

# CI/CD

Integration Doctor is designed to run in CI, not just from a developer's terminal.

The repository includes a GitHub Actions workflow that exercises:

- dependency installation
- the test suite
- CLI checks
- baseline scanning
- SARIF generation
- SARIF upload

The exit-code contract is also tested.

In other words:

```text
No findings
     │
     ▼
 exit 0

New findings
     │
     ▼
 exit 1
```

That makes the tool usable as a quality gate.

---

# Testing

Testing is a major part of the project.

Current validation includes:

```text
279 tests passing
pytest -W default
No warnings
ruff check .
git diff --check
```

The test suite covers much more than individual detector examples.

It includes:

- detector unit tests
- false-positive regression tests
- resolver tests
- call-graph tests
- scanner tests
- configuration tests
- suppression tests
- baseline tests
- AI investigation tests
- integration tests
- E2E behavior
- compatibility behavior
- error handling
- performance safeguards

### Examples of regression cases

The project explicitly tests cases such as:

- a payment loop that is not actually a retry
- `"Retry"` appearing only inside a message
- ambiguous bare function names
- a helper whose name contains `"webhook"` but is not a webhook entry point
- a crypto comparison whose result is ignored
- a signature variable being reassigned before verification
- the legacy webhook analyzer compatibility shim

These tests are important because static-analysis quality is not just about catching bad code.

It is also about **not confidently flagging unrelated code**.

---

# Detector evaluation

The webhook detector has a dedicated evaluation corpus containing safe and unsafe fixtures.

### Safe cases

- direct HMAC verification
- trusted SDK verification
- trusted helper verification
- simple signature reassignment

### Unsafe cases

- missing signature
- signature header without verification
- truthiness-based verification
- insecure equality
- ignored `compare_digest`
- unrelated `compare_digest`

On this deliberately constructed evaluation corpus, the detector currently achieves:

```text
Precision: 1.00
Recall:    1.00
```

This result should be interpreted correctly.

It means the detector performed perfectly **on this evaluation corpus**.

It does not mean the detector is mathematically proven to have perfect precision and recall on every Python codebase.

The project treats the evaluation corpus as evidence of detector quality, not as a substitute for broader real-world validation.

---

# Robustness and performance

Static-analysis tools can run into pathological code structures.

Integration Doctor therefore puts explicit bounds around graph exploration.

The call graph supports:

```text
max_depth
max_paths
node-count limits
cycle prevention
```

The scanner also handles problematic source files without turning one bad file into a failed repository scan.

Examples include:

- invalid Python syntax
- unreadable directories
- files that cannot be decoded as UTF-8
- unexpected detector errors

The full test suite currently completes in roughly **7 seconds** on the development environment.

---

# Packaging

Integration Doctor is packaged as a normal Python project.

```toml
[project]
name = "integration-doctor"
version = "0.1.0"
requires-python = ">=3.10"
```

It provides the CLI:

```bash
integration-doctor
```

The release has been validated by:

- building a wheel
- building a source distribution
- running `twine check`
- installing into a fresh environment outside the development project
- running the installed CLI
- scanning both safe and intentionally broken fixtures
- validating JSON and SARIF output

This matters because a tool should not only work from its source tree.

It should also survive the path a user actually takes to install and run it.

---

# Project structure

```text
integration-doctor/
│
├── analyzer/
│   ├── ai/
│   │   ├── context.py
│   │   ├── display.py
│   │   └── investigator.py
│   │
│   ├── analysis/
│   │   ├── call_graph.py
│   │   ├── models.py
│   │   ├── resolver.py
│   │   └── symbols.py
│   │
│   ├── detectors/
│   │   ├── webhook.py
│   │   ├── idempotency.py
│   │   ├── retry.py
│   │   └── security_path.py
│   │
│   ├── baseline.py
│   ├── config.py
│   ├── suppression.py
│   ├── scanner.py
│   └── webhook_analyzer.py
│
├── integrations/
│   ├── broken_webhook/
│   └── safe_webhook/
│
├── tests/
│   ├── detector tests
│   ├── analysis tests
│   ├── evaluation fixtures
│   ├── integration tests
│   └── E2E tests
│
├── .github/
│   └── workflows/
│       └── tests.yml
│
├── pyproject.toml
├── README.md
└── .gitignore
```

The major pieces have deliberately different responsibilities:

| Component | Responsibility |
|---|---|
| `scanner.py` | Repository scanning, orchestration, CLI, outputs and exit codes |
| `detectors/` | Individual static-analysis rules |
| `analysis/` | Symbols, resolution and call-graph reasoning |
| `ai/` | Optional AI investigation |
| `baseline.py` | Existing-finding filtering |
| `config.py` | Project configuration |
| `suppression.py` | Inline suppression handling |
| `tests/` | Automated and evaluation coverage |

---

# Installation

## From the repository

```bash
git clone <repository-url>
cd integration-doctor

python -m venv .venv
source .venv/bin/activate
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
```

For the example integrations:

```bash
pip install -e ".[examples]"
```

---

# Quick start

Scan the included intentionally broken integration:

```bash
integration-doctor integrations/broken_webhook
```

Scan the safe example:

```bash
integration-doctor integrations/safe_webhook
```

Run with JSON:

```bash
integration-doctor . --json
```

Run with SARIF:

```bash
integration-doctor . --sarif
```

Run AI investigation:

```bash
integration-doctor . --ai
```

Generate a baseline:

```bash
integration-doctor . --generate-baseline baseline.json
```

Use an existing baseline:

```bash
integration-doctor . --baseline baseline.json
```

See the installed version:

```bash
integration-doctor --version
```

---

# What gets scanned

Python files are currently supported.

The scanner automatically skips common generated, virtual-environment, cache, and build directories such as:

```text
.git
.venv
venv
__pycache__
node_modules
.tox
.pytest_cache
.mypy_cache
.ruff_cache
build
dist
.eggs
```

Additional directories can be excluded through configuration.

Unreadable directories are skipped with a warning.

Files with decoding problems, invalid Python syntax, or unexpected detector failures are reported as scanner/parser findings rather than crashing the entire scan.

---

# Design principles

## Deterministic first

The core detectors should be reproducible.

Same source code, same analysis, same findings.

## Conservative resolution

When the analyzer cannot confidently resolve a call, it should prefer an unresolved result over a potentially incorrect target.

## Useful over clever

The goal is not to build a complete Python compiler.

The goal is to catch meaningful integration mistakes with analysis that developers can understand.

## Security tools should be honest

A static analyzer has limits.

Integration Doctor documents those limits instead of presenting heuristic detection as proof of security.

## AI should assist, not replace

AI can provide useful context, but deterministic analysis remains the foundation.

## Ship the whole tool

A useful analyzer needs more than detectors.

It also needs:

- a CLI
- configuration
- suppressions
- baselines
- machine-readable output
- CI integration
- tests
- packaging
- documentation

---

# Limitations

Integration Doctor is intentionally not a complete program-analysis engine.

It does not execute application code.

It cannot fully understand:

- arbitrary dynamic Python behavior
- every framework abstraction
- every middleware architecture
- arbitrary helper-module verification
- runtime-generated calls
- every possible data-flow relationship

A project can therefore contain safe code that the analyzer flags, or unsafe code that the current rules do not recognize.

That is why the intended workflow is:

```text
Static finding
      │
      ▼
Developer review
      │
      ▼
Fix, suppress, or investigate
```

The tool is an additional safety layer, not a replacement for provider documentation, SDK guarantees, code review, tests, or runtime security controls.

---

# Current status

**Version:** `0.1.0`

The current release includes:

- AST-based static analysis
- payment-focused detection
- webhook security detection
- webhook idempotency analysis
- payment retry analysis
- repository-wide analysis
- symbol tables
- call resolution
- call graphs
- path analysis
- cycle and path-explosion safeguards
- optional AI investigation
- human-readable CLI output
- JSON output
- SARIF 2.1.0 output
- configuration
- inline suppressions
- baselines
- CI/CD integration
- GitHub Code Scanning support through SARIF
- regression testing
- E2E testing
- precision/recall evaluation
- performance and robustness checks
- Python packaging
- fresh-install validation

### Quality checks

```text
279 tests passing
0 warnings under pytest -W default
ruff check .
git diff --check
```

---

# Why this project is interesting

Most static-analysis projects stop at:

```text
parse file
    ↓
find pattern
    ↓
print warning
```

Integration Doctor goes further:

```text
repository
    ↓
AST analysis
    ↓
symbols
    ↓
resolution
    ↓
call graph
    ↓
security/payment detectors
    ↓
findings
    ↓
suppression + baseline
    ↓
optional AI investigation
    ↓
JSON / SARIF
    ↓
CI / GitHub Code Scanning
```

That broader workflow is the part of the project I care about most.

The project is not trying to claim that a few AST visitors can prove a payment system is secure.

It is trying to build a practical developer tool that can identify suspicious integration patterns, provide useful context, and fit into an existing engineering workflow.

---

# Roadmap

The `0.1.0` scope is complete.

Future work can build on the existing architecture rather than expanding the project randomly.

Possible future directions include:

- broader framework recognition
- deeper interprocedural analysis
- richer data-flow tracking
- more payment providers
- additional payment safety rules
- larger real-world evaluation corpora
- improved finding explanations
- incremental analysis
- IDE/editor integration
- richer SARIF metadata
- additional CI providers

These are future directions, not requirements for the current release.

---

# Contributing

Contributions and experiments are welcome.

If you want to add a detector, the preferred workflow is:

1. Define the unsafe pattern.
2. Add a representative unsafe fixture.
3. Add safe cases that should not trigger.
4. Add regression tests for likely false positives.
5. Implement the detector.
6. Run the full test suite.
7. Run Ruff.
8. Update the documentation.

For security-sensitive rules, explain the limitation of the heuristic as well.

---

# License

Add the project's chosen license here before publishing the repository publicly.

---

## Built with

Python • `ast` • pytest • Ruff • SARIF • GitHub Actions

---

> **Integration Doctor is a static-analysis safety net for payment and webhook integrations.**
>
> It does not promise that your integration is safe.
>
> It tries to make the dangerous parts harder to miss.
