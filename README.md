# Integration Doctor

**Static analysis for payment and webhook integrations.**

Catch risky integration patterns before they become production incidents.

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-279%20passing-brightgreen?logo=pytest)](https://pytest.org/)
[![Ruff](https://img.shields.io/badge/code%20quality-ruff-brightgreen?logo=ruff)]
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-purple)](https://sarifweb.azurewebsites.net/)
[![Version](https://img.shields.io/badge/version-0.1.0-informational)](https://packaging.python.org/)

---

## Why Integration Doctor?

Payment and webhook code is often small, but mistakes in that code can be expensive.

A webhook can receive a request without actually verifying its signature. A retry loop can repeat a payment operation. A duplicate event can process an order twice.

The problem is that these bugs often look perfectly reasonable during a normal code review.

**Integration Doctor is built to make those risky patterns easier to notice.**

It analyzes Python source without executing it and combines:

- AST-based static analysis
- repository-wide symbol resolution
- call-graph reasoning
- deterministic security and integration detectors
- optional AI-assisted investigation
- JSON and SARIF output
- suppressions and baselines
- CI-friendly exit codes

A finding means **"this deserves a closer look"**, not **"this is definitely a vulnerability."**

No findings does not mean an integration is secure.

---

## Quick look

Run it against a repository:

```bash
integration-doctor .
```

Or generate SARIF for GitHub Code Scanning:

```bash
integration-doctor . --sarif
```

For example, this code contains a signature comparison, but never uses the result:

```python
import hmac

def webhook_handler(request):
    signature = request.headers.get("X-Webhook-Signature")
    expected = "expected-signature"

    hmac.compare_digest(signature, expected)

    process_event(request)
```

The important question is not just:

> "Does the code contain a security check?"

It is:

> "Does the security check actually control the sensitive operation?"

That distinction is one of the main ideas behind Integration Doctor.

---

## What it checks

| Area | What it looks for |
| --- | --- |
| Webhook signatures | Missing or weak signature verification |
| Webhook enforcement | Verification that exists but does not actually gate the handler |
| Webhook idempotency | Payment or order mutations without an obvious duplicate-event guard |
| Payment retries | Retry or loop behavior around payment operations without visible safety mechanisms |
| Security paths | Risky paths between externally controlled input and sensitive operations |
| Repository analysis | Syntax, encoding, and detector failures that need to be surfaced safely |

The exact rule IDs are defined by the detectors and are also included in machine-readable output.

---

## How it works

```text
Python repository
       |
       v
  Source scanner
       |
       v
    Python AST
       |
       +--------------------+
       |                    |
       v                    v
  Symbol table          Detectors
       |                    |
       v                    |
    Resolver                |
       |                    |
       +---------+----------+
                 |
                 v
             Call graph
                 |
                 v
          Static findings
                 |
        +--------+--------+
        |        |        |
        v        v        v
   Suppressions Baseline  AI (optional)
        |        |        |
        +--------+--------+
                 |
                 v
          CLI / JSON / SARIF
```

The architecture is deliberately layered.

### 1. Parse source

Python files are parsed into ASTs. The analyzer works from source code and does not execute the target repository.

### 2. Build repository context

Integration Doctor builds symbols for functions, methods, classes, and nested functions and resolves calls across the repository where it can do so safely.

Resolution is conservative. If the analyzer cannot confidently determine which function a call refers to, it prefers leaving the call unresolved over guessing.

### 3. Build control-flow context

The call graph tracks branches, returns, raises, loops, back-edges, asynchronous functions, and recursive edges.

Path exploration has explicit limits such as `max_depth` and `max_paths`, preventing unrestricted traversal from becoming expensive on larger repositories.

### 4. Run deterministic detectors

Detectors inspect the source and repository context for specific integration patterns.

### 5. Apply project controls

Findings can be filtered through:

- disabled rules
- inline suppressions
- baselines

### 6. Optionally investigate with AI

The AI layer is an additional investigation step. It is not required for scanning and does not replace deterministic analysis.

### 7. Produce useful output

Results can be printed for humans or exported as JSON and SARIF for automation.

---

## Detectors

### Webhook signature verification

The webhook detector looks for common signature-verification patterns, including HMAC comparisons and trusted SDK-style verification.

It also understands an important difference between:

```python
hmac.compare_digest(signature, expected)
```

and:

```python
if hmac.compare_digest(signature, expected):
    process_event()
```

The first contains a comparison. The second actually uses that comparison to control the operation.

The detector can also follow simple local reassignment of signature variables.

It is intentionally not a general-purpose data-flow engine, so complicated helper modules and dynamic abstractions can remain outside its scope.

### Webhook idempotency

Webhook handlers can receive the same event more than once.

The idempotency detector looks for payment or order mutations where there is no obvious duplicate-event protection. It recognizes common evidence such as event IDs, processed-event checks, and idempotency-related logic.

A variable with a promising name is not treated as proof of correctness.

### Payment retry safety

Retries around payment operations deserve special attention because repeating an operation can have real consequences.

The detector looks for the combination of payment-related behavior and retry or loop structure, while considering visible safety mechanisms such as:

- idempotency keys
- retry limits
- backoff
- other explicit retry controls

It is also tested against false positives such as an ordinary loop over payments and the word `retry` appearing only inside a log message.

### Security paths

The security-path analysis helps identify potentially dangerous paths from externally controlled input toward sensitive operations.

This gives the project a broader security-analysis direction without pretending to be a full taint-analysis engine.

---

## Optional AI investigation

The deterministic analysis remains the foundation:

```text
detector
   |
   v
finding
   |
   v
optional AI investigation
   |
   v
additional triage context
```

When `--ai` is enabled, the investigator receives a finding together with bounded source and repository context.

The investigator can return:

- `TRUE_POSITIVE`
- `FALSE_POSITIVE`
- `UNCERTAIN`

with supporting evidence.

The AI layer is deliberately optional. A normal scan does not require an API key or an AI service.

That keeps the core tool deterministic, testable, and usable in environments where external model access is not appropriate.

---

## Output formats

Integration Doctor supports three main output styles.

### Human-readable

The default output is intended for developers running the scanner locally.

### JSON

```bash
integration-doctor . --json
```

Useful for scripts, integrations, and further processing.

### SARIF

```bash
integration-doctor . --sarif
```

SARIF 2.1.0 output includes rule information, severity mapping, file locations, and findings suitable for GitHub Code Scanning.

---

## Configuration

Create `integration-doctor.toml`:

```toml
[tool.integration-doctor]

exclude = ["generated", "vendor"]

disabled_rules = ["WEBHOOK-001"]
```

This keeps repository-specific configuration outside the Python source itself.

---

## Suppressions

For a finding that has been reviewed and intentionally accepted:

```python
# integration-doctor-ignore: WEBHOOK-001 -- verified in middleware

def webhook():
    ...
```

Suppressions are tied to a specific location rather than disabling an entire rule everywhere.

That makes exceptions visible during code review and keeps them close to the code they explain.

---

## Baselines

Introducing static analysis to an existing repository should not require fixing every historical finding immediately.

Create a baseline:

```bash
integration-doctor . --generate-baseline baseline.json
```

Then scan against it:

```bash
integration-doctor . --baseline baseline.json
```

The baseline records existing findings so that newly introduced findings can still be surfaced.

Fingerprints are based on:

```text
rule_id + file + line
```

using SHA-256.

`--baseline` and `--generate-baseline` are mutually exclusive.

---

## CI/CD

Integration Doctor is designed to work as a CI check, not just a local developer command.

Exit codes provide a simple contract:

| Exit code | Meaning |
| --- | --- |
| `0` | Clean scan |
| `1` | Findings exist |
| `2` | Invocation or analysis error |

The repository also contains a GitHub Actions workflow that runs the test suite, exercises scanning, generates SARIF, and uploads results for Code Scanning.

The goal is straightforward:

```text
developer change
      |
      v
   CI scan
      |
      +---- clean ------> pass
      |
      +---- finding ----> review / fix
```

---

## Testing

The project currently has:

```text
279 tests passing
0 warnings with pytest -W default
ruff check .
git diff --check
```

The tests cover more than the obvious happy paths.

There are regression cases for things such as:

- ordinary payment loops that are not retries
- `retry` appearing only in a log message
- functions named like webhooks that are not actually entry points
- ignored `compare_digest()` results
- signature variables being reassigned
- branching and loop behavior in call-graph analysis
- recursive and asynchronous calls
- baseline behavior
- suppression behavior
- JSON and SARIF output
- scanner failure handling

### Detector evaluation

The webhook detector also has a dedicated evaluation corpus containing safe and unsafe examples.

The current corpus produces:

```text
Precision: 1.00
Recall:    1.00
```

That result is useful evidence, but it should be interpreted correctly.

**It means perfect performance on this particular corpus. It does not prove perfect performance on arbitrary Python repositories.**

The project deliberately treats evaluation data as evidence rather than as a marketing claim.

---

## Robustness and performance

Static analysis tools need to handle code that is messy, incomplete, or simply unusual.

Integration Doctor includes tests around:

- invalid Python
- unreadable or problematic source
- detector failures
- bounded call-graph traversal
- maximum node limits
- path limits
- repository-wide scanning

The analyzer is designed to fail safely where possible rather than turning one problematic file into a broken repository scan.

---

## Installation

Requires Python 3.10+.

```bash
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

## Common commands

Scan a repository:

```bash
integration-doctor .
```

Scan the example fixtures:

```bash
integration-doctor integrations/broken_webhook
integration-doctor integrations/safe_webhook
```

JSON output:

```bash
integration-doctor . --json
```

SARIF output:

```bash
integration-doctor . --sarif
```

AI investigation:

```bash
integration-doctor . --ai
```

Version:

```bash
integration-doctor --version
```

---

## Project structure

```text
integration-doctor/
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
│   └── scanner.py
│
├── integrations/
│   ├── broken_webhook/
│   └── safe_webhook/
│
├── tests/
│   ├── detector tests
│   ├── analysis tests
│   ├── evaluation tests
│   └── integration / E2E tests
│
├── .github/
│   └── workflows/
│       └── tests.yml
│
├── pyproject.toml
├── README.md
└── LICENSE
```

---

## Design principles

### Deterministic first

The same source should produce the same deterministic findings.

### Conservative over confident

If the analyzer cannot resolve something safely, it should avoid inventing an answer.

### Useful over clever

The project is not trying to become a Python compiler. It is trying to catch integration mistakes that developers can understand and act on.

### AI assists, not replaces

AI can help investigate a finding, but the core scanner remains useful without it.

### Findings should be explainable

A developer should be able to understand why something was reported and decide whether to fix it, suppress it, or investigate it further.

---

## Limitations

Integration Doctor is intentionally not a full program-analysis framework.

It does not execute application code and does not completely understand:

- arbitrary dynamic Python behavior
- every web framework or middleware abstraction
- complex helper-module boundaries
- general interprocedural data flow
- every provider-specific integration
- runtime configuration and external infrastructure

Because of that, the tool can miss real problems and can report safe code for review.

The right mental model is:

```text
static finding
      |
      v
developer review
      |
      +---- fix
      |
      +---- suppress with reason
      |
      +---- investigate further
```

---

## Roadmap

The `0.1.0` foundation is complete.

The next improvements should deepen the existing analysis rather than add unrelated features:

- broader framework and provider recognition
- stronger interprocedural data-flow analysis
- more payment and webhook patterns
- larger evaluation corpora from code not authored specifically for the detector
- richer SARIF metadata
- better developer-facing diagnostics
- additional CI integrations

The long-term goal is not to produce the largest static-analysis tool.

It is to produce a focused tool that is **good at finding integration mistakes and honest about what it cannot prove.**

---

## Contributing

A useful detector change should usually follow this workflow:

1. Define the unsafe pattern.
2. Add an unsafe fixture.
3. Add safe cases that should not trigger.
4. Add regression tests for likely false positives.
5. Implement the detector.
6. Run the full test suite and Ruff.
7. Update the documentation.

For security-sensitive rules, document the heuristic and its limitations alongside the rule.

---

## License

Integration Doctor is released under the **MIT License**.

See the [`LICENSE`](LICENSE) file for the full license text.

---

> Integration Doctor is a static-analysis safety net for payment and webhook integrations.
>
> It does not promise that your integration is safe. It tries to make the dangerous parts harder to miss.
