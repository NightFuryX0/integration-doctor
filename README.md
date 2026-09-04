# Integration Doctor

Integration Doctor is a static-analysis tool for catching unsafe patterns in payment and webhook integrations before they turn into an incident.

Payment integrations can look fine at first while still missing something important. A signature check might never actually get called. A webhook handler might process the same event twice. A retry loop might repeat a payment operation without an idempotency key.

Integration Doctor scans your code and flags those patterns for review.

Right now it checks three main things:

- Webhook signature verification

- Duplicate webhook/event handling

- Retry safety around payment operations

There's also an optional AI layer. Once a detector flags something, you can have an AI model take a second look at the finding along with the relevant source code and repository context. It can agree with the detector or point out that the detector got it wrong.

Integration Doctor is not a replacement for your payment provider's SDK or documentation. It's another layer of analysis on top of them.

---

## What it checks

### Webhook verification

Webhook endpoints should verify that a request actually came from the payment provider before doing anything with it.

The webhook detector looks at each handler and checks for signs of verification. This can include cryptographic comparisons, trusted SDK helpers such as `stripe.Webhook.construct_event`, or other recognizable verification logic.

The detector is static and heuristic. It does not run your code, so it cannot prove that verification is correct at runtime. It can only look for verification logic that it recognizes.

### Webhook idempotency

Payment providers retry webhook deliveries. That's normal. It also means the same event can reach your handler more than once.

The idempotency detector looks for webhook handlers that appear to change payment or order state without an obvious guard against processing the same event again.

It looks for things such as:

- `event_id`

- `webhook_id`

- `already_processed` / `processed`

- `idempotency`

### Payment retries

Retries are useful for temporary failures, but blindly retrying a payment operation can result in the same operation happening more than once.

The retry detector looks for functions that:

1. Call something that appears to be payment-related

2. Retry that operation through a loop or retry-style logic

3. Do not show an obvious safety mechanism

Examples of safety mechanisms include an idempotency key, backoff, or an explicit retry limit.

---

## How it works

Under the hood, Integration Doctor uses Python's `ast` module. The source code is parsed and inspected. It is never executed.

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

 |

 +-------> JSON output

 |

 +-------> Optional AI investigation

```

The detectors are deterministic. Given the same code, they produce the same findings.

When AI investigation is enabled, each finding is sent to the investigator along with the relevant source file and a bounded amount of repository context. The AI then gives an independent assessment of the finding.

The AI layer sits on top of the detectors rather than replacing them. You can still run the whole scanner without using an AI provider.

---

## Installation

Clone the repository and create a virtual environment:

```bash

git clone <repository-url>

cd integration-doctor

python -m venv .venv

source .venv/bin/activate   # macOS/Linux

```

Install Integration Doctor in editable mode:

```bash

pip install -e .

```

Editable installation is useful during development because changes to the source code are picked up without reinstalling the package every time.

---

## Usage

The main command is:

```bash

integration-doctor

```

With no target given, it scans `integrations/broken_webhook` by default.

To scan another project or directory:

```bash

integration-doctor path/to/project

```

You can also run the scanner directly as a Python module:

```bash

python -m analyzer.scanner

```

### Command-line options

````text

usage: integration-doctor [-h] [--ai] [--json] [-v] [--version]
[--sarif] [--baseline PATH]
[--generate-baseline PATH] [target]

Scan a repository for payment integration issues.

positional arguments:

target                 Directory to scan.

options:

-h, --help             show this help message and exit

--ai                   Run AI investigation on detected findings.

--json                 Emit machine-readable JSON output.

-v, --verbose          Enable debug logging.

--version              Show the installed Integration Doctor version.

--sarif                Emit SARIF 2.1.0 output.

--baseline PATH        Ignore findings already recorded in a baseline.

--generate-baseline PATH
Write the current findings to a baseline file.

[tool.integration-doctor]
exclude = [
    "generated",
    "legacy",
]

disabled_rules = [
    "WEBHOOK-001",
]

Excluding directories

Use exclude when there are directories you do not want Integration Doctor to scan.

These are added to the scanner's normal ignored directories. The built-in ignored directories are still skipped automatically.

For example:

[tool.integration-doctor]
exclude = [
    "generated",
    "vendor",
]

Disabling rules

Use disabled_rules when you want to turn off a specific rule for a project.

For example:

[tool.integration-doctor]
disabled_rules = [
    "WEBHOOK-001",
]

This disables that rule for the scan target. It does not disable the other rules.

The configuration file is optional. If there is no integration-doctor.toml, Integration Doctor uses its normal defaults.

Suppressions

Sometimes a finding is intentional or is handled somewhere else in the application. In those cases, you can suppress an individual finding directly in the source file.

Use a comment with the rule ID:

# integration-doctor-ignore: WEBHOOK-001
def webhook():
    pass

You can also add a reason:

# integration-doctor-ignore: WEBHOOK-001 -- verified in middleware
def webhook():
    pass

The suppression applies to the comment's line or the immediately following source line.

Suppressions are intentionally line-specific. They do not turn off a rule for the whole file.

This is useful when you have checked a finding and want to keep the decision close to the code that caused the finding.

Baselines

A baseline lets you accept findings that already exist in a project and focus future scans on new findings.

First, create a baseline from the current scan:

integration-doctor . --generate-baseline baseline.json

Integration Doctor writes the current findings to baseline.json.

Later, scan the project with that baseline:

integration-doctor . --baseline baseline.json

Findings that are already in the baseline are filtered out. If nothing new has been introduced, the scan reports:

No findings.

If a new finding appears, it is still reported normally.

This makes baselines useful when adding Integration Doctor to an existing project that already has findings. You can start with the current state instead of having to fix every existing finding before using the scanner in development or CI.

--baseline and --generate-baseline cannot be used together.

What gets scanned

Python files are scanned for now.

These directories are skipped automatically:

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

````

Directories that cannot be read are skipped with a warning instead of stopping the whole scan.

Files that cannot be decoded as UTF-8, contain invalid Python syntax, or cause an unexpected detector error are reported as parser or scanner findings instead of crashing the entire scan.

---

## Findings

A finding looks roughly like this:

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

| Field | What it is |

| --------------- | ----------------------------------- |

| `rule_id` | Which rule fired |

| `type` | The specific issue |

| `severity` | How serious the issue appears to be |

| `file` / `line` | Where it was found |

| `message` | Plain-English explanation |

Current rule families include:

- `WEBHOOK-*`

- `PAYMENT-003`

- `PARSER-*`

One naming detail worth mentioning: `WEBHOOK-002` is the idempotency check. It is not part of an `IDEMPOTENCY-*` rule family. It was grouped under `WEBHOOK-*` because the check is specifically about duplicate webhook delivery.

---

## Example integrations

The repository includes a few small example integrations:

```text

integrations/

├── broken_webhook/

│   ├── app.py

│   ├── duplicate_webhook.py

│   ├── safe_retry.py

│   └── unsafe_retry.py

└── safe_webhook/

└── middleware\_verified.py

```

The examples make it easy to see what the detectors are looking for.

For example, scan the intentionally broken integration:

```bash

integration-doctor integrations/broken_webhook

```

Then scan the verified webhook example:

```bash

integration-doctor integrations/safe_webhook

```

The first should produce findings. The second is intended to show that recognizable webhook signature verification is accepted by the detector.

The safe webhook example demonstrates signature verification specifically. It is not meant to represent a complete production payment integration.

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

├── pyproject.toml

├── requirements.txt

├── .env.example

├── README.md

└── .gitignore

```

- **`analyzer/scanner.py`** is the main entry point. It finds files, skips directories that should not be scanned, checks for encoding and syntax problems, runs the detectors, optionally starts AI investigation, prints the results, and returns the appropriate exit code.

- **`analyzer/detectors/`** contains the individual static-analysis rules.

- **`analyzer/ai/`** contains the optional AI layer, including repository context, provider clients, structured results, and error handling.

- **`integrations/`** contains the example applications used to exercise the detectors.

- **`tests/`** contains the automated test suite.

- **`pyproject.toml`** contains the package metadata, dependencies, version, and CLI entry point.

---

## Limitations

The detectors are heuristics, not proofs.

They read code structure. They do not run the application or trace what happens during a real request.

A detector can miss verification that happens through a helper function, middleware, another module, or a framework-specific abstraction that it does not recognize.

The same goes for idempotency and retry safety. A control may exist somewhere the detector cannot see.

So a finding means "this is worth checking," not "this is definitely broken."

Likewise, getting no findings does not mean an integration is completely safe. It only means the scanner did not find anything that matched its current rules.

That's the actual goal of the project: catch obvious problems early and give you something concrete to investigate. It is not meant to replace a proper security review.

---

## Testing

Run the test suite with:

```bash

pytest -q

```

The tests cover the scanner, all three detectors, false-positive cases, repository context, and the AI investigator.

AI tests are mocked, so the test suite does not make real API calls.

After making changes, run:

```bash

pytest -q

git diff --check

integration-doctor --help

```

The GitHub Actions workflow also runs the test suite automatically on pushes and pull requests to `main`.

---

## Where things stand

The core project is working.

Current functionality includes:

- AST-based static analysis for webhook signature verification, idempotency, and retry safety

- Detector-level failure isolation

- Parser and file-error handling

- Human-readable terminal output

- JSON output

- Stable exit codes

- Optional AI investigation through NVIDIA or Gemini

- Bounded repository context for the AI layer

- Concurrent AI investigations

- A packaged CLI command

- Version reporting

- Example broken and safer integrations

- An automated test suite

- GitHub Actions CI

The current version is `0.1.0`.

The next work is mostly release and distribution polish rather than adding another major feature.

---

## Scope

Integration Doctor does not replace your payment provider's SDK, webhook verification mechanism, idempotency support, or documentation.

Those remain the source of truth for how a provider expects its integration to work.

What Integration Doctor does is look at your code and ask a narrower question:

> Does this integration appear to be handling these safety concerns, or does it only look like it should?

That makes it useful as an early check during development, testing, and code review.
