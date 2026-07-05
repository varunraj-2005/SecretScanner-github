# secretscanner

A lightweight, robust, and highly configurable Python CLI tool that scans codebases and git history for leaked secrets (API keys, credentials, private keys, database tokens) using a low-false-positive multi-signal approach.

Unlike naive scanners that trigger on every random test fixture or string pattern, `secretscanner` balances high recall with high precision by combining structural patterns, character entropy, and surrounding context.

---

## Features

- **Three-Signal Detection**: Combines regex structural shapes, Shannon entropy checks, and context heuristics (comments, variable names, documentation conventions).
- **Working Tree & Git History**: Scans your active filesystem or parses standard git commits to catch credentials committed and later "deleted."
- **Allowlist / Baseline Store**: Create a portable baseline JSON containing only hashed versions of previously accepted findings. CI only flags newly introduced leaks.
- **Rich Reporting**: Outputs human-friendly colorized CLI text, machine-readable JSON, or GitHub-native **SARIF 2.1.0** format.
- **CI/CD Integration**: Return exit codes based on customizable severity and confidence level policies.

---

## Getting Started

### Installation

Install the package in editable mode from the project root:

```bash
pip install -e .
```

To install with test and development dependencies:

```bash
pip install -e .[dev]
```

### Basic Usage

To scan the working tree in your current directory:

```bash
secretscanner
```

To scan a specific path or single file:

```bash
secretscanner path/to/project
```

### Advanced Scan Flags

- **Git History**: Scan all git log history (added lines in diffs only):
  ```bash
  secretscanner --history
  ```
- **Git History Only**: Skip the working tree and scan git history only:
  ```bash
  secretscanner --history-only --max-commits 50
  ```
- **Reporting Formats**: Save results in JSON or SARIF formats:
  ```bash
  secretscanner -o report.json --format json
  secretscanner -o report.sarif --format sarif
  ```
- **CI Exit Policy**: Fail the build if any `confirmed` confidence leak is found:
  ```bash
  secretscanner --fail-on confirmed
  ```

---

## The Three-Signal Detection Engine

To maintain a low false-positive rate, findings are scored using three distinct layers:

### 1. Structural Detection
Specific compiled patterns identify known signature shapes of credentials. These include:
- **AWS Key Pairs** (Access Keys: `AKIA`..., Secret Keys: 40-char base64 assignments)
- **GitHub PATs** (`ghp_`...)
- **Stripe API Keys** (`sk_live_`..., `rk_live_`...)
- **Google API & GCP Keys** (`AIza`..., `"type": "service_account"`)
- **Slack Webhooks & Tokens** (`xox`...)
- **Database Connection Strings** with embedded credentials (`postgres://user:pass@host`)
- **PEM Private Keys**
- **JWTs, npm tokens, Twilio keys, and SendGrid keys**.

### 2. Entropy Detection
For raw strings that don't match specific structures, a candidate token extraction routine scans for:
- 20+ character Base64 / urlsafe runs (clearing entropy threshold **$\ge 4.3$**)
- 32+ character Hex runs (clearing entropy threshold **$\ge 3.0$**)
Tokens under 20 characters are automatically ignored to prevent coincidence false positives.

### 3. Context Heuristics & Confidence Scoring
Raw matches are analyzed against surrounding lines and paths, and mapped to a confidence level (`confirmed` / `likely` / `possible` / `suppressed`):
- **Placeholders**: Matches are automatically **suppressed** if they contain the literal AWS document substring `"EXAMPLE"` or keywords like `dummy`, `fake`, `test`, `your-api-key-here`, or low-character-variety repeated patterns (e.g. `xxxxxxxx`).
- **Path Suppression**: Hits from generic/entropy checkers are **suppressed** in `/tests/`, `/fixtures/`, or `/mocks/` directories. Specific structural hits in those paths are kept but downgraded to **`likely`** (since checking in real keys to test folders remains a leak).
- **Proximity Boost**: If a credential-like variable name (`api_key`, `secret`, `token`, `password`, etc.) exists in the same line, the confidence score is boosted (e.g., `possible` $\rightarrow$ `likely`).
- **Comments Check**: Hits residing inside line comments (preceded by `#`, `//`, etc.) are automatically downgraded by one level.
- **Capping**: Verdicts with caveats (e.g., in a test path or comment) cap at **`likely`**, reserving **`confirmed`** for clean, unambiguous structural matches in production paths.

---

## Baseline / Allowlist Workflow

To prevent false alarms in existing codebases, `secretscanner` supports a baseline system inspired by `detect-secrets`.

1. Run the scanner to generate a baseline. This hashes all detected secrets (using SHA-256) combined with their paths and line numbers, ensuring **no plaintext secrets are ever saved in files**:
   ```bash
   secretscanner --update-baseline
   ```
2. Check the generated `.secretscanner-baseline.json` file into git.
3. Future runs will load this baseline automatically and only report **newly introduced secrets**:
   ```bash
   secretscanner --baseline .secretscanner-baseline.json
   ```

---

## GitHub Actions CI Pipeline Example

The following workflow snippet scans your pull requests, generates a SARIF report, and uploads it to GitHub Security Code Scanning:

```yaml
name: Secret Security Scanner

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  scan:
    name: Codebase Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3
        with:
          fetch-depth: 0 # Fetch all history for git diff scans

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-python: '3.10'

      - name: Install Secret Scanner
        run: |
          pip install .

      - name: Execute Scan and Emit SARIF
        run: |
          secretscanner . --history --format sarif -o results.sarif --fail-on confirmed

      - name: Upload SARIF Results to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        if: always() # Upload results even if scan steps failed the gate
        with:
          sarif_file: results.sarif
```

---

## Running Tests

Tests are orchestrated with `pytest`. Run them with:

```bash
pytest
```
