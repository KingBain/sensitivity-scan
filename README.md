# Sensitivity Scan 🛡️

A low-noise, context-aware GitHub Action that detects Canadian PII (SIN, PRI, DOB) in your codebase before it gets merged.

The scanner uses YARA rules to look for **a labelled identifier with a full name, or both first and last names**. In XML, JSON and YAML, the fields must belong to the same record. Other text files use file-wide matching.

Reports show the files and line numbers of the findings, but safely **omit the matched sensitive values**.

## 🚀 Quick Start

Add this workflow to your repository at `.github/workflows/sensitivity-scan.yml`:

```yaml
name: Sensitivity scan

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0 # Required for PR diff scans
          persist-credentials: false
          
      - name: Scan sensitive information
        uses: KingBain/sensitivity-scan@v1.0.0
        with:
          fail-on: NONE # Start in report-only mode
```
> **Tip:** Start with `fail-on: NONE` to review the job summary report without breaking your builds. Once your baseline is clean, change it to `HIGH` to block Pull Requests containing new SINs, or `MEDIUM` to block PRI/DOB findings.

## 🧠 How it Works

The Action automatically adapts its behavior based on how it is triggered (`mode: auto`):
* **Pull Requests (Changes Mode):** Only scans for *newly introduced* sensitive data. It compares the PR head to the base branch so you don't fail builds for legacy data checked in years ago.
* **Pushes & Manual Runs (Full Mode):** Scans the entire repository at the selected commit.

### What does it look for?
By default, the scanner requires an English or French label + a valid identifier format + the supporting name fields.

| Combination | Severity |
|---|---|
| 🇨🇦 **SIN / NAS** + Name | `HIGH` |
| 🏢 **PRI / CIDP** + Name | `MEDIUM` |
| 🎂 **Date of Birth** + Name | `MEDIUM` |
| 🛡️ **NATO / UK Security Markings** | *Optional* (See `profile` input) |

### Structured files

XML tags and attributes, JSON properties, and YAML keys are read as fields. You
can use natural data structures without repeating labels inside their values:

```xml
<employee>
  <firstname>John</firstname>
  <lastname>Example</lastname>
  <pri>12345678</pri>
  <dob>1990-01-01</dob>
</employee>
```

This produces PRI/name and DOB/name findings. A first name alone still does not
qualify. Separate records are scanned independently, and reports retain the
original file's line numbers.

Extraction handles **every scalar field**, not a fixed list of personal-data
keys. YARA rules decide what matches. For example, the opt-in
[Protected A flag rule](examples/structured/protected-a.yar) matches
`"PROTECTED A": true` but not `false`. The [structured-data guide](docs/structured-data.md)
explains record boundaries, examples, and supported formats.

Structured extraction was added after `v1.0.0`; use a release containing this
change or a reviewed commit SHA to use it.

## ⚙️ Key Configuration Inputs

You can customize the Action using `with:`

| Input | Default | Description |
|---|---|---|
| `fail-on` | `NONE` | Fails the job if findings meet this severity: `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `profile` | `code` | Set to `code-with-markings` to include NATO/UK security marking detection. |
| `exclusions` | `'[]'` | JSON array of glob patterns to ignore (e.g., test fixtures). See below. |

**Example: Excluding test files**
```yaml
        with:
          fail-on: HIGH
          exclusions: >-
            [{"glob":"testdata/synthetic/*","reason":"Reviewed synthetic test fixtures"}]
```

## 📊 Outputs & Code Scanning
The Action generates artifacts in the runner's temporary directory:
* **Job Summary:** A Markdown summary is automatically attached to your GitHub Actions run.
* **SARIF & JSON:** Generates `findings.sarif` and `findings.json`. You can easily upload the SARIF file to GitHub Advanced Security (Code Scanning) to see alerts directly in the PR changes tab. (See [SARIF Upload Example](examples/sarif-upload.md)).

---

<details>
<summary><b>🔍 Matching Behavior & Limitations</b></summary>

* **File Types:** Scans UTF-8/ASCII text in Git blobs. Files over 2 MiB, binaries, encoded/encrypted files, and Git LFS objects are skipped.
* **Formatting:** `.xml`, `.json`, `.yaml` and `.yml` files use structured extraction. Other text requires labelled fields such as `first_name: Jane` or `lastName = "Example"`. A full name requires at least two words.
* **Record boundaries:** Nested objects and separate array/list items are independent. Parent fields are not inherited by child records. Invalid or unsupported structured input fails the scan with exit `2`; it is not reported as clean.
* **Validation:** DOB accepts numeric dates from 1800–2099 but does not validate real calendar dates. SIN has no checksum validation.
* **Context is Key:** A bare identifier without a supported name field will *not* produce a finding. This tool complements, rather than replaces, standard API key/secret scanners.
</details>

<details>
<summary><b>🛠️ Local Development & Custom Rules</b></summary>

Want to run it locally or write custom YARA rules? You'll need Python 3.12 and Git.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run a full scan locally
python -I src/scan.py --repo /path/to/your/repo --mode full --output scan-results
```

* **Custom Rules:** Want to scan for Credit Cards or custom company data? See [Create your own rules](docs/custom-rules.md).
* **Testing:** See the [Examples folder](examples/README.md) for dummy workflows demonstrating passing and failing pipelines. 
</details>

<details>
<summary><b>📦 Maintainers & Release Process</b></summary>

* **Trust Model:** Scanned files are read strictly from Git objects, not executed or imported. External users should pin to a specific release tag (e.g., `v1.0.0`).
* **Releases:** This project uses [Release Please](.github/workflows/release-please.yml) on pushes to `main`. Use Conventional Commits (`fix:`, `feat:`, etc.) to trigger automatic changelog generation and semantic version tagging.
</details>
