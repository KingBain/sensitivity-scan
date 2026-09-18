# Sensitivity Scan

A GitHub Action that uses YARA to flag potentially sensitive information in
committed text files. It scans a whole repository or checks what a pull request
introduces, without executing the code being scanned.

The default rules look for **a labelled identifier together with a name**:
PRI/CIDP, date of birth, or SIN/NAS. Findings are candidates for review, not
authoritative security classifications. Reports show files and line numbers,
but omit matched values.

## Quick start

Add this as `.github/workflows/sensitivity-scan.yml` in the repository to scan:

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
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          fetch-depth: 0
          persist-credentials: false
          ref: ${{ github.event.pull_request.head.sha || github.sha }}
      - name: Scan sensitive information
        id: sensitive
        uses: KingBain/sensitivity-scan@v1.0.0
        with:
          fail-on: NONE
```

Start in report-only mode (`NONE`), review the job summary, then change
`fail-on` to `HIGH` to block HIGH/CRITICAL findings. `MEDIUM` also blocks
PRI/name and DOB/name findings. Scanner errors fail regardless of this setting.
A green report-only run does **not** mean there were no findings.

`mode: auto` is the default: pull requests scan for newly introduced findings;
pushes and manual runs scan the selected commit in full. Keep `fetch-depth: 0`
for PR comparisons. Change `main` if your default branch has another name.

For artifact uploads (including failed scans) and a scheduled full scan, copy
[examples/scan.yml](examples/scan.yml). For production, pin the action to the full
commit SHA of the release you reviewed. This project uses exact version tags
such as `v1.0.0`, not a moving `v1` tag.

## Try a passing and a failing pipeline

| Example | Expected result |
|---|---|
| [Passing scan](.github/workflows/example-passing.yml) | Synthetic fixture with a redacted identifier; green, zero findings |
| [Failing scan](.github/workflows/example-failing.yml) | Synthetic SIN + name; red, one HIGH finding |

These are manual demos using the published action. They create a tiny temporary
Git repository, commit the fixture locally, scan it and save reports. The failing
demo is intentionally red; it is not run automatically on pushes or PRs.
See [how to run the examples](examples/README.md).

## Create your own rules

Follow [Create your own rules](docs/custom-rules.md) for a copyable, tested
credit-card-number example, an explanation of the required YARA metadata, and
instructions for adding it to a fork of the action.

The current action loads bundled profiles only; it does not accept a
`rules-path` input or auto-load rules from the repository being scanned.
The credit-card example is opt-in and is **not** enabled by `v1.0.0`.
It detects labelled 16-digit candidates, not validated card accounts.

## Rules and folders

| File or folder | Purpose | Rule count |
|---|---|---:|
| `rules/indicators/identifiers.yar` | PRI/CIDP and SIN/NAS short and long labels | 8 private |
| `rules/indicators/names.yar` | English/French full, given and family-name fields | 9 private |
| `rules/indicators/dates.yar` | DOB/DDN and long labels | 4 private |
| `rules/logic/pri-with-name.yar` | Personnel identifier plus full or split name, EN/FR | 2 public |
| `rules/logic/dob-with-name.yar` | Date of birth plus full or split name, EN/FR | 2 public |
| `rules/logic/sin-with-name.yar` | SIN/NAS plus full or split name, EN/FR | 2 public |
| `rules/logic/security-markings.yar` | Optional NATO/OTAN and UK/RU marking indicators | 6 public |

Entry points are `rules/profiles/code.yar` (27 rules) and
`rules/profiles/code-with-markings.yar` (33 rules). They use YARA `include`
statements, so referenced rules compile in the same namespace. Private helpers
never create standalone findings.

| Combination | Suggested classification | Scanner severity |
|---|---|---|
| PRI/CIDP + name | Protected A | MEDIUM |
| Date of birth + name | Protected A | MEDIUM |
| SIN/NAS + name | Protected B | HIGH |

Both a full name field and a first/given + family/last name pair are supported.
Names and identifiers must use the same language group, but can occur anywhere
in the same file. Proximity selects the supporting locations shown in reports;
it is **not** an enforced distance limit or proof that the fields describe the
same person.

The optional markings detect NATO Restricted, OTAN Diffusion restreinte, NATO
Unclassified, OTAN Non-classifié, UK Official and RU Officiel. Restricted/Official
indicators are MEDIUM; the two Unclassified indicators are LOW. An Unclassified
marking does not establish sensitive content. This small inherited pack is not
an exhaustive government classification-marking library.

## Matching behavior

These are revised patterns for labelled data, rather than a verbatim conversion
of the legacy SQL. Examples of supported fields include `SIN: 123456789`,
`"first_name": "Jane"`, `lastName = "Example"`, and `date_of_birth: 1987-03-21`.
Names require `:` or `=` and nonempty values; a full name requires at least two
words. Label case, spaces, hyphens and underscores are accommodated. PRI/CIDP
accepts 8 or 9 digits; SIN/NAS accepts 9, with common spaces/dots/hyphens.

Limits to keep in mind:

- This scans UTF-8/ASCII text in Git blobs, not language syntax or arbitrary
  documents. Encoded, encrypted, compressed, binary, UTF-16 and non-UTF-8 content
  are not extracted. Git LFS content, submodules and symlink targets are not fetched.
- It finds labelled values. Bare identifiers, CSV header/value associations,
  comment prefixes, values split across lines, and other layouts may be missed.
- DOB currently accepts year-first numeric dates from 1800–2099. It does not
  validate real calendar dates. SIN has no checksum validation.
- Name matching is a bounded heuristic covering ASCII and many Latin-1 letters
  encoded in UTF-8. It is not a universal Unicode name recognizer. Synthetic
  examples with realistic labels can match too.
- A helper alone does not report. For example, SIN without a supported name
  field produces no finding in this profile. This package does not replace a
  conventional secret scanner.
- Reports omit matched values and source snippets, but include filenames, rule
  titles, candidate classifications and line numbers.

## Full scans and pull requests

**Full mode** scans all regular tracked files in the selected commit. It includes
code, configuration, documentation, tests and workflow files. It never scans
untracked files or uncommitted working-tree edits. Files above 2 MiB are skipped
by default. No path exclusions are applied unless you provide them.

**Changes mode** resolves the merge base of `base` and `head`, selects changed
files, and scans each complete head/base file with the same bundled rules. It
compares occurrence counts using the matched identifier and its selected name
evidence in memory. It reports newly introduced evidence combinations, including
additional identical occurrences. Moving unchanged evidence to different lines
alone does not create a new finding. Adding a name can activate a previously
unreported identifier. Changing the selected supporting name may reflag an
existing identifier; that conservative behavior is intentional.

Deleted files produce no findings. Exact-content renames retain their baseline;
renames with edits are treated conservatively as new files. Identical findings
in separate files remain separate. A skipped baseline cannot suppress a head
finding. An unavailable base commit or missing history is a scan error: the
action does not silently switch modes. Keep `fetch-depth: 0` in the checkout.

JSON includes counts and skip reasons for selected files. Unchanged files are
not inspected during changes scans; use a full scan to review repository-wide
coverage. `fail-on-skips: 'true'` makes any skipped selected file fail the action,
including deliberately excluded files.

## Action inputs

| Input | Default | Meaning |
|---|---|---|
| `repository` | `.` | Path to the checked-out repository |
| `mode` | `auto` | PR events use `changes`; other events use `full` |
| `base` | event base | Base ref/commit; required for explicit changes mode outside PR events |
| `head` | event head / `HEAD` | Commit to scan |
| `profile` | `code` | `code` or `code-with-markings` |
| `fail-on` | `NONE` | `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `fail-on-skips` | `'false'` | Fail on any selected head/base file skipped |
| `max-file-bytes` | `2097152` | Size limit per file |
| `timeout` | `10` | YARA timeout in seconds per file per revision |
| `exclusions` | `'[]'` | JSON array with `glob` and `reason` for each exclusion |

For example, an explicit reviewed exception for synthetic fixtures:

```yaml
with:
  exclusions: >-
    [{"glob":"testdata/synthetic/*","reason":"Reviewed synthetic test fixtures"}]
```

Patterns use Python `fnmatchcase` against repository-relative paths; matching is
case-sensitive and `*` can span `/`. Exceptions are supplied by the workflow,
not loaded automatically from a file on the scanned branch.

The action runs on Linux GitHub-hosted runners (examples use `ubuntu-latest`).
Self-hosted runners need a compatible current GitHub runner, Git, Python venv
support and network access to install the pinned runtime. One YARA timeout applies
to one file; set an overall workflow job timeout as the example does. More than
10,000 findings or a YARA match-limit warning causes a scan failure.

## Outputs and GitHub Code Scanning

Outputs: `findings-count`, `json`, `sarif`, `report-directory`, and `exit-code`.
Reports are placed in the runner's temporary directory. `findings.json` includes
findings, coverage, skips and errors. `findings.sarif` uses actual identifier lines
and related locations for name evidence. `summary.md` is added to the job summary.
Exit codes are 0 (passed), 1 (finding threshold reached), or 2 (scan/coverage failure).

`examples/scan.yml` preserves reports even when a finding fails the scan. If
installation or argument validation fails before scanning, reports may not exist.
For optional Code Scanning integration, see `examples/sarif-upload.md`. The
artifact workflow works without a Code Scanning subscription. SARIF fingerprints
use rule, path and occurrence order, never hashes of sensitive values. Reordering
occurrences or renaming a file can change alert identity.

## Local use and development

Python 3.12 and Git are required. From this package's directory:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -I src/scan.py --repo /path/to/your/repo --mode full --output scan-results
.venv/bin/python -I src/scan.py --repo /path/to/your/repo --mode changes --base main --head HEAD --fail-on HIGH
.venv/bin/python -m unittest discover -s tests -v
```

All local scans read **commits**, so commit your sample fixtures first. To update
patterns, edit `tools/build_rules.py`, run it, then run the tests. Generated helper
and public evidence strings deliberately share a source: YARA does not return
referenced helper strings with a public match, so the public rules also include
the corresponding evidence patterns for location reporting.

For a raw YARA CLI scan of a text file (without Git comparison or redacted JSON):

```bash
yara rules/profiles/code.yar sample.txt
```

Avoid YARA's `-s` option if you do not want matched values printed. The wrapper
uses a Python binding with its YARA runtime, so the separate CLI is not needed
for the action.

## Trust model

Consumer workflows call a pinned release of this action, keeping its code and
rules outside the pull request being scanned. Inputs are passed through
quoted arguments; scanned files are read from Git objects, not imported or run.
Use the standard `pull_request` event and a read-only token. Do not use
`pull_request_target` with an untrusted checkout. The maintainer CI uses `./`
only to test changes to this action itself; copy the external-action consumer
example for scanning other repositories.

## Releases (maintainers)

[Release Please](.github/workflows/release-please.yml) runs on pushes to `main`.
It opens or updates a release PR with the changelog, `version.txt` and the
release manifest. Merging that PR publishes the GitHub Release and exact
`vMAJOR.MINOR.PATCH` tag. There is no moving major-tag updater.
Scanner JSON and SARIF versions come from `version.txt`.

The release job uses the `release` environment. Install a GitHub App on this
repository with Contents, Pull requests and Issues read/write permissions.
Configure `SENS_RELEASE_APP_CLIENT_ID` as an environment variable under GitHub
Actions **Variables** (not a shell variable) and `SENS_RELEASE_APP_PRIVATE_KEY`
as an environment secret. These names match the workflow. Consumers running the
scanner do not need this App or these secrets.

Use Conventional Commit titles: `fix:` for patches, `feat:` for features,
and a breaking-change marker for major changes. `docs:` or `chore:` changes
alone do not normally open a new release PR. See the
[release-please action guide](https://github.com/googleapis/release-please-action).

## References

- [YARA Python API](https://yara.readthedocs.io/en/stable/yarapython.html)
- [GitHub action metadata](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax)
- [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
