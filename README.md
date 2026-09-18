# Generic Sensitive Information Scan

A reusable GitHub Action that runs YARA over committed text files. It flags
labelled personal identifiers combined with names, reports evidence locations,
and compares pull-request changes against their common ancestor with the base
branch. It does not execute the repository being scanned.

**27 core rules: 21 private helpers and 6 reporting rules.** The optional security
markings profile brings the total to 33. All form-specific rules have been removed.

## Release this action

The repository is live at [KingBain/sensitivity-scan](https://github.com/KingBain/sensitivity-scan).
Check that the **Test scanner** workflow passes on `main`, then tag the reviewed
commit to make the action reusable by version:

```bash
git checkout main
git pull --ff-only
git tag v1.0.0
git tag v1
git push origin v1.0.0 v1
```

For subsequent releases, create a new version tag and move the `v1` major
version tag to that release. Consumers can pin the full release commit SHA
instead if they require an immutable reference.

## Use it in another repository

Copy `examples/scan.yml` to `.github/workflows/sensitive-scan.yml` in the repository
that should be scanned. Use `KingBain/sensitivity-scan@v1` after the tag exists. Pin it to the full
release commit SHA for production use.

The example runs on pull requests, pushes to `main`, a weekly schedule, and manual
requests. Change the default branch name if needed. It uploads reports as an
artifact and requires only `contents: read`.

The action defaults to **report-only** (`fail-on: NONE`). To block new HIGH or
CRITICAL findings on pull requests:

```yaml
- name: Scan sensitive information
  id: sensitive
  uses: KingBain/sensitivity-scan@v1
  with:
    fail-on: HIGH
```

`MEDIUM` also blocks PRI/name and DOB/name findings. Scanner errors fail the step
regardless of this setting. A match is a review candidate, not an authoritative
security classification.

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

## References

- [YARA Python API](https://yara.readthedocs.io/en/stable/yarapython.html)
- [GitHub action metadata](https://docs.github.com/en/actions/reference/workflows-and-actions/metadata-syntax)
- [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
