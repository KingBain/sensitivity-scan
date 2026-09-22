# Configure and operate the action

Use Sensitivity Smell to identify possible sensitive data for review and support
your organization's security controls. An implementation includes a scan scope,
a reviewer, a response process, and retained evidence. The scan provides findings;
the team makes the handling decision.

## Deploy

1. Choose a reviewed action release or commit. Pin production workflows to its
   full commit SHA; a tag is a convenient version reference but can be moved.
2. Copy the [consumer workflow](../examples/scan.yml). It runs on PRs, pushes to
   `main`, a weekly schedule, and manual requests. Use a Linux runner, read access
   to repository contents, and `fetch-depth: 0` for comparison history.
3. Start with `fail-on: NONE`. Inspect a full scan, coverage, and the
   [synthetic pipeline examples](../examples/README.md) before choosing a threshold.
4. Assign report review to an existing code-review or security-review process.
   Define when to escalate a possible exposure and how to record exceptions.

Use the `pull_request` event for PR scanning. The action reads committed Git
objects using its own runtime and bundled rules; it does not execute or import
the scanned files. Changes to the scanned repository's `.yar` files do not
automatically change the active rules. The action installs its pinned runtime
dependency on the runner and needs package-download access.

The examples use `v1.1.0`, which includes common field extraction and GC boolean
flags. Renamed report identifiers require a release containing the rename or a
reviewed commit after `v1.1.0`.

## Upgrading existing integrations

Use `KingBain/sensitivity-smell@<reviewed-ref>` in consumer workflows and update
links to the renamed repository. Published tags retain their original code; a
new repository path does not change a pinned release's behavior or report names.

The rename changes these identifiers in current source:

| Surface | Previous value | New value |
|---|---|---|
| JSON `tool` and SARIF `tool.driver.name` | `generic-sensitive-scan` | `sensitivity-smell` |
| SARIF `automationDetails.id` prefix | `generic-sensitive-scan/` | `sensitivity-smell/` |
| Example SARIF upload category | `generic-sensitive-scan` | `sensitivity-smell` |

Update downstream filters that inspect these values. The JSON structure, action
inputs/outputs, CLI arguments, report filenames, and YARA rule IDs are unchanged.
For existing Code Scanning uploads, see the
[SARIF migration note](../examples/sarif-upload.md#upgrading-from-the-previous-name)
before switching report identities.

Consumer workflow names, filenames and artifact names are examples; renaming
them is optional. If you rename a required check, update the corresponding
repository rule. Release automation continues to use the existing
`SENS_RELEASE_APP_CLIENT_ID` variable and `SENS_RELEASE_APP_PRIVATE_KEY` secret;
the repository name is obtained from the event.

## Inputs

| Input | Default | Behavior |
|---|---|---|
| `repository` | `.` | Path to the checked-out Git repository |
| `mode` | `auto` | `auto`, `full`, or `changes`; auto uses changes mode for `pull_request`, otherwise full |
| `base` | inferred on PRs | Base ref/commit for changes mode; comparison uses its merge base with head |
| `head` | PR head or `HEAD` | Commit to scan |
| `profile` | `code` | `code` for identifier/name combinations; `code-with-markings` also enables classification flags and NATO/UK markings |
| `fail-on` | `NONE` | Fail on findings at or above `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`; `NONE` disables finding-based failure |
| `fail-on-skips` | `false` | Return exit `2` if any selected head or baseline file is skipped, including exclusions |
| `max-file-bytes` | `2097152` | Maximum size of each Git blob, in bytes (2 MiB) |
| `timeout` | `10` | Per-file scan budget in seconds, on each revision, shared across extracted records |
| `exclusions` | `[]` | JSON array of objects with a path `glob` and nonempty `reason` |

In explicit `changes` mode, supply `base` and the intended `head`; automatic PR
ref inference occurs in `auto` mode. Both commits and their history must be
available locally.

Full mode scans eligible files at one commit. Changes mode scans complete changed
head/base files and subtracts matching evidence occurrences already present in
the baseline. It is not limited to added diff lines. Repeated occurrences count
separately; changing supporting evidence can produce a new finding. Exact renames
preserve the baseline, while edited renames are treated conservatively as new.
If a baseline file is skipped, its findings cannot be subtracted.

Neither mode scans working-tree changes, untracked files, or all historical
commits. Full scans do not fetch Git LFS content or follow submodules.

## Results and coverage

| Output | Meaning |
|---|---|
| `findings-count` | Number of reported occurrences, not number of people or documents |
| `json` | Absolute path to `findings.json`: findings, mode, profile, selected revisions, coverage and errors when available |
| `sarif` | Absolute path to `findings.sarif` |
| `report-directory` | Directory containing JSON, SARIF and `summary.md` |
| `exit-code` | Scanner outcome below; setup failures can occur before outputs are available |

The action also appends the summary to the Actions job summary. Preserve reports
with an `always()` artifact step, as in the consumer example. The example retains
artifacts for seven days; choose retention appropriate to your review process.

| Exit code | Interpretation |
|---|---|
| `0` | No scan error and no configured failure condition reached; findings and skipped files may still exist |
| `1` | At least one finding meets the configured severity threshold |
| `2` | Scan/coverage failure; includes skipped files when `fail-on-skips: true` |

A report-only run can be green with HIGH findings. A zero-findings run can also
have gaps. Inspect `coverage.scanned_head`, `scanned_base`, `unchanged`, and
`skipped`, plus each skipped path's `side` and `reason`. A scan error can produce
an empty findings list and incomplete coverage; do not interpret it as a clean
result. Check the exit code as well as `errors`, because skip-based failure is
reported through coverage and exit `2`.

Selected files are skipped for size, exclusions, symlink/submodule mode, Git LFS
pointers, NUL-containing binary/UTF-16 content, or invalid UTF-8. Unchanged files
in changes mode are not rescanned. There is no default path-exclusion list.
Encoded text that remains UTF-8 may be scanned without its payload being decoded;
it is not necessarily recorded as a skip. Scan counts describe processing scope,
not detection completeness. See [matching limits](field-syntax.md#scope-and-limits).

Reports omit matched values and source snippets, but contain paths, line numbers,
rule titles, severities and candidate labels. Reviewers can inspect the original
source using repository access. Protect reports according to their metadata and
avoid copying actual values into tickets or PR comments.

## Review findings

1. Check the scanned revision, rule, source line and supporting evidence lines.
   For a PR, remember that the report contains newly introduced evidence only.
2. Decide whether the match represents real sensitive information, approved
   synthetic data, an unrelated pattern, or a declared marking requiring review.
   A classification candidate and a severity are prompts for that decision.
3. For real or uncertain exposure, use your organization's handling and incident
   process. Removing data in a later commit does not remove earlier Git objects,
   clones, artifacts or other copies.
4. Record the disposition, reviewer and follow-up in the team's review system.
   The scanner does not track remediation, approvals, or incident status.

For recurring false positives, narrow the relevant rule with synthetic regression
cases or add a narrowly scoped path exclusion. Every exclusion needs a reason:

```yaml
with:
  fail-on: NONE
  exclusions: >-
    [{"glob":"testdata/synthetic/*","reason":"Reviewed synthetic fixtures; owner: platform team; review by 2027-01-01"}]
```

The owner and date above are a documentation convention; the scanner does not
validate or enforce them. Path exclusions suppress the entire file, including
future content, and appear as coverage skips. Review them when content or rules
change. Do not broadly exclude all tests or documentation just to obtain a green
check. There is no per-finding approval or inline suppression mechanism.

## Optional merge gate

After reviewing behavior on your repository, set a threshold if the team needs a
failed check to trigger action:

```yaml
with:
  fail-on: HIGH
```

This fails the check for HIGH/CRITICAL findings. To require it before merging,
configure the scan job as a required status check in your repository rules.
See [GitHub's required status checks](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches#require-status-checks-before-merging).
Consider bypass permissions and who can change the workflow/rules in that design.
The sample workflow does not configure repository protection for you.

This is a post-push review gate. It cannot prevent the initial commit/push,
guarantee detection, or retract exposed data. If you use a merge queue, configure
and verify its separate check triggers; the supplied example has no `merge_group`
trigger. Report-only operation is also a valid choice when reviewers act on
findings through another process.

## Support a security control

Define the intended control outcome first. An example implementation statement is:

> Selected repositories run automated checks for documented sensitive-data
> patterns on pull requests and on the default branch. Assigned reviewers assess
> findings, record decisions and exceptions, and escalate possible exposures.

This is a suggested process statement, not a claim of compliance with a specific
framework. Have the control owner determine whether its scope, timing and evidence
satisfy the applicable requirement.

Retain evidence of the process, not just a green badge:

| Evidence | What to record |
|---|---|
| Configuration | Repository scope, workflow revision, action commit, profile, threshold, exclusions, size/timeout limits |
| Execution | Run URL/time, scanned head/base revisions, exit code, reports, skips and errors |
| Review | Finding disposition, responsible reviewer, corrective action or approved exception |
| Maintenance | Synthetic test results, rule changes, known gaps and periodic exception review |

The JSON report supplies some execution details; workflow history and your review
records supply the rest. The tool does not create a compliance attestation or
prove that all sensitive data was found.

Evaluate usefulness using representative synthetic cases, actionable findings,
review effort, missed cases discovered elsewhere, and unresolved findings. Avoid
an accuracy or effectiveness percentage unless you define the dataset and metric.

## Run locally

From a clone of the action, install its runtime and scan a separate Git repository:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -I src/scan.py --repo /path/to/repository --mode full --fail-on NONE --output scan-results
```

Use Python 3.12 and Git. The local command still reads committed blobs. Commit
synthetic sample data before using it to exercise the scanner. For custom YARA
rules, follow the [rule-authoring guide](custom-rules.md).
