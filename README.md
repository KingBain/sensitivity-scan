# Sensitivity Smell

Help people notice possible sensitive data, decide what to do next, and support
their organization's security controls.

Sensitivity Smell is a GitHub Action that uses YARA rules to flag a documented set
of patterns in committed text and source code. Findings identify files and lines
for human review. Reports omit matched values.

The name borrows from "code smell": a sensitivity smell is a pattern worth
investigating. It points to a possible concern and leaves the handling decision
to the reviewer.

Detection is best effort: false positives and missed sensitive data are expected.
A finding does not establish sensitivity or classification, and zero findings
does not establish that a repository is safe. The action runs after content has
been committed and pushed to GitHub. It cannot prevent that initial exposure or
remove existing copies. Its role is to add visibility to development and review
workflows.

## Start with reporting

Add `.github/workflows/sensitivity-smell.yml` to the repository you want to scan:

```yaml
name: Sensitivity Smell

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
      - name: Review possible sensitive data
        id: sensitive
        uses: KingBain/sensitivity-smell@v1.1.0
        with:
          fail-on: NONE
      - name: Preserve reports
        if: ${{ always() && steps.sensitive.outputs.report-directory != '' }}
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: sensitivity-smell-results
          path: ${{ steps.sensitive.outputs.report-directory }}
          retention-days: 7
          if-no-files-found: error
```

The example uses the published `v1.1.0` release, which includes common field
extraction and GC boolean flags. Pin production workflows to the full commit SHA
you reviewed. This guide describes the current source; check the
[release notes](https://github.com/KingBain/sensitivity-smell/releases) for the version
you deploy. The renamed report identifiers are in source after `v1.1.0`; see
[upgrading existing integrations](docs/implementation.md#upgrading-existing-integrations).

Read the job summary and the `findings.json` artifact, including coverage and
skip reasons. With `fail-on: NONE`, findings do not fail the check; scan errors
still do. Assign someone to review the reports. A green check alone is not a
review decision.

## Coverage

The default `code` profile looks for these English/French labelled combinations:

| Pattern in the same scan record | Finding severity | Candidate label |
|---|---|---|
| SIN / NAS + full name, or first and last names | HIGH | Protected B |
| PRI / CIDP + full name, or first and last names | MEDIUM | Protected A |
| DOB / DDN + full name, or first and last names | MEDIUM | Protected A |

Numeric patterns check format. SIN checksums, real calendar dates, and a person's
identity are not validated. A first name alone or an unlabelled identifier does
not satisfy these combinations. Synthetic fixtures can match the same patterns
as real information.

The optional `code-with-markings` profile adds GC boolean classification flags
and selected NATO/UK markings. These identify declarations for review; they do
not independently determine the content's classification. Severities express
this project's review priorities, not confidence scores or official classification
equivalents.

The current extractor recognizes common field syntax in eligible UTF-8 text,
regardless of filename: colon fields, assignments, object literals, property
access, XML tags and attributes. Visible record boundaries limit combinations;
flat text can retain file-wide context. Complex syntax, runtime values, encoded
content, and unsupported labels can be missed. Binary documents are not decoded.
See [field syntax and limits](docs/field-syntax.md).

## Scan modes and decisions

| Event with `mode: auto` | Scan behavior |
|---|---|
| `pull_request` | Compare complete changed files at the PR head and merge base; report newly introduced matching evidence |
| Push, schedule, manual run | Scan eligible tracked files at the selected head commit |

Neither mode scans every historical commit. Working-tree edits and untracked files
are outside scope. A PR report is a delta, so use full scans to review existing
findings at a commit.

Start with reporting, review representative findings and gaps, then choose any
failure threshold. `fail-on: HIGH` fails the check for HIGH/CRITICAL findings;
`MEDIUM` also includes MEDIUM findings. Merge gating additionally requires a
repository rule that requires the check to pass. It does not stop the original
commit or push.

For a security control, document what is checked, who reviews results, what
response is expected, and what evidence is retained. The scanner can support
that process; enabling it alone does not establish that a control is satisfied.

## Implementer guides

- [Configure and operate the action](docs/implementation.md): inputs, outputs,
  coverage, review decisions, exceptions, and security-control evidence.
- [Understand field matching](docs/field-syntax.md): supported syntax, record
  boundaries, classification flags, and known gaps.
- [Create custom rules](docs/custom-rules.md): a credit-card candidate example,
  reporting requirements, and integration through a reviewed fork.
- [Exercise passing and failing pipelines](examples/README.md): synthetic
  fixtures and expected exit codes.
- [Upload SARIF](examples/sarif-upload.md): optional Code Scanning integration
  for full-scan results.

## Maintainers

GitHub Actions runs the test suite, checks generated rules, and exercises the
action on pull requests. Keep rule fixtures synthetic and describe known misses
alongside expected matches. Tests establish behavior for those cases, not a
general detection-accuracy percentage.

Releases use [Release Please](.github/workflows/release-please.yml) on pushes to
`main`. Conventional Commits feed a release PR with the changelog and version
update; merging that PR lets Release Please publish the versioned release.
