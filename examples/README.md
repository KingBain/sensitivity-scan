# Pipeline examples

Use [scan.yml](scan.yml) for a real repository. It runs on pull requests, pushes,
a schedule and manual requests; the default `fail-on: NONE` reports findings
without blocking. Change it to `HIGH` to block HIGH and CRITICAL findings.

## See a passing and a failing scan

This repository contains two manually triggered demonstration workflows:

| Workflow | Data | Expected result |
|---|---|---|
| [Example - passing scan](../.github/workflows/example-passing.yml) | Synthetic name, redacted SIN | Green; 0 findings; exit `0` |
| [Example - failing scan](../.github/workflows/example-failing.yml) | Synthetic name + `000-000-000` SIN | Red; 1 HIGH finding; exit `1` |

After these workflow files are merged to the default branch, open **Actions**,
select either workflow, then choose **Run workflow**. The failing example really
fails: it does not use `continue-on-error`. Both save redacted reports as an artifact.
They run only on manual request, not on every push or PR.

Each workflow checks out these fixtures, copies just one file into a temporary
Git repository, commits it locally, and scans that repository using the published
`KingBain/sensitivity-scan@v1.0.0` action with `mode: full` and `fail-on: HIGH`.
Nothing is pushed. This avoids other source files or test fixtures affecting the
demonstration. Merely writing a file without committing it would not test this
scanner, because it reads committed Git blobs.

You can copy the workflows and their matching `examples/fixtures/*.txt` file into
a sandbox repository. Keep the fixture paths in sync. For an actual codebase,
use `scan.yml` instead of the temporary fixture setup.

## What green and red mean

- Exit `0`: below the chosen threshold. With `fail-on: NONE`, this can still mean
  findings exist; always read the report.
- Exit `1`: findings meet or exceed the threshold. This is the intended result
  for the failing demo, not a scanner malfunction.
- Exit `2`: scanning/coverage failure. This is **not** an acceptable substitute
  for the failing demo's detection result.

The regular test workflow checks these same fixtures and exit codes automatically;
its test passes when the expected blocked scan returns `1`.

For a pull-request exercise in a sandbox, commit the passing fixture to `main`,
then open a PR that replaces it with the failing fixture. Use the normal consumer
workflow with `fail-on: HIGH`. Auto mode compares complete changed files against
the merge base and blocks the newly introduced SIN/name combination.

## Custom rules and reporting

The pipeline demos use the bundled SIN/name rule. The separate
[credit-card example](credit-card/credit-card.yar) is an opt-in teaching rule,
not part of the published default profile. Follow [Create your own rules](../docs/custom-rules.md)
to test it and integrate it into a fork. For optional GitHub Code Scanning upload,
see [sarif-upload.md](sarif-upload.md).

## Structured records

The [structured examples](structured) contain the same synthetic employees in
XML, JSON and YAML. Each should produce three findings with the new adapter:
SIN/name (HIGH), PRI/name (MEDIUM), and DOB/name (MEDIUM). The test workflow checks
these fixtures through the scanner and checks their original line numbers.

That directory also includes an opt-in `PROTECTED A` boolean-flag rule and a JSON
fixture with both `true` and `false`. Only the `true` record matches that example
rule. See [Structured data](../docs/structured-data.md) for how to use it. These
structured examples require a release newer than `v1.0.0` that includes the
adapter, or a reviewed commit SHA; the manual pipeline demos above still exercise
the published text-scanning release.
