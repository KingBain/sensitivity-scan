# Pipeline examples

Use [scan.yml](scan.yml) for a real repository. It runs on pull requests, pushes,
a schedule and manual requests; the default `fail-on: NONE` reports findings
without failing the check on findings. Change it to `HIGH` to fail the check on
HIGH and CRITICAL findings. Merge gating also requires repository rules that
require the check to pass. Neither setting prevents the initial commit or push.

These examples demonstrate configuration and known matching behavior. A passing
fixture is an expected non-match, not proof that a repository is safe. A failing
fixture is a review signal, not proof of real PII. Start with reports and assign
someone to review them; see the [implementation guide](../docs/implementation.md).

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
`KingBain/sensitivity-smell@v1.1.0` action with `mode: full` and `fail-on: HIGH`.
Nothing is pushed. This avoids other source files or test fixtures affecting the
demonstration. Merely writing a file without committing it would not test this
scanner, because it reads committed Git blobs.

You can copy the workflows and their matching `examples/fixtures/*.txt` file into
a sandbox repository. Keep the fixture paths in sync. For an actual codebase,
use `scan.yml` instead of the temporary fixture setup.

## What green and red mean

- Exit `0`: no scan error or configured failure condition reached. With
  `fail-on: NONE`, findings can still exist. Skipped files can also exist unless
  `fail-on-skips: true`; read the report and coverage.
- Exit `1`: findings meet or exceed the threshold. This is the intended result
  for the failing demo, not a scanner malfunction.
- Exit `2`: scanning/coverage failure. This is **not** an acceptable substitute
  for the failing demo's detection result.

The regular test workflow checks these same fixtures and exit codes automatically;
its test passes when the expected threshold failure returns `1`. These cases do
not measure general detection accuracy.

For a pull-request exercise in a sandbox, commit the passing fixture to `main`,
then open a PR that replaces it with the failing fixture. Use the normal consumer
workflow with `fail-on: HIGH`. Auto mode compares complete changed files against
the merge base and fails the check for the newly introduced SIN/name combination.
Repeat with `fail-on: NONE`: the same finding should appear while the scan step
succeeds. That is the reporting-first behavior intended for initial adoption.

## Custom rules and reporting

The pipeline demos use the bundled SIN/name rule. The separate
[credit-card example](credit-card/credit-card.yar) is an opt-in teaching rule,
not part of the published default profile. Follow [Create your own rules](../docs/custom-rules.md)
to test it and integrate it into a fork. For optional GitHub Code Scanning upload,
see [sarif-upload.md](sarif-upload.md).

## Common field patterns

The [structured examples](structured) contain the same synthetic employees in
XML, JSON and YAML. Each should produce three findings with the new adapter:
SIN/name (HIGH), PRI/name (MEDIUM), and DOB/name (MEDIUM). The test workflow checks
these fixtures through the scanner and checks their original line numbers.
The extractor uses field syntax rather than file extensions; the same patterns
are supported inside source files. Tests also cover object literals, assignments,
named arguments and property access in files with arbitrary names.

That directory also includes a `PROTECTED A` teaching rule and a JSON fixture
with both `true` and `false`. Select `profile: code-with-markings` to use the
built-in GC flags; only the `true` record matches. It reports an enabled
declaration for review, without establishing the content's classification.
The profile covers every term
from the sensitivity grid in English and French. See
[Field syntax](../docs/field-syntax.md) for the list and severities. These
structured examples require `v1.1.0` or later. The manual pipeline demos use the
same published release through the renamed `KingBain/sensitivity-smell` path.
