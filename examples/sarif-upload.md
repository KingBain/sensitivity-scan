# Optional GitHub Code Scanning upload

Use Code Scanning as another place for reviewers to see and track findings.
Uploading a finding does not confirm sensitive data, assign an official
classification, or satisfy a control on its own. Record the review and response
through your team's process.

The standard example saves reports as artifacts. If Code Scanning is enabled
for your repository, you can also upload SARIF from **full scans** on pushes,
schedules and manual runs. Keep pull-request delta reports as artifacts and use
the action's exit status for the PR check; delta-only SARIF is not a full snapshot
of the repository's outstanding findings.

In `examples/scan.yml`, add the permission:

```yaml
permissions:
  contents: read
  security-events: write
```

Then append this step after the scan and artifact steps:

```yaml
- name: Upload full scan to Code Scanning
  if: >-
    ${{ always() && github.event_name != 'pull_request' &&
        steps.sensitive.outputs.sarif != '' &&
        steps.sensitive.outputs.exit-code != '2' }}
  uses: github/codeql-action/upload-sarif@b96794f015dfd88f77b49b1c93e0fa7110f94c63 # v4
  with:
    sarif_file: ${{ steps.sensitive.outputs.sarif }}
    category: generic-sensitive-scan
```

This example assumes the checkout is the same commit as the full scan's `head`
(the default). If you override `head`, align the checkout and upload ref/SHA too.
Do not upload a failed scan as a clean set of findings.
Exit `1` can still produce a usable full-scan report: it means a finding threshold
was reached. Exit `2`, a missing output, or a setup failure needs investigation.
Skipped files still require review even when the scan exits `0`. Retain the JSON
artifact alongside SARIF because it contains coverage and skip reasons.

GitHub Code Scanning is available for public repositories and for eligible
organization repositories with GitHub Code Security enabled. Ordinary artifact
reports do not require that feature. See [GitHub's SARIF documentation](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

All reports produced by this scanner omit matched values and source snippets.
Paths, line numbers, rule titles, and candidate labels remain visible. Code
Scanning links to existing source in the repository, where authorized viewers
can see its contents. A dismissed alert records a review decision in GitHub; it
does not remove source data or change this action's rule matching or exit policy.
Zero alerts can also reflect limited coverage or unavailable results; inspect
the scan run before treating it as evidence of a completed check.

For retention and control evidence, see the [implementation guide](../docs/implementation.md#support-a-security-control).
