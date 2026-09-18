# Optional GitHub Code Scanning upload

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

GitHub Code Scanning is available for public repositories and for eligible
organization repositories with GitHub Code Security enabled. Ordinary artifact
reports do not require that feature. See [GitHub's SARIF documentation](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

All reports produced by this scanner omit matched values. Code Scanning's web
interface links to the existing source in your repository, where authorized
viewers can naturally see the corresponding content.
