# Create your own rules

A rule describes what to look for, how to label the finding, and when it matches.
Start with one narrow pattern and synthetic examples that should and should not match.

**Current limitation:** the action loads its bundled `code` or `code-with-markings`
profile. It does not have a `rules-path` input and does not discover `.yar` files
in the repository being scanned. To use your own rules with the action, add them
to a fork of this action, test them, and pin consumers to a release of that fork.
You can also test a standalone rule locally without changing the bundled profiles.

## Example: a credit card number candidate

The ready-to-copy rule is [examples/credit-card/credit-card.yar](../examples/credit-card/credit-card.yar).
It looks for a labelled **16-digit number**: `credit_card`, `credit card number`,
or `card_number`, followed by `:` or `=` and a value on the same line. Values can
be contiguous digits or four groups of four digits separated by spaces or hyphens.

For example, this should match:

```text
credit_card: 4242 4242 4242 4242
```

This should not:

```text
credit_card: **** **** **** 4242
```

`4242 4242 4242 4242` is a [public Stripe test number](https://docs.stripe.com/testing#cards).
Use synthetic/provider test data, never real card details, in rule tests.

The example rule has three parts:

```yara
rule example_credit_card_number : financial_information
{
    meta:
        title = "Possible credit card number in a labelled field"
        severity = "HIGH"
        assessment = "review_required"
        evidence_model = "marking"
    strings:
        $marking = /(^|[\r\n{,;])[ \t]*["']?(credit[_ \t-]*card([_ \t-]*number)?|card[_ \t-]*number)["']?[ \t]*[:=][ \t]*["']?([0-9]{16}|[0-9]{4} [0-9]{4} [0-9]{4} [0-9]{4}|[0-9]{4}-[0-9]{4}-[0-9]{4}-[0-9]{4})(["']|[ \t]*[,;}\r\n]|[ \t]*$)/ nocase
    condition:
        $marking
}
```

- `meta` describes the finding. `HIGH` makes it block a scan using `fail-on: HIGH`.
- `strings` contains the pattern. `nocase` ignores label case. The boundaries
  avoid matching a 16-digit prefix of a longer value; `.` is not used as a wildcard separator.
- `condition` decides when the rule reports. Here, finding `$marking` is enough;
  no name field is required.

The wrapper needs a little more than valid YARA syntax:

| Field | Requirement for a standalone pattern |
|---|---|
| Rule name | Unique YARA identifier, for example `example_credit_card_number` |
| `title` | A readable description; do not put matched values in it |
| `severity` | `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL` |
| `evidence_model` | `"marking"` with a matching string named `$marking` |
| `condition` | Must require `$marking` so there is a location to report |

Despite its name, `marking` is the existing single-pattern reporting mode; using
it does **not** assign a security classification. The other supported mode,
`identifier_and_name`, requires `$identifier` plus `$full_name` or both
`$first_name` and `$last_name`. Private helper matches are not automatically
returned as evidence for a public rule. Other models/string names need scanner
code changes; do not silently rename `$marking` to `$card`.

This example is deliberately limited. It does **not** validate Luhn checksums,
issuer prefixes, whether a card is active, or every card-number length. It misses
unlabelled numbers, multiline values, and layouts outside the illustrated field
formats. A 16-digit order number in a card-labelled field can still match. Treat
the result as a candidate for review, not proof of a real card or a classification.
The example is **not enabled in the default profiles**.

## Use the same rule with XML, JSON and YAML

The action extracts all scalar fields from structured files and runs YARA once
per record. The credit-card rule above can therefore also match these inputs:

```xml
<payment><credit_card>4242424242424242</credit_card></payment>
```

```json
{"credit_card": "4242424242424242"}
```

```yaml
credit_card: "4242424242424242"
```

Each record is presented to YARA as one quoted key/value pair per line:

```text
"credit_card": "4242424242424242"
```

All scalar values become strings, including numbers and booleans. Key names are
preserved; aliases such as `card_number` belong in your YARA rule. XML namespace
prefixes are removed. Reports map findings back to the original value's source
line; the normalized text is not written to reports.

For a different kind of field, see the opt-in
[Protected A flag rule](../examples/structured/protected-a.yar). It requires the
normalized field `"PROTECTED A": "true"` (also accepting `PROTECTED_A` or
`PROTECTED-A`) and leaves `false`, `null`, and schema declarations unmatched.
Both boolean `true` and string `"true"` match because normalization is textual.
Enable it in your fork using the same steps below, substituting
`structured/protected-a.yar` and `custom/protected-a` for the card example paths.

The adapter is part of this action, not the YARA CLI. Running `yara` directly on
an XML file does not perform extraction. The CI cases in `tests/test_structured.py`
exercise both example rules through the adapter. See
[Structured data](structured-data.md) for boundaries and limitations. Structured
extraction was added after `v1.0.0`; consumers need a release containing it or a
reviewed commit SHA.

## Test it locally

From a clone of this repository, install the same runtime as the action:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -p test_examples.py -v
```

These tests cover positive/negative formats, the two fixture files, duplicate
occurrences, report redaction, and the fork integration below. They also verify
that a finding exits with code `1`, not a scanner error (`2`).

If you already have the YARA CLI, you can try the rule directly:

```bash
yara examples/credit-card/credit-card.yar examples/credit-card/passing.txt
yara examples/credit-card/credit-card.yar examples/credit-card/failing.txt
```

The first prints no matches; the second prints the rule name and file path.
Raw YARA does not implement this action's `fail-on` policy or its exit-code
contract. Avoid `yara -s`, which prints matched values.

## Add it to your fork of the action

1. Copy `examples/credit-card/credit-card.yar` to `rules/custom/credit-card.yar`
   (create the `custom` directory).
2. In `tools/build_rules.py`, find the line that writes `rules/profiles/code.yar`.
   Add `'custom/credit-card'` to the end of its tuple of include paths. Its end
   changes from `'logic/dob-with-name','logic/sin-with-name'` to
   `'logic/dob-with-name','logic/sin-with-name','custom/credit-card'`.
3. Run `.venv/bin/python tools/build_rules.py`. The generated `code.yar` will now
   include `../custom/credit-card.yar`. `code-with-markings` includes `code`, so it
   gains the rule too. Do not only edit the generated profile: the next generation
   would overwrite it.
4. Update the deliberate rule-count expectations in `tests/test_scan.py`:
   **27 → 28** core rules, **6 → 7** public rules, and **33 → 34** with markings.
   Run `.venv/bin/python -m unittest discover -s tests -v` and commit the custom
   rule, generator change, generated profile and updated tests together.
5. Publish a versioned release of your fork. In consumer workflows, replace
   `KingBain/sensitivity-scan@v1.0.0` with your fork and its actual release tag
   (or full commit SHA). Keep `profile: code` and use `fail-on: HIGH` to block hits.

The upstream `v1.0.0` release will not acquire your fork's rule. The repository
being scanned supplies data, not executable code or an automatically trusted
rule pack. Review rule changes separately and do not load rules from an untrusted
pull-request checkout into a privileged workflow.

To test the complete forked scanner against a new sample repository, **commit
the sample file first**, then run:

```bash
.venv/bin/python -I src/scan.py --repo /path/to/sample-repo --mode full --fail-on HIGH
```

A bare `.yar` match is only the first test. Also check the report's line numbers,
that matched values remain omitted, and that clean files still pass.
