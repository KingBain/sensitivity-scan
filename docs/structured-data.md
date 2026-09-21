# Scanning structured data

The scanner reads `.json`, `.yaml`, `.yml`, and `.xml` files as structured data.
It extracts all scalar fields, presents each record to the selected YARA profile,
and maps findings back to the original file. There is no PRI-specific parser or
field allowlist: the same extraction works with current and custom rules.

Other file extensions keep the existing raw-text scan. Structured extraction was
added after `v1.0.0`; pin the action to a release containing it or a reviewed commit
SHA. No new action input is required.

## Natural field values

All three [employee fixtures](../examples/structured) contain equivalent synthetic
data and should produce one HIGH SIN/name finding and two MEDIUM PRI/DOB/name
findings. The XML example uses both attributes and elements:

```xml
<employee first_name="Jane" last_name="Example">
  <sin>000-000-000</sin>
</employee>
```

This is presented to YARA as:

```text
"first_name": "Jane"
"last_name": "Example"
"sin": "000-000-000"
```

The same record can be written as a JSON object or a YAML mapping. Name/identifier
requirements and severities are unchanged. `<firstname>John</firstname>` with a
PRI needs a last-name field too; a two-word full-name field is the alternative.

## What counts as one record?

| Format | Fields scanned together |
|---|---|
| JSON | The direct scalar properties of each object |
| YAML | The direct scalar fields of each mapping; each document is independent |
| XML | An element's attributes and its direct leaf-child text fields |
| Scalar documents / list items | Each scalar is its own record under a `value` key |

Nested mappings, objects, and list items are scanned separately. Parent fields
are not copied into children. For example, a name in one employee record cannot
support a SIN in another employee record. A nested `name` object is also separate
from an identifier on its parent: use direct name fields if you need a combined
finding with the bundled rules.

In XML, `<employees><employee>…</employee><employee>…</employee></employees>` has
separate employee records. Namespace prefixes are removed from field names.
Entity escapes such as `&#233;` are decoded; comments, processing instructions and
namespace declarations are not fields. An element's direct mixed text uses a
`text` field, without pooling text from nested elements.

## Any field can have a rule

These are both ordinary fields that the extractor passes to YARA:

```json
{
  "PROTECTED A": true,
  "credit_card": "4242424242424242"
}
```

The [flag example](../examples/structured/protected-a.yar) requires `true` and
does not flag `false`. The existing
[credit-card example](../examples/credit-card/credit-card.yar) works through the
same adapter. These are opt-in teaching rules, not additions to the default
profile. See [Create your own rules](custom-rules.md) to enable them in a fork.

Normalization quotes every key and value, including booleans, numbers and nulls.
It preserves key spelling and scalar text, so YAML leading zeroes remain intact.
A boolean `true` and string `"true"` both appear as `"true"`. YARA rules determine
accepted labels and values; extracting a field does not automatically flag it.
Newlines and quotes within values are escaped. Multiline scalar contents are not
rescanned as a second document or as separate labelled lines.

## Reporting and limits

JSON, SARIF and the job summary continue to omit matched values. Locations refer
to the original field value's start line (the block marker for YAML block
scalars). YAML aliases reuse their anchor's source lines. Repeated records count
as separate occurrences, even when those source locations coincide. Changes mode
compares normalized evidence in the base and head revisions; reformatting an
otherwise identical record does not create a new finding.

Malformed input fails with exit `2` and a value-free error. The scanner does not
silently fall back to raw text for a structured file it cannot parse. These limits
also produce an error rather than a clean scan:

- XML must be a complete document. DTDs and external entities are rejected.
- YAML scalar keys and nonrecursive aliases are supported. Complex keys,
  recursive aliases, and merge keys (`<<`) are rejected; expand merges first.
  Tags are read as data and never construct Python objects.
- Nesting is limited to 64 levels, with a 100,000-node/event budget. YAML alias
  expansion is also bounded to 4 Mi characters of extracted keys and values.
- The file timeout is shared across all records. Parser limits bound extraction;
  timeout checks happen between extraction/matching operations.

Existing Git-blob size and encoding limits still apply. JSON with comments,
newline-delimited JSON, XML fragments, and embedded documents in source-code
strings are outside this adapter's scope. Choose a reviewed exclusion with a
reason for unsupported files you intentionally keep in the repository.

The existing **Test scanner** workflow discovers `tests/test_structured.py`.
Its cases cover the employee fixtures, record boundaries, generic fields,
true/false flags, original lines, PR comparisons, redacted errors and reports,
and resource limits.
