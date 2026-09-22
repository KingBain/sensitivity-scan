# Common field syntax

The scanner recognizes field patterns in **every eligible text file**. There is
no extension list, language selection, or requirement for a valid standalone
document. A field written in source code receives the same handling as one in a
configuration file or a text document.

This extraction was added after `v1.0.0`; use a release containing it or a reviewed
commit SHA. Existing Git-blob size, encoding and exclusion settings still apply.

## Recognized patterns

| Pattern | Example |
|---|---|
| Key and colon | `sin: "000000000"` |
| Assignment | `sin = "000000000"` |
| Hash entry | `'sin' => '000000000'` |
| Object literal | `{name: "Jane Example", sin: "000000000"}` |
| Named arguments | `person(name="Jane Example", sin="000000000")` |
| Property access | `person.name = "Jane Example"; person.sin = "000000000"` |
| Literal subscript | `person["sin"] = "000000000"` |
| XML leaf | `<sin>000000000</sin>` |
| XML attribute | `<person name="Jane Example" sin="000000000"/>` |
| Indented/list fields | `- name: Jane Example` followed by an indented SIN field |

Keys can be quoted or unquoted. Common declaration prefixes such as `const`,
`let`, `var`, and `string` are recognized on assignments. String escapes and
ordinary XML character/entity escapes are decoded without executing code or
loading external entities. Source comments and documentation can contain
sensitive text too; they are scanned, rather than evaluated as program behavior.

Labels remain a rule concern. The extractor passes any field that uses these
patterns, including custom fields, identifiers, names, cards and marking flags.
It does not contain a detector-name allowlist.

## Records and source locations

Braces, brackets, parentheses, XML containers, indented blocks and list items
provide visible boundaries. Each record is scanned separately. Property
assignments sharing a path, such as `person.name` and `person.sin`, share a record;
`alice.name` and `bob.sin` do not. Nested paths and containers are separate and
do not inherit their parent's name fields. Horizontal/document separators
(`---` and `...`) start a new text record.

Text without a visible boundary retains file-wide context. These are lexical
boundaries, not a language's complete object, variable-scope or data-flow model.
For example, the scanner does not resolve a variable to a value defined elsewhere.

Extracted fields are presented to YARA as quoted key/value pairs:

```text
"name": "Jane Example"
"sin": "000000000"
```

Ordinary non-field text remains available for text rules. Identifier/name rules
still require actual values and a full name or both first and last names. A
first name with a PRI alone remains insufficient.

Reports retain the original field value's start line and omit matched values.
Changes mode compares normalized evidence between revisions. Repeated records
remain separate occurrences. Changing a filename's extension does not change
matching behavior or turn an existing occurrence into a new one.

## Boolean classification flags

Use `profile: code-with-markings` for the GC flags below and the existing NATO/UK
markings. The default `code` profile remains focused on identifiers with names.

| English flag | French flag | Severity |
|---|---|---|
| Protected | Protégé | LOW |
| Protected A | Protégé A | MEDIUM |
| Protected B | Protégé B | HIGH |
| Protected C | Protégé C | CRITICAL |
| Classified | Classifié | LOW |
| Confidential | Confidentiel | MEDIUM |
| Secret | Secret | HIGH |
| Top Secret | Très secret | CRITICAL |
| Unclassified | Non classifié | LOW |
| Protected when Completed | Protégé lorsque rempli | LOW |

The 19 rules cover all ten terms in both languages; `Secret` shares one rule.
They require `true`, ignoring case and accepting spaces, underscores or hyphens
in multiword keys. For example, `PROTECTED_B = true` and `"PROTECTED B": true`
both produce a HIGH finding. These report a declared classification for review;
scanner severities are project priorities, not an additional government scale.

Explicit `false`, null (`null`, `None`, `nil`, `~`) and empty field values supply
no positive evidence. This also prevents disabled NATO/UK flags from matching
on their key alone. True flags and markings written as text or field values
remain detectable. GC flags reject `0` and `trueish` as well.

Values are normalized as text, so boolean `true` and string `"true"` behave alike.
A boolean cannot replace an actual identifier or name in a combined PII rule.
These boolean conventions apply to custom rules too.

The optional profile has 52 rules: 27 core rules, six NATO/UK marking rules, and
19 GC flag rules. See the [flag teaching rule](../examples/structured/protected-a.yar)
and [custom-rule guide](custom-rules.md) for examples.

## Scope and limits

This is a text scanner, not a compiler or a universal parser. It does not
evaluate expressions, expand aliases/merges, follow references, infer types, or
guarantee every language's syntax. Template interpolation, computed keys,
encoded payloads and complex multiline literals may be missed. Newlines within
extracted values are escaped; they do not become extra fields.

Complete XML leaf tags and attributes can be recognized inside a larger snippet;
the whole file need not be valid XML. Likewise, an incomplete object literal
can still contain recognizable fields. There is no syntax-validation failure
just because an input resembles malformed JSON or XML. Resource-limit failures
still fail the scan with exit `2` and a value-free error.

Extraction is bounded to 64 nesting levels, 100,000 token steps and 4 Mi characters
of extracted field text. The per-file timeout is shared across records, with
checks between extraction and matching operations. Values are never executed.

GitHub Actions discovers `tests/test_structured.py`, covering equivalent syntax
across arbitrary filenames, record separation, original lines, boolean flags,
PII combinations, PR comparisons, redaction and resource limits.
