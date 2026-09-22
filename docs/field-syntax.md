# Matching coverage and field syntax

The scanner looks for known text and field patterns to give reviewers a reason
to inspect a location. It applies the same extraction to every eligible text
file, with no extension list or language selection. A recognized field in source
code receives the same handling as one in configuration or documentation.
This does not imply complete support for those languages or data formats.

This extraction is available in `v1.1.0` and later. Existing Git-blob size,
encoding and exclusion settings still apply.

## Bundled patterns

The `code` profile contains 21 private helper rules and six public combination
rules: English/French variants of SIN/name, PRI/name and DOB/name. A public rule
requires a labelled numeric value plus a labelled full name of at least two
words, or both first and last names, within the same extracted record.

| Combination | Severity | Candidate classification |
|---|---|---|
| SIN / NAS + name | HIGH | Protected B |
| PRI / CIDP + name | MEDIUM | Protected A |
| DOB / DDN + name | MEDIUM | Protected A |

These are format matches. There is no SIN checksum validation or verification of
the person's identity. DOB patterns accept numeric dates in 1800–2099 without
checking calendar validity. The name patterns cannot recognize every name.
Candidate labels need assessment against the actual content and context;
severity represents review priority, not certainty or an official equivalence.

For example, this synthetic record produces PRI/name and DOB/name findings:

```xml
<employee>
  <firstname>John</firstname>
  <lastname>Example</lastname>
  <pri>12345678</pri>
  <dob>1990-01-01</dob>
</employee>
```

Removing `lastname` leaves only a first name, which is insufficient. Removing
the labels or splitting supporting fields across separate records can also
remove findings even when a person could still recognize sensitive information.
The scanner makes a limited matching decision, not a safety decision.

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
sensitive text too; their text is also scanned without executing program behavior.

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
There is no maximum character-distance requirement between name and identifier
matches in a record. Unrelated fields in flat text can therefore combine, while
related fields separated into different records can be missed.

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

The text markings are NATO Restricted / OTAN Diffusion restreinte (MEDIUM),
NATO Unclassified / OTAN Non-classifié (LOW), and UK Official / RU Officiel
(MEDIUM). They can match quoted examples and documentation. GC rules below require
an enabled field; they do not detect every standalone GC marking in prose.

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
An enabled `Unclassified` flag is a LOW finding because a declaration was found,
not because the scanner verified that the content is unclassified. A flag in
sample code can be a false positive for an actual sensitive-data concern.

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

The bundled profiles do not cover every category of PII, credentials, financial
or health data. Credit-card detection is a separate teaching rule, disabled by
default. Form-title rules are not included. There is no PDF/Office text extraction,
OCR, archive expansion, or general decryption/decoding stage.

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

A successfully scanned file with no matches can still contain sensitive data.
Review [coverage and skip reasons](implementation.md#results-and-coverage) with the
findings; neither file counts nor passing tests measure real-world recall.

GitHub Actions discovers `tests/test_structured.py`, covering equivalent syntax
across arbitrary filenames, record separation, original lines, boolean flags,
PII combinations, PR comparisons, redaction and resource limits.
