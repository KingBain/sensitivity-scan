// Teaching rule: isolates one flag already provided by code-with-markings.
// The adapter presents all scalar values as strings, including boolean flags.
rule example_protected_a_flag : security_marking
{
    meta:
        title = "Protected A flag is enabled"
        severity = "MEDIUM"
        suggested_classification = "Protected A"
        assessment = "review_required"
        evidence_model = "marking"
    strings:
        $marking = /(^|[\r\n])[ \t]*"PROTECTED[ _-]+A"[ \t]*:[ \t]*"true"[ \t]*(\r?\n|$)/ nocase
    condition:
        $marking
}
