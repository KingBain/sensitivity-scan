// Teaching example: labelled 16-digit candidates, not validated payment cards.
// This file is NOT part of the default profiles. See docs/custom-rules.md.
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
