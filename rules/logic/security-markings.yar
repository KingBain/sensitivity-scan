// Optional text indicators, including two Unclassified labels.

rule marking_nato_restricted_en : security_marking
{
    meta:
        title = "NATO Restricted marking"
        severity = "MEDIUM"
        evidence_model = "marking"
        assessment = "review_required"
    strings:
        $marking = /\bNATO[ \t]+RESTRICTED\b/ nocase
    condition:
        $marking
}

rule marking_nato_restricted_fr : security_marking
{
    meta:
        title = "OTAN Diffusion restreinte marking"
        severity = "MEDIUM"
        evidence_model = "marking"
        assessment = "review_required"
    strings:
        $marking = /\bOTAN[ \t]+DIFFUSION[ \t]+RESTREINTE\b/ nocase
    condition:
        $marking
}

rule marking_nato_unclassified_en : security_marking
{
    meta:
        title = "NATO Unclassified marking"
        severity = "LOW"
        evidence_model = "marking"
        assessment = "review_required"
    strings:
        $marking = /\bNATO[ \t]+UNCLASSIFIED\b/ nocase
    condition:
        $marking
}

rule marking_nato_unclassified_fr : security_marking
{
    meta:
        title = "OTAN Non-classifié marking"
        severity = "LOW"
        evidence_model = "marking"
        assessment = "review_required"
    strings:
        $marking = /\bOTAN[ \t]+NON-CLASSIFI(\xC3\x89|\xC3\xA9)/ nocase
    condition:
        $marking
}

rule marking_uk_official_en : security_marking
{
    meta:
        title = "UK Official marking"
        severity = "MEDIUM"
        evidence_model = "marking"
        assessment = "review_required"
    strings:
        $marking = /\bUK[ \t:]+OFFICIAL\b/ nocase
    condition:
        $marking
}

rule marking_uk_official_fr : security_marking
{
    meta:
        title = "RU Officiel marking"
        severity = "MEDIUM"
        evidence_model = "marking"
        assessment = "review_required"
    strings:
        $marking = /\bRU[ \t:]+OFFICIEL\b/ nocase
    condition:
        $marking
}
