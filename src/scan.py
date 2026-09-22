#!/usr/bin/env python3
"""Sensitivity Smell: scan committed Git blobs with YARA; emit value-free reports."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from dataclasses import dataclass
import fnmatch
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
from urllib.parse import quote

import yara

ROOT = Path(__file__).resolve().parents[1]
# -I omits the script directory. Add only the action's own trusted source path,
# never the working directory of the repository being scanned.
sys.path.insert(0, str(ROOT / "src"))
import field_syntax

VERSION = (ROOT / "version.txt").read_text(encoding="utf-8").strip()
SEVERITIES = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class ScanError(Exception):
    """Messages must describe operations, never contents of scanned files."""


@dataclass(frozen=True)
class Blob:
    mode: str
    oid: str
    size: int


def git(repo, *args):
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), *args], capture_output=True, timeout=120,
            env={**os.environ, "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ScanError("Git could not complete the requested operation.") from exc
    if result.returncode:
        raise ScanError("Git operation failed; check repository, commit references and fetch-depth: 0.")
    return result.stdout


def commit(repo, ref):
    # --end-of-options stops user-supplied refs becoming command options.
    return git(repo, "rev-parse", "--verify", "--end-of-options", ref + "^{commit}").decode().strip()


def tree(repo, rev):
    entries = {}
    for row in git(repo, "ls-tree", "-rz", "--long", rev).split(b"\0"):
        if not row:
            continue
        header, name = row.split(b"\t", 1)
        mode, kind, oid, size = header.split()
        try:
            path = name.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ScanError("A tracked filename is not UTF-8; rename it before scanning.") from exc
        entries[path] = Blob(mode.decode(), oid.decode(), int(size) if kind == b"blob" else 0)
    return entries


def compile_profile(profile):
    return yara.compile(filepath=str(ROOT / "rules" / "profiles" / (profile + ".yar")))


def evidence(data, instance):
    start = instance.offset
    end = start + instance.matched_length
    while start < end and data[start] in b"\r\n{,; \t":
        start += 1
    return {
        "offset": start,
        "line": data.count(b"\n", 0, start) + 1,
        # Used only in memory for comparison. Never serialized to output.
        "value": data[start:end].strip(),
    }


def detect(rules, data, timeout=10):
    warnings = []
    matches = rules.match(data=data, timeout=timeout,
                          warnings_callback=lambda kind, info: warnings.append(kind))
    if warnings:
        raise ScanError("YARA reached a matching limit; scan coverage is incomplete.")
    results = []
    for match in matches:
        roles = defaultdict(list)
        for string in match.strings:
            roles[string.identifier].extend(evidence(data, i) for i in string.instances)
        model = match.meta.get("evidence_model")
        if model == "identifier_and_name":
            # Name regexes accept words, but boolean/null tokens are not names.
            # Apply this to evidence roles, independent of each rule's aliases.
            flag_value = re.compile(rb'''[:=][ \t]*["']?(true|false|null|none|nil)["']?[ \t]*$''', re.IGNORECASE)
            for role in ("$full_name", "$first_name", "$last_name"):
                roles[role] = [item for item in roles[role] if not flag_value.search(item["value"])]
            if not roles["$full_name"] and not (roles["$first_name"] and roles["$last_name"]):
                continue
            primary = roles["$identifier"]
        elif model == "marking":
            primary = roles["$marking"]
        else:
            raise ScanError("Bundled rule has no supported evidence model.")
        # YARA alternatives may produce identical spans: count each span once.
        primary = list({(p["offset"], p["value"]): p for p in primary}.values())
        for ordinal, item in enumerate(sorted(primary, key=lambda p: p["offset"]), 1):
            support = []
            if model == "identifier_and_name":
                def nearest(items):
                    return min(items, key=lambda p: (abs(p["offset"] - item["offset"]), p["offset"]))
                choices = []
                if roles["$full_name"]:
                    choices.append([nearest(roles["$full_name"])])
                if roles["$first_name"] and roles["$last_name"]:
                    choices.append([nearest(roles["$first_name"]), nearest(roles["$last_name"])])
                support = min(choices, key=lambda group: sum(abs(p["offset"]-item["offset"]) for p in group))
            results.append({
                "rule": match.rule, "title": match.meta["title"],
                "severity": match.meta["severity"],
                "suggested_classification": match.meta.get("suggested_classification"),
                "line": item["line"], "ordinal": ordinal,
                "evidence_lines": sorted({p["line"] for p in support}),
                "_signature": (match.rule, item["value"], tuple(p["value"] for p in support)),
            })
    return results


def detect_file(rules, data, path, timeout=10):
    """Use the same rules on each record, restoring original source locations."""
    deadline = time.monotonic() + timeout
    try:
        records = field_syntax.extract(data)
        results = []
        for record in records:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ScanError('Structured scan exceeded the per-file timeout.')
            normalised, source_lines = field_syntax.normalise(record)
            if not source_lines:
                continue
            for finding in detect(rules, normalised, max(1, math.ceil(remaining))):
                finding['line'] = source_lines[finding['line'] - 1]
                finding['evidence_lines'] = sorted({source_lines[n - 1] for n in finding['evidence_lines']})
                results.append(finding)
            if len(results) > 10000:
                raise ScanError('More than 10,000 findings in a structured file.')
        if time.monotonic() > deadline:
            raise ScanError('Structured scan exceeded the per-file timeout.')
        # detect() counts within one record. SARIF needs unique per-file ordinals.
        counts = Counter()
        for finding in sorted(results, key=lambda f: (f['line'], f['rule'])):
            counts[finding['rule']] += 1
            finding['ordinal'] = counts[finding['rule']]
        return results
    except field_syntax.StructureError as exc:
        raise ScanError(f'Structured scan failed for {path}: {exc}') from exc


def introduced(head, base):
    remaining = Counter(f["_signature"] for f in base)
    new = []
    for finding in head:
        signature = finding["_signature"]
        if remaining[signature]:
            remaining[signature] -= 1
        else:
            new.append(finding)
    return new


def exclusion_list(raw):
    try:
        entries = json.loads(raw)
        if not isinstance(entries, list):
            raise ValueError
        for entry in entries:
            if (not isinstance(entry, dict) or set(entry) != {"glob", "reason"}
                or not all(isinstance(entry[k], str) and entry[k].strip() for k in entry)):
                raise ValueError
        return entries
    except (ValueError, TypeError) as exc:
        raise ScanError('Exclusions must be JSON objects with nonempty "glob" and "reason" strings.') from exc


def load_blob(repo, path, blob, options, exclusions, coverage, side):
    reason = None
    if blob.mode not in ("100644", "100755"):
        reason = "symlink_or_submodule"
    elif blob.size > options.max_file_bytes:
        reason = "size_limit"
    for entry in exclusions:
        if fnmatch.fnmatchcase(path, entry["glob"]):
            reason = "excluded: " + entry["reason"]
            break
    data = None
    if reason is None:
        data = git(repo, "cat-file", "blob", blob.oid)
        if len(data) != blob.size:
            raise ScanError("Git blob size changed unexpectedly.")
        if data.startswith(b"version https://git-lfs.github.com/spec/v1\n"):
            reason = "git_lfs_pointer"
        elif b"\0" in data:
            reason = "binary_or_utf16"
        else:
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                reason = "non_utf8"
    if reason is not None:
        coverage["skipped"].append({"path": path, "side": side, "reason": reason})
        return None
    coverage["scanned_" + side] += 1
    return data


def select_revisions(options):
    mode = options.mode
    base, head = options.base, options.head
    if mode == "auto":
        event = os.environ.get("GITHUB_EVENT_NAME", "")
        if event == "pull_request":
            event_path = os.environ.get("GITHUB_EVENT_PATH")
            if not event_path:
                raise ScanError("Pull request event payload is missing.")
            try:
                payload = json.loads(Path(event_path).read_text())
                base = base or payload["pull_request"]["base"]["sha"]
                head = head or payload["pull_request"]["head"]["sha"]
            except (OSError, ValueError, KeyError) as exc:
                raise ScanError("Pull request event payload has no base/head commits.") from exc
            mode = "changes"
        elif event == "pull_request_target":
            raise ScanError("Use pull_request, not pull_request_target, for this action.")
        else:
            mode = "full"
    head = commit(options.repo, head or "HEAD")
    if mode == "changes":
        if not base:
            raise ScanError("Changes mode requires --base or a pull_request event.")
        base = commit(options.repo, base)
        base = git(options.repo, "merge-base", base, head).decode().strip()
    else:
        base = None
    return mode, base, head


def scan(options):
    exclusions = exclusion_list(options.exclusions)
    rules = compile_profile(options.profile)
    mode, base, head = select_revisions(options)
    head_tree = tree(options.repo, head)
    base_tree = tree(options.repo, base) if base else {}
    coverage = {"tracked_head": len(head_tree), "scanned_head": 0, "scanned_base": 0,
                "unchanged": 0, "deleted": len(base_tree.keys() - head_tree.keys()), "skipped": []}
    # Exact renames preserve the baseline. Edited renames are conservatively new.
    deleted_by_oid = defaultdict(list)
    for path in base_tree.keys() - head_tree.keys():
        deleted_by_oid[base_tree[path].oid].append(path)
    findings = []
    for path, blob in sorted(head_tree.items()):
        old_path = path if path in base_tree else None
        if old_path is None and len(deleted_by_oid[blob.oid]) == 1:
            old_path = deleted_by_oid[blob.oid][0]
        old = base_tree.get(old_path)
        if mode == "changes" and old == blob:
            coverage["unchanged"] += 1
            continue
        data = load_blob(options.repo, path, blob, options, exclusions, coverage, "head")
        if data is None:
            continue
        current = detect_file(rules, data, path, options.timeout)
        previous = []
        if mode == "changes" and old:
            old_data = load_blob(options.repo, old_path, old, options, exclusions, coverage, "base")
            if old_data is not None:
                previous = detect_file(rules, old_data, old_path, options.timeout)
        for finding in introduced(current, previous) if mode == "changes" else current:
            finding.pop("_signature")
            finding["path"] = path
            findings.append(finding)
        if len(findings) > 10000:
            raise ScanError("More than 10,000 findings; narrow the scan with reviewed exclusions.")
    return {"tool": "sensitivity-smell", "version": VERSION, "mode": mode,
            "profile": options.profile, "head": head, "base": base,
            "findings": findings, "coverage": coverage, "errors": []}


def sarif(report):
    rules = {}
    for f in report["findings"]:
        rules[f["rule"]] = {"id": f["rule"], "shortDescription": {"text": f["title"]},
                            "properties": {"tags": ["sensitive-information", "review-required"]}}
    results = []
    def location(path, line):
        return {"physicalLocation": {"artifactLocation": {"uri": quote(path, safe="/")},
                                     "region": {"startLine": line}}}
    for f in report["findings"]:
        message = f["title"] + ". Review required; matched values are omitted."
        if f["suggested_classification"]:
            message += " Candidate: " + f["suggested_classification"] + "."
        # Fingerprints contain only path/rule/occurrence order, never content hashes.
        fingerprint = hashlib.sha256((f["path"] + "\0" + f["rule"] + "\0" + str(f["ordinal"])).encode()).hexdigest()
        result = {"ruleId": f["rule"], "level": "error" if f["severity"] in ("HIGH", "CRITICAL") else "warning" if f["severity"] == "MEDIUM" else "note",
                  "message": {"text": message}, "locations": [location(f["path"], f["line"])],
                  "partialFingerprints": {"rulePathOccurrence/v1": fingerprint},
                  "properties": {"severity": f["severity"], "assessment": "review_required"}}
        if f["evidence_lines"]:
            result["relatedLocations"] = [{"id": n, **location(f["path"], line), "message": {"text": "Supporting name field (value omitted)."}}
                                          for n, line in enumerate(f["evidence_lines"], 1)]
        results.append(result)
    errors = report["errors"]
    return {"version": "2.1.0", "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/schemas/sarif-schema-2.1.0.json", "runs": [{
        "tool": {"driver": {"name": "sensitivity-smell", "version": VERSION, "rules": list(rules.values())}},
        "automationDetails": {"id": "sensitivity-smell/" + report.get("profile", "code") + "/"},
        "invocations": [{"executionSuccessful": not errors, "toolExecutionNotifications": [
            {"level": "error", "message": {"text": error}} for error in errors]}],
        "results": results}]}


def write_reports(report, directory):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "findings.json").write_text(json.dumps(report, indent=2) + "\n")
    (directory / "findings.sarif").write_text(json.dumps(sarif(report), indent=2) + "\n")
    counts = Counter(f["severity"] for f in report["findings"])
    coverage = report.get("coverage", {})
    lines = ["## Sensitivity Smell", "", f"Findings: **{len(report['findings'])}**. Mode: **{report.get('mode', 'unknown')}**.", "",
             "Matched values are omitted. Classification labels are candidates for review.", ""]
    lines.extend(f"- {key}: {counts[key]}" for key in SEVERITIES if counts[key])
    lines += ["", f"Files scanned: {coverage.get('scanned_head', 0)}; baseline files scanned: {coverage.get('scanned_base', 0)}; skipped: {len(coverage.get('skipped', []))}.",
              "See findings.json for skip reasons and coverage. Unchanged files are not rescanned in changes mode."]
    if report["errors"]:
        lines += ["", "**Scan failed; this is not a clean result.**"]
    summary = "\n".join(lines) + "\n"
    (directory / "summary.md").write_text(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as handle:
            handle.write(summary)
    if os.environ.get("GITHUB_OUTPUT"):
        outputs = {"findings-count": len(report["findings"]), "sarif": str(directory / "findings.sarif"),
                   "json": str(directory / "findings.json"), "report-directory": str(directory)}
        with open(os.environ["GITHUB_OUTPUT"], "a") as handle:
            for key, value in outputs.items():
                delimiter = "VALUE_" + uuid.uuid4().hex
                handle.write(f"{key}<<{delimiter}\n{value}\n{delimiter}\n")


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--profile", choices=["code", "code-with-markings"], default="code")
    parser.add_argument("--mode", choices=["auto", "full", "changes"], default="auto")
    parser.add_argument("--head", default="")
    parser.add_argument("--base", default="")
    parser.add_argument("--output", type=Path, default=Path("scan-results"))
    parser.add_argument("--fail-on", choices=["NONE", *SEVERITIES], default="NONE")
    parser.add_argument("--fail-on-skips", action="store_true")
    parser.add_argument("--max-file-bytes", type=int, default=2 * 1024 * 1024)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--exclusions", default="[]", help='JSON array of {"glob": "...", "reason": "..."}')
    options = parser.parse_args(argv)
    if options.max_file_bytes < 1 or options.timeout < 1:
        parser.error("Size and timeout must be positive.")
    options.output = options.output.resolve()
    return options


def main(argv=None):
    options = arguments(argv)
    try:
        report = scan(options)
    except ScanError as exc:
        report = {"profile": options.profile, "findings": [], "errors": [str(exc)]}
    except Exception as exc:
        # Exceptions from native libraries can contain input text. Report their type only.
        report = {"profile": options.profile, "findings": [], "errors": ["Scan failed (" + type(exc).__name__ + "). Check rules, Git history and resource limits."]}
    write_reports(report, options.output)
    print(f"Sensitivity Smell: {len(report['findings'])} findings; {len(report['errors'])} errors.")
    if report["errors"]:
        print(report["errors"][0], file=sys.stderr)
        return 2
    if options.fail_on_skips and report["coverage"]["skipped"]:
        print("Scan coverage includes skipped files; fail-on-skips is enabled.", file=sys.stderr)
        return 2
    if options.fail_on != "NONE" and any(SEVERITIES[f["severity"]] >= SEVERITIES[options.fail_on] for f in report["findings"]):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
