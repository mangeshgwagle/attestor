#!/usr/bin/env python3
"""Changed-lines CI and GitHub annotation integration for Attestor 3.0."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from dataclasses import asdict, is_dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

import release_hardening
import scanengine


SCHEMA = "attestor-ci-gate/3.0"
BASELINE_SCHEMA = "attestor-ci-baseline/3.0"
MAX_DIFF_BYTES = 4 * 1024 * 1024
MAX_ANNOTATIONS = 500
SEVERITY = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
REF_RX = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@{}~^+\-]{0,199}$")
HUNK_RX = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


class CiError(ValueError):
    pass


def _safe_relative(path: str) -> str | None:
    path = path.replace("\\", "/")
    if path.startswith(("a/", "b/")):
        path = path[2:]
    value = PurePosixPath(path)
    if value.is_absolute() or not value.parts or any(part in {"", ".", ".."} for part in value.parts):
        return None
    return value.as_posix()


def parse_unified_diff(text: str) -> dict[str, list[tuple[int, int]]]:
    if not isinstance(text, str) or len(text.encode("utf-8")) > MAX_DIFF_BYTES:
        raise CiError("diff is invalid or exceeds 4 MiB")
    changed: dict[str, list[tuple[int, int]]] = {}
    current: str | None = None
    for line in text.splitlines():
        if line.startswith("+++ "):
            name = line[4:].split("\t", 1)[0]
            current = None if name == "/dev/null" else _safe_relative(name)
            if current:
                changed.setdefault(current, [])
            continue
        match = HUNK_RX.match(line)
        if match and current:
            start = int(match.group(1)); count = int(match.group(2) or "1")
            if count:
                changed[current].append((start, start + count - 1))
    return {path: ranges for path, ranges in changed.items() if ranges}


def git_diff(root: str | os.PathLike[str], base: str, head: str = "HEAD") -> str:
    if not REF_RX.fullmatch(base or "") or not REF_RX.fullmatch(head or ""):
        raise CiError("git revision is invalid")
    repository = Path(root).expanduser().resolve()
    git = shutil.which("git")
    if not git:
        raise CiError("git executable is unavailable")
    command = [git, "-C", str(repository), "diff", "--unified=0", "--no-ext-diff",
               "%s...%s" % (base, head), "--"]
    try:
        completed = subprocess.run(
            command, capture_output=True, timeout=30, check=False,
            env=release_hardening.sanitized_environment())
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CiError("git diff failed safely: %s" % type(exc).__name__) from exc
    if completed.returncode:
        raise CiError("git diff returned exit %d" % completed.returncode)
    if len(completed.stdout) > MAX_DIFF_BYTES:
        raise CiError("git diff exceeds 4 MiB")
    return completed.stdout.decode("utf-8", "replace")


def _row(value: Any) -> dict[str, Any]:
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "__dict__"):
        return vars(value)
    return value if isinstance(value, dict) else {}


def changed_findings(findings: Iterable[Any],
                     changed: dict[str, list[tuple[int, int]]]) -> list[dict[str, Any]]:
    output = []
    for finding in findings:
        row = _row(finding)
        path = _safe_relative(str(row.get("path", "")))
        try:
            line = max(1, int(row.get("line", 1)))
        except (TypeError, ValueError):
            continue
        if path and any(start <= line <= end for start, end in changed.get(path, [])):
            output.append(dict(row))
    return output


def finding_fingerprint(finding: Any) -> str:
    row = _row(finding)
    existing = row.get("fingerprint")
    if isinstance(existing, str) and re.fullmatch(r"[0-9a-f]{64}", existing):
        return existing
    payload = "%s\0%s\0%s\0%s" % (
        row.get("rule", "finding"), _safe_relative(str(row.get("path", ""))) or "unknown",
        row.get("line", 1), row.get("message", ""))
    return hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest()


def baseline(findings: Iterable[Any]) -> dict[str, Any]:
    fingerprints = sorted(set(finding_fingerprint(item) for item in findings))
    return {"schema": BASELINE_SCHEMA, "fingerprints": fingerprints,
            "count": len(fingerprints), "secret_material_stored": False}


def load_baseline(path: str | os.PathLike[str]) -> set[str]:
    item = Path(path)
    if not item.is_file() or item.stat().st_size > 4 * 1024 * 1024:
        raise CiError("baseline is missing or too large")
    try:
        value = json.loads(item.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CiError("baseline cannot be parsed") from exc
    fingerprints = value.get("fingerprints")
    if value.get("schema") != BASELINE_SCHEMA or not isinstance(fingerprints, list) or any(
            not isinstance(item, str) or not re.fullmatch(r"[0-9a-f]{64}", item)
            for item in fingerprints):
        raise CiError("baseline schema is invalid")
    return set(fingerprints)


def evaluate(findings: Iterable[Any], *, baseline_fingerprints: set[str] | None = None,
             fail_on: str = "HIGH") -> dict[str, Any]:
    if fail_on != "NEVER" and fail_on not in SEVERITY:
        raise CiError("fail_on severity is invalid")
    known = baseline_fingerprints or set()
    rows = [dict(_row(item)) for item in findings]
    new = [item for item in rows if finding_fingerprint(item) not in known]
    threshold = SEVERITY.get(fail_on, 99)
    blocking = [item for item in new if SEVERITY.get(str(item.get("severity", "INFO")).upper(), 1) >= threshold]
    counts = {severity: sum(str(item.get("severity", "INFO")).upper() == severity for item in new)
              for severity in SEVERITY}
    return {"schema": SCHEMA, "status": "blocked" if blocking else "passed",
            "findings": len(rows), "new_findings": len(new), "blocking": len(blocking),
            "fail_on": fail_on, "severity": counts, "new": new, "blocking_findings": blocking}


def _escape_message(value: Any) -> str:
    return str(value).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: Any) -> str:
    return _escape_message(value).replace(":", "%3A").replace(",", "%2C")


def github_annotations(findings: Iterable[Any]) -> list[str]:
    output = []
    for item in findings:
        if len(output) >= MAX_ANNOTATIONS:
            break
        row = _row(item); path = _safe_relative(str(row.get("path", "")))
        if not path:
            continue
        try:
            line = max(1, int(row.get("line", 1)))
        except (TypeError, ValueError):
            line = 1
        severity = str(row.get("severity", "INFO")).upper()
        command = "error" if severity in {"CRITICAL", "HIGH"} else "warning" if severity == "MEDIUM" else "notice"
        title = "Attestor %s: %s" % (severity, row.get("rule", "finding"))
        message = "%s Fix: %s" % (row.get("message", "Review this evidence."),
                                   row.get("fix", "Apply a verified remediation."))
        output.append("::%s file=%s,line=%d,title=%s::%s" % (
            command, _escape_property(path), line, _escape_property(title), _escape_message(message)))
    return output


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--diff-file")
    parser.add_argument("--diff-from")
    parser.add_argument("--diff-to", default="HEAD")
    parser.add_argument("--baseline")
    parser.add_argument("--write-baseline")
    parser.add_argument("--fail-on", choices=tuple(SEVERITY) + ("NEVER",), default="HIGH")
    parser.add_argument("--format", choices=("github", "json", "sarif"), default="github")
    args = parser.parse_args(argv)
    if args.diff_file and args.diff_from:
        parser.error("choose --diff-file or --diff-from")
    result = scanengine.scan([args.root], tools=False, use_cache=False, deep=True)
    findings: list[Any] = list(result.issues)
    if args.diff_file:
        text = Path(args.diff_file).read_text(encoding="utf-8")
        findings = changed_findings(findings, parse_unified_diff(text))
    elif args.diff_from:
        findings = changed_findings(findings, parse_unified_diff(
            git_diff(args.root, args.diff_from, args.diff_to)))
    known = load_baseline(args.baseline) if args.baseline else set()
    report = evaluate(findings, baseline_fingerprints=known, fail_on=args.fail_on)
    if args.write_baseline:
        Path(args.write_baseline).write_text(
            json.dumps(baseline(findings), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    elif args.format == "sarif":
        filtered = [item for item in result.issues if finding_fingerprint(item) in {
            finding_fingerprint(row) for row in findings}]
        copy = scanengine.WorkspaceResult(
            result.version, result.roots, result.status, result.files_discovered,
            result.files_scanned, result.cache_hits, filtered, result.files,
            result.errors, result.skipped, result.elapsed_ms)
        print(json.dumps(scanengine.to_sarif(copy), indent=2))
    else:
        for line in github_annotations(report["new"]):
            print(line)
        print("Attestor CI: %s; new=%d; blocking=%d" % (
            report["status"], report["new_findings"], report["blocking"]))
    return 2 if result.errors else (1 if report["status"] == "blocked" else 0)


if __name__ == "__main__":
    raise SystemExit(main())
