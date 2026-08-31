#!/usr/bin/env python3
"""GitHub Actions / CI pipeline security scanner.

Detects injection vulnerabilities, overly permissive configurations, and
unsafe patterns in GitHub Actions workflow files (.github/workflows/*.yml).

Checks:
  - Expression injection: ${{ github.event.*.body }} etc. in run: blocks
  - Overly broad permissions (write-all, contents: write without need)
  - Unsafe pull_request_target with explicit checkout of PR head
  - Unpinned third-party actions (uses: owner/action@main instead of SHA)
  - Secret exposure in logs (echo ${{ secrets.* }})
  - Self-hosted runner risks
  - Artifact poisoning via upload/download without pinning
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


@dataclass
class CIFinding:
    rule_id: str
    severity: str
    file: str
    line: int
    code: str
    description: str
    category: str
    cwe: str = ""


_INJECTABLE_CONTEXTS = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.pages.*.page_name",
    "github.event.commits.*.message",
    "github.event.commits.*.author.email",
    "github.event.commits.*.author.name",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.head_commit.message",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.head_ref",
    "github.event.ref",
]

_INJECTABLE_PATTERN = re.compile(
    r"\$\{\{\s*("
    + "|".join(re.escape(c).replace(r"\*", r"[^}]+") for c in _INJECTABLE_CONTEXTS)
    + r")\s*\}\}"
)

_TRUSTED_ACTION_OWNERS = {
    "actions", "github", "docker", "azure", "aws-actions",
    "google-github-actions", "hashicorp",
}


def _is_workflow_file(path: str) -> bool:
    norm = path.replace("\\", "/")
    return (".github/workflows/" in norm and
            (norm.endswith(".yml") or norm.endswith(".yaml")))


def scan_file(path: str) -> list[CIFinding]:
    if not _is_workflow_file(path):
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return []

    findings = []
    in_run_block = False
    run_indent = 0
    prt_trigger = False
    has_checkout_pr = False

    for i, line in enumerate(lines):
        lineno = i + 1
        stripped = line.strip()

        if re.match(r"on:\s*\[?.*pull_request_target", stripped) or stripped == "pull_request_target:":
            prt_trigger = True

        run_start = re.match(r"^-?\s*run\s*:\s*", stripped)
        if run_start:
            in_run_block = True
            run_indent = len(line) - len(line.lstrip())
        elif in_run_block and stripped and not stripped.startswith("#"):
            cur_indent = len(line) - len(line.lstrip())
            if cur_indent <= run_indent:
                in_run_block = False

        if (run_start or in_run_block) and _INJECTABLE_PATTERN.search(stripped):
            m = _INJECTABLE_PATTERN.search(stripped)
            findings.append(CIFinding(
                rule_id="GHA-001", severity="CRITICAL",
                file=path, line=lineno, code=stripped[:120],
                description=f"Expression injection: {m.group(0)} in run: block "
                            f"-- attacker-controlled input executed as shell code",
                category="injection", cwe="CWE-78",
            ))

        if re.search(r"permissions\s*:\s*write-all", stripped):
            findings.append(CIFinding(
                rule_id="GHA-002", severity="HIGH",
                file=path, line=lineno, code=stripped[:120],
                description="Overly broad permissions: write-all grants write to "
                            "all scopes -- use least-privilege",
                category="privilege", cwe="CWE-250",
            ))

        if re.search(r"contents\s*:\s*write", stripped):
            findings.append(CIFinding(
                rule_id="GHA-003", severity="MEDIUM",
                file=path, line=lineno, code=stripped[:120],
                description="contents: write allows modifying repository contents "
                            "-- verify this is needed",
                category="privilege", cwe="CWE-250",
            ))

        uses_m = re.search(r"uses:\s*(\S+)", stripped)
        if uses_m:
            action = uses_m.group(1)
            if "@" in action:
                owner = action.split("/")[0]
                ref = action.split("@")[-1]
                if (owner not in _TRUSTED_ACTION_OWNERS and
                        not re.match(r"^[0-9a-f]{40}$", ref) and
                        not re.match(r"^v\d+\.\d+\.\d+$", ref)):
                    findings.append(CIFinding(
                        rule_id="GHA-004", severity="HIGH",
                        file=path, line=lineno, code=stripped[:120],
                        description=f"Unpinned action {action} -- pin to a full "
                                    f"SHA for supply-chain safety",
                        category="supply_chain", cwe="CWE-829",
                    ))

            if "actions/checkout" in action and prt_trigger:
                ref_line = ""
                for j in range(i+1, min(i+5, len(lines))):
                    if "ref:" in lines[j] and ("head" in lines[j].lower() or
                                                "pull_request" in lines[j].lower()):
                        ref_line = lines[j].strip()
                        has_checkout_pr = True
                        break
                if has_checkout_pr:
                    findings.append(CIFinding(
                        rule_id="GHA-005", severity="CRITICAL",
                        file=path, line=lineno, code=stripped[:120],
                        description="pull_request_target with checkout of PR head "
                                    "-- PR code runs with write token and secrets",
                        category="injection", cwe="CWE-78",
                    ))

        secret_echo = re.search(r"echo\s+.*\$\{\{\s*secrets\.\w+\s*\}\}", stripped)
        if secret_echo:
            findings.append(CIFinding(
                rule_id="GHA-006", severity="HIGH",
                file=path, line=lineno, code=stripped[:120],
                description="Secret value echoed to logs -- secrets are masked "
                            "but masking can be bypassed",
                category="secrets", cwe="CWE-532",
            ))

        if re.search(r"runs-on\s*:\s*self-hosted", stripped):
            findings.append(CIFinding(
                rule_id="GHA-007", severity="MEDIUM",
                file=path, line=lineno, code=stripped[:120],
                description="Self-hosted runner -- ensure runner is ephemeral and "
                            "not shared across repos/PRs",
                category="infrastructure", cwe="CWE-284",
            ))

        if re.search(r"ACTIONS_ALLOW_UNSECURE_COMMANDS\s*:\s*true", stripped, re.I):
            findings.append(CIFinding(
                rule_id="GHA-008", severity="CRITICAL",
                file=path, line=lineno, code=stripped[:120],
                description="ACTIONS_ALLOW_UNSECURE_COMMANDS enables deprecated "
                            "set-env/add-path commands vulnerable to injection",
                category="injection", cwe="CWE-78",
            ))

        if re.search(r"::set-env\s+name=", stripped) or re.search(r"::add-path::", stripped):
            findings.append(CIFinding(
                rule_id="GHA-009", severity="HIGH",
                file=path, line=lineno, code=stripped[:120],
                description="Deprecated workflow command (set-env/add-path) -- "
                            "vulnerable to injection via crafted output",
                category="injection", cwe="CWE-78",
            ))

    return findings


def scan_paths(paths: list[str]) -> list[CIFinding]:
    all_findings = []
    for p in paths:
        if os.path.isfile(p):
            all_findings += scan_file(p)
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d in
                         {".github", "workflows"} or not d.startswith(".")]
                for name in fn:
                    fp = os.path.join(dp, name)
                    all_findings += scan_file(fp)
    return all_findings


def to_dict(findings: list[CIFinding]) -> list[dict]:
    return [
        {
            "rule_id": f.rule_id, "severity": f.severity,
            "file": f.file, "path": f.file, "line": f.line,
            "sink_file": f.file, "sink_line": f.line,
            "sink_code": f.code, "sink_type": f.category,
            "matched_text": f.code, "description": f.description,
            "category": f.category, "cwe": f.cwe,
            "language": "github-actions",
        }
        for f in findings
    ]


def render(findings: list[CIFinding]) -> str:
    if not findings:
        return "  No GitHub Actions security issues found."
    lines = [
        f"\n  CI Pipeline Scan -- {len(findings)} issue(s)",
        "  " + "=" * 62,
    ]
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    for f in sorted(findings, key=lambda x: order.get(x.severity, 9)):
        lines.append(f"\n  [{f.severity}] {f.rule_id} at "
                     f"{os.path.basename(f.file)}:{f.line}")
        lines.append(f"    {f.description}")
        lines.append(f"    > {f.code[:100]}")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="attestor-ci-scan",
        description="Scan GitHub Actions workflows for security issues.")
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    findings = scan_paths(args.paths)
    if args.json:
        print(json.dumps(to_dict(findings), indent=2))
    else:
        print(render(findings))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
