#!/usr/bin/env python3
"""Autofix with a verify loop — turn Attestor from a finder into a fixer.

Every scanner creates work; this one does it. For the rules that `confidence.py`
declares `safe_to_autofix`, we apply a deterministic, single-line transform, then
**re-scan to prove it worked**: the targeted finding must be gone and the total
finding count must not rise. Any fix that fails verification is reverted. That
find -> fix -> prove loop is what makes an autofix trustworthy enough to run.

Dry-run by default (shows a diff). `--apply` writes, but only verified fixes land.

    attestor fix src/                 # preview safe fixes (no writes)
    attestor fix src/ --apply         # apply + verify safe fixes
    attestor fix src/ --aggressive    # also propose semantic-changing fixes (preview)
"""
from __future__ import annotations

import difflib
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import detect
import confidence


@dataclass
class Edit:
    line: int          # 1-indexed
    rule: str
    before: str
    after: str
    verified: bool = False
    note: str = ""


@dataclass
class FileResult:
    path: str
    edits: list[Edit] = field(default_factory=list)
    applied: bool = False
    reverted: list[Edit] = field(default_factory=list)
    error: str = ""

    @property
    def verified_count(self) -> int:
        return sum(1 for e in self.edits if e.verified)


# --- Deterministic, single-line transforms. Each takes the flagged line text and
# --- returns the fixed line (or the same line if it cannot fix it confidently). ---

def _fix_eq_none(line: str) -> str:
    line = re.sub(r"==\s*None\b", "is None", line)
    line = re.sub(r"!=\s*None\b", "is not None", line)
    return line

def _fix_bare_except(line: str) -> str:
    return re.sub(r"except\s*:", "except Exception:", line)

def _fix_weak_hash(line: str) -> str:
    return re.sub(r"\b(md5|sha1)\s*\(", "sha256(", line)

def _fix_debug(line: str) -> str:
    return re.sub(r"\bdebug\s*=\s*True\b", "debug=False", line, flags=re.I)

def _fix_tls_verify(line: str) -> str:
    return re.sub(r"\bverify\s*=\s*False\b", "verify=True", line)

def _fix_yaml_load(line: str) -> str:
    if "Loader" in line or "safe_load" in line:
        return line
    return re.sub(r"yaml\.load\s*\(", "yaml.safe_load(", line)

def _fix_loose_eq(line: str) -> str:
    line = re.sub(r"(?<![=!<>])==(?!=)", "===", line)
    line = re.sub(r"(?<![=!<>])!=(?!=)", "!==", line)
    return line


# Rules safe to APPLY automatically (must match confidence.SAFE_AUTOFIX_RULES).
SAFE_FIXERS = {
    "py-eq-none": _fix_eq_none,
    "py-bare-except": _fix_bare_except,
    "weak-hash": _fix_weak_hash,
    "debug-enabled": _fix_debug,
    "tls-verify-disabled": _fix_tls_verify,
}

# Rules whose fix changes semantics — PREVIEW ONLY unless --aggressive.
SUGGESTED_FIXERS = {
    "py-yaml-load": _fix_yaml_load,
    "js-loose-equality": _fix_loose_eq,
}


def _read_lines(path: str) -> list[str] | None:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.readlines()
    except OSError:
        return None


def plan_fixes(path: str, aggressive: bool = False) -> FileResult:
    """Compute the edits for a file without writing anything."""
    result = FileResult(path=path)
    lines = _read_lines(path)
    if lines is None:
        result.error = "unreadable"
        return result

    fixers = dict(SAFE_FIXERS)
    if aggressive:
        fixers.update(SUGGESTED_FIXERS)

    try:
        findings = detect.scan_file(path)
    except Exception as exc:
        result.error = f"scan failed: {exc}"
        return result

    seen = set()
    for f in findings:
        rule = getattr(f, "rule", "")
        ln = getattr(f, "line", 0)
        if rule not in fixers or ln < 1 or ln > len(lines):
            continue
        key = (rule, ln)
        if key in seen:
            continue
        seen.add(key)
        before = lines[ln - 1]
        after = fixers[rule](before.rstrip("\n")) + ("\n" if before.endswith("\n") else "")
        if after != before:
            note = "" if rule in SAFE_FIXERS else "semantic-change (aggressive)"
            result.edits.append(Edit(line=ln, rule=rule, before=before.rstrip("\n"),
                                     after=after.rstrip("\n"), note=note))
    return result


def _count_by_rule_line(findings) -> set:
    return {(getattr(f, "rule", ""), getattr(f, "line", 0)) for f in findings}


def apply_and_verify(path: str, aggressive: bool = False) -> FileResult:
    """Apply edits, then re-scan. Keep only fixes that (a) removed their target
    finding and (b) introduced no new finding. Revert the rest."""
    result = plan_fixes(path, aggressive)
    if result.error or not result.edits:
        return result

    original = _read_lines(path)
    if original is None:
        result.error = "unreadable"
        return result

    try:
        before_findings = detect.scan_file(path)
    except Exception as exc:
        result.error = f"scan failed: {exc}"
        return result
    before_set = _count_by_rule_line(before_findings)
    before_total = len(before_findings)

    # Apply every planned edit (single-line, line count preserved).
    working = list(original)
    for e in result.edits:
        suffix = "\n" if working[e.line - 1].endswith("\n") else ""
        working[e.line - 1] = e.after + suffix

    with open(path, "w", encoding="utf-8", newline="") as f:
        f.writelines(working)

    # Re-scan the whole file once; verify each edit against the new state.
    try:
        after_findings = detect.scan_file(path)
    except Exception:
        after_findings = None

    if after_findings is None:
        # scanner broke on our output -> unsafe, revert everything.
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.writelines(original)
        result.reverted = list(result.edits)
        result.edits = []
        result.error = "reverted: re-scan failed after edit"
        return result

    after_set = _count_by_rule_line(after_findings)
    after_total = len(after_findings)
    new_findings = after_set - before_set  # anything that appeared = regression

    verified, reverted = [], []
    for e in result.edits:
        target_gone = (e.rule, e.line) not in after_set
        no_regression = not new_findings and after_total <= before_total
        if target_gone and no_regression:
            e.verified = True
            verified.append(e)
        else:
            e.note = ("target not removed" if not target_gone
                      else "introduced a new finding")
            reverted.append(e)

    if reverted:
        # Roll back ONLY if we cannot cleanly separate good from bad. Since a
        # single regression is judged globally, the safe move is: if any edit is
        # unverified, revert unverified lines to their original text.
        for e in reverted:
            suffix = "\n" if working[e.line - 1].endswith("\n") else ""
            working[e.line - 1] = original[e.line - 1] if original[e.line - 1].endswith("\n") \
                else original[e.line - 1]
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.writelines(working)

    result.edits = verified
    result.reverted = reverted
    result.applied = bool(verified)
    return result


def fix_paths(paths: list[str], apply: bool = False,
              aggressive: bool = False) -> list[FileResult]:
    results = []
    files = _gather_python(paths)
    for path in files:
        if apply:
            results.append(apply_and_verify(path, aggressive))
        else:
            results.append(plan_fixes(path, aggressive))
    return [r for r in results if r.edits or r.reverted or r.error]


SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
FIXABLE_EXT = (".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")


def _gather_python(paths: list[str]) -> list[str]:
    out = []
    for p in paths:
        if os.path.isfile(p):
            out.append(p)
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in SKIP_DIRS]
                for name in fn:
                    if name.endswith(FIXABLE_EXT):
                        out.append(os.path.join(dp, name))
    return out


@dataclass
class TestReport:
    ran: bool
    passed: bool
    summary: str
    command: str = ""


def run_tests(repo_root: str, cmd: str | None = None, timeout: int = 300) -> TestReport:
    """Run the project's test suite. Returns whether it ran and whether it passed.
    Detects pytest by default; honors an explicit command."""
    if cmd:
        argv, shell = cmd, True
    elif shutil.which("pytest") or True:  # python -m pytest is portable
        argv, shell = [sys.executable, "-m", "pytest", "-q", "-x"], False
    try:
        p = subprocess.run(argv, cwd=repo_root, capture_output=True, text=True,
                           timeout=timeout, shell=shell, encoding="utf-8",
                           errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        return TestReport(ran=False, passed=False, summary=f"could not run tests: {exc}",
                          command=str(cmd or "pytest"))
    tail = "\n".join((p.stdout or "").strip().splitlines()[-3:])
    # pytest exit 5 == no tests collected -> we cannot gate on it
    if p.returncode == 5:
        return TestReport(ran=False, passed=True, summary="no tests collected",
                          command="pytest")
    return TestReport(ran=True, passed=(p.returncode == 0),
                      summary=tail or f"exit {p.returncode}", command="pytest")


def _repo_root_for(path: str) -> str:
    rc, root, _ = _git(["rev-parse", "--show-toplevel"], os.path.dirname(os.path.abspath(path)))
    return root if rc == 0 and root else os.path.dirname(os.path.abspath(path))


def apply_with_test_gate(paths: list[str], aggressive: bool = False,
                         test_cmd: str | None = None) -> tuple[list[FileResult], TestReport | None]:
    """Apply verified fixes, then run the test suite. If tests FAIL, revert every
    file we touched -- a fix that breaks the build is not a fix."""
    files = _gather_python(paths)
    planned = {f: plan_fixes(f, aggressive) for f in files}
    targets = {f: r for f, r in planned.items() if r.edits}
    if not targets:
        return [r for r in planned.values() if r.edits or r.error], None

    snapshots = {}
    for f in targets:
        lines = _read_lines(f)
        if lines is not None:
            snapshots[f] = lines

    results = [apply_and_verify(f, aggressive) for f in targets]
    changed = [r for r in results if r.applied]
    if not changed:
        return results, None

    repo_root = _repo_root_for(changed[0].path)
    report = run_tests(repo_root, test_cmd)

    if report.ran and not report.passed:
        for f, lines in snapshots.items():           # roll back everything
            with open(f, "w", encoding="utf-8", newline="") as fh:
                fh.writelines(lines)
        for r in results:
            r.reverted += r.edits
            for e in r.edits:
                e.verified = False
                e.note = "reverted: test suite failed"
            r.edits = []
            r.applied = False
    return results, report


def _git(args: list[str], cwd: str) -> tuple[int, str, str]:
    try:
        p = subprocess.run(["git"] + args, cwd=cwd, capture_output=True,
                           text=True, timeout=120, encoding="utf-8", errors="replace")
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, "", str(exc)


def _compare_url(remote_url: str, base: str, branch: str) -> str:
    """Build a GitHub 'create PR' compare URL from an origin remote URL."""
    u = remote_url.strip()
    if u.startswith("git@"):                     # git@github.com:owner/repo.git
        u = u.replace(":", "/").replace("git@", "https://")
    if u.endswith(".git"):
        u = u[:-4]
    return f"{u}/compare/{base}...{branch}?expand=1"


def create_pr(results: list[FileResult], base: str | None = None) -> dict:
    """Put verified fixes on a new branch and open (or link) a PR.

    Uses plain git; opens the PR via `gh` if available, otherwise returns a
    GitHub compare URL to click. Leaves the working tree back on the base branch
    so base stays unmodified -- the fixes live only on the new branch / PR."""
    fixed = [r for r in results if r.applied and r.edits]
    if not fixed:
        return {"error": "no verified fixes to open a PR for"}

    repo_root_rc, repo_root, _ = _git(
        ["rev-parse", "--show-toplevel"], os.path.dirname(os.path.abspath(fixed[0].path)))
    if repo_root_rc != 0 or not repo_root:
        return {"error": "not inside a git repository"}

    if base is None:
        rc, base, _ = _git(["rev-parse", "--abbrev-ref", "HEAD"], repo_root)
        if rc != 0 or not base:
            base = "main"

    branch = f"attestor/autofix-{datetime.now():%Y%m%d-%H%M%S}"
    rc, _, err = _git(["checkout", "-b", branch], repo_root)
    if rc != 0:
        return {"error": f"could not create branch: {err}"}

    rel_files = []
    for r in fixed:
        rc, rel, _ = _git(["ls-files", "--full-name", "--", r.path], repo_root)
        rel_files.append(rel or os.path.relpath(r.path, repo_root))
    _git(["add", "--"] + rel_files, repo_root)

    n = sum(len(r.edits) for r in fixed)
    rules = sorted({e.rule for r in fixed for e in r.edits})
    msg = (f"Attestor autofix: {n} verified fix(es) across {len(fixed)} file(s)\n\n"
           f"Rules fixed: {', '.join(rules)}\n"
           f"Every change was verified by re-scan (target removed, no regressions).\n\n"
           f"Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>")
    rc, _, err = _git(["commit", "-m", msg], repo_root)
    if rc != 0:
        _git(["checkout", base], repo_root)
        return {"error": f"commit failed: {err}", "branch": branch}

    push_rc, _, push_err = _git(["push", "-u", "origin", branch], repo_root)
    pushed = push_rc == 0

    pr_url, method = "", ""
    if pushed and shutil.which("gh"):
        try:
            p = subprocess.run(
                ["gh", "pr", "create", "--fill", "--base", base, "--head", branch],
                cwd=repo_root, capture_output=True, text=True, timeout=120)
            if p.returncode == 0:
                pr_url = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
                method = "gh"
        except (OSError, subprocess.TimeoutExpired):
            pass
    if not pr_url:
        rc, remote, _ = _git(["remote", "get-url", "origin"], repo_root)
        if rc == 0 and remote:
            pr_url = _compare_url(remote, base, branch)
            method = "compare-url"

    _git(["checkout", base], repo_root)   # restore working tree to base (clean)

    return {"branch": branch, "base": base, "pushed": pushed,
            "push_error": push_err if not pushed else "",
            "pr_url": pr_url, "method": method, "fixes": n, "files": len(fixed)}


def render_pr(info: dict) -> str:
    if info.get("error"):
        return f"\n  PR: {info['error']}"
    lines = [f"\n  Pull request for {info['fixes']} verified fix(es):"]
    lines.append(f"    branch: {info['branch']}  (base: {info['base']})")
    if info.get("pushed"):
        lines.append(f"    pushed: yes")
    else:
        lines.append(f"    pushed: NO -- {info.get('push_error','')[:120]}")
        lines.append(f"    (push the branch manually, then open a PR)")
    if info.get("pr_url"):
        label = "opened PR" if info.get("method") == "gh" else "open a PR here"
        lines.append(f"    {label}: {info['pr_url']}")
    lines.append(f"    (base branch left unmodified -- fixes live on the branch)")
    return "\n".join(lines)


def render(results: list[FileResult], apply: bool) -> str:
    if not results:
        return "  No autofixable findings."
    lines = []
    total_edits = sum(len(r.edits) for r in results)
    total_reverted = sum(len(r.reverted) for r in results)
    verb = "Applied" if apply else "Proposed"
    lines.append(f"\n  Autofix -- {verb} {total_edits} fix(es) across {len(results)} file(s)")
    lines.append("  " + "=" * 60)

    for r in results:
        if r.error and not r.edits:
            lines.append(f"\n  {r.path}: {r.error}")
            continue
        lines.append(f"\n  {r.path}")
        for e in r.edits:
            tag = "verified" if e.verified else ("suggest" if e.note else "fix")
            lines.append(f"    [{tag}] line {e.line}  ({e.rule})")
            lines.append(f"      - {e.before.strip()}")
            lines.append(f"      + {e.after.strip()}")
        for e in r.reverted:
            lines.append(f"    [reverted] line {e.line}  ({e.rule}) -- {e.note}")

    if apply:
        lines.append(f"\n  {total_edits} fix(es) applied and verified.")
        if total_reverted:
            lines.append(f"  {total_reverted} reverted (failed verification).")
    else:
        lines.append(f"\n  Dry run -- no files changed. Re-run with --apply to write "
                     f"(each fix is verified by re-scan).")
    return "\n".join(lines)


def to_dict(results: list[FileResult]) -> list[dict]:
    return [
        {
            "path": r.path,
            "applied": r.applied,
            "edits": [{"line": e.line, "rule": e.rule, "before": e.before,
                       "after": e.after, "verified": e.verified, "note": e.note}
                      for e in r.edits],
            "reverted": [{"line": e.line, "rule": e.rule, "note": e.note}
                         for e in r.reverted],
            "error": r.error,
        }
        for r in results
    ]
