#!/usr/bin/env python3
"""github42 -- paste a GitHub link, Owen reviews it, optionally applies it.

    repo link:  https://github.com/user/repo
    PR link:    https://github.com/user/repo/pull/123
    raw file:   https://raw.githubusercontent.com/user/repo/branch/file.py

Pipeline:
    clone/fetch -> Owen's full review stack (reader42 + source_hardening
    + detector) -> signed report -> optionally apply PR patches.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

REPOS_DIR = Path(__file__).resolve().parent.parent / "repos"

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")

GH_SCHEMA = "attestor-github-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def parse_github_url(url):
    """Parse a GitHub URL into (type, owner, repo, extra)."""
    url = url.strip().rstrip("/")
    m = re.match(r"https?://github\.com/([\w.-]+)/([\w.-]+)(?:/(pull|tree|blob)/([\w./-]+))?", url)
    if not m:
        raise ValueError("not a recognized GitHub URL: %s" % url)
    return {
        "type": m.group(3) or "repo",
        "owner": m.group(1),
        "repo": m.group(2),
        "extra": m.group(4),
        "url": url,
    }


def clone_repo(owner, repo, dest, branch=None):
    url = "https://github.com/%s/%s.git" % (owner, repo)
    cmd = ["git", "clone", "--depth", "1"]
    if branch:
        cmd += ["-b", branch]
    cmd += [url, str(dest)]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if result.returncode != 0:
        raise RuntimeError("clone failed: %s" % result.stderr[:300])
    return dest


def fetch_pr_diff(owner, repo, pr_number):
    url = "https://github.com/%s/%s/pull/%d.diff" % (owner, repo, pr_number)
    import urllib.request
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read().decode("utf-8", errors="replace")


def apply_patch(repo_dir, diff_text):
    patch_file = Path(repo_dir) / "_owen_patch.diff"
    patch_file.write_text(diff_text, encoding="utf-8")
    result = subprocess.run(
        ["git", "apply", "--whitespace=nowarn", str(patch_file)],
        cwd=str(repo_dir), capture_output=True, text=True, timeout=60)
    patch_file.unlink(missing_ok=True)
    return result.returncode == 0


def review_repo(repo_dir):
    """Run Owen's full review stack on a checked-out repo."""
    sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")

    findings = {"reader": None, "hardening": [], "total": 0}

    # reader42 - design-level analysis
    try:
        import reader42 as rd
        report = rd.read_repo(str(repo_dir))
        findings["reader"] = {
            "files_read": report["files_read"],
            "functions": report["functions_understood"],
            "q1_unauth_sinks": report["q1_count"],
            "q2_inconsistent_validation": report["q2_count"],
            "narrative": report["narrative"],
        }
        findings["total"] += report["q1_count"] + report["q2_count"]
    except Exception as exc:  # noqa: BLE001
        findings["reader"] = {"error": str(exc)[:200]}

    # source_hardening - secrets, bidi, entropy
    try:
        import source_hardening42 as hard
        hits = []
        for py_file in Path(repo_dir).rglob("*.py"):
            if any(p in (".git", "__pycache__", ".venv") for p in py_file.parts):
                continue
            try:
                hits.extend(hard.scan_file(str(py_file)))
            except OSError:
                continue
        findings["hardening"] = hits[:100]
        findings["total"] += len(hits)
    except Exception as exc:  # noqa: BLE001
        findings["hardening"] = [{"error": str(exc)[:200]}]

    return findings


def run(url, apply_pr=False):
    info = parse_github_url(url)
    print("parsed:", json.dumps(info, indent=2))

    repos_dir = REPOS_DIR
    repos_dir.mkdir(parents=True, exist_ok=True)
    dest = repos_dir / ("%s-%s" % (info["owner"], info["repo"]))

    if info["type"] == "pull":
        pr_num = int(info["extra"])
        print("fetching PR #%d..." % pr_num)
        diff = fetch_pr_diff(info["owner"], info["repo"], pr_num)
        print("cloning base repo...")
        clone_repo(info["owner"], info["repo"], str(dest))
        if apply_pr:
            print("applying PR patch...")
            applied = apply_patch(str(dest), diff)
            print("applied:", applied)
    elif info["type"] == "tree":
        print("cloning branch %s..." % info["extra"])
        clone_repo(info["owner"], info["repo"], str(dest),
                   branch=info["extra"])
    else:
        print("cloning %s/%s..." % (info["owner"], info["repo"]))
        clone_repo(info["owner"], info["repo"], str(dest))

    print("running Owen's review stack...")
    findings = review_repo(str(dest))

    report = {
        "schema": GH_SCHEMA,
        "tool": "github-review",
        "url": url,
        "info": info,
        "local_path": str(dest),
        "findings": findings,
        "report_sha256": sha256_hex(
            json.dumps(findings, sort_keys=True, default=str).encode()),
    }

    if info["type"] == "pull" and apply_pr:
        report["pr_applied"] = True
        report["pr_diff_chars"] = len(diff) if 'diff' in dir() else 0

    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="github42", description="GitHub link -> Owen review -> apply")
    parser.add_argument("url", help="GitHub repo/PR URL")
    parser.add_argument("--apply-pr", action="store_true",
                        help="apply the PR patch before reviewing")
    parser.add_argument("--format", choices=["text", "json"],
                        default="json")
    args = parser.parse_args(argv)

    try:
        report = run(args.url, apply_pr=args.apply_pr)
    except (ValueError, RuntimeError, OSError) as exc:
        print("github42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID

    if args.format == "text":
        f = report["findings"]
        if f.get("reader") and "narrative" in f["reader"]:
            print(f["reader"]["narrative"])
        if f["hardening"]:
            print("\nSecurity findings: %d" % len(f["hardening"]))
            for h in f["hardening"][:10]:
                print("  %s:%s - %s" % (h.get("file", "?"),
                                        h.get("line", "?"), h["check"]))
        print("\nTotal findings: %d" % f["total"])
        print("Local copy: %s" % report["local_path"])
    else:
        print(json.dumps(report, indent=2, sort_keys=True, default=str))

    return EXIT_FINDING if report["findings"]["total"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
