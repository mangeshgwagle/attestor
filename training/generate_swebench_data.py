#!/usr/bin/env python3
"""Generate training data from SWE-bench Verified.

Extracts (vulnerable_code -> vulnerability_label) pairs from the 500
verified bug instances. Each instance has a buggy commit and a fix patch,
giving us ground truth: the code BEFORE the patch is the vulnerable version.

Two pair types per instance:
  1. DETECT: given the buggy function, identify the vulnerability
  2. FIX: given the buggy function, produce the fixed version

Output: swebench_training_data.jsonl
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import re
import subprocess
import shutil
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bench"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))

CWE_HINTS = {
    "sql": "CWE-89", "inject": "CWE-89", "xss": "CWE-79", "csrf": "CWE-352",
    "traversal": "CWE-22", "path": "CWE-22", "command": "CWE-78",
    "deserializ": "CWE-502", "pickle": "CWE-502", "eval": "CWE-95",
    "exec": "CWE-78", "overflow": "CWE-190", "auth": "CWE-287",
    "permission": "CWE-862", "redirect": "CWE-601", "ssrf": "CWE-918",
    "upload": "CWE-434", "escape": "CWE-116", "sanitiz": "CWE-20",
    "password": "CWE-798", "secret": "CWE-798", "token": "CWE-798",
    "cors": "CWE-942", "session": "CWE-384", "race": "CWE-362",
    "null": "CWE-476", "type": "CWE-843", "logic": "CWE-840",
    "dos": "CWE-400", "regex": "CWE-1333", "unicode": "CWE-176",
    "encoding": "CWE-838",
}

DETECT_TEMPLATE = """Analyze this Python code for bugs and vulnerabilities. Report what you find in this format:
CATEGORY: <category>
CWE: <CWE-ID>
SEVERITY: <CRITICAL|HIGH|MEDIUM|LOW>
DESCRIPTION: <what is wrong>
FIX: <how to fix it>

```python
{code}
```"""

FIX_TEMPLATE = """Fix the bug in this Python code. The issue is: {description}

```python
{code}
```"""


def _guess_cwe(text: str) -> str:
    text_lower = text.lower()
    for keyword, cwe in CWE_HINTS.items():
        if keyword in text_lower:
            return cwe
    return ""


def _guess_category(text: str) -> str:
    text_lower = text.lower()
    categories = {
        "sql injection": "sql_injection", "xss": "xss", "csrf": "csrf",
        "command injection": "command_injection", "path traversal": "path_traversal",
        "deserialization": "insecure_deserialization", "authentication": "broken_auth",
        "authorization": "broken_access_control", "overflow": "overflow",
        "race condition": "race_condition", "redirect": "open_redirect",
        "upload": "unrestricted_upload", "injection": "injection",
        "denial": "dos", "crash": "crash", "error": "error_handling",
        "validation": "input_validation", "sanitiz": "input_validation",
        "escape": "output_encoding",
    }
    for pattern, cat in categories.items():
        if pattern in text_lower:
            return cat
    return "logic_error"


def _guess_severity(text: str) -> str:
    text_lower = text.lower()
    if any(w in text_lower for w in ("sql inject", "command inject", "rce", "deserializ")):
        return "CRITICAL"
    if any(w in text_lower for w in ("xss", "csrf", "auth", "permission", "traversal")):
        return "HIGH"
    if any(w in text_lower for w in ("redirect", "dos", "crash", "overflow")):
        return "MEDIUM"
    return "LOW"


def _extract_functions_from_patch(patch: str) -> list[dict]:
    current_file = None
    functions = []

    for line in patch.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                current_file = parts[3].lstrip("b/")
        elif line.startswith("@@ "):
            m = re.search(r"\+(\d+)", line)
            start_line = int(m.group(1)) if m else 0
            func_m = re.search(r"@@.*?def\s+(\w+)", line)
            if func_m and current_file:
                functions.append({
                    "file": current_file,
                    "function": func_m.group(1),
                    "line": start_line,
                })
        elif current_file and not line.startswith("---"):
            func_m = re.match(r"[ +-]*\s*def\s+(\w+)", line)
            if func_m:
                functions.append({
                    "file": current_file,
                    "function": func_m.group(1),
                    "line": 0,
                })

    seen = set()
    unique = []
    for f in functions:
        key = (f["file"], f["function"])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def _extract_changed_code(patch: str) -> list[dict]:
    chunks = []
    current_file = None
    before_lines = []
    after_lines = []
    context_lines = []

    for line in patch.splitlines():
        if line.startswith("diff --git"):
            if current_file and (before_lines or after_lines):
                chunks.append({
                    "file": current_file,
                    "before": "\n".join(before_lines),
                    "after": "\n".join(after_lines),
                    "context": "\n".join(context_lines),
                })
            parts = line.split()
            current_file = parts[3].lstrip("b/") if len(parts) >= 4 else None
            before_lines, after_lines, context_lines = [], [], []
        elif line.startswith("@@"):
            continue
        elif line.startswith("---") or line.startswith("+++"):
            continue
        elif line.startswith("-"):
            before_lines.append(line[1:])
            context_lines.append(line[1:])
        elif line.startswith("+"):
            after_lines.append(line[1:])
        else:
            text = line[1:] if line.startswith(" ") else line
            before_lines.append(text)
            after_lines.append(text)
            context_lines.append(text)

    if current_file and (before_lines or after_lines):
        chunks.append({
            "file": current_file,
            "before": "\n".join(before_lines),
            "after": "\n".join(after_lines),
            "context": "\n".join(context_lines),
        })

    return [c for c in chunks if c["before"].strip() != c["after"].strip()]


def _clone_and_extract_function(repo: str, commit: str, filepath: str,
                                function_name: str, workdir: str) -> str | None:
    repo_url = f"https://github.com/{repo}.git"
    repo_dir = os.path.join(workdir, repo.replace("/", "_"))

    if not os.path.isdir(repo_dir):
        result = subprocess.run(
            ["git", "clone", "--filter=blob:none", repo_url, repo_dir],
            capture_output=True, timeout=300)
        if result.returncode != 0:
            return None

    result = subprocess.run(
        ["git", "checkout", commit],
        cwd=repo_dir, capture_output=True, timeout=30)
    if result.returncode != 0:
        return None

    full_path = os.path.join(repo_dir, filepath)
    if not os.path.isfile(full_path):
        return None

    try:
        with open(full_path, encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return None

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None

    lines = source.splitlines()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if node.name == function_name:
                start = node.lineno
                end = node.end_lineno or start
                return "\n".join(lines[start - 1:end])

    return None


def generate_from_patches(instances: list[dict], clone: bool = False,
                          workdir: str = "") -> list[dict]:
    pairs = []
    stats = Counter()

    for inst in instances:
        iid = inst["instance_id"]
        patch = inst.get("patch", "")
        problem = inst.get("problem_statement", "")
        repo = inst.get("repo", "")

        if not patch:
            stats["no_patch"] += 1
            continue

        changed = _extract_changed_code(patch)
        functions = _extract_functions_from_patch(patch)

        if not changed:
            stats["no_changes"] += 1
            continue

        cwe = _guess_cwe(problem + " " + patch)
        category = _guess_category(problem)
        severity = _guess_severity(problem)

        problem_short = problem[:500].replace("\n", " ").strip()
        if not problem_short:
            problem_short = f"Bug in {iid}"

        for chunk in changed:
            before = chunk["before"].strip()
            after = chunk["after"].strip()
            if not before or len(before) < 20:
                continue
            if len(before.splitlines()) > 300:
                continue

            cwe_str = f" ({cwe})" if cwe else ""
            detect_output = (
                f"CATEGORY: {category}\n"
                f"CWE: {cwe or 'Unknown'}\n"
                f"SEVERITY: {severity}\n"
                f"DESCRIPTION: {problem_short}\n"
                f"FIX: See the patched version of this code"
            )

            pairs.append({
                "instruction": DETECT_TEMPLATE.format(code=before),
                "output": detect_output,
                "_meta": {
                    "instance_id": iid, "repo": repo, "type": "detect",
                    "category": category, "cwe": cwe, "severity": severity,
                    "source": "swebench",
                },
            })
            stats["detect"] += 1

            pairs.append({
                "instruction": FIX_TEMPLATE.format(
                    description=problem_short, code=before),
                "output": f"```python\n{after}\n```",
                "_meta": {
                    "instance_id": iid, "repo": repo, "type": "fix",
                    "category": category, "cwe": cwe, "severity": severity,
                    "source": "swebench",
                },
            })
            stats["fix"] += 1

        if clone and workdir and functions:
            base_commit = inst.get("base_commit", "")
            for func_info in functions[:3]:
                fn_code = _clone_and_extract_function(
                    repo, base_commit, func_info["file"],
                    func_info["function"], workdir)
                if fn_code and len(fn_code.splitlines()) >= 5:
                    pairs.append({
                        "instruction": DETECT_TEMPLATE.format(code=fn_code),
                        "output": detect_output,
                        "_meta": {
                            "instance_id": iid, "repo": repo,
                            "type": "detect_full_fn",
                            "category": category, "cwe": cwe,
                            "severity": severity, "source": "swebench",
                            "function": func_info["function"],
                        },
                    })
                    stats["detect_full_fn"] += 1

    return pairs, stats


def main():
    parser = argparse.ArgumentParser(
        description="Generate training data from SWE-bench Verified")
    parser.add_argument("--limit", type=int, default=500,
                        help="max instances (default: all 500)")
    parser.add_argument("--filter", choices=["all", "security", "python"],
                        default="python")
    parser.add_argument("--clone", action="store_true",
                        help="clone repos to extract full functions (slow)")
    parser.add_argument("--out", default="swebench_training_data.jsonl")
    args = parser.parse_args()

    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    print("Loading SWE-bench Verified dataset...")
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bench"))
    import swe_bench
    instances = swe_bench.load_dataset(limit=args.limit, filter_mode=args.filter)
    print(f"  {len(instances)} instances loaded")

    workdir = ""
    if args.clone:
        workdir = tempfile.mkdtemp(prefix="swebench_train_")
        print(f"  Cloning repos to {workdir}")

    print("Generating training pairs...")
    pairs, stats = generate_from_patches(instances, clone=args.clone,
                                          workdir=workdir)
    print(f"  {len(pairs)} pairs generated")

    if workdir:
        shutil.rmtree(workdir, ignore_errors=True)

    seen = set()
    unique = []
    for p in pairs:
        import hashlib
        key = hashlib.md5(p["instruction"].strip().encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            unique.append(p)

    print(f"  {len(unique)} after dedup")

    with open(args.out, "w", encoding="utf-8") as f:
        for p in unique:
            f.write(json.dumps({
                "instruction": p["instruction"],
                "output": p["output"],
            }, ensure_ascii=False) + "\n")

    repo_counts = Counter(p["_meta"]["repo"] for p in unique)
    type_counts = Counter(p["_meta"]["type"] for p in unique)
    cat_counts = Counter(p["_meta"]["category"] for p in unique)
    sev_counts = Counter(p["_meta"]["severity"] for p in unique)

    print(f"\n{'='*60}")
    print(f"  SWE-BENCH TRAINING DATA REPORT")
    print(f"{'='*60}")
    print(f"\n  Total pairs:    {len(unique)}")
    print(f"  From instances: {len(instances)}")
    print(f"\n  Pair types:")
    for t, c in type_counts.most_common():
        print(f"    {t:20s}: {c:5d}")
    print(f"\n  Categories:")
    for cat, c in cat_counts.most_common(15):
        print(f"    {cat:25s}: {c:5d}")
    print(f"\n  Severity:")
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        c = sev_counts.get(s, 0)
        print(f"    {s:10s}: {c:5d}")
    print(f"\n  Top repos:")
    for repo, c in repo_counts.most_common(10):
        print(f"    {repo:40s}: {c:5d}")
    print(f"\n  Pipeline stats:")
    for k, v in stats.most_common():
        print(f"    {k:20s}: {v}")
    print(f"\n  Output: {args.out}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
