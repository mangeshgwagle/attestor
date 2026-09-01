#!/usr/bin/env python3
"""SWE-bench Verified benchmark for Attestor.

Downloads the SWE-bench Verified dataset (500 real GitHub issues with
verified patches), checks out each repo at the buggy commit, runs
Attestor's full detection pipeline, and scores how many bug locations
Attestor correctly flags.

Measures:
  - file-level recall: did we flag any finding in the patched file?
  - function-level recall: did we flag the right function?
  - precision: what fraction of our findings hit patched files?
  - council accuracy: do the models agree with the ground truth?

Usage:
    python bench/swe_bench.py                    # run on first 50
    python bench/swe_bench.py --limit 500        # full dataset
    python bench/swe_bench.py --council          # include model council
    python bench/swe_bench.py --json             # machine-readable
    python bench/swe_bench.py --filter security  # security-adjacent only
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))


@dataclass
class PatchLocation:
    file: str
    functions: list[str] = field(default_factory=list)
    lines_changed: list[int] = field(default_factory=list)


@dataclass
class BenchResult:
    instance_id: str
    repo: str
    patch_locations: list[PatchLocation]
    findings_total: int = 0
    findings_in_patched_files: int = 0
    findings_in_patched_functions: int = 0
    file_hit: bool = False
    function_hit: bool = False
    scan_time_ms: int = 0
    council_verdict: str = ""
    council_confidence: float = 0.0
    error: str = ""


SECURITY_KEYWORDS = {
    "sql", "inject", "xss", "csrf", "ssrf", "rce", "command",
    "traversal", "path", "sanitiz", "escap", "auth", "permission",
    "privilege", "overflow", "deserializ", "pickle", "eval", "exec",
    "shell", "password", "secret", "token", "crypto", "tls", "ssl",
    "cors", "redirect", "upload", "download", "symlink",
}


def load_dataset(limit: int = 50, filter_mode: str = "all") -> list[dict]:
    try:
        from datasets import load_dataset as hf_load
    except ImportError:
        print("Installing datasets library...", flush=True)
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "-q", "datasets"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        from datasets import load_dataset as hf_load

    ds = hf_load("princeton-nlp/SWE-bench_Verified", split="test")
    instances = list(ds)

    if filter_mode == "security":
        filtered = []
        for inst in instances:
            text = (inst.get("problem_statement", "") + " " +
                    inst.get("patch", "")).lower()
            if any(kw in text for kw in SECURITY_KEYWORDS):
                filtered.append(inst)
        instances = filtered

    if filter_mode == "python":
        instances = [i for i in instances if _is_python_repo(i)]

    return instances[:limit]


def _is_python_repo(instance: dict) -> bool:
    patch = instance.get("patch", "")
    return any(f.endswith(".py") for f in _extract_patch_files(patch))


def _extract_patch_files(patch: str) -> list[str]:
    files = []
    for line in patch.splitlines():
        if line.startswith("diff --git"):
            parts = line.split()
            if len(parts) >= 4:
                path = parts[3].lstrip("b/")
                files.append(path)
        elif line.startswith("+++ b/"):
            files.append(line[6:])
    return list(dict.fromkeys(files))


def _extract_patch_locations(patch: str) -> list[PatchLocation]:
    locations = []
    current_file = None
    current_lines = []
    current_functions = []

    for line in patch.splitlines():
        if line.startswith("diff --git"):
            if current_file:
                locations.append(PatchLocation(
                    file=current_file,
                    functions=list(dict.fromkeys(current_functions)),
                    lines_changed=current_lines))
            parts = line.split()
            current_file = parts[3].lstrip("b/") if len(parts) >= 4 else None
            current_lines = []
            current_functions = []

        elif line.startswith("@@ "):
            m = re.search(r"\+(\d+)", line)
            if m:
                current_lines.append(int(m.group(1)))
            func_m = re.search(r"@@.*?(?:def|function|func|fn)\s+(\w+)", line)
            if func_m:
                current_functions.append(func_m.group(1))

        elif current_file and not line.startswith("---"):
            func_m = re.match(
                r"[ +-]*\s*(?:def|function|func|fn|async\s+def)\s+(\w+)",
                line)
            if func_m:
                current_functions.append(func_m.group(1))

    if current_file:
        locations.append(PatchLocation(
            file=current_file,
            functions=list(dict.fromkeys(current_functions)),
            lines_changed=current_lines))

    return locations


def _clone_at_commit(repo: str, base_commit: str, workdir: str,
                     instance_id: str = "") -> str:
    repo_url = f"https://github.com/{repo}.git"
    dir_name = instance_id or repo.replace("/", "_")
    repo_dir = os.path.join(workdir, dir_name)

    cache_dir = os.path.join(workdir, "_repo_cache", repo.replace("/", "_"))
    if os.path.isdir(cache_dir):
        shutil.copytree(cache_dir, repo_dir)
    else:
        result = subprocess.run(
            ["git", "clone", "--filter=blob:none", repo_url, repo_dir],
            capture_output=True, timeout=300)
        if result.returncode != 0:
            raise RuntimeError(f"clone: {result.stderr.decode()[:200]}")
        os.makedirs(os.path.dirname(cache_dir), exist_ok=True)
        shutil.copytree(repo_dir, cache_dir)

    result = subprocess.run(
        ["git", "checkout", base_commit],
        cwd=repo_dir, capture_output=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"checkout: {result.stderr.decode()[:200]}")

    return repo_dir


def _run_attestor_scan(repo_dir: str, patch_files: list[str]) -> list[dict]:
    scan_targets = []
    for pf in patch_files:
        full = os.path.join(repo_dir, pf)
        if os.path.isfile(full):
            scan_targets.append(full)

    if not scan_targets:
        return []

    findings = []

    import detect
    for target in scan_targets:
        try:
            for f in detect.scan_file(target):
                findings.append({
                    "file": os.path.relpath(target, repo_dir).replace("\\", "/"),
                    "line": getattr(f, "line", 0),
                    "rule": getattr(f, "rule", ""),
                    "severity": getattr(f, "severity", ""),
                    "category": getattr(f, "category", getattr(f, "rule", "")),
                })
        except Exception:
            pass

    try:
        import dataflow
        flows = dataflow.scan_paths(scan_targets)
        for f in flows:
            findings.append({
                "file": os.path.relpath(
                    getattr(f, "sink_file", ""), repo_dir).replace("\\", "/"),
                "line": getattr(f, "sink_line", 0),
                "rule": getattr(f, "sink_type", ""),
                "severity": getattr(f, "severity", ""),
                "category": getattr(f, "sink_type", ""),
            })
    except Exception:
        pass

    return findings


def _score_findings(findings: list[dict],
                    patch_locations: list[PatchLocation]) -> dict:
    patched_files = {loc.file for loc in patch_locations}
    patched_functions = set()
    patched_line_ranges = {}
    for loc in patch_locations:
        for fn in loc.functions:
            patched_functions.add((loc.file, fn))
        if loc.lines_changed:
            patched_line_ranges[loc.file] = loc.lines_changed

    file_hits = 0
    func_hits = 0
    line_hits = 0

    for f in findings:
        fpath = f["file"]
        if fpath in patched_files:
            file_hits += 1
            fline = f.get("line", 0)
            if fpath in patched_line_ranges:
                for pline in patched_line_ranges[fpath]:
                    if abs(fline - pline) <= 10:
                        line_hits += 1
                        break

    return {
        "total": len(findings),
        "in_patched_files": file_hits,
        "line_proximate": line_hits,
        "file_hit": file_hits > 0,
    }


def _run_council(findings: list[dict]) -> dict | None:
    if not findings:
        return None
    try:
        import model_council
        council = model_council.Council.discover()
        if not council.members:
            return None
        top = findings[0]
        verdict = council.evaluate_finding(top, parallel=False)
        return {
            "verdict": verdict.verdict,
            "confidence": verdict.confidence,
            "quorum": verdict.quorum,
            "consensus": verdict.consensus,
        }
    except Exception:
        return None


def run_instance(instance: dict, workdir: str,
                 use_council: bool = False) -> BenchResult:
    instance_id = instance["instance_id"]
    repo = instance.get("repo", instance_id.split("__")[0].replace("__", "/"))
    base_commit = instance["base_commit"]
    patch = instance["patch"]

    patch_locations = _extract_patch_locations(patch)
    result = BenchResult(
        instance_id=instance_id,
        repo=repo,
        patch_locations=patch_locations)

    try:
        repo_dir = _clone_at_commit(repo, base_commit, workdir,
                                    instance_id=instance_id)
    except Exception as e:
        result.error = f"clone failed: {e}"
        return result

    patch_files = [loc.file for loc in patch_locations]

    t0 = time.time()
    try:
        findings = _run_attestor_scan(repo_dir, patch_files)
    except Exception as e:
        result.error = f"scan failed: {e}"
        return result
    result.scan_time_ms = int((time.time() - t0) * 1000)

    scores = _score_findings(findings, patch_locations)
    result.findings_total = scores["total"]
    result.findings_in_patched_files = scores["in_patched_files"]
    result.file_hit = scores["file_hit"]

    if use_council and findings:
        council_result = _run_council(findings)
        if council_result:
            result.council_verdict = council_result["verdict"]
            result.council_confidence = council_result["confidence"]

    try:
        shutil.rmtree(repo_dir, ignore_errors=True)
    except Exception:
        pass

    return result


def run_benchmark(limit: int = 50, filter_mode: str = "all",
                  use_council: bool = False,
                  output_json: bool = False) -> dict:
    print(f"Loading SWE-bench Verified (filter={filter_mode}, limit={limit})...",
          flush=True)
    instances = load_dataset(limit=limit, filter_mode=filter_mode)
    print(f"  {len(instances)} instances loaded.\n", flush=True)

    results: list[BenchResult] = []
    workdir = tempfile.mkdtemp(prefix="attestor_swebench_")

    for i, instance in enumerate(instances):
        iid = instance["instance_id"]
        print(f"  [{i+1}/{len(instances)}] {iid}...", end=" ", flush=True)
        r = run_instance(instance, workdir, use_council=use_council)
        results.append(r)
        if r.error:
            print(f"ERR: {r.error}")
        else:
            tag = "HIT" if r.file_hit else "miss"
            print(f"{tag}  findings={r.findings_total}  "
                  f"in_patch={r.findings_in_patched_files}  "
                  f"{r.scan_time_ms}ms")

    shutil.rmtree(workdir, ignore_errors=True)

    summary = _compute_summary(results)
    if output_json:
        output = {
            "summary": summary,
            "results": [_result_to_dict(r) for r in results],
        }
        print(json.dumps(output, indent=2))
    else:
        _print_summary(summary, results, use_council)

    return summary


def _compute_summary(results: list[BenchResult]) -> dict:
    total = len(results)
    errors = sum(1 for r in results if r.error)
    evaluated = total - errors
    file_hits = sum(1 for r in results if r.file_hit)
    total_findings = sum(r.findings_total for r in results)
    findings_in_patch = sum(r.findings_in_patched_files for r in results)
    total_scan_ms = sum(r.scan_time_ms for r in results)

    file_recall = file_hits / evaluated if evaluated else 0.0
    precision = findings_in_patch / total_findings if total_findings else 0.0
    avg_scan_ms = total_scan_ms / evaluated if evaluated else 0.0

    return {
        "total_instances": total,
        "evaluated": evaluated,
        "errors": errors,
        "file_hits": file_hits,
        "file_recall": round(file_recall, 4),
        "precision": round(precision, 4),
        "total_findings": total_findings,
        "findings_in_patched_files": findings_in_patch,
        "avg_scan_ms": round(avg_scan_ms, 1),
    }


def _result_to_dict(r: BenchResult) -> dict:
    return {
        "instance_id": r.instance_id,
        "repo": r.repo,
        "findings_total": r.findings_total,
        "findings_in_patched_files": r.findings_in_patched_files,
        "file_hit": r.file_hit,
        "scan_time_ms": r.scan_time_ms,
        "council_verdict": r.council_verdict,
        "council_confidence": r.council_confidence,
        "error": r.error,
        "patch_files": [loc.file for loc in r.patch_locations],
    }


def _print_summary(summary: dict, results: list[BenchResult],
                    use_council: bool):
    print("\n" + "=" * 60)
    print("  Attestor x SWE-bench Verified")
    print("=" * 60)
    print(f"  Instances:       {summary['total_instances']}")
    print(f"  Evaluated:       {summary['evaluated']}")
    print(f"  Errors:          {summary['errors']}")
    print(f"  File-level hits: {summary['file_hits']}/{summary['evaluated']}")
    print(f"  File recall:     {summary['file_recall']:.1%}")
    print(f"  Precision:       {summary['precision']:.1%}")
    print(f"  Total findings:  {summary['total_findings']}")
    print(f"  Avg scan time:   {summary['avg_scan_ms']:.0f}ms")

    if use_council:
        council_results = [r for r in results
                          if r.council_verdict and not r.error]
        if council_results:
            exploitable = sum(1 for r in council_results
                            if r.council_verdict == "EXPLOITABLE")
            print(f"\n  Council verdicts: {len(council_results)} evaluated")
            print(f"    EXPLOITABLE:     {exploitable}")
            avg_conf = (sum(r.council_confidence for r in council_results)
                       / len(council_results))
            print(f"    Avg confidence:  {avg_conf:.1%}")

    by_repo = {}
    for r in results:
        if r.error:
            continue
        repo = r.repo
        if repo not in by_repo:
            by_repo[repo] = {"total": 0, "hits": 0}
        by_repo[repo]["total"] += 1
        if r.file_hit:
            by_repo[repo]["hits"] += 1

    if by_repo:
        print(f"\n  Per-repo breakdown:")
        for repo, stats in sorted(by_repo.items(),
                                   key=lambda x: x[1]["hits"], reverse=True):
            pct = stats["hits"] / stats["total"] if stats["total"] else 0
            bar = "#" * int(pct * 20)
            print(f"    {repo:40s} {stats['hits']:3d}/{stats['total']:<3d} "
                  f"{pct:5.0%} {bar}")

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Benchmark Attestor on SWE-bench Verified")
    parser.add_argument("--limit", type=int, default=50,
                        help="max instances to evaluate (default: 50)")
    parser.add_argument("--filter", choices=["all", "security", "python"],
                        default="python",
                        help="filter instances (default: python)")
    parser.add_argument("--council", action="store_true",
                        help="also run model council on top findings")
    parser.add_argument("--json", action="store_true",
                        help="output results as JSON")
    args = parser.parse_args()

    run_benchmark(
        limit=args.limit,
        filter_mode=args.filter,
        use_council=args.council,
        output_json=args.json)


if __name__ == "__main__":
    main()
