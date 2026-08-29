#!/usr/bin/env python3
"""Fetch real CVE vulnerability data from GitHub commit search + NVD API.

Strategy:
  1. Search GitHub for commits mentioning CVE IDs (the actual fixes)
  2. Fetch commit diffs to get before/after code
  3. Look up CVE metadata from NVD (severity, CWE, description)
  4. Build training pairs from real patches

No API key required for basic usage (GitHub: 10 req/min unauthenticated,
NVD: 5 req/30s). Set GITHUB_TOKEN for 30 req/min.

Output: real_cve_pairs.jsonl
"""
import json
import os
import re
import sys
import time
import hashlib
from collections import Counter, defaultdict
from pathlib import Path

import requests

SUPPORTED_LANGS = {"Python", "C", "C++", "Java", "JavaScript", "Go", "Rust", "C#", "Ruby", "PHP"}

EXT_TO_LANG = {
    ".py": "Python", ".pyx": "Python",
    ".c": "C", ".h": "C",
    ".cpp": "C++", ".cxx": "C++", ".cc": "C++", ".hpp": "C++",
    ".java": "Java",
    ".js": "JavaScript", ".mjs": "JavaScript", ".jsx": "JavaScript",
    ".ts": "JavaScript", ".tsx": "JavaScript",
    ".go": "Go",
    ".rs": "Rust",
    ".cs": "C#",
    ".rb": "Ruby",
    ".php": "PHP",
}

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_SEARCH_API = "https://api.github.com/search/commits"
GITHUB_COMMIT_API = "https://api.github.com/repos/{owner}/{repo}/commits/{sha}"

MIN_LINES = 3
MAX_LINES = 500
MAX_DIFF_LINES = 150

SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "OwenCoder-TrainingPipeline/1.0",
    "Accept": "application/vnd.github.cloak-preview+json",
})

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
if GITHUB_TOKEN:
    SESSION.headers["Authorization"] = f"token {GITHUB_TOKEN}"
    GITHUB_DELAY = 2.5
else:
    GITHUB_DELAY = 7.0

NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
NVD_DELAY = 0.7 if NVD_API_KEY else 6.5
if NVD_API_KEY:
    SESSION.headers["apiKey"] = NVD_API_KEY

CVE_CACHE = {}
STATS = {"commits_searched": 0, "commits_fetched": 0, "nvd_lookups": 0,
         "pairs_created": 0, "files_processed": 0, "errors": 0, "rate_waits": 0}


def log(msg):
    print(f"  [{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def line_count(code):
    return len(code.strip().splitlines()) if code else 0


def code_hash(text):
    return hashlib.md5(text.strip().encode("utf-8", errors="replace")).hexdigest()


def severity_label(score):
    if score is None:
        return "UNKNOWN"
    try:
        s = float(score)
    except (ValueError, TypeError):
        return "UNKNOWN"
    if s >= 9.0: return "CRITICAL"
    if s >= 7.0: return "HIGH"
    if s >= 4.0: return "MEDIUM"
    return "LOW"


def detect_lang(filename):
    return EXT_TO_LANG.get(Path(filename).suffix.lower())


def github_request(url, params=None):
    try:
        resp = SESSION.get(url, params=params, timeout=20)
        if resp.status_code == 403:
            reset = resp.headers.get("X-RateLimit-Reset")
            wait = min(max(int(reset) - int(time.time()), 1), 120) if reset else 60
            log(f"GitHub rate limited, waiting {wait}s...")
            STATS["rate_waits"] += 1
            time.sleep(wait)
            resp = SESSION.get(url, params=params, timeout=20)
        if resp.status_code in (422, 404):
            return None
        if resp.status_code != 200:
            STATS["errors"] += 1
            return None
        return resp.json()
    except Exception as e:
        STATS["errors"] += 1
        return None


def search_cve_commits(query, per_page=30):
    params = {"q": query, "per_page": per_page, "sort": "author-date", "order": "desc"}
    data = github_request(GITHUB_SEARCH_API, params)
    STATS["commits_searched"] += 1
    return data.get("items", []) if data else []


def fetch_commit_detail(owner, repo, sha):
    url = GITHUB_COMMIT_API.format(owner=owner, repo=repo, sha=sha)
    data = github_request(url)
    STATS["commits_fetched"] += 1
    return data


def extract_cve_id(text):
    match = re.search(r"CVE-\d{4}-\d{4,}", text, re.IGNORECASE)
    return match.group(0).upper() if match else None


def parse_patch_hunks(patch_text):
    if not patch_text:
        return None, None
    before, after = [], []
    for line in patch_text.splitlines():
        if line.startswith("@@"):
            continue
        elif line.startswith("-") and not line.startswith("---"):
            before.append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            after.append(line[1:])
        else:
            stripped = line[1:] if line.startswith(" ") else line
            before.append(stripped)
            after.append(stripped)
    return "\n".join(before), "\n".join(after)


def lookup_cve_nvd(cve_id):
    if cve_id in CVE_CACHE:
        return CVE_CACHE[cve_id]
    try:
        resp = SESSION.get(NVD_API, params={"cveId": cve_id}, timeout=20)
        STATS["nvd_lookups"] += 1
        if resp.status_code == 403:
            time.sleep(30)
            resp = SESSION.get(NVD_API, params={"cveId": cve_id}, timeout=20)
        if resp.status_code != 200:
            CVE_CACHE[cve_id] = None
            return None
        data = resp.json()
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            CVE_CACHE[cve_id] = None
            return None
        cve = vulns[0].get("cve", {})
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")
        metrics = cve.get("metrics", {})
        score = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                score = metrics[key][0].get("cvssData", {}).get("baseScore")
                break
        cwes = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                v = d.get("value", "")
                if v.startswith("CWE-"):
                    cwes.append(v)
        result = {"cve_id": cve_id, "description": desc, "cvss_score": score,
                  "severity": severity_label(score), "cwe_ids": cwes}
        CVE_CACHE[cve_id] = result
        return result
    except Exception:
        STATS["errors"] += 1
        CVE_CACHE[cve_id] = None
        return None


def process_commit(commit_item):
    msg = commit_item.get("commit", {}).get("message", "")
    cve_id = extract_cve_id(msg)
    if not cve_id:
        return []
    repo_data = commit_item.get("repository", {})
    full_name = repo_data.get("full_name", "")
    if "/" not in full_name:
        return []
    owner, repo = full_name.split("/", 1)
    sha = commit_item.get("sha", "")

    time.sleep(GITHUB_DELAY)
    detail = fetch_commit_detail(owner, repo, sha)
    if not detail:
        return []

    time.sleep(NVD_DELAY)
    cve_meta = lookup_cve_nvd(cve_id)
    cve_desc = cve_meta["description"] if cve_meta else msg.split("\n")[0][:200]
    sev = cve_meta["severity"] if cve_meta else "UNKNOWN"
    cwe_str = ", ".join(cve_meta["cwe_ids"]) if cve_meta and cve_meta["cwe_ids"] else "Unknown"

    pairs = []
    for f in detail.get("files", []):
        filename = f.get("filename", "")
        lang = detect_lang(filename)
        if not lang:
            continue
        STATS["files_processed"] += 1
        patch = f.get("patch", "")
        if not patch:
            continue
        total_changes = (f.get("additions", 0) + f.get("deletions", 0))
        if total_changes < 1 or total_changes > MAX_DIFF_LINES:
            continue
        before_code, after_code = parse_patch_hunks(patch)
        if not before_code or not after_code:
            continue
        if line_count(before_code) < MIN_LINES or line_count(before_code) > MAX_LINES:
            continue
        if before_code.strip() == after_code.strip():
            continue

        short_desc = cve_desc[:300] + ("..." if len(cve_desc) > 300 else "")

        pairs.append({
            "instruction": f"Review this {lang} code for security vulnerabilities:\n```{lang.lower()}\n{before_code.strip()}\n```",
            "output": f"**Vulnerability: {cve_id}** [{sev}] (CWE: {cwe_str})\n\n{short_desc}\n\n**File:** {filename}",
            "_meta": {"cve_id": cve_id, "cwe_str": cwe_str, "severity": sev,
                      "language": lang, "source": "github+nvd", "type": "review"},
        })
        pairs.append({
            "instruction": f"Fix the security vulnerability ({cve_id}) in this {lang} code:\n```{lang.lower()}\n{before_code.strip()}\n```",
            "output": f"**Fixed version** ({cve_id} — {cwe_str}):\n```{lang.lower()}\n{after_code.strip()}\n```\n\n**Patch:** {short_desc}",
            "_meta": {"cve_id": cve_id, "cwe_str": cwe_str, "severity": sev,
                      "language": lang, "source": "github+nvd", "type": "fix"},
        })
        STATS["pairs_created"] += 2

    return pairs


def deduplicate(pairs):
    seen = set()
    unique = []
    for p in pairs:
        key = code_hash(p["instruction"])
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def report_stats(pairs):
    if not pairs:
        print("\n  No pairs generated.")
        return
    lang_counts = Counter(p["_meta"]["language"] for p in pairs)
    sev_counts = Counter(p["_meta"]["severity"] for p in pairs)
    type_counts = Counter(p["_meta"]["type"] for p in pairs)
    cwe_counts = Counter(p["_meta"]["cwe_str"] for p in pairs)

    print(f"\n{'='*60}")
    print(f"  REAL CVE TRAINING DATA REPORT")
    print(f"{'='*60}")
    print(f"\n  Total pairs: {len(pairs)}")
    print(f"  Unique CVEs: {len(set(p['_meta']['cve_id'] for p in pairs))}")
    print(f"\n  Pairs per language:")
    for lang, count in lang_counts.most_common():
        print(f"    {lang:15s}: {count:5d}  ({100*count/len(pairs):.1f}%)")
    print(f"\n  CVE severity distribution:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        count = sev_counts.get(sev, 0)
        print(f"    {sev:15s}: {count:5d}  ({100*count/len(pairs):.1f}%)")
    print(f"\n  Pair types:")
    for t, count in type_counts.most_common():
        print(f"    {t:15s}: {count:5d}")
    print(f"\n  Top 10 CWE types:")
    for cwe, count in cwe_counts.most_common(10):
        print(f"    {cwe:30s}: {count:5d}")
    print(f"\n  Pipeline stats:")
    for k, v in STATS.items():
        print(f"    {k:20s}: {v}")
    print(f"{'='*60}\n")


SEARCH_QUERIES = [
    'CVE fix language:python',
    'CVE fix language:java',
    'CVE fix language:javascript',
    'CVE fix language:go',
    'CVE fix language:c',
    'CVE fix language:cpp',
    'CVE fix language:ruby',
    'CVE fix language:php',
    'CVE fix language:rust',
    'CVE fix language:csharp',
    'CVE patch vulnerability language:python',
    'CVE patch vulnerability language:java',
    'CVE patch vulnerability language:javascript',
    'CVE patch vulnerability language:go',
    'CVE security fix language:python',
    'CVE security fix language:java',
    'CVE security fix language:javascript',
    'CVE security fix language:go',
    'CVE sql injection fix',
    'CVE xss fix',
    'CVE command injection fix',
    'CVE path traversal fix',
    'CVE deserialization fix',
    'CVE buffer overflow fix',
    'CVE ssrf fix',
    'CVE xxe fix',
]


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Fetch real CVE data from GitHub + NVD")
    parser.add_argument("--out", default="real_cve_pairs.jsonl")
    parser.add_argument("--queries", type=int, default=len(SEARCH_QUERIES))
    parser.add_argument("--per-query", type=int, default=30)
    parser.add_argument("--max-commits-per-query", type=int, default=10)
    args = parser.parse_args()

    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    all_pairs = []
    seen_cves = set()
    queries = SEARCH_QUERIES[:args.queries]

    log(f"Running {len(queries)} search queries, up to {args.per_query} results each")
    log(f"GitHub delay: {GITHUB_DELAY}s | NVD delay: {NVD_DELAY}s")
    if not GITHUB_TOKEN:
        log("No GITHUB_TOKEN — rate limited to ~10 req/min. Set GITHUB_TOKEN for 30 req/min")

    for i, query in enumerate(queries):
        log(f"\n[{i+1}/{len(queries)}] Searching: '{query}'")
        time.sleep(GITHUB_DELAY)
        commits = search_cve_commits(query, per_page=args.per_query)
        if not commits:
            log("  No results")
            continue

        cve_commits = []
        for c in commits:
            cid = extract_cve_id(c.get("commit", {}).get("message", ""))
            if cid and cid not in seen_cves:
                cve_commits.append(c)
                seen_cves.add(cid)

        log(f"  {len(commits)} commits, {len(cve_commits)} with new CVE IDs")

        for j, commit in enumerate(cve_commits[:args.max_commits_per_query]):
            cid = extract_cve_id(commit.get("commit", {}).get("message", ""))
            log(f"  Processing {cid}...")
            pairs = process_commit(commit)
            if pairs:
                all_pairs.extend(pairs)
                log(f"    -> {len(pairs)} pairs ({len(all_pairs)} total)")

        log(f"  Running total: {len(all_pairs)} pairs")

    all_pairs = deduplicate(all_pairs)
    log(f"\nAfter dedup: {len(all_pairs)} pairs")

    with open(args.out, "w", encoding="utf-8") as f:
        for p in all_pairs:
            f.write(json.dumps({"instruction": p["instruction"], "output": p["output"]},
                               ensure_ascii=False) + "\n")

    sz = os.path.getsize(args.out) / 1024 / 1024
    log(f"Saved {len(all_pairs)} pairs to {args.out} ({sz:.1f} MB)")
    report_stats(all_pairs)


if __name__ == "__main__":
    main()
