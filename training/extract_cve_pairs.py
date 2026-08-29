#!/usr/bin/env python3
"""Extract real CVE training pairs from CVEfixes.db.

Download: https://zenodo.org/records/13118970/files/CVEfixes_v1.0.8.zip
Unzip and place CVEfixes.db in this directory (or pass --db path).

Output: real_cve_pairs.jsonl
"""
import argparse
import json
import hashlib
import os
import sqlite3
import sys
from collections import Counter, defaultdict
from pathlib import Path

SUPPORTED_LANGS = {
    "Python", "C", "C++", "Java", "JavaScript", "Go", "Rust", "C#", "Ruby", "PHP",
    "TypeScript",
}
LANG_ALIASES = {
    "c++": "C++", "cpp": "C++", "c#": "C#", "csharp": "C#",
    "python": "Python", "java": "Java", "javascript": "JavaScript",
    "typescript": "TypeScript", "go": "Go", "rust": "Rust",
    "ruby": "Ruby", "php": "PHP", "c": "C",
}
MIN_LINES = 5
MAX_LINES = 500

def severity_label(score):
    if score is None: return "UNKNOWN"
    try: s = float(score)
    except: return "UNKNOWN"
    if s >= 9.0: return "CRITICAL"
    if s >= 7.0: return "HIGH"
    if s >= 4.0: return "MEDIUM"
    return "LOW"

def normalize_lang(lang):
    if not lang: return None
    l = lang.strip()
    return l if l in SUPPORTED_LANGS else LANG_ALIASES.get(l.lower())

def line_count(code):
    return len(code.strip().splitlines()) if code else 0

def code_hash(code):
    return hashlib.md5(code.strip().encode("utf-8", errors="replace")).hexdigest()


def extract_file_pairs(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
    SELECT cv.cve_id, cv.description AS cve_desc,
           COALESCE(cv.cvss3_base_score, cv.cvss2_base_score) AS severity_score,
           cc.cwe_id, cw.cwe_name,
           f.programming_language, f.filename,
           f.code_before, f.code_after, f.num_lines_added, f.num_lines_deleted
    FROM file_change f
    JOIN commits c ON f.hash = c.hash
    JOIN fixes fx ON c.hash = fx.hash
    JOIN cve cv ON fx.cve_id = cv.cve_id
    LEFT JOIN cwe_classification cc ON cv.cve_id = cc.cve_id
    LEFT JOIN cwe cw ON cc.cwe_id = cw.cwe_id
    WHERE f.code_before IS NOT NULL AND f.code_after IS NOT NULL
      AND f.code_before != '' AND f.code_after != ''
      AND f.change_type = 'MODIFY'
    ORDER BY cv.cve_id
    """)
    rows = cur.fetchall()
    conn.close()
    return rows


def build_pairs(rows):
    pairs = []
    for row in rows:
        lang = normalize_lang(row["programming_language"])
        if not lang: continue
        code_before, code_after = row["code_before"], row["code_after"]
        if line_count(code_before) < MIN_LINES or line_count(code_before) > MAX_LINES: continue
        if line_count(code_after) < MIN_LINES or line_count(code_after) > MAX_LINES: continue
        if code_before.strip() == code_after.strip(): continue
        changes = (row["num_lines_added"] or 0) + (row["num_lines_deleted"] or 0)
        if changes > 100: continue

        cve_desc = row["cve_desc"] or ""
        cwe_id = row["cwe_id"] or ""
        cwe_name = row["cwe_name"] or ""
        sev = severity_label(row["severity_score"])
        cwe_info = f" ({cwe_id}: {cwe_name})" if cwe_id and cwe_name else ""

        pairs.append({
            "instruction": f"Review this {lang} code for security vulnerabilities:\n```{lang.lower()}\n{code_before.strip()}\n```",
            "output": f"**Vulnerability: {row['cve_id']}** [{sev}]{cwe_info}\n\n{cve_desc}",
            "_meta": {"cve_id": row["cve_id"], "cwe_id": cwe_id, "severity": sev,
                      "language": lang, "source": "cvefixes", "type": "review"},
        })
        pairs.append({
            "instruction": f"Fix the security vulnerability ({row['cve_id']}) in this {lang} code:\n```{lang.lower()}\n{code_before.strip()}\n```",
            "output": f"**Fixed version** ({row['cve_id']}):\n```{lang.lower()}\n{code_after.strip()}\n```",
            "_meta": {"cve_id": row["cve_id"], "cwe_id": cwe_id, "severity": sev,
                      "language": lang, "source": "cvefixes", "type": "fix"},
        })
    return pairs


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="CVEfixes.db")
    parser.add_argument("--out", default="real_cve_pairs.jsonl")
    args = parser.parse_args()
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    if not os.path.exists(args.db):
        print(f"ERROR: {args.db} not found.")
        print(f"Download from: https://zenodo.org/records/13118970/files/CVEfixes_v1.0.8.zip")
        sys.exit(1)

    print("Extracting file-level pairs...")
    rows = extract_file_pairs(args.db)
    print(f"  {len(rows)} file change records")
    pairs = build_pairs(rows)
    print(f"  {len(pairs)} raw pairs")

    seen = set()
    unique = [p for p in pairs if code_hash(p["instruction"]) not in seen and not seen.add(code_hash(p["instruction"]))]
    print(f"  {len(unique)} after dedup")

    with open(args.out, "w", encoding="utf-8") as f:
        for p in unique:
            f.write(json.dumps({"instruction": p["instruction"], "output": p["output"]}, ensure_ascii=False) + "\n")

    lang_counts = Counter(p["_meta"]["language"] for p in unique)
    sev_counts = Counter(p["_meta"]["severity"] for p in unique)
    cwe_counts = Counter(p["_meta"]["cwe_id"] for p in unique if p["_meta"]["cwe_id"])
    unique_cves = len(set(p["_meta"]["cve_id"] for p in unique))

    print(f"\n{'='*60}")
    print(f"  REAL CVE TRAINING DATA REPORT")
    print(f"{'='*60}")
    print(f"\n  Total pairs: {len(unique)}  |  Unique CVEs: {unique_cves}")
    print(f"\n  Per language:")
    for l, c in lang_counts.most_common(): print(f"    {l:15s}: {c:5d}  ({100*c/len(unique):.1f}%)")
    print(f"\n  Severity:")
    for s in ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"]:
        c = sev_counts.get(s,0); print(f"    {s:15s}: {c:5d}  ({100*c/len(unique):.1f}%)")
    print(f"\n  Top 15 CWEs:")
    for cwe, c in cwe_counts.most_common(15): print(f"    {cwe:15s}: {c:5d}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
