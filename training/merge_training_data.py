#!/usr/bin/env python3
"""Merge all training data sources into a single file.

Sources (in order of priority):
  1. training_data.jsonl         — Original 1,011 Attestor-specific pairs
  2. training_data_bulk.jsonl    — Bulk-generated vulnerability patterns
  3. training_data_expanded.jsonl — Additional vuln types and edge cases
  4. real_cve_pairs.jsonl        — Real CVE data from GitHub+NVD or CVEfixes
  5. tool_use_training.jsonl     — Attestor tool-use training pairs
  6. pentagi_training_data.jsonl — PentAGI cybersecurity knowledge extraction

Output: training_data_merged.jsonl
"""
import json
import os
import sys
import hashlib
import random
from collections import Counter

SOURCES = [
    ("training_data.jsonl", "original"),
    ("training_data_bulk.jsonl", "bulk"),
    ("training_data_expanded.jsonl", "expanded"),
    ("real_cve_pairs.jsonl", "real_cve"),
    ("tool_use_training.jsonl", "tool_use"),
    ("pentagi_training_data.jsonl", "pentagi"),
]

def load_jsonl(path):
    pairs = []
    if not os.path.exists(path):
        print(f"  SKIP: {path} (not found)")
        return pairs
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line: continue
            try:
                pairs.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return pairs


def deduplicate(pairs):
    seen = set()
    unique = []
    for p in pairs:
        key = hashlib.md5(p.get("instruction", "").strip().encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    all_pairs = []
    source_counts = {}

    print(f"\nMerging training data sources:\n")
    for filename, tag in SOURCES:
        pairs = load_jsonl(filename)
        for p in pairs:
            p["_source"] = tag
        source_counts[tag] = len(pairs)
        all_pairs.extend(pairs)
        print(f"  {filename:35s}: {len(pairs):5d} pairs")

    print(f"\n  Total before dedup: {len(all_pairs)}")
    all_pairs = deduplicate(all_pairs)
    print(f"  Total after dedup:  {len(all_pairs)}")

    random.seed(42)
    random.shuffle(all_pairs)

    out = "training_data_merged.jsonl"
    with open(out, "w", encoding="utf-8") as f:
        for p in all_pairs:
            row = {"instruction": p["instruction"], "output": p["output"]}
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    size_mb = os.path.getsize(out) / 1024 / 1024

    source_in_final = Counter(p.get("_source", "unknown") for p in all_pairs)

    print(f"\n{'='*60}")
    print(f"  MERGED TRAINING DATA REPORT")
    print(f"{'='*60}")
    print(f"\n  Total pairs: {len(all_pairs)}")
    print(f"  Output: {out} ({size_mb:.1f} MB)")
    print(f"\n  By source:")
    for tag, _ in SOURCES:
        name = tag.rsplit(".", 1)[0]
        for src_tag, src_name in SOURCES:
            if src_tag == tag:
                name = src_name
                break
        count = source_in_final.get(name, 0)
        print(f"    {name:20s}: {count:5d}  ({100*count/len(all_pairs):.1f}%)")
    print(f"\n  Source contributions:")
    for name, count in source_counts.items():
        final = source_in_final.get(name, 0)
        lost = count - final
        print(f"    {name:20s}: {count:5d} loaded, {final:5d} kept, {lost:3d} dupes removed")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
