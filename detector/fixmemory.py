#!/usr/bin/env python3
"""
fixmemory.py -- durable memory for repeated safe repair patterns.

When evolve.py sees the same mechanical fix across harvested code, Attestor can
record it as a known repair pattern with counts and examples. This is not model
training; it is a plain, inspectable JSON memory.
"""
from __future__ import annotations

import argparse
import json
import os
import time

DEFAULT_MEMORY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "attestor_fix_memory.json")


def load(path: str = DEFAULT_MEMORY) -> dict:
    if not os.path.exists(path):
        return {"version": 1, "patterns": {}}
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save(memory: dict, path: str = DEFAULT_MEMORY) -> str:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(memory, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def learn(memory: dict, rid: str, note: str, count: int, source: dict | None = None) -> dict:
    key = note or rid
    patterns = memory.setdefault("patterns", {})
    rec = patterns.setdefault(key, {
        "rule": rid,
        "note": note,
        "count": 0,
        "sources": [],
        "first_seen": time.strftime("%Y-%m-%d"),
        "last_seen": "",
        "promoted": False,
    })
    rec["count"] += int(count)
    rec["last_seen"] = time.strftime("%Y-%m-%d")
    if source:
        example = {
            "repo": source.get("repo") or "unknown",
            "path": source.get("path") or "unknown",
            "url": source.get("url") or "",
        }
        if example not in rec["sources"]:
            rec["sources"].append(example)
        rec["sources"] = rec["sources"][-10:]
    if rec["count"] >= 3:
        rec["promoted"] = True
    return rec


def learn_from_evolve_run(run: dict, path: str = DEFAULT_MEMORY) -> dict:
    memory = load(path)
    for result in run.get("results", []):
        source = result.get("source", {})
        for rid, count, note in result.get("applied", []):
            learn(memory, rid, note, count, source)
    save(memory, path)
    return memory


def render(memory: dict) -> str:
    patterns = memory.get("patterns", {})
    out = ["Fix Memory", "=" * 10]
    if not patterns:
        out.append("No repair patterns recorded yet.")
        return "\n".join(out)
    for key, rec in sorted(patterns.items(), key=lambda item: (-item[1].get("count", 0), item[0])):
        badge = "known repair" if rec.get("promoted") else "observed"
        out.append("  %s x%d [%s] %s" % (
            rec.get("rule") or "unknown", rec.get("count", 0), badge, key))
    return "\n".join(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--memory", default=DEFAULT_MEMORY)
    args = ap.parse_args(argv)
    print(render(load(args.memory)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
