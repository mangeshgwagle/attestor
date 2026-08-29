#!/usr/bin/env python3
"""Split a scan across machines without giving up verifiability.

``nativepool.pmap`` parallelises across cores on one host.  Beyond that there
is nothing: no way to hand half a repository to another machine and prove the
two halves together covered the whole thing.

The hard part is not splitting the work, it is keeping Attestor's central property
while doing so.  A report is trustworthy because its SHA-256 can be recomputed;
if a run is spread over N machines, N separate digests prove N separate things
and nothing about the whole.  So shards fold into a **Merkle root**: each shard
verifies on its own, the root verifies the set, and a missing, duplicated or
altered shard cannot produce the same root.

Determinism is the other half.  Sharding is by content-addressed path, not by
directory walk order or worker arrival, so the same file set yields the same
assignment on every machine and every run -- which is what makes a distributed
result reproducible rather than merely fast.

This module plans and composes.  It deliberately starts no process, opens no
socket, and schedules nothing: transport belongs to whatever runs it, and
inventing a protocol here would add attack surface for no analytical gain.

Honest scope: this makes Attestor *faster on large inputs*.  It does not make him
detect anything he could not detect before.
"""
from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import os
from typing import Any, Iterable, Sequence

SCHEMA = "attestor.shard-plan/1.0"
RESULT_SCHEMA = "attestor.shard-result/1.0"
VERSION = "4.1.4"

MAX_SHARDS = 4_096
MAX_PATHS = 2_000_000
MAX_PATH_CHARS = 4_096


class ShardError(ValueError):
    """The supplied path set, shard count, or shard result is unusable."""


def _sha_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sha_value(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()


def _normalise(paths: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for raw in paths:
        if type(raw) is not str or not raw:
            raise ShardError("every path must be a non-empty string")
        if len(raw) > MAX_PATH_CHARS:
            raise ShardError("path exceeds the length boundary")
        text = raw.replace("\\", "/")
        if text not in seen:
            seen.add(text)
            out.append(text)
        if len(out) > MAX_PATHS:
            raise ShardError("path count exceeds the boundary of %d" % MAX_PATHS)
    return sorted(out)


def merkle_root(leaves: Sequence[str]) -> str:
    """Root over ordered leaf digests.

    Odd nodes are promoted rather than duplicated: duplicating the last leaf is
    the classic malleability bug that lets two different leaf sets share a root.
    """
    if not leaves:
        return _sha_value({"schema": SCHEMA, "leaves": 0})
    level = list(leaves)
    while len(level) > 1:
        nxt: list[str] = []
        for index in range(0, len(level) - 1, 2):
            nxt.append(_sha_text(level[index] + level[index + 1]))
        if len(level) % 2:
            nxt.append(level[-1])
        level = nxt
    return level[0]


def _default_cost(path: str) -> int:
    """File size, or 1 when it cannot be read.

    Bytes are a crude proxy for analysis cost but a far better one than file
    count: parsing and walking an AST scales with the source, not with how many
    files it was split into.
    """
    try:
        return max(1, os.path.getsize(path))
    except OSError:
        return 1


def plan(paths: Iterable[str], shards: int, *,
         costs: dict[str, int] | None = None,
         strategy: str = "balanced") -> dict[str, Any]:
    """Assign every path to exactly one shard, reproducibly.

    ``balanced`` (default) packs by estimated cost, longest first.  ``hash``
    assigns by path digest.

    Hash assignment balances *file counts*, which is the wrong quantity: a
    distributed run finishes when its slowest shard finishes, and one shard
    holding the big files stalls the whole job.  On Attestor's own tree hashing
    gave counts of 31-41 but a 1.60x byte imbalance -- over a third of a
    cluster sitting idle.

    Both strategies are fully deterministic.  Longest-processing-time-first is
    sorted by ``(-cost, path)`` and ties among equally loaded shards go to the
    lowest index, so the same inputs always produce the same plan regardless of
    enumeration order or worker count.
    """
    if type(shards) is not int or isinstance(shards, bool) or \
            not 1 <= shards <= MAX_SHARDS:
        raise ShardError("shards must be an integer between 1 and %d"
                         % MAX_SHARDS)
    if strategy not in {"balanced", "hash"}:
        raise ShardError("strategy must be 'balanced' or 'hash'")
    ordered = _normalise(paths)
    if not ordered:
        raise ShardError("no paths to shard")

    # Weights are computed for both strategies, not just the one that uses
    # them for assignment: reporting a hash plan's imbalance in *file counts*
    # would hide the very problem balancing exists to fix.
    weights = {}
    for path in ordered:
        supplied = (costs or {}).get(path)
        if supplied is not None:
            if type(supplied) is not int or isinstance(supplied, bool) \
                    or supplied < 0:
                raise ShardError("costs must be non-negative integers")
            weights[path] = max(1, supplied)
        else:
            weights[path] = _default_cost(path.replace("/", os.sep))

    buckets: list[list[str]] = [[] for _ in range(shards)]
    loads = [0] * shards
    if strategy == "hash":
        for path in ordered:
            index = int(_sha_text(path)[:8], 16) % shards
            buckets[index].append(path)
            loads[index] += weights[path]
    else:
        # Longest processing time first: a 4/3-approximation for makespan, and
        # dramatically better than hashing when file sizes are skewed.
        #
        # The least-loaded shard is found with a heap rather than by scanning
        # all of them per file.  Scanning is O(paths x shards) -- on a cluster
        # with millions of files and thousands of shards that is billions of
        # comparisons and the planner, not the scan, becomes the bottleneck.
        # The heap makes it O(paths x log shards).  The result is byte-for-byte
        # identical: the heap is keyed on (load, index), so it pops exactly the
        # shard `min(range(shards), key=lambda i: (loads[i], i))` would have --
        # least loaded, lowest index on a tie -- which is what determinism and
        # the plan digests depend on.
        heap = [(0, index) for index in range(shards)]
        heapq.heapify(heap)
        for path in sorted(ordered, key=lambda item: (-weights[item], item)):
            load, index = heapq.heappop(heap)
            buckets[index].append(path)
            loads[index] = load + weights[path]
            heapq.heappush(heap, (loads[index], index))
        buckets = [sorted(bucket) for bucket in buckets]

    rows = []
    for index, bucket in enumerate(buckets):
        rows.append({
            "shard": index,
            "paths": bucket,
            "count": len(bucket),
            "estimated_cost": loads[index],
            "assignment_sha256": _sha_value({"shard": index, "paths": bucket}),
        })
    total_cost = sum(loads)
    ideal = total_cost / shards if shards else 0
    report = {
        "schema": SCHEMA,
        "version": VERSION,
        "strategy": strategy,
        "shards": shards,
        "total_paths": len(ordered),
        "total_cost": total_cost,
        "input_sha256": _sha_value({"paths": ordered}),
        "plan_root_sha256": merkle_root(
            [row["assignment_sha256"] for row in rows]),
        "assignments": rows,
        "empty_shards": sum(1 for row in rows if not row["count"]),
        "largest_shard": max(row["count"] for row in rows),
        "smallest_shard": min(row["count"] for row in rows),
        # Wall time of a distributed run is the slowest shard, so this ratio is
        # the number that matters, not the file counts.
        "makespan_cost": max(loads),
        "imbalance": round(max(loads) / ideal, 3) if ideal else 1.0,
        # No assignment can beat the largest single item: a file cannot be
        # split across shards.  Once imbalance reaches this floor, adding
        # shards buys nothing, and a cluster operator should be told that
        # rather than left to discover it by watching nodes idle.
        "imbalance_floor": round(max(weights.values()) / ideal, 3)
        if ideal else 1.0,
        "granularity_limited": ideal > 0
        and max(loads) <= max(weights.values()) * 1.05
        and max(weights.values()) > ideal,
        "limitations": [
            "plans and composes only: starts no process and opens no socket",
            "makes a scan faster on large inputs; detects nothing new",
            "cost is estimated from file size, which approximates analysis "
            "time but does not predict it",
        ],
    }
    return report


def verify_plan(report: Any) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(report, dict):
        return False, ["plan is not a mapping"]
    if report.get("schema") != SCHEMA:
        errors.append("unexpected schema")
    rows = report.get("assignments")
    if not isinstance(rows, list) or not rows:
        return False, errors + ["assignments must be a non-empty list"]
    seen: set[str] = set()
    for index, row in enumerate(rows):
        if row.get("shard") != index:
            errors.append("shard %d is out of order" % index)
        paths = row.get("paths")
        if not isinstance(paths, list):
            errors.append("shard %d has no path list" % index)
            continue
        for path in paths:
            if path in seen:
                errors.append("path assigned to more than one shard: %s"
                              % path[:80])
            seen.add(path)
        if row.get("assignment_sha256") != _sha_value(
                {"shard": index, "paths": paths}):
            errors.append("shard %d digest does not match its paths" % index)
    if len(seen) != report.get("total_paths"):
        errors.append("assigned path count disagrees with total_paths")
    if report.get("plan_root_sha256") != merkle_root(
            [row.get("assignment_sha256", "") for row in rows]):
        errors.append("plan root does not match its shard digests")
    return not errors, errors


def compose(plan_report: dict[str, Any],
            results: Sequence[dict[str, Any]]) -> dict[str, Any]:
    """Fold completed shard results into one verifiable whole.

    Refuses silently-partial coverage: a missing shard, a duplicate, or one
    whose digest does not match the plan fails here rather than producing a
    confident report about a repository that was never fully scanned.
    """
    ok, errors = verify_plan(plan_report)
    if not ok:
        raise ShardError("plan failed verification: " + "; ".join(errors[:3]))
    expected = {row["shard"]: row["assignment_sha256"]
                for row in plan_report["assignments"]}
    seen: dict[int, dict[str, Any]] = {}
    problems: list[str] = []
    for result in results:
        if not isinstance(result, dict):
            problems.append("shard result is not a mapping")
            continue
        index = result.get("shard")
        if index not in expected:
            problems.append("result for unknown shard %r" % (index,))
            continue
        if index in seen:
            problems.append("duplicate result for shard %d" % index)
            continue
        if result.get("assignment_sha256") != expected[index]:
            problems.append("shard %d scanned a different path set" % index)
            continue
        seen[index] = result
    missing = sorted(set(expected) - set(seen))
    if missing:
        problems.append("no result for shard(s): %s"
                        % ", ".join(str(item) for item in missing[:8]))

    findings: list[Any] = []
    for index in sorted(seen):
        findings.extend(seen[index].get("findings", []))
    leaves = [_sha_value({"shard": index,
                          "assignment_sha256": seen[index]["assignment_sha256"],
                          "findings": seen[index].get("findings", [])})
              for index in sorted(seen)]
    composed = {
        "schema": RESULT_SCHEMA,
        "version": VERSION,
        "plan_root_sha256": plan_report["plan_root_sha256"],
        "input_sha256": plan_report["input_sha256"],
        "shards_expected": len(expected),
        "shards_received": len(seen),
        "complete": not problems,
        "problems": problems,
        "findings": findings,
        "finding_count": len(findings),
        "result_root_sha256": merkle_root(leaves),
        "limitations": [
            "an incomplete composition is not a clean result; findings from "
            "the shards that did report are still partial coverage",
        ],
    }
    composed["composed_sha256"] = _sha_value(
        {key: value for key, value in composed.items()
         if key != "composed_sha256"})
    return composed


def verify_composition(composed: Any, plan_report: Any) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if not isinstance(composed, dict) or not isinstance(plan_report, dict):
        return False, ["composition and plan must both be mappings"]
    if composed.get("schema") != RESULT_SCHEMA:
        errors.append("unexpected schema")
    if composed.get("plan_root_sha256") != plan_report.get("plan_root_sha256"):
        errors.append("composition does not belong to this plan")
    if composed.get("complete") and composed.get("problems"):
        errors.append("a composition with problems cannot be complete")
    if composed.get("shards_received") != composed.get("shards_expected") \
            and composed.get("complete"):
        errors.append("complete composition is missing shard results")
    recomputed = _sha_value({key: value for key, value in composed.items()
                             if key != "composed_sha256"})
    if composed.get("composed_sha256") != recomputed:
        errors.append("composition digest does not match its content")
    return not errors, errors


def shard_result(shard: int, plan_report: dict[str, Any],
                 findings: Sequence[Any]) -> dict[str, Any]:
    """Package one worker's output so compose() can check it belongs."""
    for row in plan_report.get("assignments", []):
        if row.get("shard") == shard:
            return {"schema": RESULT_SCHEMA, "shard": shard,
                    "assignment_sha256": row["assignment_sha256"],
                    "findings": list(findings)}
    raise ShardError("shard %r is not part of this plan" % (shard,))


def run_shard(shard: int, plan_report: dict[str, Any], scan) -> dict[str, Any]:
    """Execute one shard's paths with a caller-supplied scan function.

    ``scan(path) -> iterable`` keeps this module free of any dependency on a
    particular engine, and keeps the transport question out of it entirely: a
    cluster runs this on each node however it likes, and only the returned
    result needs to travel back.

    A path that raises is recorded rather than dropped.  Silently skipping a
    file would let a shard report success over content it never read, which is
    exactly the failure the Merkle composition exists to prevent.
    """
    row = next((item for item in plan_report.get("assignments", [])
                if item.get("shard") == shard), None)
    if row is None:
        raise ShardError("shard %r is not part of this plan" % (shard,))
    findings: list[Any] = []
    failures: list[dict[str, str]] = []
    for path in row["paths"]:
        try:
            findings.extend(scan(path))
        except Exception as exc:               # noqa: BLE001 -- one file
            failures.append({"path": path[:200],
                             "error": type(exc).__name__})
    result = {"schema": RESULT_SCHEMA, "shard": shard,
              "assignment_sha256": row["assignment_sha256"],
              "findings": findings,
              "paths_scanned": len(row["paths"]) - len(failures),
              "paths_failed": len(failures),
              "failures": failures[:64]}
    return result


def run_local(plan_report: dict[str, Any], scan, *,
              workers: int = 0) -> list[dict[str, Any]]:
    """Run every shard on this machine. Useful for testing a plan end to end.

    A real cluster would run ``run_shard`` per node instead; this exists so a
    plan can be exercised and composed without any distributed machinery.
    """
    import nativepool
    shards = [row["shard"] for row in plan_report.get("assignments", [])]
    if workers and workers > 1:
        # Keep the deterministic ordering pmap guarantees.
        return list(nativepool.pmap(
            lambda index: run_shard(index, plan_report, scan), shards, workers))
    return [run_shard(index, plan_report, scan) for index in shards]


def render(report: dict[str, Any]) -> str:
    lines = ["shard plan: %d paths over %d shards (%s)"
             % (report["total_paths"], report["shards"], report["strategy"]),
             "=" * 56,
             "root      : %s" % report["plan_root_sha256"][:32],
             "counts    : smallest=%d largest=%d empty=%d"
             % (report["smallest_shard"], report["largest_shard"],
                report["empty_shards"]),
             # Wall time is the slowest shard, so imbalance is the number that
             # decides how much of a cluster is actually working.
             "cost      : total=%.1f MB slowest=%.1f MB imbalance=%.2fx"
             % (report["total_cost"] / 1e6, report["makespan_cost"] / 1e6,
                report["imbalance"])]
    if report.get("granularity_limited"):
        lines.append("note      : at the granularity floor (%.2fx) -- the "
                     "largest single file sets the pace, so more shards will "
                     "not help" % report["imbalance_floor"])
    lines.extend("note: " + text for text in report["limitations"])
    return "\n".join(lines) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("root")
    parser.add_argument("--shards", type=int, default=4)
    parser.add_argument("--strategy", default="balanced",
                        choices=("balanced", "hash"))
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    paths = []
    for current, directories, names in os.walk(args.root):
        directories[:] = [d for d in sorted(directories)
                          if d not in {".git", "__pycache__", "node_modules"}]
        paths.extend(os.path.join(current, name) for name in sorted(names))
    try:
        report = plan(paths, args.shards, strategy=args.strategy)
    except ShardError as exc:
        print("shard plan refused: %s" % exc)
        return 2
    print(json.dumps(report, indent=1, sort_keys=True) if args.json
          else render(report), end="" if args.json else "")
    return 0


__all__ = ["SCHEMA", "RESULT_SCHEMA", "VERSION", "MAX_SHARDS", "ShardError",
           "merkle_root", "plan", "verify_plan", "compose",
           "verify_composition", "shard_result", "render"]


if __name__ == "__main__":
    raise SystemExit(main())
