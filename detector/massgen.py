#!/usr/bin/env python3
"""
massgen.py -- Attestor's code factory: deterministic generation at scale, every file
proven clean before it counts.

codegen.py instantiates a full service from a spec, deterministically. This drives
it at volume: generate N services, and VERIFY every generated Python file with
Attestor's own engines (deepscan for semantics, grade for the A-F verdict). A file is
counted only if it grades A with zero high/medium findings. "No mistakes" is not a
claim here -- it is a gate. If a file ever failed, the factory would report it as a
defect (and Attestor would have caught its own generator).

It is honest about what it is: correct service/CRUD/infrastructure code at
arbitrary scale -- millions of lines of *accurate* code -- not millions of unique
novel programs. Accuracy is total; diversity is template-bounded. No API key, no
network: pure deterministic generation plus verification.

    python3 massgen.py --services 50 --resources 20 --jobs 0
    python3 massgen.py --services 2600 --resources 20 --jobs 0   # ~10M+ verified lines
    python3 massgen.py --services 1 --resources 5 --out ./generated --run-tests
"""
from __future__ import annotations

import argparse
import functools
import json
import os
import subprocess
import sys
import time

import codegen
import grade
import metrics
import nativepool


def _verify_service(index: int, resources: int) -> dict:
    """Generate one service and grade every .py file. Top-level & picklable so the
    process pool can run it. A file counts as clean only at grade A with no
    high/medium findings."""
    files = codegen.generate(codegen.big_spec(resources))
    lines = 0
    py_files = 0
    clean = 0
    defects = []
    for name, content in files.items():
        lines += content.count("\n") + 1
        if not name.endswith(".py"):
            continue
        py_files += 1
        fg = grade.grade_source(content, "svc%d/%s" % (index, name), metrics.DEFAULT_LIMITS)[0]
        if fg.grade == "A" and fg.findings_high == 0 and fg.findings_medium == 0:
            clean += 1
        else:
            defects.append("svc%d/%s: %s (%dH %dM)"
                           % (index, name, fg.grade, fg.findings_high, fg.findings_medium))
    return {"files": len(files), "py_files": py_files, "lines": lines,
            "clean": clean, "defects": defects}


def factory(services: int, resources: int, jobs: int = 1) -> dict:
    if services < 0:
        raise ValueError("services must be >= 0")
    if resources < 1:
        raise ValueError("resources must be >= 1")
    worker = functools.partial(_verify_service, resources=resources)
    start = time.perf_counter()
    results = nativepool.pmap(worker, range(services), jobs)
    elapsed = time.perf_counter() - start
    totals = {"services": services, "files": 0, "py_files": 0, "lines": 0,
              "clean": 0, "defects": [], "seconds": round(elapsed, 3)}
    for result in results:
        totals["files"] += result["files"]
        totals["py_files"] += result["py_files"]
        totals["lines"] += result["lines"]
        totals["clean"] += result["clean"]
        totals["defects"] += result["defects"]
    totals["lines_per_sec"] = round(totals["lines"] / elapsed) if elapsed else 0
    return totals


def _run_sample_tests(resources: int, out_dir: str) -> str:
    """Write one service to disk and actually run its generated unittest suite --
    proof the code doesn't just parse and grade well, it behaves."""
    codegen.write_files(codegen.generate(codegen.big_spec(resources)), out_dir, force=True)
    proc = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
        cwd=out_dir, capture_output=True, text=True, timeout=300)
    tail = (proc.stderr or proc.stdout or "").strip().splitlines()[-1:] or ["(no output)"]
    return ("PASS" if proc.returncode == 0 else "FAIL") + " -- " + tail[0]


def render(totals: dict, sample: str = "") -> str:
    verdict = "ALL CLEAN" if not totals["defects"] else "%d DEFECT(S)!" % len(totals["defects"])
    lines = [
        "Attestor code factory",
        "=" * 60,
        "services generated : %d" % totals["services"],
        "files written      : %d" % totals["files"],
        "Python files graded: %d" % totals["py_files"],
        "lines of code      : %d" % totals["lines"],
        "verified grade A    : %d / %d  (%s)" % (totals["clean"], totals["py_files"], verdict),
        "time               : %.2fs  (%s lines/sec)" % (totals["seconds"],
                                                        format(totals["lines_per_sec"], ",")),
    ]
    if totals["lines_per_sec"]:
        for label, target in (("1M", 1_000_000), ("10M", 10_000_000)):
            secs = target / totals["lines_per_sec"]
            lines.append("  -> %s verified lines: ~%.0fs at this rate" % (label, secs))
    if sample:
        lines.append("sample test run    : " + sample)
    for defect in totals["defects"][:10]:
        lines.append("  DEFECT " + defect)
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--services", type=int, default=20, help="how many services to generate")
    ap.add_argument("--resources", type=int, default=20, help="resources per service (~425 lines each)")
    ap.add_argument("--jobs", type=int, default=1, help="parallel workers (0 = all cores)")
    ap.add_argument("--out", help="also write one service here (for inspection)")
    ap.add_argument("--run-tests", action="store_true",
                    help="write one service and run its generated unittest suite")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    try:
        totals = factory(args.services, args.resources, args.jobs)
    except ValueError as exc:
        print("massgen: %s" % exc, file=sys.stderr)
        return 2
    sample = ""
    if args.run_tests or args.out:
        out_dir = args.out or os.path.join(os.getcwd(), "attestor_factory_sample")
        os.makedirs(out_dir, exist_ok=True)
        if args.run_tests:
            sample = _run_sample_tests(args.resources, out_dir)
        else:
            codegen.write_files(codegen.generate(codegen.big_spec(args.resources)), out_dir, force=True)

    if args.json:
        print(json.dumps({**totals, "sample": sample}, indent=2))
    else:
        print(render(totals, sample))
    return 1 if totals["defects"] else 0


if __name__ == "__main__":
    sys.exit(main())
