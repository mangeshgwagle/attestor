#!/usr/bin/env python3
"""CrashForge 4.2 -- the crash-to-exploit pipeline.

    coverage-guided fuzzing (coverage_fuzz42)
      -> crash minimization (offensive_fuzz42 kernel)
      -> shape classification (exception taxonomy)
      -> severity grading (pure-asm triage kernel when built)
      -> standalone reproducer script (poc_writer42-style header)
      -> digest-pinned pipeline report

Everything runs on operator-supplied callables, offline.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")

import coverage_fuzz42 as cfuzz  # noqa: E402
from offensive_fuzz42 import minimize  # noqa: E402

CR_SCHEMA = "attestor-crashforge-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

CRASH_TAXONOMY = {
    "IndexError": ("out-of-bounds-index", 0.7),
    "KeyError": ("unhandled-key-lookup", 0.4),
    "RecursionError": ("uncontrolled-recursion", 0.5),
    "TypeError": ("type-confusion-shape", 0.6),
    "ValueError": ("parser-state-fault", 0.5),
    "ZeroDivisionError": ("unchecked-divisor", 0.45),
    "UnicodeDecodeError": ("encoding-boundary-fault", 0.4),
    "struct.error": ("binary-layout-fault", 0.75),
    "RuntimeError": ("asserted-fault", 0.8),
}

REPRODUCER_TEMPLATE = '''#!/usr/bin/env python3
# CrashForge 4.2 reproducer -- {crash_id}
# classification: {classification}   grade: {grade} ({grade_label})
# evidence digest: {digest}
#
# AUTHORIZED TESTING ONLY -- run against code you own.
TARGET_SOURCE = {source!r}

TARGET = {{}}
exec(compile(TARGET_SOURCE, "target.py", "exec"), TARGET)
CRASH_INPUT = bytes.fromhex({input_hex!r})
TARGET[{entry!r}](CRASH_INPUT)
'''


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def classify(crash):
    exception_name = str(crash.get("exception", "")).split(":", 1)[0]
    classification, weight = CRASH_TAXONOMY.get(
        exception_name, ("uncategorized-fault", 0.35))
    tail = crash.get("traceback_tail", "")
    location = ""
    for line in reversed(tail.splitlines()):
        line = line.strip()
        if line.startswith("File "):
            location = line[:120]
            break
    return {
        "exception_class": exception_name,
        "classification": classification,
        "severity_weight": weight,
    }


def _grade_with_asm(severity_float):
    try:
        sys.path.insert(0, __file__.rsplit("\\", 1)[0] +
                        "\\triage_kernel42" if "\\" in __file__
                        else "./triage_kernel42")
        import triage_asm42 as tasm
        dll = tasm.load()
        scored = tasm.score(dll, [0.30, 0.20, 0.25, 0.15, 0.10],
                            [severity_float, severity_float,
                             severity_float, severity_float, 0.0])
        verdict = tasm.grade(dll, scored["score"], kev=False)
        return {"engine": "x86-64 assembly",
                "grade": verdict["grade"],
                "label": verdict["label"]}
    except (ImportError, FileNotFoundError, OSError):
        bands = [(0.70, 4, "readily-exploitable"),
                 (0.50, 3, "exploitable-with-preconditions"),
                 (0.30, 2, "chained-only")]
        score = severity_float
        for threshold, grade, label in bands:
            if score >= threshold:
                return {"engine": "python-mirror", "grade": grade,
                        "label": label}
        return {"engine": "python-mirror", "grade": 1,
                "label": "theoretical-only"}


def run_pipeline(fn, seeds=None, iterations=4000, seconds=25.0,
                 seed_rng=0, write_dir=None):
    fuzz_report = cfuzz.fuzz(fn, seeds=seeds, iterations=iterations,
                             seconds=seconds, seed_rng=seed_rng)

    processed = []
    source = None
    try:
        import inspect
        source = inspect.getsource(fn)
    except (OSError, TypeError):
        source = "def target_unavailable(): pass"

    for crash in fuzz_report["crashes"]:
        small = bytes.fromhex(crash["input_hex"])  # minimized upstream
        info = classify(crash)
        verdict = _grade_with_asm(info["severity_weight"])
        crash_id = sha256_hex((info["classification"] +
                               small.hex()).encode())[:16]
        entry = {
            "crash_id": crash_id,
            "minimized_hex": small.hex(),
            "minimized_len": len(small),
            **info,
            **verdict,
            "path_label": crash.get("path") or
            crash.get("corpus_generation"),
        }
        if write_dir and source:
            from pathlib import Path
            outdir = Path(write_dir)
            outdir.mkdir(parents=True, exist_ok=True)
            script = REPRODUCER_TEMPLATE.format(
                crash_id=crash_id,
                classification=info["classification"],
                grade=verdict["grade"],
                grade_label=verdict["label"],
                digest=sha256_hex(small),
                source=source.rstrip(),
                input_hex=small.hex(),
                entry=getattr(fn, "__name__", "target"))
            path = outdir / ("repro_%s.py" % crash_id)
            path.write_text(script, encoding="utf-8")
            entry["reproducer"] = str(path)
        processed.append(entry)

    processed.sort(key=lambda item: (-item["severity_weight"],
                                     item["crash_id"]))
    report = {
        "schema": CR_SCHEMA,
        "tool": "crashforge-pipeline",
        "fuzz_iterations": fuzz_report["iterations_run"],
        "lines_discovered_total": fuzz_report["lines_discovered_total"],
        "crashes_processed": len(processed),
        "crashes": processed,
        "boundary": ("pipeline operates on operator-supplied functions; "
                     "grades are static review points, not runtime "
                     "exploitation proof"),
    }
    report["report_sha256"] = sha256_hex(canonical_json(
        {k: v for k, v in report.items()}).encode())
    return report


def canonical_json(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def run_selftest():
    checks = []

    def parser_with_planted_oob(data):
        if len(data) < 6:
            return None
        if data[0:3] != b"PWN":
            return None
        if data[5:6] != b"\x00":
            return None
        table = [1, 2]
        return table[data[4]]          # IndexError by construction

    report = run_pipeline(parser_with_planted_oob, seeds=[b"PWN\x00\x00"],
                          iterations=3000, seconds=20.0, seed_rng=3)
    checks.append(("pipeline found the planted OOB",
                   report["crashes_processed"] >= 1))
    if report["crashes"]:
        top = report["crashes"][0]
        checks.append(("classified as out-of-bounds-index",
                       top["classification"] == "out-of-bounds-index"))
        checks.append(("graded by an engine", "engine" in top))
        checks.append(("minimizer shrank input",
                       top["minimized_len"] <= 16
                       and bytes.fromhex(top["minimized_hex"])
                       .startswith(b"PWN")))

    def clean(data):
        return sum(data) % 251

    quiet = run_pipeline(clean, iterations=500, seconds=10.0, seed_rng=1)
    checks.append(("clean target yields zero crashes",
                   quiet["crashes_processed"] == 0))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": CR_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="crashforge42", description="Crash-to-exploit pipeline")
    parser.add_argument("--target-module", required=True)
    parser.add_argument("--target-entry", required=True)
    parser.add_argument("--iterations", type=int, default=4000)
    parser.add_argument("--seconds", type=float, default=25.0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--write-dir")
    args = parser.parse_args(argv)


    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "attestor_crashforge_target", args.target_module)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    fn = getattr(module, args.target_entry, None)
    if not callable(fn):
        print("crashforge42: entry %r is not callable"
              % args.target_entry, file=sys.stderr)
        return EXIT_INVALID

    try:
        report = run_pipeline(fn, iterations=args.iterations,
                              seconds=args.seconds, seed_rng=args.seed,
                              write_dir=args.write_dir)
    except OSError as exc:
        print("crashforge42: %s" % exc, file=sys.stderr)
        return EXIT_OPERATIONAL

    print(json.dumps(report, indent=2, sort_keys=True))
    return EXIT_FINDING if report["crashes_processed"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
