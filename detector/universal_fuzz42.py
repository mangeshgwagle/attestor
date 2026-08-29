#!/usr/bin/env python3
"""Universal Fuzzer 4.2 -- language-agnostic dynamic discovery.

Runs ANY executable target through the mutation + minimization kernels:
C, C++, Rust, Go, Java, C#, Python, anything that runs. Two harness modes:

    --command "./target @@"     testcase written to a temp file, path
                                substituted for @@
    --command "./target" --stdin  testcase piped to stdin

Crash classification reads exit status and stderr signatures (ASan/UBSan/
panic/assert/traceback). No coverage feedback without instrumentation --
this is crash-feedback fuzzing, stated honestly; pair it with
coverage_fuzz42 when the target is Python.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")

from offensive_fuzz42 import gen_input, minimize  # noqa: E402

UF_SCHEMA = "attestor-universal-fuzzer-4.2"
EXIT_CLEAN = 0
EXIT_CRASHES = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

CRASH_SIGNATURES = (
    "AddressSanitizer", "LeakSanitizer", "UndefinedBehaviorSanitizer",
    "SEGV on unknown address", "stack-overflow", "panicked at",
    "Traceback (most recent call last)", "AssertionError",
    "Segmentation fault", "runtime error:",
)
TIMEOUT_EXIT = -99


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class UfError(ValueError):
    pass


def build_runner(command, use_stdin, timeout=None):
    placeholder_present = any(part == "@@" for part in command)

    def run(data):
        tmp_path = None
        argv = list(command)
        if not use_stdin and placeholder_present:
            handle = tempfile.NamedTemporaryFile(delete=False,
                                                 suffix=".tc")
            try:
                handle.write(data)
                tmp_path = handle.name
            finally:
                handle.close()
            argv = [tmp_path if part == "@@" else part for part in command]
        try:
            completed = subprocess.run(
                argv,
                input=data if use_stdin else None,
                capture_output=True,
                timeout=timeout or None,
            )
            return completed.returncode, completed.stderr[-2048:]
        except subprocess.TimeoutExpired:
            return TIMEOUT_EXIT, b"target timeout"
        finally:
            if tmp_path and os.path.exists(tmp_path):
                os.unlink(tmp_path)

    return run


def is_crash(returncode, stderr_tail, expected_clean=(0,)):
    if returncode == TIMEOUT_EXIT:
        return True
    text = stderr_tail.decode("latin-1", errors="replace")
    if any(signature in text for signature in CRASH_SIGNATURES):
        return True
    return returncode not in expected_clean


def light_mutate(rng, parent, tokens=()):
    """Seed-preserving mutations; token insertion follows AFL practice."""
    buf = bytearray(parent or b"A")
    roll = rng.random()
    if tokens and roll < 0.35:
        token = rng.choice(list(tokens))
        i = rng.randrange(len(buf) + 1)
        buf[i:i] = token
    elif roll < 0.5:
        buf.extend(bytes(rng.randrange(256)
                         for _ in range(rng.randint(1, 6))))
    elif roll < 0.65 and buf:
        i = rng.randrange(len(buf))
        buf[i:i] = bytes([rng.randrange(256)])
    elif roll < 0.8 and buf:
        i = rng.randrange(len(buf))
        buf[i] = rng.randrange(256)
    elif roll < 0.92 and len(buf) > 2:
        i = rng.randrange(len(buf) - 1)
        buf[i] ^= 1 << rng.randrange(8)
    else:
        chunk = bytes(buf[:2]) or b"\x00"
        buf.extend(chunk * 2)
    return bytes(buf[:512])


def fuzz_binary(runner, seeds=None, iterations=2000, seconds=30.0,
                seed_rng=0, expected_clean=(0,), corpus_cap=256,
                tokens=()):
    deadline = time.monotonic() + seconds if seconds else None
    rng = random.Random(seed_rng)
    parents = [bytes(s) for s in (seeds or [b"A"])]
    crashes = []
    seen_crash_hex = set()
    tried = 0
    stop_reason = "iterations"

    def execute(data):
        rc, err = runner(data)
        return rc, err, is_crash(rc, err, expected_clean)

    for seed in list(parents):
        tried += 1
        rc, err, crashed = execute(seed)
        if crashed:
            hexed = seed.hex()
            seen_crash_hex.add(hexed)
            crashes.append({"input_hex": hexed,
                            "returncode": rc,
                            "stderr_tail": err.decode("latin-1",
                                                      errors="replace")[:400]})

    seed_pool = [bytes(s) for s in (seeds or [])]
    for step in range(iterations):
        if deadline and time.monotonic() >= deadline:
            stop_reason = "time-budget"
            break
        if seed_pool and rng.random() < 0.85:
            # rotate through seeds so prefix-shaped starts stay dominant;
            # pure random parent choice buries them under resident junk
            parent = seed_pool[step % len(seed_pool)]
        elif parents:
            parent = rng.choice(parents)
        else:
            parent = b"A"
        if rng.random() < 0.7:
            data = light_mutate(rng, parent, tokens=tokens)
        else:
            data = gen_input(rng, parents[:32])
        tried += 1
        rc, err, crashed = execute(data)
        if crashed:
            small = minimize(
                data,
                lambda d: (lambda r2: r2[2])(execute(d)),
                (KeyboardInterrupt, SystemExit))
            hexed = small.hex()
            if hexed not in seen_crash_hex:
                seen_crash_hex.add(hexed)
                crashes.append({
                    "input_hex": hexed,
                    "input_repr": repr(small)[:160],
                    "returncode": rc,
                    "stderr_tail": err.decode("latin-1",
                                              errors="replace")[:400],
                    "generation": step,
                })
                parents.append(small)

        elif len(parents) < corpus_cap and data not in parents:
            parents.append(data)

    return {
        "schema": UF_SCHEMA,
        "tool": "universal-fuzzer",
        "inputs_tried": tried,
        "stop_reason": stop_reason,
        "parents_retained": len(parents),
        "crashes_found": len(crashes),
        "crashes": crashes,
        "seed_rng": seed_rng,
        "boundary": ("subprocess execution of an operator-supplied "
                     "command against operator-supplied inputs"),
    }


def run_selftest():
    checks = []
    script = os.path.join(tempfile.gettempdir(), "attestor_uf_target.py")
    with open(script, "w", encoding="utf-8") as handle:
        handle.write(
            "import sys\n"
            "data = sys.stdin.buffer.read()\n"
            "if data.startswith(b'PWN'):\n"
            "    raise IndexError('planted-oob')\n"
        )
    command = [sys.executable, script]
    runner = build_runner(command, use_stdin=True, timeout=5.0)
    report = fuzz_binary(runner, seeds=[b"PW"], iterations=6000,
                         seconds=25.0, seed_rng=11, expected_clean=(0,),
                         tokens=(b"PWN",))
    checks.append(("dictionary-driven subprocess crash found",
                   report["crashes_found"] >= 1))

    clean_runner = build_runner([sys.executable, "-c", "pass"],
                                use_stdin=True, timeout=5.0)
    quiet = fuzz_binary(clean_runner, iterations=100, seconds=8.0,
                        seed_rng=2)
    checks.append(("clean target stays clean", quiet["crashes_found"] == 0))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": UF_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="universal_fuzz42",
        description="Language-agnostic crash-feedback fuzzer")
    parser.add_argument("--command", required=True, nargs="+",
                        help="argv; '@@' becomes the testcase path")
    parser.add_argument("--stdin", action="store_true",
                        help="feed testcases via stdin instead")
    parser.add_argument("--seeds", nargs="*", default=[])
    parser.add_argument("--iterations", type=int, default=2000)
    parser.add_argument("--seconds", type=float, default=30.0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--expected-clean", type=int, nargs="*",
                        default=[0])
    parser.add_argument("--tokens", nargs="*", default=[],
                        help="hex-encoded dictionary tokens")
    args = parser.parse_args(argv)


    try:
        runner = build_runner(args.command, use_stdin=args.stdin,
                              timeout=5.0)
        seeds = [bytes.fromhex(s) if all(ch in "0123456789abcdefABCDEF"
                                         for ch in s) else s.encode()
                 for s in args.seeds]
        tok = [bytes.fromhex(t) for t in args.tokens]
        report = fuzz_binary(runner, seeds=seeds or None,
                             iterations=args.iterations,
                             seconds=args.seconds, seed_rng=args.seed,
                             expected_clean=tuple(args.expected_clean),
                             tokens=tok)
    except (UfError, OSError) as exc:
        print("universal_fuzz42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID

    print(json.dumps(report, indent=2, sort_keys=True))
    return EXIT_CRASHES if report["crashes_found"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
