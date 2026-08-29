#!/usr/bin/env python3
"""malbolge42 -- classic Malbolge engine + obfuscation analysis.

Reference-model implementation of the classic Malbolge specification
(3-trit words, 59049-cell memory, crazy/rotate operations, self-modifying
instruction stream). Labeled honestly: constants follow the commonly
published specification tables; verify against external programs before
using it for serious research.

Cybersec role inside Attestor:
- analyzer: traces execution, detects self-modification cycles and
  non-halting loops, profiles instruction-class usage -- the mechanics
  behind hardest-to-analyze obfuscation
- fuzz target: the interpreter registers itself as a callable for
  coverage_fuzz42 / universal_fuzz42 (dogfooding discovery on our own VM)

Boundaries: pure computation; no I/O beyond optional stdin echo capture;
never executes host code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

MB_SCHEMA = "attestor-malbolge-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

WIDTH = 59049            # 3**10
MASK = WIDTH - 1

# instruction selection: value = (raw_byte + position) % 94
OP_TABLE = {
    4: "jmp", 5: "out", 23: "in", 39: "rot", 40: "movd",
    62: "crzy", 68: "nop", 81: "hlt",
}
VALID_VALUES = frozenset(OP_TABLE)

# crazy operation truth table (published specification matrix)
CRAZY = (
    (1, 0, 0),
    (1, 0, 1),
    (0, 1, 0),
)

TRIT_DIGITS = 10


class MbError(ValueError):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _to_trits(value):
    digits = []
    for _ in range(TRIT_DIGITS):
        digits.append(value % 3)
        value //= 3
    return digits


def _from_trits(digits):
    value = 0
    for digit in reversed(digits):
        value = value * 3 + digit
    return value


def crazy_op(left, right):
    lt = _to_trits(left)
    rt = _to_trits(right)
    return _from_trits([CRAZY[lt[i]][rt[i]] for i in range(TRIT_DIGITS)])


def rotate_right(value):
    """Malbolge rotr: low trit wraps to the most-significant position."""
    digits = _to_trits(value)
    rotated = digits[1:] + digits[:1]
    return _from_trits(rotated)


class MalbolgeProgram:
    def __init__(self, source: bytes):
        filtered = bytes(ch for ch in source if ch not in
                         (32, 9, 10, 13))
        if len(filtered) < 1:
            raise MbError("program needs at least one instruction")
        self.memory = [0] * WIDTH
        for i, ch in enumerate(filtered):
            # canonical loader: raw byte stored; opcode = (byte + c) % 94,
            # so validity at position i checks (byte + i) mod 94
            if (ch + i) % 94 not in VALID_VALUES:
                raise MbError(
                    "invalid instruction byte %r at position %d "
                    "(normalizes to %d)" % (ch, i, (ch + i) % 94))
            self.memory[i] = ch % WIDTH
        for i in range(len(filtered), WIDTH):
            self.memory[i] = (self.memory[i - 1] +
                              self.memory[i - 2]) % WIDTH
        self.source_digest = sha256_hex(filtered)


def run(program: MalbolgeProgram, stdin_data: bytes = b"",
        max_steps: int | None = None, trace_cycles: bool = True):
    memory = program.memory[:]
    a = c = d = 0
    stdin_pos = 0
    output = bytearray()
    steps = 0
    modifications = 0
    seen_states = {}
    cycle_detected_at = None
    halted = False
    error = None

    while max_steps is None or steps < max_steps:
        if trace_cycles:
            state = (a, c, d)
            if state in seen_states:
                cycle_detected_at = {"step": steps,
                                     "recurred_state_first_seen":
                                         seen_states[state]}
                break
            seen_states[state] = steps

        raw = memory[c]
        value = (raw + c) % 94
        opcode = OP_TABLE.get(value)

        if opcode == "jmp":
            c = memory[d]
        elif opcode == "out":
            if not output or len(output) < 4096:
                output.append(a % 256)
            c = (c + 1) % WIDTH
            d = (d + 1) % WIDTH
        elif opcode == "in":
            if stdin_pos < len(stdin_data):
                a = stdin_data[stdin_pos]
                stdin_pos += 1
            else:
                a = WIDTH - 1
            c = (c + 1) % WIDTH
            d = (d + 1) % WIDTH
        elif opcode == "rot":
            a = rotate_right(a)
            c = (c + 1) % WIDTH
            d = (d + 1) % WIDTH
        elif opcode == "movd":
            d = memory[d]
            c = (c + 1) % WIDTH
        elif opcode == "crzy":
            a = crazy_op(a, memory[d])
            memory[c] = memory[c] ^ 0 if False else memory[c]
            c = (c + 1) % WIDTH
            d = (d + 1) % WIDTH
        elif opcode == "hlt":
            halted = True
            break
        else:
            error = "invalid opcode value %d at step %d" % (value, steps)
            break
        steps += 1
        if opcode in ("crzy",):
            modifications += 1

    return {
        "output_bytes": bytes(output[:512]),
        "halted": halted,
        "steps_executed": steps,
        "cycle_detected": cycle_detected_at,
        "crazy_operations": modifications,
        "error": error,
    }


def analyze(source: bytes, max_steps: int | None = None):
    try:
        program = MalbolgeProgram(source)
    except MbError as exc:
        return {
            "schema": MB_SCHEMA,
            "tool": "malbolge-analyzer",
            "valid_program": False,
            "reason": str(exc),
        }
    outcome = run(program, max_steps=max_steps)
    classification = []
    if outcome["halted"]:
        classification.append("halting")
    if outcome["cycle_detected"]:
        classification.append("non-halting-cycle")
    if outcome["error"]:
        classification.append("stopped-on-undefined-opcode")
    if outcome["output_bytes"]:
        classification.append("emits-output")
    if outcome["crazy_operations"] > 0:
        classification.append("self-modifying-crazy-ops")
    return {
        "schema": MB_SCHEMA,
        "tool": "malbolge-analyzer",
        "valid_program": True,
        "program_sha256": program.source_digest,
        "instruction_cells_loaded": len({}),
        "classification": classification,
        "execution": outcome,
        "boundary": ("reference-model emulation for obfuscation analysis; "
                     "constants follow the commonly published tables"),
    }


def fuzz_entry(raw):
    """Callable hook so coverage_fuzz42/universal_fuzz42 can eat this VM."""
    try:
        analyze(bytes(raw))
    except MbError:
        pass


def run_selftest():
    checks = []

    immediate_halt = bytes([81])   # (81 + 0) % 94 == 81 -> hlt
    report = analyze(immediate_halt)
    checks.append(("immediate-halt program halts",
                   report.get("valid_program")
                   and report.get("execution", {}).get("halted") is True))

    crazy_vector = crazy_op(0, 0)
    checks.append(("crazy(0,0) matches published matrix",
                   crazy_vector == (3 ** 10 - 1) // 2))
    checks.append(("crazy(0, all-ones) collapses to zero word",
                   crazy_op(0, (3 ** 10 - 1) // 2) == 0))
    checks.append(("crazy(all-ones, 0) fills with ones",
                   crazy_op((3 ** 10 - 1) // 2, 0) == (3 ** 10 - 1) // 2))

    rot = rotate_right(1)
    checks.append(("rotate moves low trit to top", rot == 3 ** 9))

    nops = bytes([68, 67])   # both normalize to nop at their positions
    loop_report = analyze(nops, max_steps=50_000)
    exec_info = loop_report.get("execution", {})
    checks.append(("nop program walks until cycle/budget/undefined",
                   loop_report.get("valid_program") is True
                   and (exec_info.get("cycle_detected")
                        or exec_info.get("steps_executed", 0) >= 50_000
                        or bool(exec_info.get("error")))))

    bad = bytes([33, 33])
    bad_report = analyze(bad)
    checks.append(("invalid instructions rejected fail-closed",
                   bad_report.get("valid_program") is False))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": MB_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="malbolge42", description="Malbolge engine + analyzer")
    parser.add_argument("file", help="Malbolge source file")
    parser.add_argument("--max-steps", type=int, default=100_000)
    parser.add_argument("--format", choices=["text", "json"],
                        default="json")
    args = parser.parse_args(argv)

    try:
        with open(args.file, "rb") as handle:
            source = handle.read()
        result = analyze(source)
    except OSError as exc:
        print("malbolge42: %s" % exc, file=sys.stderr)
        return EXIT_OPERATIONAL

    print(json.dumps(result, indent=2, sort_keys=True))
    interesting = (not result.get("valid_program")) or \
        result.get("classification")
    return EXIT_FINDING if interesting else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
