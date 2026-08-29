"""Attestor reads mc.asm.

Attestor analyses Java, Python, C, C++, JavaScript, PHP and Terraform, and not
the one language this project actually invented. That is the gap this
closes: the same discipline, pointed at the VM's own bytecode.

Analysing the *bytecode* rather than the source is the whole trick. mc.asm
source is A1Z26 -- `1-4-4` is ADD -- so a regex over the text sees digits
and hyphens and nothing else. The bytecode is where the meaning is: every
opcode's stack effect is known, jumps are resolved to offsets, and the
routine table says what is reachable. A rule written here can prove things
a text rule could only guess at.

What it proves, and what it will not
------------------------------------
Stack depth is tracked along every path from the entry point, so an
underflow is reported only when some *reachable* path arrives at an opcode
with too few operands. Where two paths disagree, the smaller depth is kept:
the question is whether an operand can be missing, not whether it usually
is, so that is the sound direction.

It does not decide whether a loop terminates. That is the halting problem,
and a rule that guessed would be wrong quietly.
"""

from __future__ import annotations

import pathlib
import sys
from dataclasses import dataclass

_HERE = pathlib.Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import compiler                     # noqa: E402
import mc_asm                       # noqa: E402

__all__ = ["Finding", "analyse", "analyse_source", "EFFECTS", "main"]

#: (operands taken, results left) per opcode. PUSH and the jumps are handled
#: separately because they carry an operand in the code stream.
EFFECTS = {
    "ADD": (2, 1), "SUB": (2, 1), "MUL": (2, 1), "DIV": (2, 1), "MOD": (2, 1),
    "NEG": (1, 1), "DUP": (1, 2), "DROP": (1, 0), "SWAP": (2, 2),
    "OVER": (2, 3), "EQ": (2, 1), "LT": (2, 1), "GT": (2, 1), "NOT": (1, 1),
    "PRINT": (1, 0), "EMIT": (1, 0), "PUTC": (1, 0), "NL": (0, 0),
    "STORE": (2, 0), "LOAD": (1, 1), "HALT": (0, 0),
    "ROT": (3, 3), "DEPTH": (0, 1), "CALL": (1, 0), "RET": (0, 0),
    "FRAME": (1, 0), "GET": (1, 1), "PUT": (2, 0),
}


@dataclass(frozen=True)
class Finding:
    offset: int
    rule: str
    severity: str
    message: str
    fix: str

    def __str__(self) -> str:
        return "%5d  [%s] %s" % (self.offset, self.rule, self.message)


def _depths(code, routines):
    """Offsets reachable from an entry point, with the depth on arrival.

    A worklist, not a straight walk: a jump target is reachable from
    wherever jumps to it, so the depths arriving there have to be merged.
    """
    push = compiler.OPCODES["PUSH"]
    jz = compiler.OPCODES["JZ"]
    jmp = compiler.OPCODES["JMP"]
    call = compiler.OPCODES["CALL"]
    stops = (compiler.OPCODES["HALT"], compiler.OPCODES["RET"])

    depth: dict = {}
    work = [(0, 0)]
    # A routine's depth on entry depends on its callers, which are dynamic.
    # Analysing from zero would report every routine that takes an argument
    # as an underflow, so routines start at the depth their own FRAME/GET
    # usage implies they were handed -- approximated here as "enough".
    for entry in routines.values():
        work.append((entry, 8))

    while work:
        position, arriving = work.pop()
        if position < 0 or position >= len(code):
            continue
        if position in depth and depth[position] <= arriving:
            continue
        depth[position] = min(depth.get(position, arriving), arriving)
        opcode = code[position]
        if opcode == push:
            work.append((position + 2, arriving + 1))
            continue
        if opcode == jz:
            after = max(arriving - 1, 0)
            work.append((code[position + 1], after))
            work.append((position + 2, after))
            continue
        if opcode == jmp:
            work.append((code[position + 1], arriving))
            continue
        if opcode in stops:
            continue
        taken, left = EFFECTS.get(compiler.NAMES.get(opcode), (0, 0))
        after = max(arriving - taken, 0) + left
        work.append((position + (2 if opcode == call else 1), after))
    return depth


def _previous(code, position):
    last = None
    for candidate in compiler._walk(code):
        if candidate >= position:
            break
        last = candidate
    return last


def analyse(code) -> list:
    """Every finding Attestor has for this bytecode."""
    routines = dict(getattr(code, "routines", {}) or {})
    depth = _depths(code, routines)
    findings: list = []

    for position in compiler._walk(code):
        opcode = code[position]
        name = compiler.NAMES.get(opcode, "?")
        if position not in depth:
            findings.append(Finding(
                position, "mcasm-unreachable", "LOW",
                "%s can never run: nothing jumps here and control does not "
                "fall through to it." % name,
                "delete it, or check that the jump above goes where you "
                "meant it to."))
            continue
        if opcode == compiler.OPCODES["PUSH"]:
            continue
        taken, _ = EFFECTS.get(name, (0, 0))
        if taken and depth[position] < taken:
            findings.append(Finding(
                position, "mcasm-stack-underflow", "HIGH",
                "%s takes %d value(s) and only %d can be on the stack on "
                "some path here." % (name, taken, depth[position]),
                "push what it consumes, or look at the branch that arrives "
                "with a shallower stack."))
        if name in ("DIV", "MOD"):
            before = _previous(code, position)
            if (before is not None
                    and code[before] == compiler.OPCODES["PUSH"]
                    and code[before + 1] == 0):
                findings.append(Finding(
                    position, "mcasm-divide-by-zero", "HIGH",
                    "%s by a literal zero, which always fails." % name,
                    "the divisor is written into the program, so this is a "
                    "typo rather than a case to guard at runtime."))

    calls = [p for p in compiler._walk(code)
             if code[p] == compiler.OPCODES["CALL"]]
    if routines and not calls:
        for rid, entry in sorted(routines.items()):
            findings.append(Finding(
                entry, "mcasm-unused-routine", "LOW",
                "routine %d is defined and never called." % rid,
                "call it or delete it; a routine nothing reaches is weight "
                "the reader carries for nothing."))
    return sorted(findings, key=lambda f: (f.offset, f.rule))


def analyse_source(text: str) -> list:
    """Compile, then analyse. Raises McAsmError if it will not compile."""
    return analyse(compiler.to_bytecode(mc_asm.parse(text)))


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        sys.stdout.write("usage: attestor_mcasm.py FILE.mcasm|FILE.mcb\n")
        return 2
    path = pathlib.Path(argv[0])
    if not path.is_file():
        sys.stderr.write("attestor: %s is not a file\n" % argv[0])
        return 2
    import attestorvm
    try:
        findings = analyse(attestorvm._read(path))
    except (mc_asm.McAsmError, compiler.CompileError) as failed:
        sys.stderr.write("attestor: %s\n" % failed)
        return 1
    for finding in findings:
        sys.stdout.write("%s\n      fix: %s\n" % (finding, finding.fix))
    sys.stdout.write("%d finding(s).\n" % len(findings))
    return 1 if findings else 0


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(main())
