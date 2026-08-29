#!/usr/bin/env python3
"""attestorvm -- run, build, inspect and debug mc.asm programs.

The pieces existed and none of them was a tool. `mc_asm.py` interprets
source, `compiler.py` emits C++ and assembly, and `run_bytecode` is a fast
VM you could only reach by importing it. This is the thing you actually use:

    attestorvm run     prog.mcasm          run it
    attestorvm build   prog.mcasm -o p.mcb compile once, run many times
    attestorvm run     p.mcb               run compiled bytecode
    attestorvm disasm  p.mcb               a readable listing
    attestorvm trace   prog.mcasm          every step, with the stack
    attestorvm stats   prog.mcasm          where the time actually went
    attestorvm repl                        type words, watch the stack

The object file
---------------
A `.mcb` is UTF-8 text, not a binary blob, and that is deliberate: this
project's whole method is diffing two implementations against each other,
and an object format you cannot read in a terminal or check into git is a
format you cannot diff. It carries a magic line, the compiler version, the
routine table, the code, and a SHA-256 of the code itself -- so a file that
was truncated in transit fails when it is loaded rather than halfway
through the run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
import time

_HERE = pathlib.Path(__file__).resolve().parent
if str(_HERE) not in sys.path:
    sys.path.insert(0, str(_HERE))

import compiler                      # noqa: E402
import mc_asm                        # noqa: E402
from mc_asm import McAsmError        # noqa: E402

MAGIC = "attestor.mcb/1"
__all__ = ["Machine", "build", "load", "save", "disassemble", "trace",
           "stats", "repl", "main", "MAGIC"]


# --------------------------------------------------------------------------- #
# Building and loading
# --------------------------------------------------------------------------- #

def build(source_text: str):
    """Source to bytecode, with its routine table attached."""
    return compiler.to_bytecode(mc_asm.parse(source_text))


def save(code, path: pathlib.Path) -> None:
    body = {
        "magic": MAGIC,
        "compiler": compiler.VERSION,
        "code": list(code),
        "routines": {str(k): v for k, v in
                     (getattr(code, "routines", {}) or {}).items()},
        "sha256": _digest(code),
    }
    path.write_text(json.dumps(body, indent=1) + "\n", encoding="utf-8")


def load(path: pathlib.Path):
    """Read a .mcb, refusing anything that does not check out.

    A truncated or edited object file should fail here, loudly, rather than
    part-way through a run where the symptom is a nonsense answer.
    """
    try:
        body = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as broken:
        raise McAsmError("%s is not a readable object file: %s"
                         % (path.name, broken)) from broken
    if not isinstance(body, dict) or body.get("magic") != MAGIC:
        raise McAsmError("%s is not an %s object file" % (path.name, MAGIC))
    raw = body.get("code")
    if not isinstance(raw, list) or not all(isinstance(x, int) for x in raw):
        raise McAsmError("%s has no usable code section" % path.name)
    code = compiler._Bytecode(raw)
    code.routines = {int(k): v for k, v in (body.get("routines") or {}).items()}
    if body.get("sha256") != _digest(code):
        raise McAsmError(
            "%s does not match its own digest; it was truncated or edited "
            "after it was built" % path.name)
    return code


def _digest(code) -> str:
    return hashlib.sha256(
        ",".join(str(number) for number in code).encode("ascii")).hexdigest()


def _read(path: pathlib.Path):
    """A .mcb is loaded; anything else is compiled."""
    if path.suffix == ".mcb":
        return load(path)
    return build(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- #
# Inspection
# --------------------------------------------------------------------------- #

def disassemble(code) -> str:
    """A listing: offsets, words, operands, and where the routines start."""
    routines = {offset: rid
                for rid, offset in (getattr(code, "routines", {}) or {}).items()}
    targets = {code[p + 1] for p in compiler._walk(code)
               if code[p] in (compiler.OPCODES["JZ"], compiler.OPCODES["JMP"])}
    lines = []
    for position in compiler._walk(code):
        opcode = code[position]
        word = compiler.NAMES.get(opcode, "?%d" % opcode)
        mark = ""
        if position in routines:
            mark = "  <- routine %d" % routines[position]
        elif position in targets:
            mark = "  <- jump target"
        if opcode in compiler.OPERAND and opcode != compiler.OPCODES["CALL"]:
            lines.append("%5d  %-8s %d%s"
                         % (position, word, code[position + 1], mark))
        else:
            lines.append("%5d  %-8s%s" % (position, word, mark))
    return "\n".join(lines) + "\n"


def trace(code, stdin_values=None, limit: int = 200) -> str:
    """Run one step at a time, showing the stack after each.

    Deliberately capped: a trace of a million-step loop is not a debugging
    aid, it is a denial of service against your own terminal.
    """
    lines = []
    steps = [0]

    def note(position, stack):
        if steps[0] < limit:
            opcode = code[position]
            word = compiler.NAMES.get(opcode, "?")
            operand = ""
            if opcode in compiler.OPERAND and opcode != compiler.OPCODES["CALL"]:
                operand = " %d" % code[position + 1]
            lines.append("%5d  %-8s%-6s stack=%s"
                         % (position, word, operand, stack))
        steps[0] += 1

    output = compiler.run_bytecode(code, stdin_values, observer=note)
    if steps[0] > limit:
        lines.append("... %d more steps" % (steps[0] - limit))
    lines.append("output: %r" % output)
    return "\n".join(lines) + "\n"


def stats(code, stdin_values=None) -> str:
    """How many of each word ran, and how long the whole thing took."""
    counts: dict = {}

    def note(position, _stack):
        word = compiler.NAMES.get(code[position], "?")
        counts[word] = counts.get(word, 0) + 1

    started = time.perf_counter()
    output = compiler.run_bytecode(code, stdin_values, observer=note)
    elapsed = time.perf_counter() - started
    total = sum(counts.values())
    lines = ["%d instructions in %.3fs (%.0f/s)"
             % (total, elapsed, total / elapsed if elapsed else 0), ""]
    for word, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        lines.append("  %-8s %8d  %5.1f%%"
                     % (word, count, 100.0 * count / total if total else 0))
    lines.append("")
    lines.append("output: %r" % output)
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# REPL
# --------------------------------------------------------------------------- #

def repl(read=input, write=print) -> int:
    """Type mc.asm words; the stack is shown after each line.

    Plain words are accepted as well as A1Z26, because typing `1-4-4` to get
    ADD is a fine joke in a source file and a poor one at a prompt.
    """
    write("attestorvm %s -- words or A1Z26, one line at a time. :q to leave."
          % compiler.VERSION)
    history: list[str] = []
    while True:
        try:
            line = read("mc> ")
        except (EOFError, KeyboardInterrupt):
            write("")
            return 0
        if line.strip() in {":q", ":quit", ":exit"}:
            return 0
        if not line.strip():
            continue
        if line.strip() == ":clear":
            history.clear()
            write("cleared")
            continue
        attempt = history + [line]
        try:
            source = " ".join(_as_source(part) for part in attempt)
            code = build(source)
            output = compiler.run_bytecode(code)
        except (McAsmError, compiler.CompileError) as failed:
            write("  %s" % failed)
            continue
        history = attempt
        write("  %s" % (output.replace("\n", " ") if output else "(no output)"))
    return 0


def _as_source(text: str) -> str:
    """Accept `DUP ADD 21` as readily as `4-21-16 1-4-4 0-2-1`.

    Precedence matters and is not obvious. A bare `1` is ambiguous: A1Z26
    reads it as the letter A, and mc.asm spells the *number* one as `0-1`.
    At a prompt a person typing `1` means one, so a plain run of digits
    becomes a number here and only a hyphenated token is passed through as
    already-encoded. Getting this backwards made `21 1 CALL` fail with "A is
    not a word this language knows", which is a confusing way to be told you
    typed a number.
    """
    out = []
    for token in text.split():
        if token.startswith(";"):
            break
        if token.lstrip("-").isdigit() and "-" not in token.lstrip("-"):
            sign = "-" if token.startswith("-") else ""
            out.append(sign + "0-" + "-".join(token.lstrip("-")))
        elif all(part.isdigit() for part in token.split("-") if part != ""):
            out.append(token)                       # already A1Z26
        else:
            out.append("-".join(str(ord(c) - 64) for c in token.upper()))
    return " ".join(out)


# --------------------------------------------------------------------------- #

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="attestorvm", description="run, build and inspect mc.asm programs")
    sub = parser.add_subparsers(dest="command")

    for name, helptext in (("run", "run a program"),
                           ("disasm", "print a bytecode listing"),
                           ("trace", "run one step at a time"),
                           ("stats", "count instructions and time the run")):
        one = sub.add_parser(name, help=helptext)
        one.add_argument("path")
        one.add_argument("--stdin", default="",
                         help="comma-separated numbers the program may read")
        if name == "trace":
            one.add_argument("--limit", type=int, default=200)

    builder = sub.add_parser("build", help="compile to a .mcb object file")
    builder.add_argument("path")
    builder.add_argument("-o", "--out", required=True)

    sub.add_parser("repl", help="an interactive prompt")

    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 2
    if args.command == "repl":
        return repl()

    path = pathlib.Path(args.path)
    if not path.is_file():
        sys.stderr.write("attestorvm: %s is not a file\n" % args.path)
        return 2
    try:
        code = _read(path)
        if args.command == "build":
            target = pathlib.Path(args.out)
            save(code, target)
            sys.stdout.write("wrote %s (%d opcodes, %d routine(s))\n"
                             % (target.name, len(code),
                                len(getattr(code, "routines", {}) or {})))
            return 0
        values = [int(part) for part in args.stdin.split(",") if part.strip()]
        if args.command == "disasm":
            sys.stdout.write(disassemble(code))
        elif args.command == "trace":
            sys.stdout.write(trace(code, values, limit=args.limit))
        elif args.command == "stats":
            sys.stdout.write(stats(code, values))
        else:
            sys.stdout.write(compiler.run_bytecode(code, values))
    except (McAsmError, compiler.CompileError) as failed:
        sys.stderr.write("attestorvm: %s\n" % failed)
        return 1
    return 0


if __name__ == "__main__":       # pragma: no cover
    raise SystemExit(main())


# --------------------------------------------------------------------------- #
# A machine you can hold on to.
# --------------------------------------------------------------------------- #

class Machine:
    """One loaded program, ready to run more than once.

    The functions above are fine for a command line, where every invocation
    starts from nothing. They are the wrong shape for using the VM *inside*
    something -- Attestor's analyser, a test harness, a REPL -- where you load a
    program once and then run it repeatedly with different inputs, look at
    what it did, and run it again.

    A Machine is that: parse and compile happen at construction, and each
    `run` is a fresh execution against the same compiled code. Nothing is
    carried between runs, because a VM that remembers the last run is a VM
    whose second answer you cannot trust.
    """

    def __init__(self, source=None, code=None, max_steps=2_000_000):
        if (source is None) == (code is None):
            raise ValueError("a Machine needs either source or code")
        self.source = source
        self.code = build(source) if code is None else code
        self.max_steps = max_steps
        self.last_output = ""
        self.last_steps = 0
        self.last_counts: dict = {}

    @classmethod
    def from_path(cls, path, **kwargs):
        """Load a .mcasm or a .mcb, whichever it is."""
        return cls(code=_read(pathlib.Path(path)), **kwargs)

    @property
    def routines(self) -> dict:
        return dict(getattr(self.code, "routines", {}) or {})

    def run(self, stdin_values=None, count=False) -> str:
        """Execute once. `count` records a per-word tally as it goes."""
        counts: dict = {}
        observer = None
        if count:
            def observer(position, _stack):
                word = compiler.NAMES.get(self.code[position], "?")
                counts[word] = counts.get(word, 0) + 1
        self.last_output = compiler.run_bytecode(
            self.code, stdin_values, max_steps=self.max_steps,
            observer=observer)
        self.last_counts = counts
        self.last_steps = sum(counts.values())
        return self.last_output

    def check(self) -> list:
        """What Attestor has to say about this program."""
        import attestor_mcasm
        return attestor_mcasm.analyse(self.code)

    def disassemble(self) -> str:
        return disassemble(self.code)

    def agrees_with_interpreter(self, stdin_values=None) -> bool:
        """Run both engines on the same program and compare.

        This is the project's whole criterion, and it was awkward enough to
        invoke by hand that it only ran when somebody remembered. It is one
        call now, and both engines get the same step budget -- which was not
        possible until the interpreter took one as a parameter instead of
        reading a module constant.

        Needs the source, because the interpreter runs instructions and the
        VM runs bytecode; a Machine loaded from a .mcb has thrown the
        instructions away and says so rather than pretending.
        """
        if self.source is None:
            raise ValueError(
                "agreement needs the source; this Machine was loaded from "
                "compiled bytecode, which the interpreter cannot run")
        program = mc_asm.parse(self.source)
        return (mc_asm.run(program, stdin_values, max_steps=self.max_steps)
                == self.run(stdin_values))

    def __len__(self) -> int:
        return len(self.code)

    def __repr__(self) -> str:
        return "<Machine %d opcodes, %d routine(s)>" % (
            len(self.code), len(self.routines))
