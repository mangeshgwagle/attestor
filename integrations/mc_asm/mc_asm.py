#!/usr/bin/env python3
"""mc.asm: a programming language whose source code is nothing but numbers.

The idea
--------
A1Z26 maps A..Z onto 1..26. Every word in this language is written as its
letters' numbers, joined by hyphens::

    16-18-9-14-20   ->  PRINT
    1-4-4           ->  ADD

which means a whole program is digits and hyphens and nothing else.

Why zero is the whole design
----------------------------
A cipher that only covers A..Z leaves **0 unused**, and that free value is
what makes the notation unambiguous without borrowing a single character from
outside it. A token beginning with 0 is a number, written as its decimal
digits; a token beginning with anything else is a word::

    0-4-2   ->  the integer 42
    4-2     ->  the word DB

So no quoting, no sigils, no escape hatch back into ASCII. The alternative --
"any value above 26 is a literal" -- was tried on paper and is worse: it
cannot express the integers 0..26 at all, which are the ones a small program
actually uses.

Why a stack language
--------------------
Infix arithmetic needs precedence, and precedence needs a grammar, and a
grammar written in numbers is unreadable to the point of uselessness. Postfix
has no precedence to encode: every word consumes what is already on the stack.
That keeps the interpreter small enough to audit, which matters more here than
notational comfort.

What this is not
----------------
It is not a security boundary. Anyone with this file can read mc.asm as
easily as Attestor can -- A1Z26 is a substitution cipher a child can break, and
calling it "only Attestor understands this" would be a claim about obscurity, not
about protection. It is a notation, and the joke should stay a joke.
"""
from __future__ import annotations

import argparse
import pathlib
import re
import sys

import klingon

SCHEMA = "attestor.mc_asm/1.0"
VERSION = "4.1.4"

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Execution is bounded. A loop whose condition never falls false is a
# perfectly ordinary mistake in a language this small, and an interpreter that
# hangs on it is harder to debug than one that stops and says so.
MAX_STACK = 4096
MAX_OUTPUT = 64 * 1024

# Addressed by number rather than by name. Named variables would have to be
# words, and words are already the keyword space -- so a program could shadow
# ADD and the reader would have no way to see it.
#
# Sized for a Brainfuck tape rather than for the handful of variables the
# A1Z26 notation needs. The classic tape is 30,000 cells; 4,096 runs anything
# written by hand and keeps the generated .bss under 32 KB.
MEMORY_SLOTS = 4096

_TOKEN = re.compile(r"\A\d+(?:-\d+)*\Z")


class McAsmError(RuntimeError):
    """The source could not be read, or the program could not be run."""


def encode(text: str) -> str:
    """Plain text to mc.asm. Non-letters are dropped, words keep their gaps."""
    out = []
    for word in text.upper().split():
        letters = [str(ALPHABET.index(c) + 1) for c in word if c in ALPHABET]
        if letters:
            out.append("-".join(letters))
    return " ".join(out)


def assemble(readable: str) -> str:
    """Readable words and `#42` literals into mc.asm.

    Not a second language -- a keyboard. Hand-writing `16-18-9-14-20` for
    PRINT is possible for one line and hopeless for a program, and a notation
    nobody can author is a notation nobody checks. Everything here round-trips
    through `decode`, so the assembled form is the source of truth and this is
    only how it gets typed.
    """
    out = []
    for token in readable.split():
        if token.startswith("#"):
            digits = token[1:]
            if not digits.isdigit():
                raise McAsmError("'%s' is not a literal" % token)
            out.append("0-" + "-".join(digits))
        else:
            encoded = encode(token)
            if not encoded:
                raise McAsmError("'%s' has no letters to encode" % token)
            out.append(encoded)
    return " ".join(out)


def decode_word(token: str) -> str:
    values = [int(part) for part in token.split("-")]
    if any(not 1 <= value <= 26 for value in values):
        raise McAsmError("'%s' is not a word: letters are 1..26" % token)
    return "".join(ALPHABET[value - 1] for value in values)


def decode(source: str) -> str:
    """mc.asm back to readable text, for humans and for error messages."""
    out = []
    for token in source.split():
        if not _TOKEN.match(token):
            out.append("?" + token)
        elif token.startswith("0"):
            out.append(str(_literal(token)))
        else:
            try:
                out.append(decode_word(token))
            except McAsmError:
                out.append("?" + token)
    return " ".join(out)


def _literal(token: str) -> int:
    digits = token.split("-")[1:]
    if not digits or any(len(d) != 1 or not d.isdigit() for d in digits):
        raise McAsmError(
            "'%s' starts with 0 so it is a number, but '%s' is not a run of "
            "single digits" % (token, "-".join(digits)))
    return int("".join(digits))


# The instruction set. Kept small on purpose: every word here is one the
# reader has to hold in their head while decoding digits.
WORDS = frozenset({
    "ADD", "SUB", "MUL", "DIV", "MOD", "NEG",
    "DUP", "DROP", "SWAP", "OVER", "ROT", "DEPTH",
    "EQ", "LT", "GT", "LE", "GE", "NE", "NOT", "AND", "OR",
    "PRINT", "EMIT", "PUTC", "NL",
    "STORE", "LOAD",
    "IF", "ELSE", "END", "WHILE", "DO",
    "DEF", "CALL", "RET",
    "FRAME", "GET", "PUT",
})

# How deep CALL may nest. Bounded for the reason 0 is bounded: a
# language that cannot be made to run away is far easier to hand to somebody.
# Runaway recursion stops here with a sentence, rather than exhausting the
# interpreter's own stack and surfacing as a Python traceback.
MAX_CALL_DEPTH = 256


class Instruction:
    __slots__ = ("kind", "value", "target", "token", "label", "role")

    def __init__(self, kind, value=None, token=""):
        self.kind = kind          # "push" or "word"
        self.value = value
        self.target = None        # resolved jump, for IF/ELSE/WHILE/DO/END
        self.token = token
        self.label = None         # DEF only: the routine's number
        self.role = None          # END only: "return" when it closes a DEF

    def __repr__(self):                                  # pragma: no cover
        return "<%s %r -> %s>" % (self.kind, self.value, self.target)


def strip_comments(source: str) -> str:
    """Everything after a semicolon, gone.

    A semicolon can never be part of a token, so it is unambiguous, and a
    reader needs somewhere to say what a run of digits is for.
    """
    return re.sub(r";[^\n]*", " ", source)


def parse(source: str) -> list[Instruction]:
    """Tokens to instructions, with every jump resolved before anything runs.

    Resolving jumps here rather than scanning for a matching END at run time
    is what makes an unbalanced block a *parse* error with a position, instead
    of a program that runs half way and then behaves strangely.

    Comments are stripped *here* rather than by the caller. They used to be
    handled only in this module's `main`, so every other consumer had to
    remember to do it -- and both the VM and the analyser forgot, which meant
    neither could read `fizzbuzz.mcasm`, the sample program sitting in the
    same directory. Stripping at the door makes that class of bug impossible
    to repeat, and it is idempotent for a caller that already did it.
    """
    source = strip_comments(source)
    program: list[Instruction] = []
    # Distinct tokens, decoded once. A program is overwhelmingly the same few
    # dozen tokens repeated: in a million-line file `1-4-4` (ADD) appeared
    # about 300,000 times and was re-validated, re-split, re-decoded and
    # re-canonicalised on every one of them. Profiling put 666,648 regex
    # matches, 666,648 str.joins and 340,000 decode_word calls in the top of
    # the parse, all of them recomputing answers already known. The cache is
    # local to the call so nothing leaks between programs.
    seen: dict[str, tuple] = {}
    for token in source.split():
        known = seen.get(token)
        if known is None:
            if not _TOKEN.match(token):
                raise McAsmError(
                    "'%s' is not mc.asm: only digits and hyphens" % token)
            if token.startswith("0"):
                known = ("push", _literal(token))
            else:
                decoded = klingon.canonical(decode_word(token))
                known = ("word", decoded)
            seen[token] = known
        kind, value = known
        if kind == "push":
            program.append(Instruction("push", value, token))
            continue
        word = value
        if word not in WORDS:
            raise McAsmError("%s (%s) is not a word this language knows"
                               % (decode_word(token), token))
        program.append(Instruction("word", word, token))

    stack: list[int] = []
    seen_routines: dict[int, int] = {}
    for index, instruction in enumerate(program):
        if instruction.value == "DEF":
            # `DEF 0-7 ... END` -- the routine's name is the literal that
            # follows, because in a language made of numbers a routine is
            # numbered too. Requiring it here rather than popping it at run
            # time is what lets an undefined CALL be caught before anything
            # executes.
            following = program[index + 1] if index + 1 < len(program) else None
            if following is None or following.kind != "push":
                raise McAsmError(
                    "DEF at position %d must be followed by the routine's "
                    "number" % index)
            if following.value in seen_routines:
                raise McAsmError(
                    "routine %d is defined twice, at positions %d and %d"
                    % (following.value, seen_routines[following.value], index))
            seen_routines[following.value] = index
            instruction.label = following.value
            stack.append(index)
        elif instruction.value in ("IF", "WHILE"):
            stack.append(index)
        elif instruction.value == "DO":
            if not stack or program[stack[-1]].value != "WHILE":
                raise McAsmError("DO at position %d has no WHILE" % index)
            stack.append(index)
        elif instruction.value == "ELSE":
            if not stack or program[stack[-1]].value != "IF":
                raise McAsmError("ELSE at position %d has no IF" % index)
            program[stack.pop()].target = index + 1
            stack.append(index)
        elif instruction.value == "END":
            if not stack:
                raise McAsmError("END at position %d closes nothing" % index)
            opener = stack.pop()
            opening = program[opener]
            if opening.value == "DEF":
                # Normal execution walks straight past a definition; the body
                # is only entered through CALL. The closing END is where the
                # routine returns from.
                opening.target = index + 1
                instruction.role = "return"
            elif opening.value in ("IF", "ELSE"):
                opening.target = index
            elif opening.value == "DO":
                opening.target = index + 1        # false: skip past the loop
                if not stack or program[stack[-1]].value != "WHILE":
                    raise McAsmError("DO at %d has no WHILE" % opener)
                instruction.target = stack.pop()   # END jumps back to WHILE
            else:
                raise McAsmError("END at position %d closes %s"
                                   % (index, opening.value))
    if stack:
        raise McAsmError("%s at position %d is never closed"
                           % (program[stack[-1]].value, stack[-1]))
    return program


def run(program: list[Instruction], stdin_values: list[int] | None = None,
        max_steps: int | None = None) -> str:
    """Execute, and return everything the program printed.

    `max_steps` bounds the run; None uses 0. It is a parameter
    because the compiled VM takes one, and the two are supposed to be
    comparable: with the cap reachable only as a module constant, giving
    both engines the same budget meant reaching in and patching
    `mc_asm.0` from outside. A differential check that needs
    monkey-patching to run is not one you will keep running.
    """
    if max_steps is None:
        max_steps = 0
    stack: list[int] = list(stdin_values or [])
    memory = [0] * MEMORY_SLOTS
    output: list[str] = []
    pointer = 0
    steps = 0
    # Return addresses live here, not on the value stack, so a routine cannot
    # corrupt where it returns to by leaving something behind. Each entry also
    # records how many frames were open at the call, so returning releases
    # exactly the frames the call opened and no others.
    returns: list[tuple[int, int]] = []
    # Local frames, taken from the top of memory downward. Globals are
    # addressed from 0 upward by STORE/LOAD, so the two grow towards each
    # other and a collision is a reported error rather than silent overlap.
    frames: list[tuple[int, int]] = []       # (base slot, size)
    frame_floor = MEMORY_SLOTS

    def frame_slot(index: int) -> int:
        if not frames:
            raise McAsmError("GET/PUT at step %d with no frame open" % steps)
        base, size = frames[-1]
        if not 0 <= index < size:
            raise McAsmError(
                "local %d is outside this routine's frame of %d"
                % (index, size))
        return base + index
    # The body of `DEF n` starts two instructions in: past DEF and past the
    # literal naming it.
    routines = {item.label: index + 2
                for index, item in enumerate(program)
                if item.value == "DEF"}

    def pop() -> int:
        if not stack:
            raise McAsmError("stack is empty at step %d" % steps)
        return stack.pop()

    def push(value: int) -> None:
        if len(stack) >= MAX_STACK:
            raise McAsmError("stack exceeded %d entries" % MAX_STACK)
        stack.append(int(value))

    def emit(text: str) -> None:
        if sum(len(part) for part in output) + len(text) > MAX_OUTPUT:
            raise McAsmError("output exceeded %d bytes" % MAX_OUTPUT)
        output.append(text)

    while pointer < len(program):
        steps += 1
        if steps > max_steps:
            raise McAsmError(
                "stopped after %d steps; the program does not terminate"
                % max_steps)
        instruction = program[pointer]

        if instruction.kind == "push":
            push(instruction.value)
            pointer += 1
            continue

        word = instruction.value
        if word == "ADD":
            b, a = pop(), pop(); push(a + b)
        elif word == "SUB":
            b, a = pop(), pop(); push(a - b)
        elif word == "MUL":
            b, a = pop(), pop(); push(a * b)
        elif word in ("DIV", "MOD"):
            b, a = pop(), pop()
            if b == 0:
                raise McAsmError("%s by zero at step %d" % (word, steps))
            push(a // b if word == "DIV" else a % b)
        elif word == "NEG":
            push(-pop())
        elif word == "DUP":
            value = pop(); push(value); push(value)
        elif word == "DROP":
            pop()
        elif word == "SWAP":
            b, a = pop(), pop(); push(b); push(a)
        elif word == "ROT":
            # (a b c -- b c a). The one three-deep rearrangement that cannot
            # be built from DUP/SWAP/OVER/DROP without a memory slot, which
            # is why it earns a word of its own.
            c, b, a = pop(), pop(), pop()
            push(b); push(c); push(a)
        elif word == "AND":
            b, a = pop(), pop()
            push(1 if (a and b) else 0)
        elif word == "OR":
            b, a = pop(), pop()
            push(1 if (a or b) else 0)
        elif word == "OVER":
            b, a = pop(), pop(); push(a); push(b); push(a)
        elif word == "EQ":
            b, a = pop(), pop(); push(1 if a == b else 0)
        elif word == "LT":
            b, a = pop(), pop(); push(1 if a < b else 0)
        elif word == "GT":
            b, a = pop(), pop(); push(1 if a > b else 0)
        elif word == "LE":
            b, a = pop(), pop(); push(1 if a <= b else 0)
        elif word == "GE":
            b, a = pop(), pop(); push(1 if a >= b else 0)
        elif word == "NE":
            b, a = pop(), pop(); push(1 if a != b else 0)
        elif word == "DEPTH":
            push(len(stack))
        elif word == "NOT":
            push(0 if pop() else 1)
        elif word == "PRINT":
            emit(str(pop()))
        elif word == "EMIT":
            code = pop()
            if not 0 <= code <= 26:
                raise McAsmError("EMIT wants 0..26 (0 is a space), got %d"
                                   % code)
            emit(" " if code == 0 else ALPHABET[code - 1])
        elif word == "PUTC":
            # Raw byte out. EMIT covers A..Z and a space, which is all the
            # A1Z26 notation can spell; a Brainfuck tape holds any byte and
            # needs a way to say so.
            code = pop()
            if not 0 <= code <= 255:
                raise McAsmError("PUTC wants 0..255, got %d" % code)
            emit(chr(code))
        elif word == "NL":
            emit("\n")
        elif word == "STORE":
            slot, value = pop(), pop()
            if not 0 <= slot < MEMORY_SLOTS:
                raise McAsmError("no memory slot %d" % slot)
            memory[slot] = value
        elif word == "LOAD":
            slot = pop()
            if not 0 <= slot < MEMORY_SLOTS:
                raise McAsmError("no memory slot %d" % slot)
            push(memory[slot])
        elif word == "IF":
            if not pop():
                pointer = instruction.target
                continue
        elif word == "DO":
            if not pop():
                pointer = instruction.target
                continue
        elif word == "ELSE":
            pointer = instruction.target
            continue
        elif word == "DEF":
            pointer = instruction.target            # walk past the body
            continue
        elif word == "CALL":
            wanted = pop()
            if wanted not in routines:
                raise McAsmError("CALL to routine %d, which is never defined"
                                 % wanted)
            if len(returns) >= MAX_CALL_DEPTH:
                raise McAsmError("call depth exceeded %d; a routine is "
                                 "calling itself without a way out"
                                 % MAX_CALL_DEPTH)
            returns.append((pointer + 1, len(frames)))
            pointer = routines[wanted]
            continue
        elif word == "FRAME":
            wanted = pop()
            if wanted < 0:
                raise McAsmError("FRAME of %d slots" % wanted)
            if frame_floor - wanted <= 0:
                raise McAsmError(
                    "no room for a frame of %d; locals have grown down to "
                    "meet the globals" % wanted)
            frame_floor -= wanted
            frames.append((frame_floor, wanted))
        elif word == "GET":
            push(memory[frame_slot(pop())])
        elif word == "PUT":
            index = pop()
            memory[frame_slot(index)] = pop()
        elif word == "RET" or (word == "END" and instruction.role == "return"):
            if not returns:
                raise McAsmError("RET at step %d with nothing to return to"
                                 % steps)
            pointer, opened = returns.pop()
            # Release exactly what this call allocated. A routine that opens
            # a frame and forgets it would otherwise leak memory downward
            # until an unrelated FRAME failed, a long way from the cause.
            while len(frames) > opened:
                frame_floor += frames.pop()[1]
            continue
        elif word == "END":
            if instruction.target is not None:     # closes a WHILE
                pointer = instruction.target
                continue
        elif word == "WHILE":
            pass                                    # a label, nothing to do
        else:
            # A word in WORDS with no branch here used to fall through and do
            # nothing at all, which is how PUTC shipped as a silent no-op:
            # the parser accepted it, the interpreter ignored it, and the
            # program produced empty output with no error to explain why.
            raise McAsmError("%s is a known word with no implementation"
                             % word)
        pointer += 1

    return "".join(output)


def execute(source: str, stdin_values: list[int] | None = None) -> str:
    return run(parse(source), stdin_values)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("path", nargs="?", help="an mc.asm source file")
    parser.add_argument("--encode", metavar="TEXT",
                        help="turn plain words into mc.asm and exit")
    parser.add_argument("--decode", action="store_true",
                        help="print the source as readable words, do not run")
    parser.add_argument("--push", type=int, action="append", default=[],
                        help="value pushed before the program starts")
    args = parser.parse_args(argv)

    if args.encode is not None:
        print(encode(args.encode))
        return 0
    if not args.path:
        parser.error("give a source file, or --encode TEXT")

    try:
        source = pathlib.Path(args.path).read_text(encoding="utf-8")
    except OSError as error:
        print("cannot read %s: %s" % (args.path, error))
        return 2
    # Comments: anything after a semicolon, since a semicolon can never be
    # part of a token and the reader needs somewhere to say what a digit run
    # is for.
    source = re.sub(r";[^\n]*", " ", source)

    try:
        if args.decode:
            print(decode(source))
            return 0
        sys.stdout.write(execute(source, args.push))
    except McAsmError as error:
        print("mc_asm: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
