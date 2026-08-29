#!/usr/bin/env python3
"""mc.asm to bytecode, to C++, to x86-64 -- and a check that all three agree.

The layers
----------
::

    16-18-9-14-20        A1Z26 source        (or its Klingon spelling, 10-1)
        |                                     both decode to the same word
        v
    [11, 0]              bytecode            numeric opcodes, one per word
        |
        +--> C++         a translation unit gcc compiles
        +--> x86-64      assembly gas assembles

Why three backends and not one
------------------------------
Because the third one is how the first two get checked. An interpreter, a
compiler, and a code generator that all claim to run the same program either
produce identical output or one of them is wrong -- and *which* is wrong is
usually obvious from which two agree. That is a differential test, the same
criterion Attestor uses against Juliet, applied to a compiler instead of a rule.

Nothing here judges whether the generated assembly is *good*. It judges
whether it is *correct*, by running it. Quality would need a benchmark against
`gcc -O2` on the same computation, which is a separate harness and an honest
piece of work; correctness comes first because fast and wrong is worthless.

What "machine code" means here
------------------------------
Real opcodes for a real (small) machine: each mc.asm word is one byte-sized
number, and PUSH and the jumps carry an operand. That is a bytecode, not x86
machine code -- the x86 comes out of the assembly backend, assembled by `as`.
Calling the bytecode "machine code" would be a stretch, so it is called
bytecode everywhere except in the joke that produced it.
"""
from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys
import tempfile

import mc_asm
from mc_asm import McAsmError

SCHEMA = "attestor.mc_asm-compiler/1.0"
VERSION = "4.1.4"

# One opcode per word. The numbers are arbitrary but fixed: a bytecode whose
# encoding drifts between runs cannot be diffed, cached, or checked in.
OPCODES = {
    "PUSH": 0,
    "ADD": 1, "SUB": 2, "MUL": 3, "DIV": 4, "MOD": 5, "NEG": 6,
    "DUP": 7, "DROP": 8, "SWAP": 9, "OVER": 10,
    "EQ": 11, "LT": 12, "GT": 13, "NOT": 14,
    "PRINT": 15, "EMIT": 16, "NL": 17,
    "STORE": 18, "LOAD": 19,
    "JZ": 20,       # pop, jump if zero        (IF and DO compile to this)
    "JMP": 21,      # unconditional            (ELSE and looping END)
    "HALT": 22,
    "PUTC": 23,
    # Subroutines and locals. These eight had no bytecode form at all, so a
    # program using a procedure ran on the interpreter and on nothing else --
    # the C++ and x86-64 backends refused it outright. Procedures are most
    # of what the language is for, so the gap was a ceiling on the language
    # rather than a missing convenience.
    #
    # CALL and RET carry the return site on their own stack rather than the
    # data stack. A routine that leaves its return address somewhere the
    # program can DROP is not a routine, it is a hazard.
    "ROT": 24,          # (a b c -- b c a)
    "DEPTH": 25,        # push how many items are on the data stack
    "CALL": 26,         # pop a routine id, remember the return site, jump
    "RET": 27,          # return, releasing exactly this call's frame
    "FRAME": 28,        # pop n, reserve n locals growing down from the top
    "GET": 29,          # pop an index, push that local
    "PUT": 30,          # pop an index and a value, store it
}
NAMES = {number: word for word, number in OPCODES.items()}
OPERAND = frozenset({OPCODES["PUSH"], OPCODES["JZ"], OPCODES["JMP"],
                     OPCODES["CALL"]})

STACK_SIZE = 4096
MEMORY_SLOTS = mc_asm.MEMORY_SLOTS


class CompileError(RuntimeError):
    """The program could not be lowered, or a backend disagreed."""


# Words the interpreter gained that the bytecode never did, expressed in
# opcodes it already has. Doing it here rather than adding opcodes keeps the
# C++ and x86-64 emitters untouched and puts these five back inside the
# three-way agreement, which is the only reason the compiled backends exist.
#
#   LE  a<=b  is  not(a>b)          NE  a!=b  is  not(a==b)
#   GE  a>=b  is  not(a<b)
#
# AND and OR need both operands reduced to 0/1 first, because the machine's
# integers are arbitrary precision and a truthy value is any nonzero. `NOT
# NOT` is that reduction; MUL is then conjunction, and De Morgan gives OR
# without a second multiply.
#
# Not lowered, and honestly out of reach without new opcodes: ROT (no way to
# reach the third stack item without scratch memory this cannot safely
# claim), DEPTH (the stack height is not observable), and the whole of
# DEF/CALL/RET/FRAME/GET/PUT, which need a return stack and a frame pointer
# the bytecode has no notion of.
LOWERED = {
    "LE": ("GT", "NOT"),
    "GE": ("LT", "NOT"),
    "NE": ("EQ", "NOT"),
    "AND": ("NOT", "NOT", "SWAP", "NOT", "NOT", "MUL"),
    "OR": ("NOT", "SWAP", "NOT", "MUL", "NOT"),
}


def to_bytecode(program) -> list[int]:
    """Instructions to a flat [opcode, operand?, ...] list.

    Addresses are *bytecode* offsets, not instruction indices, and the two
    differ because PUSH and the jumps carry an operand. Emitting first and
    patching afterwards is the only way to know an address before the code it
    points past has been sized.
    """
    code: list[int] = []
    offset_of: dict[int, int] = {}      # instruction index -> bytecode offset
    patches: list[tuple[int, int]] = []  # (slot in code, target index)

    skip_next_push = False
    for index, instruction in enumerate(program):
        offset_of[index] = len(code)
        if instruction.kind == "push":
            if skip_next_push:
                # A DEF's routine id names the routine at compile time. It
                # was *also* emitted as a runtime PUSH, which the DEF's own
                # jump then skipped straight over -- dead bytecode in every
                # program that defines a routine. Attestor's mc.asm analyser
                # reported it as unreachable, which is precisely the sort of
                # thing an analyser is for.
                skip_next_push = False
                continue
            code += [OPCODES["PUSH"], instruction.value]
            continue
        word = instruction.value
        if word == "DEF":
            skip_next_push = True
        if word in ("IF", "DO"):
            code.append(OPCODES["JZ"])
            patches.append((len(code), instruction.target))
            code.append(0)
        elif word == "ELSE":
            code.append(OPCODES["JMP"])
            patches.append((len(code), instruction.target))
            code.append(0)
        elif word == "END":
            if getattr(instruction, "role", None) == "return":
                # `RET END` is a legal way to close a routine and emitted
                # two RETs, the second unreachable. Attestor found that one too.
                if not code or code[-1] != OPCODES["RET"]:
                    code.append(OPCODES["RET"])
                continue
            if instruction.target is None:      # closes an IF: no code
                continue
            code.append(OPCODES["JMP"])
            patches.append((len(code), instruction.target))
            code.append(0)
        elif word == "WHILE":
            continue                            # a label only
        elif word == "DEF":
            # The body is emitted where it stands and jumped over, so the
            # routine's address is known without a second pass and falling
            # off the end of the program cannot walk into a definition.
            code.append(OPCODES["JMP"])
            patches.append((len(code), instruction.target))
            code.append(0)
        elif word == "CALL":
            # The routine id is on the stack at runtime, so the operand slot
            # is unused and kept only so CALL sizes like the other jumps --
            # the address table is built from DEF sites, not from here.
            code.append(OPCODES["CALL"])
            code.append(0)
        elif word == "RET":
            code.append(OPCODES["RET"])
        elif word in LOWERED:
            code += [OPCODES[part] for part in LOWERED[word]]
        elif word not in OPCODES:
            raise CompileError(
                "%s has no bytecode form, so the compiled backends cannot "
                "run it; the interpreter can. Until it is lowered, a program "
                "using it is outside the three-way agreement" % word)
        else:
            code.append(OPCODES[word])
    offset_of[len(program)] = len(code)
    code.append(OPCODES["HALT"])

    for slot, target in patches:
        if target is None or target not in offset_of:
            raise CompileError("unresolved jump to %r" % target)
        code[slot] = offset_of[target]

    # Routine id -> where its body starts. CALL takes the id off the stack,
    # so dispatch is dynamic and the table has to survive to runtime; it is
    # attached to the code rather than returned separately so that every
    # existing caller of to_bytecode() keeps getting a plain list.
    routines: dict[int, int] = {}
    for index, instruction in enumerate(program):
        if instruction.kind == "push" or instruction.value != "DEF":
            continue
        label = getattr(instruction, "label", None)
        if label is None:
            continue
        # DEF, then the push of the id, then the body.
        routines[label] = offset_of[index + 2]
    code = _Bytecode(code)
    code.routines = routines
    return code


class _Bytecode(list):
    """A list of opcodes that also remembers where the routines are.

    Subclassing list rather than returning a pair keeps `to_bytecode`
    signature-compatible with everything that already consumes it -- the
    C++ and x86-64 emitters index it, compare it, and write it out, and none
    of them should have to learn about a wrapper to gain subroutines.
    """

    routines: dict = {}


def disassemble(code: list[int]) -> str:
    out, position = [], 0
    while position < len(code):
        opcode = code[position]
        name = NAMES.get(opcode, "?%d" % opcode)
        if opcode in OPERAND:
            out.append("%4d  %-5s %d" % (position, name, code[position + 1]))
            position += 2
        else:
            out.append("%4d  %s" % (position, name))
            position += 1
    return "\n".join(out)


# ---- C++ backend ---------------------------------------------------------- #

_CPP_OPS = {
    "ADD": "b=pop();a=pop();push(a+b);",
    "SUB": "b=pop();a=pop();push(a-b);",
    "MUL": "b=pop();a=pop();push(a*b);",
    "DIV": "b=pop();a=pop();if(!b){fail(\"DIV by zero\");}push(divf(a,b));",
    "MOD": "b=pop();a=pop();if(!b){fail(\"MOD by zero\");}push(modf_(a,b));",
    "NEG": "push(-pop());",
    "DUP": "a=pop();push(a);push(a);",
    "DROP": "pop();",
    "SWAP": "b=pop();a=pop();push(b);push(a);",
    "OVER": "b=pop();a=pop();push(a);push(b);push(a);",
    "EQ": "b=pop();a=pop();push(a==b?1:0);",
    "LT": "b=pop();a=pop();push(a<b?1:0);",
    "GT": "b=pop();a=pop();push(a>b?1:0);",
    "NOT": "push(pop()?0:1);",
    "PRINT": "printf(\"%lld\",(long long)pop());",
    "EMIT": "a=pop();if(a<0||a>26){fail(\"EMIT range\");}"
            "putchar(a==0?' ':(int)('A'+a-1));",
    "PUTC": "a=pop();if(a<0||a>255){fail(\"PUTC range\");}putchar((int)a);",
    "NL": "putchar('\\n');",
    "STORE": "b=pop();a=pop();if(b<0||b>=SLOTS){fail(\"slot\");}mem[b]=a;",
    "LOAD": "a=pop();if(a<0||a>=SLOTS){fail(\"slot\");}push(mem[a]);",
    # The stack-shuffling and frame words. CALL and RET are not here: they
    # need a label per call site, so they are emitted inline by to_cpp().
    "ROT": "c=pop();b=pop();a=pop();push(b);push(c);push(a);",
    "DEPTH": "push((long long)sp);",
    "FRAME": "a=pop();if(a<0){fail(\"FRAME negative\");}"
             "if(floor_-a<=0){fail(\"no room for frame\");}"
             "floor_-=a;fbase[fp]=floor_;fsize[fp]=a;fp++;",
    "GET": "a=pop();if(!fp){fail(\"GET with no frame\");}"
           "if(a<0||a>=fsize[fp-1]){fail(\"local out of frame\");}"
           "push(mem[fbase[fp-1]+a]);",
    "PUT": "a=pop();b=pop();if(!fp){fail(\"PUT with no frame\");}"
           "if(a<0||a>=fsize[fp-1]){fail(\"local out of frame\");}"
           "mem[fbase[fp-1]+a]=b;",
}

_CPP_PRELUDE = """\
// Generated by mc.asm compiler %s. Do not edit.
#include <cstdio>
#include <cstdlib>
#include <cstdint>

static const int SLOTS = %d;
static int64_t st[%d];
static int sp = 0;
static int64_t mem[%d];

static void fail(const char *why) { fprintf(stderr, "mc_asm: %%s\\n", why); exit(1); }
static void push(int64_t v) { if (sp >= %d) fail("stack overflow"); st[sp++] = v; }
static int64_t pop() { if (sp <= 0) fail("stack empty"); return st[--sp]; }
// mc.asm divides like Python: toward negative infinity, remainder takes the
// divisor's sign. C++ truncates toward zero, so the two disagree on negative
// operands and a program would quietly give different answers per backend.
static int64_t divf(int64_t a, int64_t b) { int64_t q = a / b; if ((a %% b) && ((a < 0) != (b < 0))) q--; return q; }
static int64_t modf_(int64_t a, int64_t b) { int64_t r = a %% b; if (r && ((r < 0) != (b < 0))) r += b; return r; }

// Locals grow down from the top of memory; globals grow up from 0. They meet
// in the middle and FRAME refuses when they would cross.
static int64_t fbase[256];
static int64_t fsize[256];
static int fp = 0;
static int64_t floor_ = %d;
// The return stack is its own array. Putting return addresses on the data
// stack would let a program DROP its own way home.
static int rstack[256];
static int rmark[256];
static int rp = 0;

int main() {
    int64_t a = 0, b = 0, c = 0;
    (void)a; (void)b; (void)c;
"""


def to_cpp(code: list[int]) -> str:
    """Bytecode to a C++ translation unit.

    CALL and RET are the awkward pair. The routine id is only known at
    runtime, and C++ has no portable computed goto, so each is emitted as a
    `switch`: a call site switches on the id to reach the routine, and RET
    switches on a per-call-site number to get back. That costs a jump table
    apiece and keeps the file compilable by any conforming compiler, which
    matters more here than the cycles -- this backend exists to *check* the
    interpreter, so it has to build everywhere the interpreter runs.
    """
    routines = getattr(code, "routines", {}) or {}
    lines = [_CPP_PRELUDE % (VERSION, MEMORY_SLOTS, STACK_SIZE,
                             MEMORY_SLOTS, STACK_SIZE, MEMORY_SLOTS)]
    targets = {code[position + 1]
               for position in _walk(code) if code[position] in
               (OPCODES["JZ"], OPCODES["JMP"])}
    targets |= set(routines.values())
    call_sites = [p for p in _walk(code) if code[p] == OPCODES["CALL"]]
    site_number = {position: index for index, position in enumerate(call_sites)}

    for position in _walk(code):
        opcode = code[position]
        if position in targets:
            lines.append("L%d:;" % position)
        if opcode == OPCODES["PUSH"]:
            lines.append("    push(%dLL);" % code[position + 1])
        elif opcode == OPCODES["JZ"]:
            lines.append("    if (!pop()) goto L%d;" % code[position + 1])
        elif opcode == OPCODES["JMP"]:
            lines.append("    goto L%d;" % code[position + 1])
        elif opcode == OPCODES["CALL"]:
            number = site_number[position]
            arms = " ".join("case %d: goto L%d;" % (rid, offset)
                            for rid, offset in sorted(routines.items()))
            lines.append(
                '    if (rp >= 256) fail("call depth exceeded");'
                ' rstack[rp] = %d; rmark[rp] = fp; rp++;' % number)
            lines.append('    switch ((int)pop()) { %s default: '
                         'fail("CALL to an undefined routine"); }' % arms)
            lines.append("R%d:;" % number)
        elif opcode == OPCODES["RET"]:
            arms = " ".join("case %d: goto R%d;" % (n, n)
                            for n in sorted(site_number.values()))
            lines.append('    if (!rp) fail("RET with nothing to return to");')
            # Release exactly what this call allocated, no more.
            lines.append("    rp--; while (fp > rmark[rp]) { fp--; "
                         "floor_ += fsize[fp]; }")
            lines.append('    switch (rstack[rp]) { %s default: '
                         'fail("corrupt return stack"); }' % arms
                         if arms else '    fail("RET with no call sites");')
        elif opcode == OPCODES["HALT"]:
            # No label here: HALT is a jump target like any other, and the
            # block above already emitted one. Emitting it twice is a
            # duplicate-label error, which is what happens whenever the last
            # statement of a program is the end of a loop.
            lines.append("    return 0;")
        else:
            lines.append("    " + _CPP_OPS[NAMES[opcode]])
    lines.append("}")
    return "\n".join(lines) + "\n"


def _walk(code: list[int]):
    position = 0
    while position < len(code):
        yield position
        position += 2 if code[position] in OPERAND else 1


# ---- x86-64 backend ------------------------------------------------------- #
#
# The stack lives in a static array with r12 as its index, rather than on the
# machine stack: mixing the language's stack with the ABI's would mean every
# call to printf had to be balanced against whatever the program left behind.
# Registers are chosen from the callee-saved set for the same reason -- printf
# may clobber anything volatile.
#
# The Windows x64 ABI needs 32 bytes of shadow space and a 16-byte aligned rsp
# at the call; System V needs only the alignment. Reserving 40 bytes once in
# the prologue satisfies both and keeps rsp aligned for the whole body.

def to_asm(code: list[int]) -> str:
    """x86-64 (AT&T syntax) for gas, targeting the Windows x64 ABI."""
    out = [
        "# Generated by mc.asm compiler %s. Do not edit." % VERSION,
        "    .text",
        "    .globl main",
        "main:",
        "    pushq %rbp",
        "    movq %rsp, %rbp",
        "    pushq %r12",
        "    pushq %r13",
        # rbx is callee-saved and this code uses it as a scratch register in
        # every binary operation. Saving it is not optional -- and it also
        # fixes the alignment: entry has rsp = 8 (mod 16), four pushes bring
        # it to 8, and subtracting 40 lands on 0, which is what the ABI
        # requires *at* a call. With three pushes the same 40 left it at 8 and
        # every call to printf crashed with an access violation.
        "    pushq %rbx",
        "    subq $40, %rsp",          # shadow space, keeps rsp 16-aligned
        "    xorl %r12d, %r12d",       # stack pointer index
        # The stack's base is loaded once, RIP-relative. Addressing it
        # absolutely -- `ostack(,%r12,8)` -- assembles and then fails at link
        # time with "relocation truncated to fit: R_X86_64_32S", because a
        # 32-bit signed displacement cannot reach .bss at a Windows image
        # base. RIP-relative has no such range problem and is position
        # independent besides.
        "    leaq ostack(%rip), %r13",
        # Locals grow down from the top of memory.
        "    leaq ffloor(%rip), %rax",
        "    movq $%d, (%%rax)" % MEMORY_SLOTS,
    ]

    def push_rax():
        return ["    movq %rax, (%r13,%r12,8)", "    incq %r12"]

    def pop_rax():
        return ["    decq %r12", "    movq (%r13,%r12,8), %rax"]

    def pop_two():                     # b -> rbx, a -> rax
        return ["    decq %r12", "    movq (%r13,%r12,8), %rbx",
                "    decq %r12", "    movq (%r13,%r12,8), %rax"]

    def compare(setcc):
        return pop_two() + [
            "    cmpq %rbx, %rax", "    %s %%al" % setcc,
            "    movzbq %al, %rax"] + push_rax()

    routines = getattr(code, "routines", {}) or {}
    targets = {code[position + 1] for position in _walk(code)
               if code[position] in (OPCODES["JZ"], OPCODES["JMP"])}
    targets |= set(routines.values())
    call_sites = [p for p in _walk(code) if code[p] == OPCODES["CALL"]]
    site_number = {position: index for index, position in enumerate(call_sites)}

    for position in _walk(code):
        opcode = code[position]
        if position in targets:
            out.append("L%d:" % position)
        name = NAMES[opcode]

        if opcode == OPCODES["PUSH"]:
            out += ["    movq $%d, %%rax" % code[position + 1]] + push_rax()
        elif name == "ADD":
            out += pop_two() + ["    addq %rbx, %rax"] + push_rax()
        elif name == "SUB":
            out += pop_two() + ["    subq %rbx, %rax"] + push_rax()
        elif name == "MUL":
            out += pop_two() + ["    imulq %rbx, %rax"] + push_rax()
        elif name in ("DIV", "MOD"):
            # Floor division, to match the interpreter and the C++ backend.
            # idivq truncates toward zero, so the quotient is corrected when
            # the remainder is non-zero and the operand signs differ.
            out += pop_two() + [
                "    testq %rbx, %rbx",
                "    jne 1f",
                # Both ABIs' first integer argument, so the same two moves
                # work whether this is assembled for Windows or System V.
                "    movl $1, %ecx",
                "    movl $1, %edi",
                "    call exit",
                "1:  cqto",
                "    idivq %rbx",          # rax = quotient, rdx = remainder
                "    testq %rdx, %rdx",
                "    je 2f",
                "    movq %rax, %rcx",
                "    xorq %rbx, %rcx",
                "    jns 2f",
            ]
            if name == "DIV":
                out += ["    decq %rax"]
            else:
                out += ["    addq %rbx, %rdx"]
            out += ["2:"]
            out += ["    movq %rdx, %rax"] if name == "MOD" else []
            out += push_rax()
        elif name == "NEG":
            out += pop_rax() + ["    negq %rax"] + push_rax()
        elif name == "DUP":
            out += pop_rax() + push_rax() + push_rax()
        elif name == "DROP":
            out += ["    decq %r12"]
        elif name == "SWAP":
            out += pop_two() + ["    movq %rax, %rcx", "    movq %rbx, %rax"] \
                + push_rax() + ["    movq %rcx, %rax"] + push_rax()
        elif name == "OVER":
            out += pop_two() + ["    movq %rax, %rcx"] + push_rax() \
                + ["    movq %rbx, %rax"] + push_rax() \
                + ["    movq %rcx, %rax"] + push_rax()
        elif name == "EQ":
            out += compare("sete")
        elif name == "LT":
            out += compare("setl")
        elif name == "GT":
            out += compare("setg")
        elif name == "NOT":
            out += pop_rax() + ["    testq %rax, %rax", "    sete %al",
                                "    movzbq %al, %rax"] + push_rax()
        elif name == "PRINT":
            out += pop_rax() + [
                "    movq %rax, %rdx",
                "    leaq fmt(%rip), %rcx",
                "    movq %rcx, %rdi", "    movq %rdx, %rsi",
                "    xorl %eax, %eax",
                "    call printf",
            ]
        elif name == "EMIT":
            out += pop_rax() + [
                "    testq %rax, %rax",
                "    jne 3f",
                "    movq $32, %rax",
                "    jmp 4f",
                "3:  addq $64, %rax",
                "4:  movq %rax, %rcx",
                "    movq %rax, %rdi",
                "    call putchar",
            ]
        elif name == "PUTC":
            out += pop_rax() + [
                "    movq %rax, %rcx",     # Windows x64 first argument
                "    movq %rax, %rdi",     # System V first argument
                "    call putchar"]
        elif name == "NL":
            out += ["    movq $10, %rcx", "    movq $10, %rdi",
                    "    call putchar"]
        elif name == "STORE":
            out += pop_two() + [           # rbx = slot, rax = value
                "    leaq omem(%rip), %rcx",
                "    movq %rax, (%rcx,%rbx,8)"]
        elif name == "LOAD":
            out += pop_rax() + [
                "    leaq omem(%rip), %rcx",
                "    movq (%rcx,%rax,8), %rax"] + push_rax()
        elif name == "ROT":
            out += pop_rax() + ["    movq %rax, %rsi"]        # c
            out += pop_rax() + ["    movq %rax, %rdi"]        # b
            out += pop_rax()                                   # a in rax
            out += ["    movq %rdi, %rdx"]
            out += ["    movq %rdx, (%r13,%r12,8)", "    incq %r12"]  # b
            out += ["    movq %rsi, (%r13,%r12,8)", "    incq %r12"]  # c
            out += push_rax()                                  # a
        elif name == "DEPTH":
            out += ["    movq %r12, %rax"] + push_rax()
        elif name == "FRAME":
            # floor -= n; remember base and size for this frame.
            out += pop_rax() + [
                "    leaq ffloor(%rip), %rcx",
                "    subq %rax, (%rcx)",
                "    movq (%rcx), %rdx",
                "    leaq ffp(%rip), %rcx",
                "    movq (%rcx), %rsi",
                "    leaq fbase(%rip), %rdi",
                "    movq %rdx, (%rdi,%rsi,8)",
                "    leaq fsize(%rip), %rdi",
                "    movq %rax, (%rdi,%rsi,8)",
                "    incq %rsi",
                "    movq %rsi, (%rcx)"]
        elif name in ("GET", "PUT"):
            # base = fbase[ffp-1]; slot = base + index.
            out += pop_rax() + [
                "    leaq ffp(%rip), %rcx",
                "    movq (%rcx), %rsi",
                "    decq %rsi",
                "    leaq fbase(%rip), %rdi",
                "    addq (%rdi,%rsi,8), %rax",
                "    leaq omem(%rip), %rcx"]
            if name == "GET":
                out += ["    movq (%rcx,%rax,8), %rax"] + push_rax()
            else:
                out += ["    movq %rax, %rdx"] + pop_rax() + [
                    "    movq %rax, (%rcx,%rdx,8)"]
        elif opcode == OPCODES["CALL"]:
            # The machine's own call and ret carry the return address, on the
            # ABI stack, where the program cannot reach it. `call` pushes 8
            # bytes and would leave rsp misaligned inside the routine, so the
            # extra 8 here is what keeps every printf in a callee from
            # crashing on the Windows ABI.
            number = site_number[position]
            out += pop_rax()
            for rid, offset in sorted(routines.items()):
                out += ["    cmpq $%d, %%rax" % rid,
                        "    je .Lcall%d_%d" % (number, rid)]
            out += ["    movl $1, %ecx", "    movl $1, %edi", "    call exit"]
            for rid, offset in sorted(routines.items()):
                out += [".Lcall%d_%d:" % (number, rid),
                        "    subq $8, %rsp",
                        "    call L%d" % offset,
                        "    addq $8, %rsp",
                        "    jmp .Lret%d" % number]
            out += [".Lret%d:" % number]
        elif opcode == OPCODES["RET"]:
            # Release exactly what this call allocated before returning.
            out += [
                "    leaq ffp(%rip), %rcx",
                "    movq (%rcx), %rsi",
                "    testq %rsi, %rsi",
                "    je 3f",
                "    decq %rsi",
                "    leaq fsize(%rip), %rdi",
                "    movq (%rdi,%rsi,8), %rax",
                "    leaq ffloor(%rip), %rdi",
                "    addq %rax, (%rdi)",
                "    movq %rsi, (%rcx)",
                "3:  ret"]
        elif opcode == OPCODES["JZ"]:
            out += pop_rax() + ["    testq %rax, %rax",
                                "    je L%d" % code[position + 1]]
        elif opcode == OPCODES["JMP"]:
            out += ["    jmp L%d" % code[position + 1]]
        elif opcode == OPCODES["HALT"]:
            out += ["    xorl %eax, %eax"]      # label already emitted above
        else:
            raise CompileError("no x86-64 lowering for %s" % name)

    out += [
        "    addq $40, %rsp",
        "    popq %rbx",
        "    popq %r13",
        "    popq %r12",
        "    popq %rbp",
        "    ret",
        "    .data",
        "fmt:    .asciz \"%lld\"",
        "    .bss",
        "    .align 16",
        "ostack: .space %d" % (STACK_SIZE * 8),
        "omem:   .space %d" % (MEMORY_SLOTS * 8),
        # Frame bookkeeping and the return stack. Both live in memory
        # rather than registers: the prologue already spends every
        # callee-saved register it can afford, and a frame pointer in
        # r14 would have to be saved and restored around every call.
        "fbase:  .space 2048",
        "fsize:  .space 2048",
        "ffp:    .space 8",
        "ffloor: .space 8",
    ]
    return "\n".join(out) + "\n"


# ---- differential verification -------------------------------------------- #

def _build_and_run(source: str, suffix: str, workdir: pathlib.Path,
                   compiler: str) -> str:
    unit = workdir / ("prog" + suffix)
    binary = workdir / "prog.exe"
    unit.write_text(source, encoding="utf-8")
    build = subprocess.run([compiler, str(unit), "-o", str(binary)],
                           capture_output=True, text=True, timeout=180)
    if build.returncode != 0:
        raise CompileError("%s failed:\n%s" % (compiler,
                                               build.stderr[-1500:]))
    done = subprocess.run([str(binary)], capture_output=True, text=True,
                          timeout=120)
    if done.returncode != 0:
        raise CompileError("generated program exited %d: %s"
                           % (done.returncode, done.stderr[-400:]))
    return done.stdout


def verify(source: str, *, allow_native_execution: bool = False) -> dict:
    """Compare implementations without executing native code by default.

    The interpreter is the reference only because it is the simplest; if the
    two compiled backends agreed with each other and not with it, the
    interpreter would be the suspect. Which is the point of running three.

    Building and launching generated C++/x86 executables crosses a materially
    different trust boundary from interpreting bounded Attestor bytecode.  Attestor
    4.2 therefore requires an exact, explicit opt-in for those legacy
    differential backends.  AttestorLang never supplies that opt-in.
    """
    program = mc_asm.parse(source)
    expected = mc_asm.run(program)
    code = to_bytecode(program)

    report = {"bytecode_length": len(code), "interpreter": expected,
              "backends": {}, "agree": True}
    for name, suffix, tool, emit in (("c++", ".cpp", "g++", to_cpp),
                                     ("x86-64", ".s", "gcc", to_asm)):
        if not allow_native_execution:
            report["backends"][name] = {
                "skipped": "native execution requires explicit opt-in"
            }
            continue
        if shutil.which(tool) is None:
            report["backends"][name] = {"skipped": "%s not found" % tool}
            continue
        with tempfile.TemporaryDirectory(prefix="mc_asm-") as raw:
            try:
                got = _build_and_run(emit(code), suffix,
                                     pathlib.Path(raw), tool)
            except CompileError as error:
                report["backends"][name] = {"error": str(error)[:900]}
                report["agree"] = False
                continue
        same = got == expected
        report["backends"][name] = {"output": got, "matches": same}
        if not same:
            report["agree"] = False
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("path", help="an mc.asm source file")
    parser.add_argument("--emit", choices=("bytecode", "cpp", "asm"),
                        help="print a lowering and stop")
    parser.add_argument("--verify", action="store_true",
                        help="verify the interpreter/bytecode path; native backends stay off")
    parser.add_argument(
        "--allow-native-execution", action="store_true",
        help=("with --verify only, compile and execute the legacy C++/x86 "
              "backends in temporary directories"),
    )
    args = parser.parse_args(argv)

    if args.allow_native_execution and not args.verify:
        parser.error("--allow-native-execution is valid only with --verify")

    import re as _re
    source = _re.sub(r";[^\n]*", " ",
                     pathlib.Path(args.path).read_text(encoding="utf-8"))

    try:
        if args.emit:
            code = to_bytecode(mc_asm.parse(source))
            print({"bytecode": lambda: disassemble(code),
                   "cpp": lambda: to_cpp(code),
                   "asm": lambda: to_asm(code)}[args.emit]())
            return 0
        if args.verify:
            report = verify(
                source,
                allow_native_execution=args.allow_native_execution,
            )
            print("bytecode: %d values" % report["bytecode_length"])
            print("interpreter output: %d bytes"
                  % len(report["interpreter"]))
            for name, result in report["backends"].items():
                if "skipped" in result:
                    print("  %-8s skipped (%s)" % (name, result["skipped"]))
                elif "error" in result:
                    print("  %-8s FAILED\n%s" % (name, result["error"]))
                else:
                    print("  %-8s %s" % (name, "matches the interpreter"
                                         if result["matches"] else "DIFFERS"))
            print("\n%s" % ("all backends agree" if report["agree"]
                            else "BACKENDS DISAGREE"))
            return 0 if report["agree"] else 1
        sys.stdout.write(mc_asm.execute(source))
    except (mc_asm.McAsmError, CompileError) as error:
        print("mc_asm: %s" % error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


def run_bytecode(code, stdin_values=None, max_steps=2_000_000,
                 observer=None):
    """Execute compiled bytecode directly.

    The interpreter in mc_asm walks a list of Instruction objects and
    compares `word == "ADD"` against a chain of string tests. This walks a
    flat list of integers and dispatches on an int, with the stack and
    memory as plain Python lists. Same language, same answers -- the tests
    require both to agree on every program -- but several times the speed,
    and it is what the language needed before subroutines were worth having
    in the compiled backends.

    Kept deliberately close to mc_asm.run's semantics, including the frame
    discipline: RET releases exactly what its own call allocated, so a
    routine that opens a frame and forgets it cannot leak memory downward
    into an unrelated FRAME a long way from the cause.
    """
    routines = getattr(code, "routines", {}) or {}
    stack: list = []
    memory = [0] * MEMORY_SLOTS
    returns: list = []
    frames: list = []
    frame_floor = MEMORY_SLOTS
    incoming = list(stdin_values or [])
    out: list = []
    pointer = 0
    steps = 0
    push = stack.append
    pop = stack.pop
    limit = len(code)

    def slot(index):
        if not frames:
            raise McAsmError("GET/PUT with no frame open")
        base, size = frames[-1]
        if not 0 <= index < size:
            raise McAsmError("local %d is outside a frame of %d"
                             % (index, size))
        return base + index

    # A program that pops an empty stack must fail as a language error, not
    # as a Python IndexError escaping from the VM's internals. The check
    # lives here rather than in pop() because a try block costs nothing
    # until it fires, while a bounds test on every pop would be paid by
    # every instruction of every run.
    try:
        return _run(code, routines, stack, memory, returns, frames,
                    frame_floor, incoming, out, pointer, steps, max_steps,
                    observer, limit)
    except IndexError:
        raise McAsmError("stack is empty") from None


def _run(code, routines, stack, memory, returns, frames, frame_floor,
         incoming, out, pointer, steps, max_steps, observer, limit):
    push = stack.append
    pop = stack.pop

    def slot(index):
        if not frames:
            raise McAsmError("GET/PUT with no frame open")
        base, size = frames[-1]
        if not 0 <= index < size:
            raise McAsmError("local %d is outside a frame of %d"
                             % (index, size))
        return base + index

    while pointer < limit:
        steps += 1
        if steps > max_steps:
            raise McAsmError("program did not finish in %d steps" % max_steps)
        if observer is not None:
            # One test per instruction, paid by every run so that trace and
            # stats can exist without a second copy of the interpreter. A
            # duplicated VM would drift from this one, and a debugger that
            # disagrees with the runtime is worse than no debugger.
            observer(pointer, list(stack))
        op = code[pointer]
        pointer += 1
        # Ordered by how often a real program executes them, not by opcode
        # number. Python walks an elif chain top to bottom, so in numeric
        # order the ops a loop runs every single iteration -- JMP at 21,
        # JZ at 20, LOAD at 19 -- each paid twenty failed comparisons first.
        # Reordering the chain was worth more than any individual opcode's
        # implementation.
        if op == 0:                                   # PUSH
            push(code[pointer]); pointer += 1
        elif op == 21: pointer = code[pointer]        # JMP
        elif op == 20:                                # JZ
            target = code[pointer]; pointer += 1
            if not pop():
                pointer = target
        elif op == 19: push(memory[pop()])            # LOAD
        elif op == 18:                                # STORE
            index = pop()
            memory[index] = pop()
        elif op == 1: b = pop(); push(pop() + b)
        elif op == 13: b = pop(); push(1 if pop() > b else 0)
        elif op == 12: b = pop(); push(1 if pop() < b else 0)
        elif op == 7: push(stack[-1])                 # DUP
        elif op == 2: b = stack.pop(); push(stack.pop() - b)
        elif op == 3: b = stack.pop(); push(stack.pop() * b)
        elif op == 4:
            b = stack.pop()
            if b == 0:
                raise McAsmError("DIV by zero")
            push(int(stack.pop() / b) if b else 0)
        elif op == 5:
            b = stack.pop()
            if b == 0:
                raise McAsmError("MOD by zero")
            a = stack.pop()
            push(a - int(a / b) * b)
        elif op == 6: push(-stack.pop())
        elif op == 7: push(stack[-1])
        elif op == 8: stack.pop()
        elif op == 9: stack[-1], stack[-2] = stack[-2], stack[-1]
        elif op == 10: push(stack[-2])
        elif op == 11: b = stack.pop(); push(1 if stack.pop() == b else 0)
        elif op == 12: b = stack.pop(); push(1 if stack.pop() < b else 0)
        elif op == 13: b = stack.pop(); push(1 if stack.pop() > b else 0)
        elif op == 14: push(0 if stack.pop() else 1)
        elif op == 15: out.append(str(stack.pop()))
        elif op == 16:                                # EMIT
            # A1Z26, not a codepoint: 0 is a space and 1..26 are A..Z. This
            # was written as a raw chr() -- PUTC's semantics -- so every
            # program that printed a word emitted control characters
            # instead. fizzbuzz.mcasm, sitting in this directory the whole
            # time, disagreed with the interpreter on its third line.
            value = stack.pop()
            if not 0 <= value <= 26:
                raise McAsmError(
                    "EMIT wants 0..26 (0 is a space), got %d" % value)
            out.append(" " if value == 0 else chr(ord("A") + value - 1))
        elif op == 17: out.append("\n")
        elif op == 18:
            index = stack.pop()
            memory[index] = stack.pop()
        elif op == 19: push(memory[stack.pop()])
        elif op == 20:                                # JZ
            target = code[pointer]; pointer += 1
            if not stack.pop():
                pointer = target
        elif op == 21: pointer = code[pointer]        # JMP
        elif op == 22: break                          # HALT
        elif op == 23: out.append(chr(stack.pop() % 0x110000))
        elif op == 24:                                # ROT
            c = stack.pop(); b = stack.pop(); a = stack.pop()
            push(b); push(c); push(a)
        elif op == 25: push(len(stack))               # DEPTH
        elif op == 26:                                # CALL
            pointer += 1                              # unused operand slot
            wanted = stack.pop()
            if wanted not in routines:
                raise McAsmError("CALL to routine %d, which is never defined"
                                 % wanted)
            if len(returns) >= mc_asm.MAX_CALL_DEPTH:
                raise McAsmError("call depth exceeded %d"
                                 % mc_asm.MAX_CALL_DEPTH)
            returns.append((pointer, len(frames)))
            pointer = routines[wanted]
        elif op == 27:                                # RET
            if not returns:
                raise McAsmError("RET with nothing to return to")
            pointer, opened = returns.pop()
            while len(frames) > opened:
                base, size = frames.pop()
                frame_floor += size
        elif op == 28:                                # FRAME
            wanted = stack.pop()
            if wanted < 0:
                raise McAsmError("FRAME of %d slots" % wanted)
            if frame_floor - wanted <= 0:
                raise McAsmError("no room for a frame of %d" % wanted)
            frame_floor -= wanted
            frames.append((frame_floor, wanted))
        elif op == 29: push(memory[slot(stack.pop())])          # GET
        elif op == 30:                                          # PUT
            index = stack.pop()
            memory[slot(index)] = stack.pop()
        else:
            raise McAsmError("unknown opcode %r at %d" % (op, pointer - 1))
    return "".join(out)
