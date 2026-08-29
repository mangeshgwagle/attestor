"""Canonical ATVM bytecode container and pre-execution verifier.

ATVM is the only "raw machine code" AttestorLang accepts.  Its bytes are decoded
as data and interpreted by :mod:`vm`; they are never mapped executable, passed
to a native compiler, or launched as a process.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import hashlib
import json
from typing import Any

if __package__:
    from .model import (
        ALLOWED_CAPABILITIES, ALLOWED_TYPES, BytecodeError,
        MAX_BYTECODE_BYTES, MAX_CODE_INSTRUCTIONS, MAX_CONSTANT_BYTES,
        MAX_CONSTANTS, MAX_LOCALS, MAX_STACK, canonical_json,
    )
else:  # pragma: no cover - standalone CLI imports this as a sibling module
    from model import (
        ALLOWED_CAPABILITIES, ALLOWED_TYPES, BytecodeError,
        MAX_BYTECODE_BYTES, MAX_CODE_INSTRUCTIONS, MAX_CONSTANT_BYTES,
        MAX_CONSTANTS, MAX_LOCALS, MAX_STACK, canonical_json,
    )


FORMAT = 1
MAGIC = b"ATVM42\x00"

HALT = 0
PUSH_I64 = 1
PUSH_TEXT = 2
LOAD_LOCAL = 3
STORE_LOCAL = 4
POP = 5
DUP = 6
SWAP = 7
ADD = 10
ADD_WRAP = 11
SUB = 12
SUB_WRAP = 13
MUL = 14
MUL_WRAP = 15
DIV = 16
MOD = 17
NEG = 18
ASR = 19
EQ = 20
LT = 21
GT = 22
BIT_AND = 23
BIT_OR = 24
BIT_XOR = 25
BIT_NOT = 26
SHL = 27
LSR = 28
CRAZY = 29
ROTRIT = 30
PRINT_NUMBER = 40
PRINT_CHAR = 41
PRINT_TEXT = 42
READ_BYTE = 43
BF_RIGHT = 50
BF_LEFT = 51
BF_INC = 52
BF_DEC = 53
BF_OUT = 54
BF_IN = 55
BF_JZ = 56
BF_JNZ = 57


OPCODE_NAMES = {
    HALT: "HALT", PUSH_I64: "PUSH_I64", PUSH_TEXT: "PUSH_TEXT",
    LOAD_LOCAL: "LOAD_LOCAL", STORE_LOCAL: "STORE_LOCAL", POP: "POP",
    DUP: "DUP", SWAP: "SWAP", ADD: "ADD", ADD_WRAP: "ADD_WRAP",
    SUB: "SUB", SUB_WRAP: "SUB_WRAP", MUL: "MUL",
    MUL_WRAP: "MUL_WRAP", DIV: "DIV", MOD: "MOD", NEG: "NEG",
    ASR: "ASR", EQ: "EQ", LT: "LT", GT: "GT", BIT_AND: "AND",
    BIT_OR: "OR", BIT_XOR: "XOR", BIT_NOT: "NOT", SHL: "SHL",
    LSR: "LSR", CRAZY: "CRAZY", ROTRIT: "ROTRIT",
    PRINT_NUMBER: "PRINT_NUMBER", PRINT_CHAR: "PRINT_CHAR",
    PRINT_TEXT: "PRINT_TEXT", READ_BYTE: "READ_BYTE",
    BF_RIGHT: "BF_RIGHT", BF_LEFT: "BF_LEFT", BF_INC: "BF_INC",
    BF_DEC: "BF_DEC", BF_OUT: "BF_OUT", BF_IN: "BF_IN",
    BF_JZ: "BF_JZ", BF_JNZ: "BF_JNZ",
}
NAME_TO_OPCODE = {name: opcode for opcode, name in OPCODE_NAMES.items()}

_NO_OPERAND = frozenset({
    HALT, POP, DUP, SWAP, ADD, ADD_WRAP, SUB, SUB_WRAP, MUL, MUL_WRAP,
    DIV, MOD, NEG, ASR, EQ, LT, GT, BIT_AND, BIT_OR, BIT_XOR, BIT_NOT,
    SHL, LSR, CRAZY, ROTRIT, PRINT_NUMBER, PRINT_CHAR, PRINT_TEXT,
    READ_BYTE, BF_RIGHT, BF_LEFT, BF_INC, BF_DEC, BF_OUT, BF_IN,
})
_ONE_OPERAND = frozenset({
    PUSH_I64, PUSH_TEXT, LOAD_LOCAL, STORE_LOCAL, BF_JZ, BF_JNZ,
})
_I64_BINARY = frozenset({
    ADD, ADD_WRAP, SUB, SUB_WRAP, MUL, MUL_WRAP, DIV, MOD, ASR, EQ, LT,
    GT, BIT_AND, BIT_OR, BIT_XOR, SHL, LSR, CRAZY,
})


@dataclass(frozen=True, slots=True)
class Program:
    code: tuple[tuple[int, ...], ...]
    constants: tuple[str, ...] = ()
    local_types: tuple[str, ...] = ()
    capabilities: tuple[str, ...] = ()


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BytecodeError("bytecode JSON contains a duplicate key")
        result[key] = value
    return result


def _payload(program: Program) -> dict[str, Any]:
    return {
        "capabilities": list(program.capabilities),
        "code": [list(instruction) for instruction in program.code],
        "constants": list(program.constants),
        "format": FORMAT,
        "local_types": list(program.local_types),
    }


def encode(program: Program) -> bytes:
    verify(program)
    payload = canonical_json(_payload(program), maximum=MAX_BYTECODE_BYTES)
    blob = MAGIC + len(payload).to_bytes(4, "big") + hashlib.sha256(payload).digest() + payload
    if len(blob) > MAX_BYTECODE_BYTES:
        raise BytecodeError("encoded bytecode exceeds its byte boundary")
    return blob


def decode(blob: bytes) -> Program:
    if type(blob) is not bytes or len(blob) > MAX_BYTECODE_BYTES:
        raise BytecodeError("bytecode must be bounded bytes")
    header = len(MAGIC) + 4 + 32
    if len(blob) < header or blob[:len(MAGIC)] != MAGIC:
        raise BytecodeError("bytecode magic or header is invalid")
    length = int.from_bytes(blob[len(MAGIC):len(MAGIC) + 4], "big")
    digest = blob[len(MAGIC) + 4:header]
    payload = blob[header:]
    if length != len(payload) or not hashlib.sha256(payload).digest() == digest:
        raise BytecodeError("bytecode length or SHA-256 is invalid")
    try:
        value = json.loads(
            payload.decode("utf-8", "strict"),
            object_pairs_hook=_strict_object,
            parse_constant=lambda raw: (_ for _ in ()).throw(
                BytecodeError("bytecode contains a non-finite number")),
        )
    except BytecodeError:
        raise
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise BytecodeError("bytecode payload is not strict JSON") from exc
    if type(value) is not dict or set(value) != {
            "capabilities", "code", "constants", "format", "local_types"}:
        raise BytecodeError("bytecode payload shape is invalid")
    if type(value["format"]) is not int or value["format"] != FORMAT:
        raise BytecodeError("bytecode format is unsupported")
    collections = (value["code"], value["constants"], value["local_types"],
                   value["capabilities"])
    if any(type(item) is not list for item in collections):
        raise BytecodeError("bytecode collections must be arrays")
    try:
        program = Program(
            code=tuple(tuple(instruction) for instruction in value["code"]),
            constants=tuple(value["constants"]),
            local_types=tuple(value["local_types"]),
            capabilities=tuple(value["capabilities"]),
        )
    except TypeError as exc:
        raise BytecodeError("bytecode instruction shape is invalid") from exc
    verify(program)
    return program


def _pop(stack: tuple[str, ...], expected: str, index: int) -> tuple[str, ...]:
    if not stack or stack[-1] != expected:
        raise BytecodeError(
            f"instruction {index} expects {expected} on the stack")
    return stack[:-1]


def _transition(
        program: Program,
        index: int,
        stack: tuple[str, ...],
        initialized: frozenset[int],
) -> tuple[tuple[str, ...], frozenset[int], tuple[int, ...]]:
    instruction = program.code[index]
    opcode = instruction[0]
    operand = instruction[1] if len(instruction) == 2 else None
    result = stack
    ready = initialized

    if opcode == PUSH_I64:
        result += ("i64",)
    elif opcode == PUSH_TEXT:
        result += ("text",)
    elif opcode == LOAD_LOCAL:
        if operand not in ready:
            raise BytecodeError(f"instruction {index} reads an uninitialized local")
        result += (program.local_types[operand],)
    elif opcode == STORE_LOCAL:
        if operand in ready:
            raise BytecodeError(f"instruction {index} rewrites an immutable local")
        result = _pop(result, program.local_types[operand], index)
        ready = frozenset((*ready, operand))
    elif opcode == POP:
        if not result:
            raise BytecodeError(f"instruction {index} pops an empty stack")
        result = result[:-1]
    elif opcode == DUP:
        if not result:
            raise BytecodeError(f"instruction {index} duplicates an empty stack")
        result += (result[-1],)
    elif opcode == SWAP:
        if len(result) < 2:
            raise BytecodeError(f"instruction {index} swaps fewer than two values")
        result = result[:-2] + (result[-1], result[-2])
    elif opcode in _I64_BINARY:
        result = _pop(_pop(result, "i64", index), "i64", index) + ("i64",)
    elif opcode in {NEG, BIT_NOT, ROTRIT}:
        result = _pop(result, "i64", index) + ("i64",)
    elif opcode in {PRINT_NUMBER, PRINT_CHAR}:
        result = _pop(result, "i64", index)
    elif opcode == PRINT_TEXT:
        result = _pop(result, "text", index)
    elif opcode == READ_BYTE:
        result += ("i64",)
    elif opcode in {
            BF_RIGHT, BF_LEFT, BF_INC, BF_DEC, BF_OUT, BF_IN,
            BF_JZ, BF_JNZ}:
        pass
    elif opcode == HALT:
        if result:
            raise BytecodeError("HALT requires an empty stack")
        return result, ready, ()
    else:  # guarded by structural verification; defensive for direct calls
        raise BytecodeError(f"instruction {index} has an unknown opcode")

    if len(result) > MAX_STACK:
        raise BytecodeError("bytecode stack exceeds its hard boundary")
    if opcode in {BF_JZ, BF_JNZ}:
        return result, ready, (index + 1, operand)
    return result, ready, (index + 1,)


def verify(program: Program) -> None:
    if type(program) is not Program:
        raise BytecodeError("program must be an exact ATVM Program")
    if not 1 <= len(program.code) <= MAX_CODE_INSTRUCTIONS:
        raise BytecodeError("instruction count is outside the bytecode boundary")
    if len(program.constants) > MAX_CONSTANTS or len(program.local_types) > MAX_LOCALS:
        raise BytecodeError("constant or local count exceeds the bytecode boundary")
    if (program.capabilities != tuple(sorted(program.capabilities))
            or len(program.capabilities) != len(set(program.capabilities))
            or any(type(cap) is not str or cap not in ALLOWED_CAPABILITIES
                   for cap in program.capabilities)):
        raise BytecodeError("bytecode capabilities are invalid")
    if any(type(kind) is not str or kind not in ALLOWED_TYPES
           for kind in program.local_types):
        raise BytecodeError("bytecode local types are invalid")
    for constant in program.constants:
        if type(constant) is not str:
            raise BytecodeError("bytecode text constant must be text")
        try:
            size = len(constant.encode("utf-8", "strict"))
        except UnicodeError as exc:
            raise BytecodeError("bytecode text constant is invalid UTF-8") from exc
        if size > MAX_CONSTANT_BYTES:
            raise BytecodeError("bytecode text constant exceeds its boundary")

    for index, instruction in enumerate(program.code):
        if (type(instruction) is not tuple or not instruction
                or any(type(value) is not int for value in instruction)):
            raise BytecodeError(f"instruction {index} is not an integer tuple")
        opcode = instruction[0]
        if opcode not in OPCODE_NAMES:
            raise BytecodeError(f"instruction {index} has unknown opcode {opcode}")
        expected = 1 if opcode in _NO_OPERAND else 2 if opcode in _ONE_OPERAND else 0
        if expected == 0 or len(instruction) != expected:
            raise BytecodeError(f"instruction {index} has invalid operand count")
        if opcode == PUSH_I64 and not -(2 ** 63) <= instruction[1] <= 2 ** 63 - 1:
            raise BytecodeError(f"instruction {index} literal is outside i64")
        if opcode == PUSH_TEXT and not 0 <= instruction[1] < len(program.constants):
            raise BytecodeError(f"instruction {index} has invalid constant index")
        if opcode in {LOAD_LOCAL, STORE_LOCAL} and not 0 <= instruction[1] < len(program.local_types):
            raise BytecodeError(f"instruction {index} has invalid local index")
        if opcode in {BF_JZ, BF_JNZ} and not 0 <= instruction[1] < len(program.code):
            raise BytecodeError(f"instruction {index} has invalid jump target")
        if opcode in {PRINT_NUMBER, PRINT_CHAR, PRINT_TEXT, BF_OUT} and \
                "console.write" not in program.capabilities:
            raise BytecodeError(f"instruction {index} lacks console.write declaration")
        if opcode in {READ_BYTE, BF_IN} and "input.read" not in program.capabilities:
            raise BytecodeError(f"instruction {index} lacks input.read declaration")

    if program.code[-1] != (HALT,) or any(
            instruction[0] == HALT for instruction in program.code[:-1]):
        raise BytecodeError("bytecode must end in exactly one HALT")

    states: dict[int, tuple[tuple[str, ...], frozenset[int]]] = {0: ((), frozenset())}
    queue = deque([0])
    while queue:
        index = queue.popleft()
        stack, initialized = states[index]
        next_stack, next_initialized, successors = _transition(
            program, index, stack, initialized)
        for successor in successors:
            if successor >= len(program.code):
                raise BytecodeError(f"instruction {index} falls outside bytecode")
            state = (next_stack, next_initialized)
            previous = states.get(successor)
            if previous is None:
                states[successor] = state
                queue.append(successor)
            elif previous != state:
                raise BytecodeError(
                    f"control-flow join at instruction {successor} has inconsistent state")
    if len(states) != len(program.code):
        raise BytecodeError("bytecode contains unreachable instructions")


def disassemble(program: Program) -> str:
    verify(program)
    lines = []
    for index, instruction in enumerate(program.code):
        name = OPCODE_NAMES[instruction[0]]
        suffix = "" if len(instruction) == 1 else f" {instruction[1]}"
        lines.append(f"{index:05d}  {name}{suffix}")
    return "\n".join(lines) + "\n"
