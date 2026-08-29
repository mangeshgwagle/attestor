"""Deterministic, capability-aware ATVM interpreter for AttestorLang 4.2.

The VM has no host filesystem, process, native compiler, socket, clock, or
randomness API.  Its two capabilities are virtual byte buffers supplied by a
caller: bounded input and bounded output.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any, Iterable

if __package__:
    from . import bytecode as bc
    from .model import (
        ALLOWED_CAPABILITIES, I64_MAX, I64_MIN, Limits, MAX_INPUT_BYTES,
        MAX_SOURCE_BYTES, MAX_STACK, REPORT_SCHEMA, TRIT_WORD_MAX, VERSION, CapabilityError,
        AttestorLangError, VmTrap, canonical_json, checked_i64, wrap_i64,
    )
else:  # pragma: no cover - standalone CLI imports this as a sibling module
    import bytecode as bc
    from model import (
        ALLOWED_CAPABILITIES, I64_MAX, I64_MIN, Limits, MAX_INPUT_BYTES,
        MAX_SOURCE_BYTES, MAX_STACK, REPORT_SCHEMA, TRIT_WORD_MAX, VERSION, CapabilityError,
        AttestorLangError, VmTrap, canonical_json, checked_i64, wrap_i64,
    )


# Malbolge's characteristic ternary operation, pinned here with explicit
# operand orientation: table[a_trit][b_trit].  AttestorLang borrows the operation,
# not Malbolge's host-independent self-encryption machinery.
CRAZY_TABLE = (
    (1, 0, 0),
    (1, 0, 2),
    (2, 2, 1),
)

_EXECUTION_KEYS = {
    "arbitrary_native_bytes_executed", "executable_memory_created",
    "host_files_read_by_vm", "host_files_written_by_vm",
    "native_compiler_invoked", "network_accessed", "processes_started",
    "shell_invoked",
}


def crazy(a: int, b: int) -> int:
    if (type(a) is not int or type(b) is not int
            or not 0 <= a <= TRIT_WORD_MAX or not 0 <= b <= TRIT_WORD_MAX):
        raise VmTrap(f"CRAZY operands must be 10-trit words 0..{TRIT_WORD_MAX}")
    result = 0
    place = 1
    left, right = a, b
    for _ in range(10):
        result += CRAZY_TABLE[left % 3][right % 3] * place
        left //= 3
        right //= 3
        place *= 3
    return result


def rotrit(value: int) -> int:
    if type(value) is not int or not 0 <= value <= TRIT_WORD_MAX:
        raise VmTrap(f"ROTRIT operand must be a 10-trit word 0..{TRIT_WORD_MAX}")
    return (value % 3) * (3 ** 9) + value // 3


def _capabilities(values: Iterable[str]) -> tuple[str, ...]:
    try:
        result = tuple(sorted(values))
    except TypeError as exc:
        raise CapabilityError("granted capabilities must be iterable text") from exc
    if (len(result) != len(set(result))
            or any(type(item) is not str or item not in ALLOWED_CAPABILITIES
                   for item in result)):
        raise CapabilityError("granted capabilities are invalid")
    return result


def _report(
        *,
        status: str,
        program: bc.Program,
        bytecode_blob: bytes,
        source_sha256: str,
        output: bytes,
        input_bytes: bytes,
        input_position: int,
        required: tuple[str, ...],
        granted: tuple[str, ...],
        used: set[str],
        denied: tuple[str, ...],
        steps: int,
        max_stack: int,
        tape_pointer_high_water: int,
        trace_sha256: str,
        limits: Limits,
        error: dict[str, str] | None,
) -> dict[str, Any]:
    body: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "version": VERSION,
        "status": status,
        "source_sha256": source_sha256,
        "bytecode_sha256": hashlib.sha256(bytecode_blob).hexdigest(),
        "trace_sha256": trace_sha256,
        "capabilities": {
            "required": list(required),
            "granted": list(granted),
            "used": sorted(used),
            "denied": list(denied),
        },
        "limits": {
            "max_steps": limits.max_steps,
            "max_stack": MAX_STACK,
            "tape_cells": limits.tape_cells,
            "max_output_bytes": limits.max_output_bytes,
            "max_input_bytes": MAX_INPUT_BYTES,
        },
        "usage": {
            "steps": steps,
            "max_stack": max_stack,
            "tape_pointer_high_water": tape_pointer_high_water,
            "input_bytes": len(input_bytes),
            "input_consumed": input_position,
            "input_sha256": hashlib.sha256(input_bytes).hexdigest(),
            "output_bytes": len(output),
        },
        "output": {
            "base64": base64.b64encode(output).decode("ascii"),
            "sha256": hashlib.sha256(output).hexdigest(),
        },
        "error": error,
        "execution": {
            "arbitrary_native_bytes_executed": False,
            "executable_memory_created": False,
            "host_files_read_by_vm": False,
            "host_files_written_by_vm": False,
            "native_compiler_invoked": False,
            "network_accessed": False,
            "processes_started": False,
            "shell_invoked": False,
        },
    }
    body["report_sha256"] = hashlib.sha256(canonical_json(body)).hexdigest()
    canonical_json(body)
    return body


def execute(
        program: bc.Program,
        *,
        granted_capabilities: Iterable[str] = ("console.write",),
        input_bytes: bytes = b"",
        source_bytes: bytes | None = None,
        limits: Limits | None = None,
) -> dict[str, Any]:
    """Verify and run a program, returning deterministic evidence.

    Capability refusal is represented as a report and happens before step
    zero.  Invalid bytecode remains an exception because no valid program
    identity exists from which to construct execution evidence.
    """
    bc.verify(program)
    selected_limits = limits or Limits()
    if type(input_bytes) is not bytes or len(input_bytes) > MAX_INPUT_BYTES:
        raise CapabilityError("virtual input must be bounded bytes")
    if (source_bytes is not None
            and (type(source_bytes) is not bytes
                 or len(source_bytes) > MAX_SOURCE_BYTES)):
        raise CapabilityError("source identity must be bounded bytes when supplied")
    granted = _capabilities(granted_capabilities)
    required = program.capabilities
    denied = tuple(sorted(set(required) - set(granted)))
    blob = bc.encode(program)
    source_sha256 = (
        hashlib.sha256(source_bytes).hexdigest() if source_bytes is not None else "")
    empty_trace = hashlib.sha256(b"").hexdigest()
    if denied:
        return _report(
            status="refused", program=program, bytecode_blob=blob,
            source_sha256=source_sha256, output=b"", input_bytes=input_bytes,
            input_position=0, required=required, granted=granted, used=set(),
            denied=denied, steps=0, max_stack=0, tape_pointer_high_water=0,
            trace_sha256=empty_trace, limits=selected_limits,
            error={"code": "capability-refused",
                   "message": "required virtual capability was not granted"},
        )

    stack: list[int | str] = []
    uninitialized = object()
    locals_: list[int | str | object] = [uninitialized] * len(program.local_types)
    tape = bytearray(selected_limits.tape_cells)
    tape_pointer = 0
    tape_pointer_high_water = 0
    output = bytearray()
    input_position = 0
    instruction_pointer = 0
    steps = 0
    max_stack = 0
    used: set[str] = set()
    trace = hashlib.sha256()
    status = "completed"
    error: dict[str, str] | None = None

    def pop_int() -> int:
        if not stack or type(stack[-1]) is not int:
            raise VmTrap("ATVM integer stack underflow")
        return int(stack.pop())

    def pop_text() -> str:
        if not stack or type(stack[-1]) is not str:
            raise VmTrap("ATVM text stack underflow")
        return str(stack.pop())

    def push(value: int | str) -> None:
        nonlocal max_stack
        if len(stack) >= MAX_STACK:
            raise VmTrap("ATVM stack exceeded its hard boundary")
        stack.append(value)
        max_stack = max(max_stack, len(stack))

    def emit(raw: bytes) -> None:
        used.add("console.write")
        if len(output) + len(raw) > selected_limits.max_output_bytes:
            raise VmTrap("virtual output exceeded its byte boundary")
        output.extend(raw)

    def read_byte() -> int:
        nonlocal input_position
        used.add("input.read")
        if input_position >= len(input_bytes):
            return 0
        value = input_bytes[input_position]
        input_position += 1
        return value

    try:
        while True:
            if steps >= selected_limits.max_steps:
                raise VmTrap("execution exceeded the deterministic step boundary")
            instruction = program.code[instruction_pointer]
            opcode = instruction[0]
            operand = instruction[1] if len(instruction) == 2 else None
            trace.update(canonical_json(
                [instruction_pointer, list(instruction)], maximum=1024))
            steps += 1
            next_pointer = instruction_pointer + 1

            if opcode == bc.HALT:
                break
            if opcode == bc.PUSH_I64:
                push(int(operand))
            elif opcode == bc.PUSH_TEXT:
                push(program.constants[int(operand)])
            elif opcode == bc.LOAD_LOCAL:
                value = locals_[int(operand)]
                if value is uninitialized:
                    raise VmTrap("immutable local was read before initialization")
                push(value)  # type: ignore[arg-type]
            elif opcode == bc.STORE_LOCAL:
                slot = int(operand)
                if locals_[slot] is not uninitialized:
                    raise VmTrap("immutable local was written more than once")
                locals_[slot] = pop_text() if program.local_types[slot] == "text" else pop_int()
            elif opcode == bc.POP:
                if not stack:
                    raise VmTrap("ATVM stack underflow")
                stack.pop()
            elif opcode == bc.DUP:
                if not stack:
                    raise VmTrap("ATVM stack underflow")
                push(stack[-1])
            elif opcode == bc.SWAP:
                if len(stack) < 2:
                    raise VmTrap("ATVM stack underflow")
                stack[-2], stack[-1] = stack[-1], stack[-2]
            elif opcode in {
                    bc.ADD, bc.ADD_WRAP, bc.SUB, bc.SUB_WRAP, bc.MUL,
                    bc.MUL_WRAP, bc.DIV, bc.MOD, bc.ASR, bc.EQ, bc.LT,
                    bc.GT, bc.BIT_AND, bc.BIT_OR, bc.BIT_XOR, bc.SHL,
                    bc.LSR, bc.CRAZY}:
                right, left = pop_int(), pop_int()
                if opcode in {bc.ASR, bc.SHL, bc.LSR} and not 0 <= right <= 63:
                    raise VmTrap("shift count must be between 0 and 63")
                if opcode == bc.ADD:
                    result = checked_i64(left + right, "ADD")
                elif opcode == bc.ADD_WRAP:
                    result = wrap_i64(left + right)
                elif opcode == bc.SUB:
                    result = checked_i64(left - right, "SUB")
                elif opcode == bc.SUB_WRAP:
                    result = wrap_i64(left - right)
                elif opcode == bc.MUL:
                    result = checked_i64(left * right, "MUL")
                elif opcode == bc.MUL_WRAP:
                    result = wrap_i64(left * right)
                elif opcode in {bc.DIV, bc.MOD}:
                    if right == 0:
                        raise VmTrap("division by zero")
                    result = left // right if opcode == bc.DIV else left % right
                    result = checked_i64(result, "DIV" if opcode == bc.DIV else "MOD")
                elif opcode == bc.ASR:
                    result = left >> right
                elif opcode == bc.EQ:
                    result = 1 if left == right else 0
                elif opcode == bc.LT:
                    result = 1 if left < right else 0
                elif opcode == bc.GT:
                    result = 1 if left > right else 0
                elif opcode == bc.BIT_AND:
                    result = wrap_i64(left & right)
                elif opcode == bc.BIT_OR:
                    result = wrap_i64(left | right)
                elif opcode == bc.BIT_XOR:
                    result = wrap_i64(left ^ right)
                elif opcode == bc.SHL:
                    result = checked_i64(left << right, "SHL")
                elif opcode == bc.LSR:
                    result = wrap_i64((left & (2 ** 64 - 1)) >> right)
                else:
                    result = crazy(left, right)
                push(result)
            elif opcode in {bc.NEG, bc.BIT_NOT, bc.ROTRIT}:
                value = pop_int()
                if opcode == bc.NEG:
                    push(checked_i64(-value, "NEG"))
                elif opcode == bc.BIT_NOT:
                    push(wrap_i64(~value))
                else:
                    push(rotrit(value))
            elif opcode == bc.PRINT_NUMBER:
                emit(str(pop_int()).encode("ascii"))
            elif opcode == bc.PRINT_CHAR:
                value = pop_int()
                if not 0 <= value <= 255:
                    raise VmTrap("letter output requires a byte value 0..255")
                emit(bytes((value,)))
            elif opcode == bc.PRINT_TEXT:
                emit(pop_text().encode("utf-8", "strict"))
            elif opcode == bc.READ_BYTE:
                push(read_byte())
            elif opcode == bc.BF_RIGHT:
                if tape_pointer + 1 >= len(tape):
                    raise VmTrap("Brainfuck tape pointer moved beyond the right boundary")
                tape_pointer += 1
                tape_pointer_high_water = max(tape_pointer_high_water, tape_pointer)
            elif opcode == bc.BF_LEFT:
                if tape_pointer == 0:
                    raise VmTrap("Brainfuck tape pointer moved beyond the left boundary")
                tape_pointer -= 1
            elif opcode == bc.BF_INC:
                tape[tape_pointer] = (tape[tape_pointer] + 1) & 0xFF
            elif opcode == bc.BF_DEC:
                tape[tape_pointer] = (tape[tape_pointer] - 1) & 0xFF
            elif opcode == bc.BF_OUT:
                emit(bytes((tape[tape_pointer],)))
            elif opcode == bc.BF_IN:
                tape[tape_pointer] = read_byte()
            elif opcode == bc.BF_JZ:
                if tape[tape_pointer] == 0:
                    next_pointer = int(operand)
            elif opcode == bc.BF_JNZ:
                if tape[tape_pointer] != 0:
                    next_pointer = int(operand)
            else:  # unreachable after verification
                raise VmTrap("verified bytecode reached an unknown opcode")
            instruction_pointer = next_pointer
    except VmTrap as exc:
        status = "trapped"
        error = {"code": exc.code, "message": str(exc)}

    return _report(
        status=status, program=program, bytecode_blob=blob,
        source_sha256=source_sha256, output=bytes(output),
        input_bytes=input_bytes, input_position=input_position,
        required=required, granted=granted, used=used, denied=(), steps=steps,
        max_stack=max_stack, tape_pointer_high_water=tape_pointer_high_water,
        trace_sha256=trace.hexdigest(), limits=selected_limits, error=error,
    )


def verify_report(report: dict[str, Any]) -> tuple[bool, list[str]]:
    errors: list[str] = []
    if type(report) is not dict or report.get("schema") != REPORT_SCHEMA:
        return False, ["report schema is invalid"]
    expected_keys = {
        "schema", "version", "status", "source_sha256", "bytecode_sha256",
        "trace_sha256", "capabilities", "limits", "usage", "output",
        "error", "execution", "report_sha256",
    }
    if set(report) != expected_keys:
        errors.append("report top-level shape is invalid")
    if report.get("version") != VERSION:
        errors.append("report version is invalid")
    status = report.get("status")
    if status not in {"completed", "refused", "trapped"}:
        errors.append("report status is invalid")

    def is_sha(value: Any, *, empty: bool = False) -> bool:
        if empty and value == "":
            return True
        return (type(value) is str and len(value) == 64
                and all(character in "0123456789abcdef" for character in value))

    if not is_sha(report.get("source_sha256"), empty=True):
        errors.append("source SHA-256 is invalid")
    if not is_sha(report.get("bytecode_sha256")):
        errors.append("bytecode SHA-256 is invalid")
    if not is_sha(report.get("trace_sha256")):
        errors.append("trace SHA-256 is invalid")

    capabilities = report.get("capabilities")
    if type(capabilities) is not dict or set(capabilities) != {
            "required", "granted", "used", "denied"}:
        errors.append("report capabilities shape is invalid")
    else:
        valid_lists = True
        for name in ("required", "granted", "used", "denied"):
            values = capabilities.get(name)
            if (type(values) is not list or values != sorted(values)
                    or len(values) != len(set(values))
                    or any(type(value) is not str or value not in ALLOWED_CAPABILITIES
                           for value in values)):
                errors.append(f"report {name} capabilities are invalid")
                valid_lists = False
        if valid_lists:
            required_set = set(capabilities["required"])
            granted_set = set(capabilities["granted"])
            if set(capabilities["denied"]) != required_set - granted_set:
                errors.append("report denied capabilities are inconsistent")
            if not set(capabilities["used"]) <= required_set & granted_set:
                errors.append("report used capabilities are inconsistent")

    limits = report.get("limits")
    usage = report.get("usage")
    if type(limits) is not dict or set(limits) != {
            "max_steps", "max_stack", "tape_cells", "max_output_bytes",
            "max_input_bytes"}:
        errors.append("report limits shape is invalid")
    else:
        try:
            Limits(
                max_steps=limits["max_steps"],
                tape_cells=limits["tape_cells"],
                max_output_bytes=limits["max_output_bytes"],
            )
        except AttestorLangError:
            errors.append("report limits are invalid")
        if (limits.get("max_stack") != MAX_STACK
                or limits.get("max_input_bytes") != MAX_INPUT_BYTES):
            errors.append("report limits are invalid")
    if type(usage) is not dict or set(usage) != {
            "steps", "max_stack", "tape_pointer_high_water", "input_bytes",
            "input_consumed", "input_sha256", "output_bytes"}:
        errors.append("report usage shape is invalid")
    elif any(type(usage.get(name)) is not int or usage[name] < 0 for name in (
            "steps", "max_stack", "tape_pointer_high_water", "input_bytes",
            "input_consumed", "output_bytes")):
        errors.append("report usage counters are invalid")
    elif type(limits) is dict and set(limits) == {
            "max_steps", "max_stack", "tape_cells", "max_output_bytes",
            "max_input_bytes"}:
        if (usage["steps"] > limits["max_steps"]
                or usage["max_stack"] > limits["max_stack"]
                or usage["tape_pointer_high_water"] >= limits["tape_cells"]
                or usage["input_consumed"] > usage["input_bytes"]
                or usage["input_bytes"] > limits["max_input_bytes"]
                or usage["output_bytes"] > limits["max_output_bytes"]):
            errors.append("report usage exceeds its recorded limits")
        if not is_sha(usage.get("input_sha256")):
            errors.append("report input SHA-256 is invalid")

    output = report.get("output")
    if type(output) is not dict or set(output) != {"base64", "sha256"}:
        errors.append("report output shape is invalid")
    else:
        try:
            output_bytes = base64.b64decode(output.get("base64"), validate=True)
        except (TypeError, ValueError):
            output_bytes = b""
            errors.append("report output base64 is invalid")
        if not is_sha(output.get("sha256")) or output.get("sha256") != \
                hashlib.sha256(output_bytes).hexdigest():
            errors.append("report output SHA-256 is invalid")
        if type(usage) is dict and usage.get("output_bytes") != len(output_bytes):
            errors.append("report output byte count is inconsistent")

    report_error = report.get("error")
    if status == "completed":
        if report_error is not None:
            errors.append("completed report cannot contain an error")
    elif (type(report_error) is not dict or set(report_error) != {"code", "message"}
          or any(type(report_error.get(name)) is not str or not report_error[name]
                 for name in ("code", "message"))):
        errors.append("non-completed report error is invalid")

    if (status == "refused" and type(capabilities) is dict
            and type(usage) is dict and type(output) is dict):
        empty_trace = hashlib.sha256(b"").hexdigest()
        if (not capabilities.get("denied")
                or capabilities.get("used") != []
                or usage.get("steps") != 0
                or usage.get("max_stack") != 0
                or usage.get("input_consumed") != 0
                or usage.get("output_bytes") != 0
                or output.get("base64") != ""
                or report.get("trace_sha256") != empty_trace
                or not isinstance(report_error, dict)
                or report_error.get("code") != "capability-refused"):
            errors.append("refused report contains post-execution evidence")
    elif status in {"completed", "trapped"} and type(capabilities) is dict:
        if capabilities.get("denied") != []:
            errors.append("executed report contains denied capabilities")
        if (status == "trapped" and isinstance(report_error, dict)
                and report_error.get("code") != "vm-trap"):
            errors.append("trapped report error code is invalid")

    digest = report.get("report_sha256")
    if not is_sha(digest):
        errors.append("report SHA-256 shape is invalid")
    else:
        body = dict(report)
        body.pop("report_sha256", None)
        try:
            expected = hashlib.sha256(canonical_json(body)).hexdigest()
        except AttestorLangError:
            expected = ""
        if digest != expected:
            errors.append("report SHA-256 does not match")
    execution = report.get("execution")
    if (type(execution) is not dict or set(execution) != _EXECUTION_KEYS
            or any(execution.get(key) is not False for key in _EXECUTION_KEYS)):
        errors.append("report execution boundary is invalid")
    return not errors, errors
