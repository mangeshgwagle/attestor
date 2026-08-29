"""Shared immutable values and hard limits for AttestorLang 4.2.

This module deliberately contains no host integration.  The language runtime
receives source, bytecode, and virtual input as already-bounded values.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any


VERSION = "4.2"
REPORT_SCHEMA = "attestorlang-run/4.2"

MAX_SOURCE_BYTES = 256 * 1024
MAX_CODE_INSTRUCTIONS = 100_000
MAX_BYTECODE_BYTES = 2 * 1024 * 1024
MAX_CONSTANTS = 4_096
MAX_CONSTANT_BYTES = 64 * 1024
MAX_LOCALS = 1_024
MAX_STACK = 4_096
DEFAULT_0 = 1_000_000
HARD_0 = 10_000_000
DEFAULT_TAPE_CELLS = 4_096
MAX_TAPE_CELLS = 65_536
DEFAULT_MAX_OUTPUT_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 1024 * 1024
MAX_INPUT_BYTES = 1024 * 1024
MAX_REPORT_BYTES = 3 * 1024 * 1024

I64_MIN = -(2 ** 63)
I64_MAX = 2 ** 63 - 1
TRIT_WORD_MAX = 3 ** 10 - 1

ALLOWED_CAPABILITIES = frozenset({"console.write", "input.read"})
ALLOWED_TYPES = frozenset({"i64", "text"})


class AttestorLangError(ValueError):
    """Base class for a deterministic language refusal or trap."""

    code = "attestorlang-error"


class SourceError(AttestorLangError):
    code = "source-error"


class BytecodeError(AttestorLangError):
    code = "bytecode-error"


class CapabilityError(AttestorLangError):
    code = "capability-refused"


class VmTrap(AttestorLangError):
    code = "vm-trap"


@dataclass(frozen=True, slots=True)
class Limits:
    """Runtime limits selected inside immutable compiled ceilings."""

    max_steps: int = DEFAULT_0
    tape_cells: int = DEFAULT_TAPE_CELLS
    max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES

    def __post_init__(self) -> None:
        checks = (
            ("max_steps", self.max_steps, 1, HARD_0),
            ("tape_cells", self.tape_cells, 1, MAX_TAPE_CELLS),
            ("max_output_bytes", self.max_output_bytes, 1, MAX_OUTPUT_BYTES),
        )
        for name, value, lower, upper in checks:
            if type(value) is not int or not lower <= value <= upper:
                raise SourceError(
                    f"{name} must be an integer between {lower} and {upper}")


def canonical_json(value: Any, *, maximum: int = MAX_REPORT_BYTES) -> bytes:
    """Encode strict deterministic JSON and enforce its byte boundary."""
    try:
        raw = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8", "strict")
    except (OverflowError, RecursionError, TypeError, UnicodeError, ValueError) as exc:
        raise AttestorLangError("value is not deterministic JSON") from exc
    if len(raw) > maximum:
        raise AttestorLangError("deterministic JSON exceeds its byte boundary")
    return raw


def checked_i64(value: int, operation: str = "integer operation") -> int:
    if type(value) is not int or not I64_MIN <= value <= I64_MAX:
        raise VmTrap(f"{operation} overflowed signed 64-bit range")
    return value


def wrap_i64(value: int) -> int:
    value &= 2 ** 64 - 1
    return value - 2 ** 64 if value >= 2 ** 63 else value
