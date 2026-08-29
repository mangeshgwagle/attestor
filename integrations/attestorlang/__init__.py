"""AttestorLang 4.2: a bounded language and private virtual machine."""
from __future__ import annotations

from .bytecode import Program, decode, disassemble, encode, verify
from .compiler import compile_source
from .model import Limits, AttestorLangError, VERSION
from .vm import execute, verify_report

__all__ = (
    "Limits", "AttestorLangError", "Program", "VERSION", "compile_source",
    "decode", "disassemble", "encode", "execute", "verify", "verify_report",
)
