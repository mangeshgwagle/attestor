#!/usr/bin/env python3
"""Read a compiled binary's hardening flags. No disassembler, no dependencies.

Attestor reads source. A source scan cannot tell you whether the thing you shipped
was actually built with the protections you assumed: the compiler flag may have
been dropped by a Makefile, overridden by a distro default, or silently undone
by one hand-written `.S` that forgot `.note.GNU-stack`. Those are decided at
link time and are only visible in the artifact.

What this reads is a fixed binary layout, so it is exactly the kind of question
that can be answered deterministically -- header fields and program-header
flags, parsed with `struct`. Every check below is a documented bit in a
documented structure.

What it is not
--------------
This is not a disassembler and makes no claim about what the code *does*. It
reports how the binary was built. A hardened binary can still be full of
defects, and an unhardened one may be perfectly safe in its context; the flags
say which mitigations are present, and nothing else.

The stack-canary and fortify checks are the one soft spot and are labelled as
such: they look for the linker-inserted symbol names rather than proving every
function is instrumented, so they answer "was this built with the flag" and not
"is every frame protected".
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
from typing import Any

SCHEMA = "attestor.binary-hardening/1.0"
VERSION = "4.1.4"

MAX_BINARY_BYTES = 256 * 1024 * 1024
MAX_SYMBOL_SCAN = 8 * 1024 * 1024

ELF_MAGIC = b"\x7fELF"
PE_MAGIC = b"MZ"

PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
PF_X = 0x1

DT_NULL, DT_RPATH, DT_BIND_NOW, DT_RUNPATH, DT_FLAGS = 0, 15, 24, 29, 30
DF_BIND_NOW = 0x8

# PE DllCharacteristics bits (winnt.h).
PE_DYNAMIC_BASE = 0x0040
PE_NX_COMPAT = 0x0100
PE_HIGH_ENTROPY_VA = 0x0020
PE_GUARD_CF = 0x4000


class BinaryError(ValueError):
    """The file is missing, too large, or not a binary this module reads."""


def _sha(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"),
        ensure_ascii=True).encode("utf-8")).hexdigest()


def _read(path: str) -> bytes:
    try:
        size = os.path.getsize(path)
    except OSError as error:
        raise BinaryError("cannot stat %s: %s" % (path[:120], error)) from error
    if size > MAX_BINARY_BYTES:
        raise BinaryError("binary is larger than the %d byte ceiling"
                          % MAX_BINARY_BYTES)
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as error:
        raise BinaryError("cannot read %s: %s" % (path[:120], error)) from error


def _elf_program_headers(data: bytes):
    """Yield (p_type, p_flags, p_offset, p_filesz) for each program header."""
    is64 = data[4] == 2
    little = data[5] == 1
    endian = "<" if little else ">"
    try:
        if is64:
            phoff = struct.unpack_from(endian + "Q", data, 32)[0]
            phentsize, phnum = struct.unpack_from(endian + "HH", data, 54)
        else:
            phoff = struct.unpack_from(endian + "I", data, 28)[0]
            phentsize, phnum = struct.unpack_from(endian + "HH", data, 42)
    except struct.error as error:
        raise BinaryError("truncated ELF header") from error
    if phnum > 4096 or phentsize < 8:
        raise BinaryError("implausible ELF program header table")
    for index in range(phnum):
        base = phoff + index * phentsize
        if base + phentsize > len(data):
            break
        if is64:
            ptype, flags = struct.unpack_from(endian + "II", data, base)
            offset, _, filesz = struct.unpack_from(endian + "QQQ", data,
                                                   base + 8)
        else:
            ptype, offset = struct.unpack_from(endian + "II", data, base)
            _, filesz = struct.unpack_from(endian + "II", data, base + 8)
            flags = struct.unpack_from(endian + "I", data, base + 24)[0]
        yield ptype, flags, offset, filesz


def _elf_dynamic_flags(data: bytes, offset: int, size: int) -> set[int]:
    """The DT_ tags present in the dynamic section, plus DF_BIND_NOW."""
    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    step = 16 if is64 else 8
    fmt = endian + ("Qq" if is64 else "Ii")
    tags: set[int] = set()
    position = offset
    limit = min(offset + size, len(data))
    while position + step <= limit:
        try:
            tag, value = struct.unpack_from(fmt, data, position)
        except struct.error:
            break
        if tag == DT_NULL:
            break
        tags.add(tag)
        if tag == DT_FLAGS and value & DF_BIND_NOW:
            tags.add(DT_BIND_NOW)
        position += step
    return tags


ELF32_HEADER_BYTES = 52
ELF64_HEADER_BYTES = 64


def _elf_report(data: bytes, path: str) -> dict[str, Any]:
    # A corrupt or truncated file must be refused, never parsed on optimism:
    # a scanner that raises struct.error on one bad artifact takes the whole
    # run down with it.
    if data[4] not in (1, 2) or data[5] not in (1, 2):
        raise BinaryError("ELF identifies neither its class nor its endianness")
    needed = ELF64_HEADER_BYTES if data[4] == 2 else ELF32_HEADER_BYTES
    if len(data) < needed:
        raise BinaryError("truncated ELF header: %d bytes, need %d"
                          % (len(data), needed))
    endian = "<" if data[5] == 1 else ">"
    try:
        etype = struct.unpack_from(endian + "H", data, 16)[0]
        headers = list(_elf_program_headers(data))
    except struct.error as error:
        raise BinaryError("malformed ELF structure: %s" % error) from error

    stack_header = next((h for h in headers if h[0] == PT_GNU_STACK), None)
    relro = any(h[0] == PT_GNU_RELRO for h in headers)
    dynamic = next((h for h in headers if h[0] == PT_DYNAMIC), None)
    tags = _elf_dynamic_flags(data, dynamic[2], dynamic[3]) if dynamic else set()

    window = data[:MAX_SYMBOL_SCAN]
    checks = {
        # An absent PT_GNU_STACK is the dangerous case, not a neutral one: the
        # kernel then falls back to an executable stack on most targets.
        "nx": {
            "ok": bool(stack_header) and not (stack_header[1] & PF_X),
            "detail": ("no PT_GNU_STACK header, so the stack is executable"
                       if stack_header is None else
                       "stack is executable (PF_X set on PT_GNU_STACK)"
                       if stack_header[1] & PF_X else
                       "stack is not executable"),
        },
        "pie": {
            "ok": etype == 3,
            "detail": ("position independent (ET_DYN)" if etype == 3
                       else "fixed load address (ET_EXEC); ASLR cannot move it"),
        },
        "relro": {
            "ok": relro and DT_BIND_NOW in tags,
            "detail": ("full RELRO" if relro and DT_BIND_NOW in tags
                       else "partial RELRO; the GOT stays writable"
                       if relro else "no RELRO"),
        },
        "stack_canary": {
            "ok": b"__stack_chk_fail" in window,
            "detail": ("__stack_chk_fail is linked in"
                       if b"__stack_chk_fail" in window
                       else "no __stack_chk_fail; built without -fstack-protector"),
            "soft": True,
        },
        "fortify": {
            "ok": b"_chk" in window and b"__memcpy_chk" in window
                  or b"__printf_chk" in window or b"__sprintf_chk" in window,
            "detail": "fortified libc calls present"
                      if (b"__memcpy_chk" in window or b"__printf_chk" in window
                          or b"__sprintf_chk" in window)
                      else "no _FORTIFY_SOURCE wrappers found",
            "soft": True,
        },
        "no_rpath": {
            "ok": DT_RPATH not in tags,
            "detail": ("DT_RPATH is set; the library search path is baked in "
                       "and cannot be overridden safely" if DT_RPATH in tags
                       else "no DT_RPATH"),
        },
    }
    return {"format": "elf",
            "bits": 64 if data[4] == 2 else 32,
            "endian": "little" if data[5] == 1 else "big",
            "type": {2: "executable", 3: "shared-object/pie"}.get(etype,
                                                                  "other"),
            "checks": checks}


def _pe_report(data: bytes, path: str) -> dict[str, Any]:
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset:pe_offset + 4] != b"PE\0\0":
            raise BinaryError("not a PE image")
        magic = struct.unpack_from("<H", data, pe_offset + 24)[0]
        plus = magic == 0x20B
        characteristics = struct.unpack_from(
            "<H", data, pe_offset + 24 + (70 if plus else 70))[0]
    except (struct.error, IndexError) as error:
        raise BinaryError("truncated PE header") from error

    checks = {
        "nx": {"ok": bool(characteristics & PE_NX_COMPAT),
               "detail": "DEP/NX compatible" if characteristics & PE_NX_COMPAT
                         else "not marked NX_COMPAT; DEP may be off"},
        "aslr": {"ok": bool(characteristics & PE_DYNAMIC_BASE),
                 "detail": "relocatable (DYNAMIC_BASE)"
                           if characteristics & PE_DYNAMIC_BASE
                           else "no DYNAMIC_BASE; ASLR cannot move it"},
        "high_entropy_aslr": {
            "ok": bool(characteristics & PE_HIGH_ENTROPY_VA),
            "detail": "64-bit high-entropy ASLR"
                      if characteristics & PE_HIGH_ENTROPY_VA
                      else "no HIGH_ENTROPY_VA"},
        "control_flow_guard": {
            "ok": bool(characteristics & PE_GUARD_CF),
            "detail": "Control Flow Guard enabled"
                      if characteristics & PE_GUARD_CF
                      else "no Control Flow Guard"},
    }
    return {"format": "pe", "bits": 64 if plus else 32,
            "endian": "little", "type": "image", "checks": checks}


def inspect(path: str) -> dict[str, Any]:
    """Hardening flags for one binary, as a verifiable report."""
    data = _read(path)
    if data[:4] == ELF_MAGIC:
        body = _elf_report(data, path)
    elif data[:2] == PE_MAGIC:
        body = _pe_report(data, path)
    else:
        raise BinaryError("not an ELF or PE binary")

    weak = sorted(name for name, check in body["checks"].items()
                  if not check["ok"])
    report = {
        "schema": SCHEMA,
        "version": VERSION,
        "path": os.path.basename(path),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "missing_mitigations": weak,
        "hardened": not weak,
        **body,
        "limitations": [
            "this reports how the binary was built, never what its code does",
            "a hardened binary can still be full of defects, and an unhardened "
            "one may be fine in its context",
            "the canary and fortify checks look for linker-inserted symbol "
            "names, so they answer 'was the flag used', not 'is every frame "
            "protected'",
        ],
    }
    report["report_sha256"] = _sha(
        {k: v for k, v in report.items() if k != "report_sha256"})
    return report


def verify_report(report: dict[str, Any]) -> tuple[bool, list[str]]:
    """Recompute a report's identity. Fails closed."""
    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        return False, ["not a binary-hardening report"]
    body = {k: v for k, v in report.items() if k != "report_sha256"}
    if report.get("report_sha256") != _sha(body):
        return False, ["report digest does not match its contents"]
    return True, []


def render(report: dict[str, Any]) -> str:
    lines = ["%s  (%s %d-bit %s)" % (report["path"], report["format"].upper(),
                                     report["bits"], report["type"])]
    for name, check in sorted(report["checks"].items()):
        mark = "ok  " if check["ok"] else "MISS"
        soft = "  (heuristic)" if check.get("soft") else ""
        lines.append("  %s  %-18s %s%s" % (mark, name, check["detail"], soft))
    lines.append("")
    lines.append("missing: %s" % (", ".join(report["missing_mitigations"])
                                  or "nothing"))
    lines.extend("note: " + item for item in report["limitations"])
    return "\n".join(lines)


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("binaries", nargs="+")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    failures = 0
    for path in args.binaries:
        try:
            report = inspect(path)
        except BinaryError as error:
            print("skip %s: %s" % (os.path.basename(path), error))
            failures += 1
            continue
        print(json.dumps(report, indent=2, sort_keys=True) if args.json
              else render(report))
        print()
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
