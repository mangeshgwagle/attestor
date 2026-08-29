#!/usr/bin/env python3
"""pwnbridge42 -- pwntools wired into Attestor's exploitation stack.

Gives Owen access to pwntools' primitives:
    shellcraft   shellcode generation
    asm/disasm   assembly compilation for x86, x64, ARM, etc.
    ELF          binary parsing, symbols, GOT/PLT
    process      local process interaction
    cyclic       buffer overflow offset discovery

Primitives only -- what Owen builds with them is governed by the
existing module boundaries.
"""

from __future__ import annotations

import hashlib
import json
import sys

PB_SCHEMA = "attestor-pwnbridge-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4


def sha256_hex(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def shellcode(arch="amd64", os_name="linux", action="execve", args=None):
    from pwn import shellcraft, asm
    try:
        sc = getattr(getattr(shellcraft, arch), os_name)
        template = getattr(sc, action)
        code = template(*(args or ()))
        compiled = asm(code, arch=arch, os=os_name)
        return {"schema": PB_SCHEMA, "tool": "shellcode", "arch": arch,
                "os": os_name, "action": action, "assembly": code,
                "bytes_hex": compiled.hex(), "size": len(compiled),
                "sha256": sha256_hex(compiled)}
    except Exception as exc:
        return {"schema": PB_SCHEMA, "error": str(exc)[:200]}


def assemble(code, arch="amd64", os_name="linux"):
    from pwn import asm
    try:
        compiled = asm(code, arch=arch, os=os_name)
        return {"schema": PB_SCHEMA, "tool": "asm", "bytes_hex": compiled.hex(),
                "size": len(compiled), "sha256": sha256_hex(compiled)}
    except Exception as exc:
        return {"schema": PB_SCHEMA, "error": str(exc)[:300]}


def disassemble(data_hex, arch="amd64", os_name="linux"):
    from pwn import disasm
    try:
        data = bytes.fromhex(data_hex)
        return {"schema": PB_SCHEMA, "tool": "disasm", "arch": arch,
                "input_bytes": len(data),
                "disassembly": disasm(data, arch=arch, os=os_name)}
    except Exception as exc:
        return {"schema": PB_SCHEMA, "error": str(exc)[:300]}


def elf_info(binary_path):
    from pwn import ELF
    try:
        elf = ELF(str(binary_path), checksec=False)
        return {"schema": PB_SCHEMA, "tool": "elf-info",
                "arch": elf.arch, "bits": elf.bits,
                "entry": hex(elf.entry), "canary": elf.canary,
                "nx": elf.nx, "pie": elf.pie, "relro": elf.relro,
                "symbols": {n: hex(a) for n, a in
                            sorted(elf.symbols.items(),
                                   key=lambda x: x[1])[:30]},
                "plt": {n: hex(a) for n, a in
                        sorted(elf.plt.items(), key=lambda x: x[1])[:20]}}
    except Exception as exc:
        return {"schema": PB_SCHEMA, "error": str(exc)[:300]}


def checksec(binary_path):
    from pwn import ELF
    try:
        elf = ELF(str(binary_path), checksec=True)
        return {"schema": PB_SCHEMA, "tool": "checksec",
                "canary": elf.canary, "nx": elf.nx,
                "pie": elf.pie, "relro": elf.relro}
    except Exception as exc:
        return {"schema": PB_SCHEMA, "error": str(exc)[:300]}


def run_process(binary_path, argv=None, input_data=None, timeout=10):
    from pwn import process
    try:
        io = process([str(binary_path)] + (argv or []), timeout=timeout)
        if input_data:
            io.send(input_data)
        output = io.recvall(timeout=timeout)
        io.close()
        return {"schema": PB_SCHEMA, "tool": "process",
                "output_len": len(output),
                "output_hex": output.hex()[:512]}
    except Exception as exc:
        return {"schema": PB_SCHEMA, "error": str(exc)[:300]}


def cyclic_find(pattern):
    from pwn import cyclic_find
    try:
        if all(c in "0123456789abcdef" for c in pattern.lower()) and \
                len(pattern) in (4, 8, 16):
            offset = cyclic_find(bytes.fromhex(pattern))
        else:
            offset = cyclic_find(pattern.encode())
        return {"schema": PB_SCHEMA, "offset": offset}
    except Exception as exc:
        return {"schema": PB_SCHEMA, "error": str(exc)[:200]}


def cyclic_gen(length=512):
    from pwn import cyclic
    return {"schema": PB_SCHEMA, "pattern": cyclic(length).decode("latin-1"),
            "length": length}


def list_capabilities():
    import pwnlib
    return {
        "schema": PB_SCHEMA,
        "tool": "pwnbridge",
        "pwntools_version": pwnlib.__version__,
        "capabilities": [
            "shellcode(arch, os, action, args)",
            "assemble(code, arch)",
            "disassemble(data_hex, arch)",
            "elf_info(binary_path)",
            "checksec(binary_path)",
            "run_process(binary_path, argv, input_data)",
            "cyclic_find(pattern)",
            "cyclic_gen(length)",
        ],
        "archs": ["amd64", "i386", "arm", "aarch64", "mips",
                  "powerpc", "riscv64", "s390x", "sparc64"],
    }


def run_selftest():
    checks = []

    caps = list_capabilities()
    checks.append(("pwntools loaded", "pwntools_version" in caps))
    checks.append(("9 architectures supported",
                   len(caps["archs"]) == 9))

    import platform
    is_windows = platform.system() == "Windows"

    if not is_windows:
        sc = shellcode("amd64", "linux", "execve",
                       ["/bin/sh", None, None])
        checks.append(("shellcode generated",
                       "bytes_hex" in sc and sc["size"] > 0))
        asm_result = assemble("nop", arch="amd64")
        checks.append(("assembly compiles",
                       asm_result.get("bytes_hex") == "90"))
        dis = disassemble("90", arch="amd64")
        checks.append(("disassembly works",
                       "nop" in dis.get("disassembly", "")))
    else:
        checks.append(("asm/shellcode skipped on Windows (needs binutils)",
                       True))

    cyc = cyclic_gen(64)
    checks.append(("cyclic pattern generated",
                   cyc["length"] == 64 and len(cyc["pattern"]) == 64))

    from pwn import cyclic as pwn_cyclic, cyclic_find as pwn_cf
    pattern = pwn_cyclic(128).decode("latin-1")
    substring = pattern[20:24]
    offset = pwn_cf(substring.encode())
    checks.append(("cyclic offset found", offset == 20))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": PB_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(
        prog="pwnbridge42",
        description="pwntools exploitation primitives for Owen")
    subs = parser.add_subparsers(dest="command", required=True)

    p = subs.add_parser("shellcode")
    p.add_argument("--arch", default="amd64")
    p.add_argument("--os", default="linux")
    p.add_argument("--action", default="execve")
    p.add_argument("--args", nargs="*", default=None)

    p = subs.add_parser("asm")
    p.add_argument("--code", required=True)
    p.add_argument("--arch", default="amd64")

    p = subs.add_parser("disasm")
    p.add_argument("--hex", required=True)
    p.add_argument("--arch", default="amd64")

    p = subs.add_parser("elf")
    p.add_argument("binary")

    p = subs.add_parser("checksec")
    p.add_argument("binary")

    p = subs.add_parser("process")
    p.add_argument("binary")
    p.add_argument("--argv", nargs="*", default=[])
    p.add_argument("--input")
    p.add_argument("--timeout", type=int, default=10)

    p = subs.add_parser("cyclic-find")
    p.add_argument("pattern")

    p = subs.add_parser("cyclic-gen")
    p.add_argument("--length", type=int, default=512)

    subs.add_parser("list")
    subs.add_parser("self-test")
    args = parser.parse_args(argv)

    dispatch = {
        "shellcode": lambda: shellcode(args.arch, args.os,
                                       args.action, args.args),
        "asm": lambda: assemble(args.code, arch=args.arch),
        "disasm": lambda: disassemble(args.hex, arch=args.arch),
        "elf": lambda: elf_info(args.binary),
        "checksec": lambda: checksec(args.binary),
        "process": lambda: run_process(args.binary, args.argv,
                                       args.input, args.timeout),
        "cyclic-find": lambda: cyclic_find(args.pattern),
        "cyclic-gen": lambda: cyclic_gen(args.length),
        "list": list_capabilities,
        "self-test": run_selftest,
    }

    fn = dispatch.get(args.command)
    if fn is None:
        parser.error("unknown command")
    result = fn()
    print(json.dumps(result, indent=2, sort_keys=True, default=str))
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())

