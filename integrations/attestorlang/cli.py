#!/usr/bin/env python3
"""Standalone isolated-mode command line for AttestorLang 4.2."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

# ``python -I path/to/cli.py`` intentionally omits the script directory from
# sys.path.  Add this fixed, release-owned directory—not a caller path—so the
# standalone command can still import its sibling modules in isolated mode.
if not __package__:
    _HERE = Path(__file__).resolve().parent
    sys.path.insert(0, str(_HERE))
    import bytecode as bc
    import compiler
    from frontends import a1z26
    from model import (
        MAX_BYTECODE_BYTES, MAX_INPUT_BYTES, MAX_SOURCE_BYTES, Limits,
        AttestorLangError,
    )
    import vm
else:  # pragma: no cover - exercised through package invocation
    from . import bytecode as bc
    from . import compiler, vm
    from .frontends import a1z26
    from .model import (
        MAX_BYTECODE_BYTES, MAX_INPUT_BYTES, MAX_SOURCE_BYTES, Limits,
        AttestorLangError,
    )


def _read_regular(path_value: str, maximum: int, label: str) -> bytes:
    path = Path(path_value)
    try:
        info = path.lstat()
    except OSError as exc:
        raise AttestorLangError(f"{label} is unavailable") from exc
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    attributes = int(getattr(info, "st_file_attributes", 0))
    if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or bool(attributes & reparse)):
        raise AttestorLangError(f"{label} must be a regular non-link file")
    if info.st_size > maximum:
        raise AttestorLangError(f"{label} exceeds its byte boundary")
    try:
        with path.open("rb") as stream:
            descriptor_before = os.fstat(stream.fileno())
            raw = stream.read(maximum + 1)
            descriptor_after = os.fstat(stream.fileno())
        final_info = path.lstat()
    except OSError as exc:
        raise AttestorLangError(f"{label} could not be read") from exc
    identities = tuple(
        (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns)
        for item in (info, descriptor_before, descriptor_after, final_info))
    final_attributes = int(getattr(final_info, "st_file_attributes", 0))
    if (len(raw) > maximum or len(set(identities)) != 1
            or not stat.S_ISREG(final_info.st_mode)
            or stat.S_ISLNK(final_info.st_mode)
            or bool(final_attributes & reparse)):
        raise AttestorLangError(f"{label} changed while it was read")
    return raw


def _source(path: str) -> tuple[str, bytes]:
    raw = _read_regular(path, MAX_SOURCE_BYTES, "source file")
    try:
        return raw.decode("utf-8", "strict"), raw
    except UnicodeError as exc:
        raise AttestorLangError("source file must be strict UTF-8") from exc


def _write_new_regular(path_value: str, raw: bytes) -> None:
    """Create one new output file without following or replacing anything."""
    if type(path_value) is not str or not path_value or "\x00" in path_value:
        raise AttestorLangError("output path is invalid")
    path = Path(path_value)
    parent = path.parent if str(path.parent) else Path(".")
    try:
        parent_info = parent.lstat()
    except OSError as exc:
        raise AttestorLangError("output parent is unavailable") from exc
    reparse = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    parent_attributes = int(getattr(parent_info, "st_file_attributes", 0))
    if (not stat.S_ISDIR(parent_info.st_mode) or stat.S_ISLNK(parent_info.st_mode)
            or bool(parent_attributes & reparse)):
        raise AttestorLangError("output parent must be a real non-link directory")

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= int(getattr(os, "O_BINARY", 0))
    flags |= int(getattr(os, "O_NOFOLLOW", 0))
    descriptor: int | None = None
    created_identity: tuple[int, int] | None = None
    complete = False
    finalization_failed = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created_info = os.fstat(descriptor)
        if not stat.S_ISREG(created_info.st_mode):
            raise AttestorLangError("created output is not a regular file")
        created_identity = (created_info.st_dev, created_info.st_ino)
        offset = 0
        while offset < len(raw):
            written = os.write(descriptor, raw[offset:])
            if written <= 0:
                raise AttestorLangError("output write did not make progress")
            offset += written
        os.fsync(descriptor)
        final_descriptor_info = os.fstat(descriptor)
        path_info = path.lstat()
        path_attributes = int(getattr(path_info, "st_file_attributes", 0))
        if (not stat.S_ISREG(path_info.st_mode) or stat.S_ISLNK(path_info.st_mode)
                or bool(path_attributes & reparse)
                or (path_info.st_dev, path_info.st_ino) != created_identity
                or final_descriptor_info.st_size != len(raw)):
            raise AttestorLangError("created output identity or size changed")
        complete = True
    except FileExistsError as exc:
        raise AttestorLangError("output already exists; refusing to overwrite it") from exc
    except OSError as exc:
        raise AttestorLangError("output could not be created safely") from exc
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                complete = False
                finalization_failed = True
        if not complete and created_identity is not None:
            try:
                candidate = path.lstat()
                attributes = int(getattr(candidate, "st_file_attributes", 0))
                if (stat.S_ISREG(candidate.st_mode)
                        and not stat.S_ISLNK(candidate.st_mode)
                        and not bool(attributes & reparse)
                        and (candidate.st_dev, candidate.st_ino) == created_identity):
                    path.unlink()
            except FileNotFoundError:
                # Already absent is the desired cleanup postcondition.
                created_identity = None
            except OSError:
                finalization_failed = True
        if finalization_failed:
            raise AttestorLangError(
                "output finalization failed; inspect the selected path")


def _render_run(report: dict, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False))
        return
    import base64
    output = base64.b64decode(report["output"]["base64"], validate=True)
    shown = output.decode("utf-8", "backslashreplace")
    print(f"AttestorLang 4.2: {report['status']}")
    print(f"steps: {report['usage']['steps']}")
    print(f"bytecode SHA-256: {report['bytecode_sha256']}")
    print("output:")
    print(shown, end="" if shown.endswith("\n") or not shown else "\n")
    if report["error"]:
        print(f"error: {report['error']['message']}")


def _limits(args: argparse.Namespace) -> Limits:
    return Limits(
        max_steps=args.max_steps,
        tape_cells=args.tape_cells,
        max_output_bytes=args.max_output_bytes,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, allow_abbrev=False)
    subparsers = parser.add_subparsers(dest="command", required=True)

    check = subparsers.add_parser("check", allow_abbrev=False)
    check.add_argument("path")
    check.add_argument("--format", choices=("text", "json"), default="text")

    run = subparsers.add_parser("run", allow_abbrev=False)
    run.add_argument("path")
    run.add_argument("--format", choices=("text", "json"), default="text")
    inputs = run.add_mutually_exclusive_group()
    inputs.add_argument("--input-text")
    inputs.add_argument("--input-hex")
    run.add_argument("--max-steps", type=int, default=1_000_000)
    run.add_argument("--tape-cells", type=int, default=4_096)
    run.add_argument("--max-output-bytes", type=int, default=64 * 1024)

    run_bytecode = subparsers.add_parser("run-bytecode", allow_abbrev=False)
    run_bytecode.add_argument("path")
    run_bytecode.add_argument("--format", choices=("text", "json"), default="text")
    run_bytecode.add_argument("--input-hex")
    run_bytecode.add_argument("--grant-input", action="store_true")
    run_bytecode.add_argument("--max-steps", type=int, default=1_000_000)
    run_bytecode.add_argument("--tape-cells", type=int, default=4_096)
    run_bytecode.add_argument("--max-output-bytes", type=int, default=64 * 1024)

    compile_parser = subparsers.add_parser("compile", allow_abbrev=False)
    compile_parser.add_argument("path")
    compile_parser.add_argument("--out")

    disasm = subparsers.add_parser("disasm", allow_abbrev=False)
    disasm.add_argument("path")

    encode_a1 = subparsers.add_parser("encode-a1z26", allow_abbrev=False)
    encode_a1.add_argument("assembly")
    decode_a1 = subparsers.add_parser("decode-a1z26", allow_abbrev=False)
    decode_a1.add_argument("source")

    args = parser.parse_args(argv)
    try:
        if args.command == "encode-a1z26":
            print(a1z26.encode_assembly(args.assembly))
            return 0
        if args.command == "decode-a1z26":
            print(a1z26.decode_assembly(args.source))
            return 0
        if args.command == "disasm":
            blob = _read_regular(args.path, MAX_BYTECODE_BYTES, "bytecode file")
            sys.stdout.write(bc.disassemble(bc.decode(blob)))
            return 0
        if args.command == "run-bytecode":
            blob = _read_regular(args.path, MAX_BYTECODE_BYTES, "bytecode file")
            program = bc.decode(blob)
            input_bytes = bytes.fromhex(args.input_hex) if args.input_hex else b""
            if len(input_bytes) > MAX_INPUT_BYTES:
                raise AttestorLangError("virtual input exceeds its byte boundary")
            grants = ["console.write"]
            if args.grant_input or args.input_hex is not None:
                grants.append("input.read")
            report = vm.execute(
                program, granted_capabilities=grants, input_bytes=input_bytes,
                limits=_limits(args))
            _render_run(report, args.format)
            return 0 if report["status"] == "completed" else (
                1 if report["status"] == "trapped" else 2)

        source, raw = _source(args.path)
        program = compiler.compile_source(source)
        blob = bc.encode(program)
        if args.command == "check":
            if args.format == "json":
                print(json.dumps({
                    "schema": "attestorlang-check/4.2", "status": "valid",
                    "bytecode_bytes": len(blob),
                    "bytecode_sha256": hashlib.sha256(blob).hexdigest(),
                    "capabilities": list(program.capabilities),
                    "instructions": len(program.code),
                }, indent=2, sort_keys=True))
            else:
                print(f"valid AttestorLang 4.2: {len(program.code)} instructions")
                print("capabilities: " + (", ".join(program.capabilities) or "none"))
            return 0
        if args.command == "compile":
            if args.out:
                _write_new_regular(args.out, blob)
                print(f"wrote {len(blob)} verified ATVM bytes")
            else:
                print(blob.hex())
            return 0

        if args.input_text is not None:
            input_bytes = args.input_text.encode("utf-8", "strict")
        elif args.input_hex is not None:
            input_bytes = bytes.fromhex(args.input_hex)
        else:
            input_bytes = b""
        if len(input_bytes) > MAX_INPUT_BYTES:
            raise AttestorLangError("virtual input exceeds its byte boundary")
        grants = ["console.write"]
        if args.input_text is not None or args.input_hex is not None:
            grants.append("input.read")
        report = vm.execute(
            program, granted_capabilities=grants, input_bytes=input_bytes,
            source_bytes=raw, limits=_limits(args))
        _render_run(report, args.format)
        return 0 if report["status"] == "completed" else (
            1 if report["status"] == "trapped" else 2)
    except (AttestorLangError, OSError, UnicodeError, ValueError) as exc:
        print(f"attestorlang: {type(exc).__name__}: {str(exc)[:500]}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
