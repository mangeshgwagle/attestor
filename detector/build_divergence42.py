#!/usr/bin/env python3
"""Capabilities present in compiled assembly that no source file explains.

The attack this exists for
--------------------------
Reviewing source cannot catch a build that adds something the source never
asked for. That is the XZ-utils shape and the SolarWinds shape: the repository
is clean, every commit reviews fine, and the artifact that ships is not what the
source describes. It is also Thompson's "trusting trust" in its modern form --
the compiler, the linker, a build plugin, or a poisoned CI runner is the
adversary, and the source is the alibi.

No amount of source analysis closes that gap, because the divergence is not in
the source. The only way to see it is to read what was actually produced.

What this module does
---------------------
Given a source tree and the assembly listings from its build, it derives two
capability sets and reports the difference:

* **from source** -- imports and calls, via `semantic_graph41`, mapped to the
  capabilities they imply (a `socket` import means networking is expected).
* **from assembly** -- syscalls, exec primitives, network syscall numbers,
  writable-executable sections, found by reading the listings.

A capability the binary has and the source never asked for is the finding.

What it is not
--------------
It never compiles and never executes. It reads a listing somebody else
produced, which keeps the whole analysis inside the same boundary as the rest
of `detector/`: no target code runs, no process starts, no socket opens.

It is also not proof of a backdoor. A compiler intrinsic, an inlined libc
routine, or a runtime's startup stub can all introduce a syscall the source did
not literally write. So an unexplained capability is a **review point with the
exact evidence attached**, never a verdict -- and the report says so in the
same words every time. The value is that the list is short and specific: a
handful of sites a human can actually check, rather than a whole binary.

Stdlib only, like everything in `detector/`.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Mapping, Sequence

HERE = Path(__file__).resolve(strict=True).parent
if os.fspath(HERE) not in sys.path:
    sys.path.insert(0, os.fspath(HERE))

import analysis_snapshot41 as snapshot41  # noqa: E402
import detect  # noqa: E402
import semantic_graph41 as semantic  # noqa: E402


SCHEMA = "attestor.build-divergence/4.2"
VERSION = "4.2"
MAX_LISTING_BYTES = 8 * 1024 * 1024
MAX_SITES_PER_CAPABILITY = 25

sys.dont_write_bytecode = True


class BuildDivergenceError(ValueError):
    """The inputs could not be read or compared, fail-closed."""


# --------------------------------------------------------------------------- #
# Capabilities: the vocabulary both sides are translated into.
# --------------------------------------------------------------------------- #
PROCESS_EXEC = "process-execution"
NETWORK = "network"
FILE_WRITE = "file-write"
DYNAMIC_CODE = "dynamic-code"
PRIVILEGE = "privilege-change"

CAPABILITIES = (PROCESS_EXEC, NETWORK, FILE_WRITE, DYNAMIC_CODE, PRIVILEGE)

# Source-side evidence. A module or callee named here means the source is
# openly asking for the capability, so finding it in the binary is expected.
# The lists are deliberately generous: over-crediting the source produces a
# false negative, which is far better than accusing a clean build.
_SOURCE_MODULES = {
    PROCESS_EXEC: (
        "subprocess", "os.system", "os.exec", "os.spawn", "os.popen", "pty",
        "multiprocessing", "java.lang.runtime", "java.lang.processbuilder",
        "os/exec", "std::process", "system.diagnostics.process", "popen",
        "unistd", "spawn", "child_process",
    ),
    NETWORK: (
        "socket", "ssl", "http", "https", "urllib", "requests", "httpx",
        "asyncio", "ftplib", "smtplib", "telnetlib", "net", "net/http",
        "java.net", "javax.net", "system.net", "hyper", "reqwest", "curl",
        "winsock", "sys/socket", "netinet", "axios", "fetch",
    ),
    FILE_WRITE: (
        "open", "io", "shutil", "pathlib", "tempfile", "os.write", "fs",
        "java.io", "java.nio", "system.io", "std::fs", "os", "fopen", "fstream",
    ),
    DYNAMIC_CODE: (
        "ctypes", "cffi", "importlib", "marshal", "pickle", "dill", "eval",
        "exec", "compile", "mmap", "dlfcn", "java.lang.reflect",
        "system.reflection", "libloading",
    ),
    PRIVILEGE: (
        "os.setuid", "os.setgid", "os.seteuid", "pwd", "grp", "win32security",
        "sys/capability", "setuid", "setgid", "seccomp",
    ),
}

# Assembly-side evidence. Linux x86-64 syscall numbers are the most reliable
# signal in a listing: the number is loaded into eax/rax immediately before the
# `syscall`, and the mapping is a stable kernel ABI.
_SYSCALL_CAPABILITY = {
    59: PROCESS_EXEC,    # execve
    322: PROCESS_EXEC,   # execveat
    57: PROCESS_EXEC,    # fork
    58: PROCESS_EXEC,    # vfork
    56: PROCESS_EXEC,    # clone
    41: NETWORK,         # socket
    42: NETWORK,         # connect
    43: NETWORK,         # accept
    44: NETWORK,         # sendto
    45: NETWORK,         # recvfrom
    49: NETWORK,         # bind
    50: NETWORK,         # listen
    1: FILE_WRITE,       # write
    2: FILE_WRITE,       # open
    257: FILE_WRITE,     # openat
    87: FILE_WRITE,      # unlink
    10: DYNAMIC_CODE,    # mprotect
    9: DYNAMIC_CODE,     # mmap
    105: PRIVILEGE,      # setuid
    106: PRIVILEGE,      # setgid
    157: PRIVILEGE,      # prctl
}

_ASM_SYMBOL_CAPABILITY = (
    (re.compile(r"\b(?:call|jmp|bl|b)\s+.*\b(execve|execl|execvp|system|posix_spawn|fork|popen)\b", re.I),
     PROCESS_EXEC),
    (re.compile(r"\b(?:call|jmp|bl|b)\s+.*\b(socket|connect|bind|listen|accept|send|recv|getaddrinfo)\b", re.I),
     NETWORK),
    (re.compile(r"\b(?:call|jmp|bl|b)\s+.*\b(fopen|fwrite|open64|creat|unlink|remove)\b", re.I),
     FILE_WRITE),
    (re.compile(r"\b(?:call|jmp|bl|b)\s+.*\b(mprotect|mmap|dlopen|dlsym|VirtualProtect|LoadLibrary)\b", re.I),
     DYNAMIC_CODE),
    (re.compile(r"\b(?:call|jmp|bl|b)\s+.*\b(setuid|setgid|seteuid|setresuid|prctl)\b", re.I),
     PRIVILEGE),
)

_SYSCALL_LOAD = re.compile(
    r"\b(?:mov|movl|movq)\s+(?:\$?(0x[0-9a-f]+|\d+)\s*,\s*%?(?:e|r)ax"
    r"|%?(?:e|r)ax\s*,\s*(0x[0-9a-f]+|\d+))\b", re.I)
_SYSCALL_INSTR = re.compile(r"\b(?:syscall|sysenter)\b|\bint\s+0x80\b", re.I)
_ASM_SUFFIXES = {".asm", ".s", ".nasm", ".lst", ".listing"}


def _sha(value: Any) -> str:
    payload = value if isinstance(value, bytes) else json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


@dataclass
class Evidence:
    """One site in one file that demonstrates a capability."""
    path: str
    line: int
    text: str
    reason: str

    def as_dict(self) -> dict[str, Any]:
        return {"path": self.path, "line": self.line,
                "text": self.text[:200], "reason": self.reason}


@dataclass
class Side:
    capabilities: dict[str, list[Evidence]] = field(default_factory=dict)

    def add(self, capability: str, item: Evidence) -> None:
        sites = self.capabilities.setdefault(capability, [])
        if len(sites) < MAX_SITES_PER_CAPABILITY:
            sites.append(item)

    def names(self) -> set[str]:
        return {name for name, sites in self.capabilities.items() if sites}


def capabilities_from_source(root: str | os.PathLike[str]) -> Side:
    """What the source openly asks for, from its imports and calls."""
    try:
        snapshot = snapshot41.capture(root)
    except (snapshot41.SnapshotError, OSError, ValueError) as exc:
        raise BuildDivergenceError("source tree could not be captured") from exc
    graph = semantic.build(snapshot)
    side = Side()

    def classify(text: str) -> str | None:
        lowered = text.lower()
        for capability, needles in _SOURCE_MODULES.items():
            for needle in needles:
                if needle in lowered:
                    return capability
        return None

    for row in graph["graph"]["imports"]:
        target = str(row.get("resolved_module") or row.get("module") or "")
        capability = classify(target)
        if capability:
            side.add(capability, Evidence(
                str(row.get("path", "")), int(row.get("line", 1) or 1),
                "import " + target, "source imports %s" % target))
    for row in graph["graph"]["calls"]:
        callee = str(row.get("resolved") or row.get("callee") or "")
        capability = classify(callee)
        if capability:
            side.add(capability, Evidence(
                str(row.get("path", "")), int(row.get("line", 1) or 1),
                callee + "()", "source calls %s" % callee))
    return side


def capabilities_from_assembly(listings: Mapping[str, str]) -> Side:
    """What the compiled output actually does, from its listings.

    Syscall numbers are read from the register load that precedes the
    `syscall`, which is how the ABI is expressed in every listing. Only the
    masked instruction view is searched, so a mnemonic inside a string constant
    or a comment describing a syscall is not counted as one.
    """
    side = Side()
    for path, text in listings.items():
        masked = detect.blank(text, "asm")
        pending: list[int] = []
        for index, line in enumerate(masked):
            for match in _SYSCALL_LOAD.finditer(line):
                raw = match.group(1) or match.group(2)
                try:
                    pending.append(int(raw, 16) if raw.lower().startswith("0x")
                                   else int(raw))
                except (TypeError, ValueError):
                    continue
            if _SYSCALL_INSTR.search(line):
                for number in pending[-4:]:
                    capability = _SYSCALL_CAPABILITY.get(number)
                    if capability:
                        side.add(capability, Evidence(
                            path, index + 1, line.strip(),
                            "syscall %d issued here" % number))
                pending = []
            for pattern, capability in _ASM_SYMBOL_CAPABILITY:
                found = pattern.search(line)
                if found:
                    side.add(capability, Evidence(
                        path, index + 1, line.strip(),
                        "calls %s" % found.group(1)))
            if re.search(r"\.section\b[^\n\"]*\"[a-z]*w[a-z]*x[a-z]*\"", line, re.I) or \
                    re.search(r"\.section\b[^\n\"]*\"[a-z]*x[a-z]*w[a-z]*\"", line, re.I):
                side.add(DYNAMIC_CODE, Evidence(
                    path, index + 1, line.strip(),
                    "section is both writable and executable"))
    return side


def read_listings(root: str | os.PathLike[str]) -> dict[str, str]:
    """Every assembly listing under *root*, keyed by relative path."""
    base = Path(root)
    if not base.exists():
        raise BuildDivergenceError("assembly directory does not exist")
    out: dict[str, str] = {}
    for path in sorted(base.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _ASM_SUFFIXES:
            continue
        try:
            if path.stat().st_size > MAX_LISTING_BYTES:
                continue
            out[path.relative_to(base).as_posix()] = path.read_text(
                encoding="utf-8", errors="replace")
        except OSError:
            continue
    if not out:
        raise BuildDivergenceError("no assembly listings found under " + str(base))
    return out


def compare(source_root: str | os.PathLike[str],
            assembly_root: str | os.PathLike[str]) -> dict[str, Any]:
    """Report capabilities the binary has that the source never asked for."""
    listings = read_listings(assembly_root)
    source = capabilities_from_source(source_root)
    binary = capabilities_from_assembly(listings)

    unexplained = sorted(binary.names() - source.names())
    findings = [
        {
            "capability": capability,
            "severity": "high" if capability in (PROCESS_EXEC, NETWORK, PRIVILEGE) else "medium",
            "claim": ("the compiled output uses %s, and no source import or call "
                      "in the analysed tree asks for it" % capability),
            "assembly_evidence": [item.as_dict()
                                  for item in binary.capabilities[capability]],
            "source_evidence": [],
            "evidence_state": "inferred",
            "runtime_verified": False,
        }
        for capability in unexplained
    ]
    body = {
        "schema": SCHEMA,
        "version": VERSION,
        "status": "divergent" if findings else "consistent",
        "summary": {
            "listings": len(listings),
            "source_capabilities": sorted(source.names()),
            "assembly_capabilities": sorted(binary.names()),
            "unexplained": unexplained,
            "finding_count": len(findings),
        },
        "findings": findings,
        "execution": {
            "target_code_executed": False,
            "compiler_invoked": False,
            "processes_started": False,
            "network_accessed": False,
            "files_written": False,
        },
        "limitations": [
            "A compiler intrinsic, an inlined libc routine, or a runtime startup "
            "stub can introduce a primitive the source never wrote; an unexplained "
            "capability is a review point, not a backdoor.",
            "Source capability detection is name-based and deliberately generous, "
            "so an unusual wrapper may under-report what the source asked for.",
            "The listings are read as supplied. This does not prove they were "
            "produced from the analysed source; pair it with a signed snapshot of "
            "both inputs to make that claim.",
            "Absence of divergence is not proof the build is clean -- only that "
            "these capability classes matched.",
        ],
    }
    body["report_sha256"] = _sha(body)
    return body


def verify_report(report: Any) -> tuple[bool, list[str]]:
    """Recompute the digest and the derived counts, fail-closed."""
    errors: list[str] = []
    if not isinstance(report, Mapping):
        return False, ["report must be an object"]
    if report.get("schema") != SCHEMA or report.get("version") != VERSION:
        errors.append("schema or version mismatch")
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    try:
        if report.get("report_sha256") != _sha(body):
            errors.append("report digest mismatch")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON")
    findings = report.get("findings")
    summary = report.get("summary")
    if not isinstance(findings, list) or not isinstance(summary, Mapping):
        return False, errors + ["findings or summary malformed"]
    if summary.get("finding_count") != len(findings):
        errors.append("summary finding_count does not match findings")
    if sorted(summary.get("unexplained") or []) != sorted(
            row.get("capability") for row in findings):
        errors.append("summary unexplained does not match findings")
    expected_status = "divergent" if findings else "consistent"
    if report.get("status") != expected_status:
        errors.append("status does not match findings")
    for row in findings:
        if row.get("runtime_verified") is not False:
            errors.append("a divergence may not claim runtime verification")
        if not row.get("assembly_evidence"):
            errors.append("a divergence must carry assembly evidence")
    return not errors, errors


def render(report: Mapping[str, Any]) -> str:
    lines = [
        "Attestor build divergence: %s" % report["status"],
        "listings=%d source_caps=%s binary_caps=%s" % (
            report["summary"]["listings"],
            ",".join(report["summary"]["source_capabilities"]) or "-",
            ",".join(report["summary"]["assembly_capabilities"]) or "-"),
    ]
    for row in report["findings"]:
        lines.append("")
        lines.append("[%s] %s" % (row["severity"], row["claim"]))
        for site in row["assembly_evidence"][:5]:
            lines.append("    %s:%d  %s   (%s)" % (
                site["path"], site["line"], site["text"][:60], site["reason"]))
    lines.append("")
    lines.append("An unexplained capability is a review point, not a backdoor; "
                 "compilers and runtimes introduce primitives too.")
    return "\n".join(lines)


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="attestor-divergence",
        description="Report capabilities in compiled assembly that the source "
                    "never asks for. Reads listings; never compiles or executes.")
    parser.add_argument("source", help="the source tree that was built")
    parser.add_argument("assembly", help="directory of assembly listings")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    try:
        report = compare(args.source, args.assembly)
        ok, errors = verify_report(report)
        if not ok:
            raise BuildDivergenceError("report did not verify: " + "; ".join(errors[:3]))
        print(json.dumps(report, indent=2, sort_keys=True)
              if args.format == "json" else render(report))
        return 1 if report["findings"] else 0
    except (BuildDivergenceError, OSError, ValueError) as exc:
        print("attestor-divergence: " + str(exc)[:400], file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(_main())
