#!/usr/bin/env python3
"""Binary analysis module -- analyzes compiled bytecode and binary formats
that source-only scanners miss. Supports Python .pyc, Java .class, and WASM."""
from __future__ import annotations

import dis
import marshal
import os
import re
import struct
import sys
import types
from dataclasses import dataclass
from pathlib import Path

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
}


@dataclass
class BinaryFinding:
    path: str
    offset: int
    rule_id: str
    description: str
    severity: str
    category: str
    details: str = ""


DANGEROUS_BUILTINS = {
    "eval": ("BIN-PY-EVAL", "eval() call in bytecode", "CRITICAL", "code_injection"),
    "exec": ("BIN-PY-EXEC", "exec() call in bytecode", "CRITICAL", "code_injection"),
    "compile": ("BIN-PY-COMPILE", "compile() call in bytecode", "HIGH", "code_injection"),
    "__import__": ("BIN-PY-IMPORT", "Dynamic __import__ in bytecode", "MEDIUM", "code_injection"),
    "getattr": ("BIN-PY-GETATTR", "Dynamic getattr in bytecode", "LOW", "reflection"),
    "setattr": ("BIN-PY-SETATTR", "Dynamic setattr in bytecode", "LOW", "reflection"),
}

DANGEROUS_MODULES = {
    "os": "system_access",
    "subprocess": "command_execution",
    "socket": "network_access",
    "ctypes": "native_code",
    "pickle": "deserialization",
    "marshal": "deserialization",
    "shelve": "deserialization",
    "importlib": "dynamic_import",
    "multiprocessing": "process_spawn",
    "shutil": "file_manipulation",
    "tempfile": "file_manipulation",
    "ssl": "network_crypto",
    "http.server": "http_server",
    "xmlrpc": "rpc_server",
    "ftplib": "ftp_access",
    "smtplib": "email_send",
    "telnetlib": "telnet_access",
}

DANGEROUS_ATTRS = {
    "system": ("BIN-PY-SYSTEM", "os.system() in bytecode", "CRITICAL"),
    "popen": ("BIN-PY-POPEN", "os.popen() in bytecode", "CRITICAL"),
    "exec": ("BIN-PY-EXEC-ATTR", "exec method in bytecode", "HIGH"),
    "connect": ("BIN-PY-CONNECT", "socket.connect() in bytecode", "MEDIUM"),
    "bind": ("BIN-PY-BIND", "socket.bind() in bytecode", "MEDIUM"),
    "listen": ("BIN-PY-LISTEN", "socket.listen() in bytecode", "MEDIUM"),
    "send": ("BIN-PY-SEND", "socket.send() in bytecode", "LOW"),
    "recv": ("BIN-PY-RECV", "socket.recv() in bytecode", "LOW"),
    "loads": ("BIN-PY-LOADS", "Deserialization .loads() in bytecode", "HIGH"),
    "load": ("BIN-PY-LOAD", "Deserialization .load() in bytecode", "HIGH"),
    "Popen": ("BIN-PY-POPEN-CLS", "subprocess.Popen in bytecode", "HIGH"),
    "call": ("BIN-PY-SUBCALL", "subprocess.call in bytecode", "HIGH"),
    "run": ("BIN-PY-SUBRUN", "subprocess.run in bytecode", "MEDIUM"),
    "urlopen": ("BIN-PY-URLOPEN", "urllib.urlopen in bytecode", "MEDIUM"),
}

STRING_INDICATORS = [
    (re.compile(rb"/bin/(?:sh|bash|zsh|csh|dash)"), "BIN-STR-SHELL", "Shell path in binary", "HIGH"),
    (re.compile(rb"(?:cmd|powershell)\.exe"), "BIN-STR-WINSHELL", "Windows shell in binary", "HIGH"),
    (re.compile(rb"(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s+", re.I), "BIN-STR-SQL", "SQL statement in binary", "MEDIUM"),
    (re.compile(rb"(?:password|passwd|secret|token|api_key)\s*=", re.I), "BIN-STR-CRED", "Credential pattern in binary", "HIGH"),
    (re.compile(rb"-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----"), "BIN-STR-PRIVKEY", "Private key in binary", "CRITICAL"),
    (re.compile(rb"(?:AKIA|AGPA|AIDA|AROA|AIPA)[A-Z0-9]{16}"), "BIN-STR-AWSKEY", "AWS key in binary", "CRITICAL"),
    (re.compile(rb"ghp_[A-Za-z0-9]{36}"), "BIN-STR-GHTOKEN", "GitHub token in binary", "CRITICAL"),
    (re.compile(rb"(?:0\.0\.0\.0|127\.0\.0\.1|localhost):\d{2,5}"), "BIN-STR-BIND", "Bind address in binary", "MEDIUM"),
    (re.compile(rb"(?:stratum\+tcp|mining|miner|xmrig)", re.I), "BIN-STR-MINER", "Mining reference in binary", "HIGH"),
    (re.compile(rb"(?:reverse.shell|backdoor|rootkit|keylog)", re.I), "BIN-STR-MALWARE", "Malware keyword in binary", "CRITICAL"),
]


def _read_pyc(path: str) -> types.CodeType | None:
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
            if len(magic) < 4:
                return None
            f.read(12)
            code = marshal.load(f)
            if isinstance(code, types.CodeType):
                return code
    except (OSError, ValueError, EOFError, TypeError):
        pass
    return None


def _analyze_code_object(code: types.CodeType, path: str, findings: list[BinaryFinding]):
    for const in code.co_consts:
        if isinstance(const, str):
            if const in DANGEROUS_BUILTINS:
                rule_id, desc, sev, cat = DANGEROUS_BUILTINS[const]
                findings.append(BinaryFinding(
                    path=path, offset=0, rule_id=rule_id,
                    description=desc, severity=sev, category=cat,
                    details=f"in function: {code.co_name}",
                ))
        if isinstance(const, types.CodeType):
            _analyze_code_object(const, path, findings)

    for name in code.co_names:
        if name in DANGEROUS_BUILTINS:
            rule_id, desc, sev, cat = DANGEROUS_BUILTINS[name]
            findings.append(BinaryFinding(
                path=path, offset=0, rule_id=rule_id,
                description=desc, severity=sev, category=cat,
                details=f"in function: {code.co_name}",
            ))
        if name in DANGEROUS_ATTRS:
            rule_id, desc, sev = DANGEROUS_ATTRS[name]
            findings.append(BinaryFinding(
                path=path, offset=0, rule_id=rule_id,
                description=desc, severity=sev, category="dangerous_call",
                details=f"in function: {code.co_name}",
            ))
        if name in DANGEROUS_MODULES:
            cat = DANGEROUS_MODULES[name]
            findings.append(BinaryFinding(
                path=path, offset=0, rule_id="BIN-PY-MOD",
                description=f"Import of {name} module in bytecode",
                severity="MEDIUM", category=cat,
                details=f"in function: {code.co_name}",
            ))


def analyze_pyc(path: str) -> list[BinaryFinding]:
    code = _read_pyc(path)
    if not code:
        return []
    findings: list[BinaryFinding] = []
    _analyze_code_object(code, path, findings)
    return findings


def analyze_class_file(path: str) -> list[BinaryFinding]:
    findings: list[BinaryFinding] = []
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return []

    if data[:4] != b'\xca\xfe\xba\xbe':
        return []

    java_dangerous = [
        (b"Runtime", b"exec", "BIN-JAVA-EXEC", "Runtime.exec() in class file", "CRITICAL"),
        (b"ProcessBuilder", b"start", "BIN-JAVA-PROC", "ProcessBuilder in class file", "HIGH"),
        (b"ScriptEngine", b"eval", "BIN-JAVA-EVAL", "ScriptEngine.eval() in class file", "CRITICAL"),
        (b"ObjectInputStream", b"readObject", "BIN-JAVA-DESER", "Deserialization in class file", "HIGH"),
        (b"URLClassLoader", b"loadClass", "BIN-JAVA-CLASSLOAD", "Dynamic class loading", "HIGH"),
        (b"Cipher", b"getInstance", "BIN-JAVA-CRYPTO", "Cryptographic operation", "LOW"),
        (b"ServerSocket", b"accept", "BIN-JAVA-SERVER", "Server socket in class file", "MEDIUM"),
        (b"DatagramSocket", b"receive", "BIN-JAVA-UDP", "UDP socket in class file", "MEDIUM"),
        (b"PreparedStatement", b"execute", "BIN-JAVA-SQL", "SQL execution in class file", "MEDIUM"),
    ]

    for cls_bytes, method_bytes, rule_id, desc, sev in java_dangerous:
        if cls_bytes in data and method_bytes in data:
            findings.append(BinaryFinding(
                path=path, offset=data.find(cls_bytes),
                rule_id=rule_id, description=desc,
                severity=sev, category="java_bytecode",
            ))

    for pat, rule_id, desc, sev in STRING_INDICATORS:
        for m in pat.finditer(data):
            findings.append(BinaryFinding(
                path=path, offset=m.start(),
                rule_id=rule_id, description=desc,
                severity=sev, category="embedded_string",
                details=m.group(0)[:60].decode("utf-8", errors="replace"),
            ))

    return findings


def analyze_wasm(path: str) -> list[BinaryFinding]:
    findings: list[BinaryFinding] = []
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return []

    if data[:4] != b'\x00asm':
        return []

    wasm_checks = [
        (b"wasi_snapshot_preview1", "BIN-WASM-WASI", "WASI system interface imported", "MEDIUM"),
        (b"fd_read", "BIN-WASM-FDREAD", "File descriptor read in WASM", "LOW"),
        (b"fd_write", "BIN-WASM-FDWRITE", "File descriptor write in WASM", "LOW"),
        (b"proc_exit", "BIN-WASM-EXIT", "Process exit in WASM", "LOW"),
        (b"sock_", "BIN-WASM-SOCK", "Socket operations in WASM", "MEDIUM"),
        (b"path_open", "BIN-WASM-PATHOPEN", "File path open in WASM", "MEDIUM"),
        (b"environ_get", "BIN-WASM-ENV", "Environment access in WASM", "MEDIUM"),
        (b"random_get", "BIN-WASM-RANDOM", "Random generation in WASM", "LOW"),
    ]

    for pattern, rule_id, desc, sev in wasm_checks:
        if pattern in data:
            findings.append(BinaryFinding(
                path=path, offset=data.find(pattern),
                rule_id=rule_id, description=desc,
                severity=sev, category="wasm_import",
            ))

    for pat, rule_id, desc, sev in STRING_INDICATORS:
        for m in pat.finditer(data):
            findings.append(BinaryFinding(
                path=path, offset=m.start(),
                rule_id=rule_id, description=desc,
                severity=sev, category="embedded_string",
                details=m.group(0)[:60].decode("utf-8", errors="replace"),
            ))

    return findings


def scan_file(path: str) -> list[BinaryFinding]:
    ext = Path(path).suffix.lower()
    if ext == ".pyc":
        return analyze_pyc(path)
    elif ext == ".class":
        return analyze_class_file(path)
    elif ext == ".wasm":
        return analyze_wasm(path)

    if ext in (".exe", ".dll", ".so", ".dylib", ".bin", ".elf"):
        findings = []
        try:
            with open(path, "rb") as f:
                data = f.read(1024 * 1024)
        except OSError:
            return []
        for pat, rule_id, desc, sev in STRING_INDICATORS:
            for m in pat.finditer(data):
                findings.append(BinaryFinding(
                    path=path, offset=m.start(),
                    rule_id=rule_id, description=desc,
                    severity=sev, category="embedded_string",
                    details=m.group(0)[:60].decode("utf-8", errors="replace"),
                ))
        return findings
    return []


BINARY_EXTENSIONS = {".pyc", ".class", ".wasm", ".exe", ".dll", ".so", ".dylib", ".bin", ".elf"}


def scan_directory(root: str) -> list[BinaryFinding]:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if Path(fname).suffix.lower() in BINARY_EXTENSIONS:
                fpath = os.path.join(dirpath, fname)
                findings.extend(scan_file(fpath))
    return findings


def render(findings: list[BinaryFinding]) -> str:
    if not findings:
        return "  No binary analysis findings."
    lines = []
    by_cat = {}
    for f in findings:
        by_cat.setdefault(f.category, []).append(f)

    lines.append(f"\n  Binary Analysis ({len(findings)} finding{'s' if len(findings) != 1 else ''})")
    lines.append(f"  {'='*50}")

    for cat in sorted(by_cat):
        group = by_cat[cat]
        label = cat.replace("_", " ").title()
        lines.append(f"\n  [{label}] ({len(group)} findings)")
        for f in sorted(group, key=lambda x: ("CRITICAL", "HIGH", "MEDIUM", "LOW").index(x.severity)):
            lines.append(f"    [{f.severity}] {f.path}  {f.rule_id}")
            lines.append(f"      {f.description}")
            if f.details:
                lines.append(f"      Details: {f.details}")

    crit = sum(1 for f in findings if f.severity == "CRITICAL")
    lines.append(f"\n  Total: {len(findings)} finding(s) ({crit} critical)")
    return "\n".join(lines)


def to_dict(findings: list[BinaryFinding]) -> list[dict]:
    return [
        {
            "path": f.path,
            "offset": f.offset,
            "rule_id": f.rule_id,
            "description": f.description,
            "severity": f.severity,
            "category": f.category,
            "details": f.details,
        }
        for f in findings
    ]
