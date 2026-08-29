#!/usr/bin/env python3
"""Semantic code similarity -- uses TF-IDF and structural fingerprinting to find
code patterns semantically similar to known CVE-vulnerable patterns, without
relying on AI models (runs entirely offline). Builds a vector database of CVE
code patterns and matches against scanned code."""
from __future__ import annotations

import ast
import hashlib
import json
import math
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build",
}


@dataclass
class CVEPattern:
    cve_id: str
    description: str
    severity: str
    cwe: str
    code_tokens: list[str] = field(default_factory=list)
    structural_hash: str = ""
    tfidf_vector: dict[str, float] = field(default_factory=dict)


@dataclass
class SimilarityMatch:
    path: str
    line_start: int
    line_end: int
    cve_id: str
    cve_description: str
    cve_severity: str
    cve_cwe: str
    similarity_score: float
    match_type: str
    matched_tokens: list[str] = field(default_factory=list)


BUILTIN_CVE_PATTERNS: list[dict] = [
    {
        "cve_id": "CVE-2021-44228",
        "description": "Log4Shell: JNDI injection via log message",
        "severity": "CRITICAL", "cwe": "CWE-917",
        "tokens": ["log", "logger", "format", "lookup", "jndi", "ldap", "rmi",
                   "user", "input", "header", "request", "interpolat"],
    },
    {
        "cve_id": "CVE-2021-42013",
        "description": "Apache path traversal via double URL encoding",
        "severity": "CRITICAL", "cwe": "CWE-22",
        "tokens": ["path", "url", "decode", "normalize", "traversal", "directory",
                   "file", "read", "open", "join", "resolve", ".."],
    },
    {
        "cve_id": "CVE-2021-3156",
        "description": "Sudo heap overflow (Baron Samedit)",
        "severity": "CRITICAL", "cwe": "CWE-787",
        "tokens": ["buffer", "heap", "overflow", "malloc", "realloc", "strcpy",
                   "memcpy", "length", "size", "boundary", "check"],
    },
    {
        "cve_id": "CVE-2022-0847",
        "description": "Dirty Pipe: Linux kernel pipe page cache corruption",
        "severity": "CRITICAL", "cwe": "CWE-281",
        "tokens": ["pipe", "splice", "page", "cache", "write", "flag", "merge",
                   "buffer", "kernel", "privilege", "escalation"],
    },
    {
        "cve_id": "CVE-2019-11043",
        "description": "PHP-FPM underflow leading to RCE",
        "severity": "CRITICAL", "cwe": "CWE-787",
        "tokens": ["fastcgi", "fpm", "path_info", "script", "underflow",
                   "execute", "remote", "code", "nginx", "location"],
    },
    {
        "cve_id": "CVE-2017-5638",
        "description": "Apache Struts OGNL injection via Content-Type",
        "severity": "CRITICAL", "cwe": "CWE-94",
        "tokens": ["content_type", "multipart", "ognl", "expression", "evaluate",
                   "parse", "header", "struts", "action", "upload"],
    },
    {
        "cve_id": "CVE-2019-0708",
        "description": "BlueKeep: RDP use-after-free",
        "severity": "CRITICAL", "cwe": "CWE-416",
        "tokens": ["rdp", "channel", "free", "use_after_free", "bind", "connect",
                   "session", "virtual", "disconnect", "remote"],
    },
    {
        "cve_id": "CVE-2020-1472",
        "description": "Zerologon: Netlogon AES-CFB8 IV of all zeros",
        "severity": "CRITICAL", "cwe": "CWE-330",
        "tokens": ["netlogon", "aes", "cfb8", "iv", "zero", "compute", "session",
                   "key", "authenticate", "credential", "domain"],
    },
    {
        "cve_id": "CVE-GENERIC-SQLI",
        "description": "SQL injection via string concatenation",
        "severity": "HIGH", "cwe": "CWE-89",
        "tokens": ["select", "insert", "update", "delete", "execute", "query",
                   "cursor", "format", "concatenat", "user", "input", "string"],
    },
    {
        "cve_id": "CVE-GENERIC-CMDI",
        "description": "Command injection via unsanitized input",
        "severity": "CRITICAL", "cwe": "CWE-78",
        "tokens": ["system", "popen", "exec", "subprocess", "shell", "command",
                   "user", "input", "os", "run", "call"],
    },
    {
        "cve_id": "CVE-GENERIC-DESER",
        "description": "Insecure deserialization of untrusted data",
        "severity": "HIGH", "cwe": "CWE-502",
        "tokens": ["pickle", "loads", "deserializ", "unserializ", "yaml", "load",
                   "marshal", "untrusted", "user", "input", "object"],
    },
    {
        "cve_id": "CVE-GENERIC-SSRF",
        "description": "Server-side request forgery",
        "severity": "HIGH", "cwe": "CWE-918",
        "tokens": ["url", "request", "fetch", "open", "user", "input", "redirect",
                   "internal", "metadata", "localhost", "127.0.0.1"],
    },
    {
        "cve_id": "CVE-GENERIC-XSS",
        "description": "Cross-site scripting via reflected input",
        "severity": "MEDIUM", "cwe": "CWE-79",
        "tokens": ["html", "render", "template", "response", "user", "input",
                   "escape", "script", "innerHTML", "write", "output"],
    },
    {
        "cve_id": "CVE-GENERIC-PATHTRAVERSAL",
        "description": "Path traversal via unvalidated file path",
        "severity": "HIGH", "cwe": "CWE-22",
        "tokens": ["path", "file", "open", "read", "join", "user", "input",
                   "directory", "..\\", "../", "resolve", "normalize"],
    },
    {
        "cve_id": "CVE-GENERIC-HARDCODED-CREDS",
        "description": "Hardcoded credentials in source code",
        "severity": "HIGH", "cwe": "CWE-798",
        "tokens": ["password", "secret", "key", "token", "credential", "api_key",
                   "hardcod", "default", "admin", "root"],
    },
]


def _tokenize_code(source: str) -> list[str]:
    source = re.sub(r'#.*$', '', source, flags=re.MULTILINE)
    source = re.sub(r'""".*?"""', '', source, flags=re.DOTALL)
    source = re.sub(r"'''.*?'''", '', source, flags=re.DOTALL)
    source = re.sub(r'"[^"]*"', 'STRING', source)
    source = re.sub(r"'[^']*'", 'STRING', source)
    tokens = re.findall(r'[a-zA-Z_]\w*', source.lower())
    stop_words = {
        "self", "cls", "none", "true", "false", "return", "def", "class",
        "if", "else", "elif", "for", "while", "import", "from", "as",
        "try", "except", "finally", "with", "in", "not", "and", "or",
        "is", "pass", "break", "continue", "raise", "yield", "lambda",
        "string", "the", "this", "that", "var", "let", "const", "function",
    }
    return [t for t in tokens if t not in stop_words and len(t) > 1]


def _compute_tfidf(tokens: list[str], idf: dict[str, float]) -> dict[str, float]:
    tf = Counter(tokens)
    total = len(tokens) or 1
    return {token: (count / total) * idf.get(token, 1.0) for token, count in tf.items()}


def _cosine_similarity(v1: dict[str, float], v2: dict[str, float]) -> float:
    common = set(v1) & set(v2)
    if not common:
        return 0.0
    dot = sum(v1[k] * v2[k] for k in common)
    mag1 = math.sqrt(sum(v * v for v in v1.values()))
    mag2 = math.sqrt(sum(v * v for v in v2.values()))
    if mag1 == 0 or mag2 == 0:
        return 0.0
    return dot / (mag1 * mag2)


def _structural_hash(tokens: list[str], window: int = 5) -> str:
    if len(tokens) < window:
        return hashlib.md5("".join(tokens).encode()).hexdigest()[:12]
    ngrams = []
    for i in range(len(tokens) - window + 1):
        ngram = "_".join(sorted(tokens[i:i + window]))
        ngrams.append(ngram)
    combined = "|".join(sorted(set(ngrams)))
    return hashlib.md5(combined.encode()).hexdigest()[:12]


class CVEDatabase:

    def __init__(self):
        self.patterns: list[CVEPattern] = []
        self.idf: dict[str, float] = {}

    def load_builtin(self):
        all_tokens: list[list[str]] = []
        for entry in BUILTIN_CVE_PATTERNS:
            tokens = entry["tokens"]
            all_tokens.append(tokens)

        doc_count = len(all_tokens)
        token_doc_freq: Counter = Counter()
        for tokens in all_tokens:
            for t in set(tokens):
                token_doc_freq[t] += 1
        self.idf = {
            token: math.log((doc_count + 1) / (freq + 1)) + 1
            for token, freq in token_doc_freq.items()
        }

        for entry in BUILTIN_CVE_PATTERNS:
            tokens = entry["tokens"]
            pattern = CVEPattern(
                cve_id=entry["cve_id"],
                description=entry["description"],
                severity=entry["severity"],
                cwe=entry["cwe"],
                code_tokens=tokens,
                structural_hash=_structural_hash(tokens),
                tfidf_vector=_compute_tfidf(tokens, self.idf),
            )
            self.patterns.append(pattern)

    def load_from_jsonl(self, path: str):
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    if "cve_id" in entry and "tokens" in entry:
                        tokens = entry["tokens"]
                        pattern = CVEPattern(
                            cve_id=entry["cve_id"],
                            description=entry.get("description", ""),
                            severity=entry.get("severity", "MEDIUM"),
                            cwe=entry.get("cwe", ""),
                            code_tokens=tokens,
                            structural_hash=_structural_hash(tokens),
                            tfidf_vector=_compute_tfidf(tokens, self.idf),
                        )
                        self.patterns.append(pattern)
        except (OSError, json.JSONDecodeError):
            pass

    def match(self, code_tokens: list[str], threshold: float = 0.35) -> list[tuple[CVEPattern, float]]:
        code_vector = _compute_tfidf(code_tokens, self.idf)
        code_hash = _structural_hash(code_tokens)

        matches = []
        for pattern in self.patterns:
            if code_hash == pattern.structural_hash:
                matches.append((pattern, 1.0))
                continue

            sim = _cosine_similarity(code_vector, pattern.tfidf_vector)
            if sim >= threshold:
                matches.append((pattern, sim))

        matches.sort(key=lambda x: -x[1])
        return matches


def scan_file(path: str, db: CVEDatabase | None = None,
              threshold: float = 0.35, window: int = 30) -> list[SimilarityMatch]:
    if not path.endswith(".py"):
        return []
    if db is None:
        db = CVEDatabase()
        db.load_builtin()

    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except (OSError, PermissionError):
        return []

    findings = []
    full_tokens = _tokenize_code("".join(lines))

    for i in range(0, len(lines), window // 2):
        chunk = "".join(lines[i:i + window])
        tokens = _tokenize_code(chunk)
        if len(tokens) < 5:
            continue

        matches = db.match(tokens, threshold)
        for pattern, score in matches[:3]:
            common_tokens = list(set(tokens) & set(pattern.code_tokens))
            findings.append(SimilarityMatch(
                path=path,
                line_start=i + 1,
                line_end=min(i + window, len(lines)),
                cve_id=pattern.cve_id,
                cve_description=pattern.description,
                cve_severity=pattern.severity,
                cve_cwe=pattern.cwe,
                similarity_score=score,
                match_type="structural" if score == 1.0 else "semantic",
                matched_tokens=common_tokens[:10],
            ))

    seen = set()
    deduped = []
    for m in findings:
        key = (m.cve_id, m.line_start // 10)
        if key not in seen:
            seen.add(key)
            deduped.append(m)
    return deduped


def scan_directory(root: str, threshold: float = 0.35) -> list[SimilarityMatch]:
    db = CVEDatabase()
    db.load_builtin()

    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            if fname.endswith(".py"):
                fpath = os.path.join(dirpath, fname)
                findings.extend(scan_file(fpath, db, threshold))

    findings.sort(key=lambda m: -m.similarity_score)
    return findings


def render(findings: list[SimilarityMatch]) -> str:
    if not findings:
        return "  No CVE-similar code patterns detected."
    lines = []
    lines.append(f"\n  Semantic Similarity Analysis ({len(findings)} match{'es' if len(findings) != 1 else ''})")
    lines.append(f"  {'='*55}")

    for m in findings[:50]:
        score_pct = f"{m.similarity_score:.0%}"
        lines.append(f"\n  [{m.cve_severity}] {m.cve_id} ({score_pct} match)")
        lines.append(f"    {m.path}:{m.line_start}-{m.line_end}")
        lines.append(f"    {m.cve_description}")
        if m.cve_cwe:
            lines.append(f"    CWE: {m.cve_cwe}")
        if m.matched_tokens:
            lines.append(f"    Matched tokens: {', '.join(m.matched_tokens[:8])}")

    if len(findings) > 50:
        lines.append(f"\n  ... and {len(findings) - 50} more matches")

    return "\n".join(lines)


def to_dict(findings: list[SimilarityMatch]) -> list[dict]:
    return [
        {
            "path": m.path,
            "line_start": m.line_start,
            "line_end": m.line_end,
            "cve_id": m.cve_id,
            "cve_description": m.cve_description,
            "cve_severity": m.cve_severity,
            "cve_cwe": m.cve_cwe,
            "similarity_score": round(m.similarity_score, 3),
            "match_type": m.match_type,
            "matched_tokens": m.matched_tokens,
        }
        for m in findings
    ]
