#!/usr/bin/env python3
"""Taint policy DSL -- declarative YAML for custom sources/sinks/sanitizers.

Users define security policies in YAML:

  sources:
    - pattern: "request\\.args\\.get\\("
      label: user_input
    - pattern: "os\\.environ\\["
      label: env_var

  sinks:
    - pattern: "os\\.system\\("
      severity: CRITICAL
      cwe: CWE-78
      category: command_injection
    - pattern: "eval\\("
      severity: CRITICAL
      cwe: CWE-95

  sanitizers:
    - pattern: "shlex\\.quote\\("
      neutralizes: [command_injection]
    - pattern: "html\\.escape\\("
      neutralizes: [xss]

  propagators:
    - pattern: "str\\("
      from: arg0
      to: return

The engine applies these policies to source code, finding taint flows
from source to sink that aren't neutralized by a sanitizer.
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


@dataclass
class SourceRule:
    pattern: re.Pattern
    label: str
    raw: str = ""


@dataclass
class SinkRule:
    pattern: re.Pattern
    severity: str = "HIGH"
    cwe: str = ""
    category: str = "taint_flow"
    raw: str = ""


@dataclass
class SanitizerRule:
    pattern: re.Pattern
    neutralizes: list[str] = field(default_factory=list)
    raw: str = ""


@dataclass
class PropagatorRule:
    pattern: re.Pattern
    from_: str = "arg0"
    to: str = "return"
    raw: str = ""


@dataclass
class TaintPolicy:
    name: str = "custom"
    sources: list[SourceRule] = field(default_factory=list)
    sinks: list[SinkRule] = field(default_factory=list)
    sanitizers: list[SanitizerRule] = field(default_factory=list)
    propagators: list[PropagatorRule] = field(default_factory=list)


@dataclass
class DSLFinding:
    source_label: str
    source_line: int
    source_code: str
    sink_category: str
    sink_line: int
    sink_code: str
    severity: str
    cwe: str
    file: str
    sanitized: bool = False
    sanitizer_pattern: str = ""


def _parse_yaml_str(text: str) -> dict:
    if HAS_YAML:
        return yaml.safe_load(text) or {}
    result: dict = {}
    current_section = ""
    current_item: dict = {}
    items: list[dict] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if not line.startswith(" ") and stripped.endswith(":"):
            if current_section and items:
                result[current_section] = items
            if current_item:
                items.append(current_item)
                current_item = {}
            current_section = stripped[:-1]
            items = []
            continue
        if stripped.startswith("- "):
            if current_item:
                items.append(current_item)
            current_item = {}
            kv = stripped[2:].strip()
            if ":" in kv:
                k, v = kv.split(":", 1)
                current_item[k.strip()] = v.strip().strip('"').strip("'")
        elif ":" in stripped and current_item is not None:
            k, v = stripped.split(":", 1)
            v = v.strip().strip('"').strip("'")
            if v.startswith("[") and v.endswith("]"):
                v = [x.strip().strip('"').strip("'")
                     for x in v[1:-1].split(",") if x.strip()]
            current_item[k.strip()] = v
    if current_item:
        items.append(current_item)
    if current_section and items:
        result[current_section] = items
    return result


def load_policy(text: str) -> TaintPolicy:
    data = _parse_yaml_str(text)
    policy = TaintPolicy(name=data.get("name", "custom"))

    for s in data.get("sources", []):
        pat = s.get("pattern", "")
        if pat:
            policy.sources.append(SourceRule(
                pattern=re.compile(pat), label=s.get("label", "tainted"),
                raw=pat,
            ))

    for s in data.get("sinks", []):
        pat = s.get("pattern", "")
        if pat:
            policy.sinks.append(SinkRule(
                pattern=re.compile(pat),
                severity=s.get("severity", "HIGH"),
                cwe=s.get("cwe", ""),
                category=s.get("category", "taint_flow"),
                raw=pat,
            ))

    for s in data.get("sanitizers", []):
        pat = s.get("pattern", "")
        if pat:
            neut = s.get("neutralizes", [])
            if isinstance(neut, str):
                neut = [neut]
            policy.sanitizers.append(SanitizerRule(
                pattern=re.compile(pat), neutralizes=neut, raw=pat,
            ))

    for s in data.get("propagators", []):
        pat = s.get("pattern", "")
        if pat:
            policy.propagators.append(PropagatorRule(
                pattern=re.compile(pat),
                from_=s.get("from", "arg0"),
                to=s.get("to", "return"),
                raw=pat,
            ))

    return policy


def load_policy_file(path: str) -> TaintPolicy:
    with open(path, encoding="utf-8") as f:
        return load_policy(f.read())


def apply_policy(source_code: str, policy: TaintPolicy,
                 filepath: str = "<string>") -> list[DSLFinding]:
    lines = source_code.splitlines()
    source_hits: list[tuple[int, str, str]] = []
    sink_hits: list[tuple[int, str, SinkRule]] = []
    sanitizer_hits: list[tuple[int, str, SanitizerRule]] = []

    for i, line in enumerate(lines):
        lineno = i + 1
        for src in policy.sources:
            if src.pattern.search(line):
                source_hits.append((lineno, line.strip(), src.label))
        for sk in policy.sinks:
            if sk.pattern.search(line):
                sink_hits.append((lineno, line.strip(), sk))
        for san in policy.sanitizers:
            if san.pattern.search(line):
                sanitizer_hits.append((lineno, line.strip(), san))

    findings = []
    for src_line, src_code, src_label in source_hits:
        for sink_line, sink_code, sink_rule in sink_hits:
            if sink_line <= src_line:
                continue
            sanitized = False
            san_pat = ""
            for san_line, san_code, san_rule in sanitizer_hits:
                if src_line < san_line < sink_line:
                    if not san_rule.neutralizes or sink_rule.category in san_rule.neutralizes:
                        sanitized = True
                        san_pat = san_rule.raw
                        break

            findings.append(DSLFinding(
                source_label=src_label, source_line=src_line,
                source_code=src_code, sink_category=sink_rule.category,
                sink_line=sink_line, sink_code=sink_code,
                severity=sink_rule.severity, cwe=sink_rule.cwe,
                file=filepath, sanitized=sanitized,
                sanitizer_pattern=san_pat,
            ))
    return findings


def scan_with_policy(paths: list[str], policy: TaintPolicy) -> list[DSLFinding]:
    findings = []
    for p in paths:
        if os.path.isfile(p) and p.endswith(".py"):
            try:
                with open(p, encoding="utf-8", errors="replace") as f:
                    findings += apply_policy(f.read(), policy, p)
            except OSError:
                pass
        elif os.path.isdir(p):
            for dp, dn, fn in os.walk(p):
                dn[:] = [d for d in dn if d not in
                         {".git", "__pycache__", ".venv", "node_modules"}]
                for n in fn:
                    if n.endswith(".py"):
                        fp = os.path.join(dp, n)
                        try:
                            with open(fp, encoding="utf-8", errors="replace") as f:
                                findings += apply_policy(f.read(), policy, fp)
                        except OSError:
                            pass
    return findings


def to_dict(findings: list[DSLFinding]) -> list[dict]:
    return [
        {
            "category": f.sink_category, "severity": f.severity,
            "file": f.file, "path": f.file,
            "sink_file": f.file, "sink_line": f.sink_line,
            "line": f.sink_line, "sink_code": f.sink_code,
            "sink_type": f.sink_category,
            "source_label": f.source_label, "source_line": f.source_line,
            "source_code": f.source_code,
            "description": (f"Taint flow: {f.source_label} (L{f.source_line}) → "
                            f"{f.sink_category} (L{f.sink_line})"
                            + (f" [SANITIZED by {f.sanitizer_pattern}]" if f.sanitized else "")),
            "cwe": f.cwe, "sanitized": f.sanitized,
        }
        for f in findings
    ]


def render(findings: list[DSLFinding]) -> str:
    active = [f for f in findings if not f.sanitized]
    sanitized = [f for f in findings if f.sanitized]
    if not findings:
        return "  no policy violations. either the code is clean or the policy needs more rules."
    lines = [
        f"\n  Taint Policy DSL -- {len(active)} active, "
        f"{len(sanitized)} sanitized",
        "  " + "=" * 62,
    ]
    for f in active:
        lines.append(f"\n  [{f.severity}] {f.sink_category} at "
                     f"{os.path.basename(f.file)}:{f.sink_line}")
        lines.append(f"    source: {f.source_label} (L{f.source_line}): {f.source_code[:80]}")
        lines.append(f"    sink: {f.sink_code[:80]}")
    if sanitized:
        lines.append(f"\n  Sanitized ({len(sanitized)}):")
        for f in sanitized:
            lines.append(f"    {f.source_label} → {f.sink_category} "
                         f"[neutralized by {f.sanitizer_pattern}]")
    return "\n".join(lines)
