#!/usr/bin/env python3
"""Kill chain synthesizer -- multi-step attack path construction.

Consumes findings from every Attestor engine and synthesizes end-to-end
attack scenarios showing how an attacker chains individual vulnerabilities
into full compromise. Connects entry points through data flows to impact.

    chains = synthesize(findings, index, threat_model)
"""
from __future__ import annotations

import os
import re
import sys
from dataclasses import dataclass, field
from enum import Enum

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


class Phase(Enum):
    RECON = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class AttackStep:
    phase: Phase
    finding: dict
    technique: str
    description: str
    preconditions: list[str] = field(default_factory=list)
    provides: list[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    cwe: str = ""
    file: str = ""
    line: int = 0


@dataclass
class KillChain:
    name: str
    steps: list[AttackStep] = field(default_factory=list)
    total_severity: str = "LOW"
    impact: str = ""
    entry_point: str = ""
    final_objective: str = ""
    files_involved: list[str] = field(default_factory=list)
    mitre_tactics: list[str] = field(default_factory=list)

    @property
    def length(self) -> int:
        return len(self.steps)


_CWE_TO_PHASE = {
    "CWE-200": Phase.COLLECTION,
    "CWE-22":  Phase.INITIAL_ACCESS,
    "CWE-78":  Phase.EXECUTION,
    "CWE-79":  Phase.INITIAL_ACCESS,
    "CWE-89":  Phase.INITIAL_ACCESS,
    "CWE-94":  Phase.EXECUTION,
    "CWE-95":  Phase.EXECUTION,
    "CWE-250": Phase.PRIVILEGE_ESCALATION,
    "CWE-284": Phase.INITIAL_ACCESS,
    "CWE-295": Phase.CREDENTIAL_ACCESS,
    "CWE-306": Phase.INITIAL_ACCESS,
    "CWE-311": Phase.COLLECTION,
    "CWE-327": Phase.CREDENTIAL_ACCESS,
    "CWE-434": Phase.INITIAL_ACCESS,
    "CWE-502": Phase.EXECUTION,
    "CWE-598": Phase.CREDENTIAL_ACCESS,
    "CWE-601": Phase.INITIAL_ACCESS,
    "CWE-613": Phase.CREDENTIAL_ACCESS,
    "CWE-639": Phase.LATERAL_MOVEMENT,
    "CWE-770": Phase.IMPACT,
    "CWE-798": Phase.CREDENTIAL_ACCESS,
    "CWE-829": Phase.INITIAL_ACCESS,
    "CWE-915": Phase.PRIVILEGE_ESCALATION,
    "CWE-918": Phase.LATERAL_MOVEMENT,
}

_CATEGORY_TECHNIQUE = {
    "sql_injection":       ("SQL Injection", "execute arbitrary queries, extract data, bypass auth"),
    "command_injection":   ("OS Command Injection", "execute system commands on the server"),
    "code_injection":      ("Code Injection", "execute arbitrary code in application context"),
    "xss":                 ("Cross-Site Scripting", "steal sessions, redirect users, deface pages"),
    "template_injection":  ("Server-Side Template Injection", "execute code via template engine"),
    "path_traversal":      ("Path Traversal", "read arbitrary files including secrets and configs"),
    "ssrf":                ("Server-Side Request Forgery", "access internal services, cloud metadata"),
    "deserialization":     ("Insecure Deserialization", "execute arbitrary code via crafted objects"),
    "open_redirect":       ("Open Redirect", "phish users via trusted domain"),
    "bola":                ("Broken Object-Level Authorization", "access other users' data"),
    "missing_auth":        ("Missing Authentication", "access endpoints without credentials"),
    "mass_assignment":     ("Mass Assignment", "modify protected fields, escalate privileges"),
    "data_exposure":       ("Excessive Data Exposure", "harvest sensitive data from API responses"),
    "weak_auth":           ("Weak Authentication", "intercept or replay credentials"),
    "credential_exposure": ("Credential Exposure", "extract API keys from logs or URLs"),
    "hardcoded_secret":    ("Hardcoded Credentials", "use embedded secrets for unauthorized access"),
    "secrets":             ("Exposed Secrets", "use leaked credentials"),
    "weak_hash":           ("Weak Cryptography", "crack hashed passwords or forge tokens"),
    "weak_crypto":         ("Weak Cryptography", "break encryption or predict tokens"),
    "tls_verify":          ("TLS Verification Disabled", "man-in-the-middle connections"),
    "privilege":           ("Privilege Escalation", "gain elevated access"),
    "supply_chain":        ("Supply Chain Risk", "compromise via dependency or build process"),
    "injection_vector":    ("Input Validation Gap", "inject payloads via unconstrained parameters"),
    "dos_vector":          ("Denial of Service", "exhaust resources via unbounded requests"),
    "enumeration":         ("Data Enumeration", "enumerate records via unprotected list endpoints"),
    "network":             ("Network Exposure", "access services from untrusted networks"),
    "access_control":      ("Access Control Misconfiguration", "access public resources"),
    "encryption":          ("Missing Encryption", "read data in transit or at rest"),
    "filesystem":          ("Filesystem Exposure", "read or write host filesystem"),
    "hardening":           ("Missing Hardening", "exploit misconfiguration"),
}

_CAPABILITY_MAP = {
    "sql_injection":     ["db_read", "db_write", "auth_bypass"],
    "command_injection": ["code_exec", "file_read", "file_write", "network_access"],
    "code_injection":    ["code_exec", "file_read"],
    "xss":               ["session_theft", "user_redirect"],
    "template_injection": ["code_exec", "file_read"],
    "path_traversal":    ["file_read", "secret_access"],
    "ssrf":              ["internal_access", "metadata_access", "credential_theft"],
    "deserialization":   ["code_exec"],
    "bola":              ["data_access", "lateral_movement"],
    "missing_auth":      ["unauthenticated_access"],
    "hardcoded_secret":  ["credential_access", "service_access"],
    "secrets":           ["credential_access"],
    "weak_crypto":       ["credential_crack", "token_forge"],
    "weak_hash":         ["credential_crack"],
    "tls_verify":        ["mitm", "credential_theft"],
    "credential_exposure": ["credential_access"],
    "privilege":         ["privilege_escalation"],
    "mass_assignment":   ["privilege_escalation", "data_modification"],
    "data_exposure":     ["data_access", "pii_harvest"],
}

_REQUIRES = {
    "sql_injection":     [],
    "command_injection": [],
    "code_injection":    [],
    "ssrf":              [],
    "path_traversal":    [],
    "missing_auth":      [],
    "bola":              ["authenticated"],
    "mass_assignment":   ["authenticated"],
    "deserialization":   [],
    "xss":               ["user_interaction"],
    "hardcoded_secret":  ["source_access"],
    "secrets":           ["source_access"],
}


def _normalize_finding(f: dict) -> dict:
    return {
        "category": (f.get("category") or f.get("sink_type") or "unknown").lower().replace(" ", "_"),
        "severity": f.get("severity", "MEDIUM"),
        "cwe": f.get("cwe", ""),
        "file": f.get("file") or f.get("path") or f.get("sink_file") or "",
        "line": f.get("line") or f.get("sink_line") or 0,
        "description": f.get("description", ""),
        "rule_id": f.get("rule_id", ""),
        "chain_length": f.get("chain_length", 0),
        "source_func": f.get("source_func", ""),
        "sink_func": f.get("sink_func", ""),
        "call_chain": f.get("call_chain", []),
    }


def classify_finding(finding: dict) -> AttackStep:
    f = _normalize_finding(finding)
    category = f["category"]
    cwe = f["cwe"]

    phase = _CWE_TO_PHASE.get(cwe, Phase.INITIAL_ACCESS)
    technique_info = _CATEGORY_TECHNIQUE.get(category, (category, "exploit vulnerability"))
    technique, impact_desc = technique_info

    provides = _CAPABILITY_MAP.get(category, [])
    preconditions = _REQUIRES.get(category, [])

    return AttackStep(
        phase=phase,
        finding=finding,
        technique=technique,
        description=f"{technique} at {os.path.basename(f['file'])}:{f['line']} -- {impact_desc}",
        preconditions=preconditions,
        provides=provides,
        severity=f["severity"],
        cwe=cwe,
        file=f["file"],
        line=f["line"],
    )


def _can_chain(step_a: AttackStep, step_b: AttackStep) -> bool:
    if not step_b.preconditions:
        return True
    for req in step_b.preconditions:
        if req in step_a.provides:
            return True
        if req == "authenticated" and any(
            p in ("auth_bypass", "credential_access", "credential_theft",
                  "credential_crack", "session_theft")
            for p in step_a.provides
        ):
            return True
        if req == "source_access":
            return True
    return False


def _capability_enables(provides: list[str], category: str) -> bool:
    enables = {
        "internal_access": {"ssrf", "bola", "data_exposure", "enumeration"},
        "credential_access": {"lateral_movement", "privilege", "data_access"},
        "credential_theft": {"lateral_movement", "privilege"},
        "code_exec": {"command_injection", "code_injection", "persistence"},
        "file_read": {"path_traversal", "data_exposure", "secrets"},
        "db_read": {"data_exposure", "enumeration"},
        "auth_bypass": {"bola", "missing_auth", "mass_assignment"},
        "session_theft": {"bola", "mass_assignment", "data_access"},
        "metadata_access": {"hardcoded_secret", "credential_access"},
    }
    for cap in provides:
        enabled = enables.get(cap, set())
        if category in enabled:
            return True
    return False


def _compute_chain_severity(steps: list[AttackStep]) -> str:
    sev_scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if not steps:
        return "LOW"
    max_individual = max(sev_scores.get(s.severity, 1) for s in steps)
    chain_bonus = min(len(steps) - 1, 2)
    total = min(max_individual + chain_bonus, 4)
    return {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW"}.get(total, "MEDIUM")


def _describe_impact(chain: KillChain) -> str:
    all_caps = set()
    for step in chain.steps:
        all_caps.update(step.provides)

    impacts = []
    if "code_exec" in all_caps:
        impacts.append("remote code execution")
    if "db_read" in all_caps and "db_write" in all_caps:
        impacts.append("full database access")
    elif "db_read" in all_caps:
        impacts.append("database data extraction")
    if "credential_access" in all_caps or "credential_theft" in all_caps:
        impacts.append("credential compromise")
    if "file_read" in all_caps and "file_write" in all_caps:
        impacts.append("arbitrary file read/write")
    elif "file_read" in all_caps:
        impacts.append("arbitrary file read")
    if "metadata_access" in all_caps:
        impacts.append("cloud metadata access (potential account takeover)")
    if "privilege_escalation" in all_caps:
        impacts.append("privilege escalation")
    if "pii_harvest" in all_caps:
        impacts.append("PII data harvest")
    if "session_theft" in all_caps:
        impacts.append("session hijacking")
    if not impacts:
        impacts.append("security bypass")
    return ", ".join(impacts)


def _name_chain(chain: KillChain) -> str:
    if not chain.steps:
        return "empty chain"
    first = chain.steps[0]
    last = chain.steps[-1]
    entry = first.technique.split("(")[0].strip()
    if len(chain.steps) == 1:
        return f"{entry}"
    last_cap = last.technique.split("(")[0].strip()
    return f"{entry} → {last_cap}"


def synthesize(findings: list[dict]) -> list[KillChain]:
    if not findings:
        return []

    steps = [classify_finding(f) for f in findings]

    phase_order = list(Phase)
    steps.sort(key=lambda s: phase_order.index(s.phase))

    chains = []

    entry_steps = [s for s in steps if s.phase in (
        Phase.INITIAL_ACCESS, Phase.RECON)]
    if not entry_steps:
        entry_steps = steps[:1]

    used_in_chain = set()

    for entry in entry_steps:
        chain = KillChain(name="", steps=[entry])
        current_caps = set(entry.provides)
        used_local = {id(entry)}

        for _ in range(8):
            best_next = None
            best_score = -1
            for candidate in steps:
                if id(candidate) in used_local:
                    continue
                if candidate.phase.value == chain.steps[-1].phase.value:
                    if candidate.file == chain.steps[-1].file:
                        continue

                if _can_chain(chain.steps[-1], candidate):
                    score = 0
                    if _capability_enables(list(current_caps), candidate.finding.get("category", "")):
                        score += 3
                    sev_scores = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                    score += sev_scores.get(candidate.severity, 1)
                    if candidate.file != chain.steps[-1].file:
                        score += 1
                    if score > best_score:
                        best_score = score
                        best_next = candidate

            if best_next:
                chain.steps.append(best_next)
                current_caps.update(best_next.provides)
                used_local.add(id(best_next))
            else:
                break

        if len(chain.steps) >= 2:
            chain.total_severity = _compute_chain_severity(chain.steps)
            chain.impact = _describe_impact(chain)
            chain.name = _name_chain(chain)
            chain.entry_point = entry.technique
            chain.final_objective = chain.impact
            chain.files_involved = list(dict.fromkeys(
                s.file for s in chain.steps if s.file))
            chain.mitre_tactics = list(dict.fromkeys(
                s.phase.value for s in chain.steps))
            for s in chain.steps:
                used_in_chain.add(id(s))
            chains.append(chain)

    standalone = [s for s in steps if id(s) not in used_in_chain
                  and s.severity in ("HIGH", "CRITICAL")]
    for s in standalone:
        chain = KillChain(
            name=s.technique,
            steps=[s],
            total_severity=s.severity,
            impact=_describe_impact(KillChain(name="", steps=[s])),
            entry_point=s.technique,
            final_objective=s.technique,
            files_involved=[s.file] if s.file else [],
            mitre_tactics=[s.phase.value],
        )
        chains.append(chain)

    chains.sort(key=lambda c: (
        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(c.total_severity, 9),
        -c.length))
    return chains


def synthesize_from_engines(paths: list[str]) -> list[KillChain]:
    all_findings = []

    try:
        import detect
        for p in paths:
            if os.path.isfile(p):
                for f in detect.scan_file(p):
                    d = {}
                    for attr in ("rule", "line", "severity", "file", "sink_type",
                                 "sink_line", "cwe", "category"):
                        val = getattr(f, attr, None)
                        if val is not None:
                            d[attr] = val
                    all_findings.append(d)
    except Exception:
        pass

    try:
        import interprocedural
        inter_findings = interprocedural.scan_paths(paths)
        all_findings.extend(interprocedural.to_dict(inter_findings))
    except Exception:
        pass

    try:
        import api_scan
        api_findings = api_scan.scan_paths(paths)
        all_findings.extend(api_scan.to_dict(api_findings))
    except Exception:
        pass

    try:
        import iac_scan
        iac_findings = iac_scan.scan_paths(paths)
        all_findings.extend(iac_scan.to_dict(iac_findings))
    except Exception:
        pass

    try:
        import threat_model
        _, _, threats = threat_model.scan_paths(paths)
        all_findings.extend(threat_model.to_dict(threats))
    except Exception:
        pass

    return synthesize(all_findings)


def to_dict(chains: list[KillChain]) -> list[dict]:
    return [
        {
            "name": c.name,
            "severity": c.total_severity,
            "length": c.length,
            "impact": c.impact,
            "entry_point": c.entry_point,
            "final_objective": c.final_objective,
            "files_involved": c.files_involved,
            "mitre_tactics": c.mitre_tactics,
            "steps": [
                {
                    "phase": s.phase.value,
                    "technique": s.technique,
                    "description": s.description,
                    "severity": s.severity,
                    "cwe": s.cwe,
                    "file": s.file,
                    "line": s.line,
                    "provides": s.provides,
                    "preconditions": s.preconditions,
                }
                for s in c.steps
            ],
        }
        for c in chains
    ]


def render(chains: list[KillChain]) -> str:
    if not chains:
        return "  no attack chains found. either the code is clean or the findings don't connect."

    multi = [c for c in chains if c.length >= 2]
    crits = sum(1 for c in chains if c.total_severity == "CRITICAL")

    lines = [
        f"\n  Kill Chain Analysis",
        "  " + "=" * 62,
        f"  {len(chains)} chain(s) synthesized"
        + (f" | {len(multi)} multi-step" if multi else "")
        + (f" | {crits} critical" if crits else ""),
    ]

    if crits:
        lines.append("  these chains show how individual findings combine into full compromise.")

    for i, chain in enumerate(chains):
        sev_color = {"CRITICAL": "!!!", "HIGH": "!!", "MEDIUM": "!", "LOW": ""}.get(
            chain.total_severity, "")
        lines.append(
            f"\n  [{chain.total_severity}]{sev_color} Chain {i + 1}: {chain.name}")
        lines.append(f"    impact: {chain.impact}")
        if chain.mitre_tactics:
            lines.append(f"    tactics: {' -> '.join(chain.mitre_tactics)}")

        for j, step in enumerate(chain.steps):
            arrow = ">>>" if j == 0 else "--->"
            loc = f"{os.path.basename(step.file)}:{step.line}" if step.file else "?"
            lines.append(f"    {arrow} [{step.phase.value}] {step.technique}")
            lines.append(f"         {step.description}")
            if step.provides:
                lines.append(f"         gains: {', '.join(step.provides)}")

        if len(chain.files_involved) > 1:
            basenames = [os.path.basename(f) for f in chain.files_involved]
            lines.append(f"    spans: {', '.join(basenames)}")

    return "\n".join(lines)
