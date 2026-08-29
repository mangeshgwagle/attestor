#!/usr/bin/env python3
"""Vulnerability chaining engine -- identifies exploit chains where individual
medium/low findings combine into critical attack paths. Models real-world
attack scenarios where vulnerability A enables exploitation of vulnerability B."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ChainLink:
    finding: dict
    role: str
    description: str


@dataclass
class ExploitChain:
    chain_id: str
    name: str
    description: str
    severity: str
    links: list[ChainLink] = field(default_factory=list)
    combined_impact: str = ""
    attack_narrative: str = ""
    mitre_tactics: list[str] = field(default_factory=list)


CHAIN_RULES = [
    {
        "id": "CHAIN-RCE-VIA-SSRF",
        "name": "RCE via SSRF + Deserialization",
        "description": "SSRF reaches internal service with insecure deserialization endpoint",
        "severity": "CRITICAL",
        "requires": [
            {"cwe": "CWE-918", "role": "entry_point"},
            {"cwe": "CWE-502", "role": "exploit_target"},
        ],
        "impact": "Remote code execution via chained SSRF and deserialization",
        "narrative": "Attacker uses SSRF to reach internal deserialization endpoint, sending crafted payload for RCE",
        "tactics": ["TA0001", "TA0002", "TA0008"],
    },
    {
        "id": "CHAIN-SQLI-TO-RCE",
        "name": "SQL Injection to Code Execution",
        "description": "SQL injection combined with file write leads to RCE",
        "severity": "CRITICAL",
        "requires": [
            {"cwe": "CWE-89", "role": "entry_point"},
            {"cwe": "CWE-78", "role": "escalation"},
        ],
        "impact": "Database compromise escalating to OS-level code execution",
        "narrative": "Attacker uses SQLi to read credentials, then leverages command injection with stolen creds",
        "tactics": ["TA0001", "TA0006", "TA0002"],
    },
    {
        "id": "CHAIN-XSS-TO-ACCOUNT-TAKEOVER",
        "name": "XSS to Account Takeover",
        "description": "XSS combined with weak session management enables account takeover",
        "severity": "HIGH",
        "requires": [
            {"cwe": "CWE-79", "role": "entry_point"},
            {"cwe": "CWE-798", "role": "amplifier"},
        ],
        "impact": "Session hijacking via XSS stealing hardcoded credentials or tokens",
        "narrative": "XSS steals hardcoded API key/token, attacker uses it for privileged access",
        "tactics": ["TA0001", "TA0006", "TA0003"],
    },
    {
        "id": "CHAIN-PATH-TRAVERSAL-TO-RCE",
        "name": "Path Traversal to Code Execution",
        "description": "Path traversal reads sensitive files, enabling further exploitation",
        "severity": "CRITICAL",
        "requires": [
            {"cwe": "CWE-22", "role": "entry_point"},
            {"cwe": "CWE-78", "role": "escalation"},
        ],
        "impact": "File read escalates to command execution via config/credential leak",
        "narrative": "Attacker reads config files via path traversal, extracts credentials for command injection",
        "tactics": ["TA0007", "TA0006", "TA0002"],
    },
    {
        "id": "CHAIN-SSRF-TO-CLOUD-TAKEOVER",
        "name": "SSRF to Cloud Metadata Theft",
        "description": "SSRF accesses cloud metadata endpoint to steal IAM credentials",
        "severity": "CRITICAL",
        "requires": [
            {"cwe": "CWE-918", "role": "entry_point"},
            {"cwe": "CWE-200", "role": "information_leak"},
        ],
        "impact": "Cloud infrastructure takeover via stolen IAM credentials",
        "narrative": "Attacker uses SSRF to hit 169.254.169.254, steals IAM role credentials, pivots to cloud services",
        "tactics": ["TA0001", "TA0006", "TA0008"],
    },
    {
        "id": "CHAIN-DESER-PLUS-EVAL",
        "name": "Deserialization + Dynamic Code Execution",
        "description": "Insecure deserialization feeds into eval/exec sink",
        "severity": "CRITICAL",
        "requires": [
            {"cwe": "CWE-502", "role": "entry_point"},
            {"cwe": "CWE-95", "role": "exploit_target"},
        ],
        "impact": "Arbitrary code execution through deserialization into eval",
        "narrative": "Crafted serialized object is deserialized and passed to eval()/exec()",
        "tactics": ["TA0001", "TA0002"],
    },
    {
        "id": "CHAIN-SECRET-LEAK-TO-LATERAL",
        "name": "Secret Leak to Lateral Movement",
        "description": "Exposed secrets enable access to additional systems",
        "severity": "HIGH",
        "requires": [
            {"cwe": "CWE-798", "role": "entry_point"},
            {"cwe": "CWE-918", "role": "amplifier"},
        ],
        "impact": "Hardcoded credentials used with SSRF for internal service access",
        "narrative": "Discovered hardcoded credentials are used via SSRF to authenticate to internal services",
        "tactics": ["TA0006", "TA0008", "TA0009"],
    },
    {
        "id": "CHAIN-TEMPLATE-INJECTION-FULL",
        "name": "Template Injection to Full Compromise",
        "description": "Server-side template injection leads to RCE",
        "severity": "CRITICAL",
        "requires": [
            {"cwe": "CWE-94", "role": "entry_point"},
        ],
        "impact": "Direct remote code execution via template engine",
        "narrative": "Attacker injects template syntax that escapes sandbox for OS command execution",
        "tactics": ["TA0001", "TA0002"],
    },
    {
        "id": "CHAIN-LOG-INJECTION-TO-BYPASS",
        "name": "Log Injection to Security Bypass",
        "description": "Log injection combined with weak monitoring enables undetected attacks",
        "severity": "MEDIUM",
        "requires": [
            {"cwe": "CWE-117", "role": "preparation"},
            {"cwe": "CWE-78", "role": "exploit_target"},
        ],
        "impact": "Attacker corrupts logs to hide command injection exploitation",
        "narrative": "Log injection masks subsequent command injection attacks from SIEM/monitoring",
        "tactics": ["TA0005", "TA0002"],
    },
    {
        "id": "CHAIN-OPEN-REDIRECT-TO-PHISH",
        "name": "Open Redirect to Credential Theft",
        "description": "Open redirect enables convincing phishing attacks",
        "severity": "MEDIUM",
        "requires": [
            {"cwe": "CWE-601", "role": "entry_point"},
            {"cwe": "CWE-79", "role": "amplifier"},
        ],
        "impact": "Users redirected to phishing page; XSS captures credentials",
        "narrative": "Trusted domain redirect + XSS combines into a convincing credential theft attack",
        "tactics": ["TA0001", "TA0006"],
    },
]


def _extract_cwe(finding: dict) -> str:
    for key in ("cwe", "sink_cwe", "cve_cwe"):
        val = finding.get(key, "")
        if val and val.startswith("CWE-"):
            return val
    rule = finding.get("rule_id", "")
    if "CWE-" in rule:
        import re
        m = re.search(r"CWE-\d+", rule)
        if m:
            return m.group(0)
    return ""


def analyze(findings: list[dict]) -> list[ExploitChain]:
    cwe_to_findings: dict[str, list[dict]] = {}
    for f in findings:
        cwe = _extract_cwe(f)
        if cwe:
            cwe_to_findings.setdefault(cwe, []).append(f)

    chains = []
    for rule in CHAIN_RULES:
        required_cwes = [r["cwe"] for r in rule["requires"]]
        all_present = all(cwe in cwe_to_findings for cwe in required_cwes)
        if not all_present:
            continue

        links = []
        for req in rule["requires"]:
            matching = cwe_to_findings.get(req["cwe"], [])
            if matching:
                best = max(matching, key=lambda x: (
                    {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                    .get(x.get("severity", "MEDIUM"), 2)
                ))
                links.append(ChainLink(
                    finding=best,
                    role=req["role"],
                    description=f"{req['cwe']}: {best.get('description', best.get('rule_id', 'unknown'))}",
                ))

        chains.append(ExploitChain(
            chain_id=rule["id"],
            name=rule["name"],
            description=rule["description"],
            severity=rule["severity"],
            links=links,
            combined_impact=rule["impact"],
            attack_narrative=rule["narrative"],
            mitre_tactics=rule.get("tactics", []),
        ))

    chains.sort(key=lambda c: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(c.severity, 4))
    return chains


def render(chains: list[ExploitChain]) -> str:
    if not chains:
        return "  No exploit chains detected."
    lines = []
    lines.append(f"\n  Vulnerability Chaining ({len(chains)} chain{'s' if len(chains) != 1 else ''})")
    lines.append(f"  {'='*55}")
    lines.append("  NOTE: These are potential attack paths where individual")
    lines.append("  vulnerabilities combine into more severe exploits.\n")

    for chain in chains:
        lines.append(f"  [{chain.severity}] {chain.name} ({chain.chain_id})")
        lines.append(f"    {chain.description}")
        lines.append(f"    Impact: {chain.combined_impact}")
        lines.append(f"    Narrative: {chain.attack_narrative}")
        if chain.mitre_tactics:
            lines.append(f"    MITRE Tactics: {', '.join(chain.mitre_tactics)}")
        lines.append(f"    Chain links:")
        for link in chain.links:
            path = link.finding.get("path", link.finding.get("file", "?"))
            line_num = link.finding.get("line", link.finding.get("line_start", "?"))
            lines.append(f"      [{link.role}] {link.description}")
            lines.append(f"        Location: {path}:{line_num}")
        lines.append("")

    crit = sum(1 for c in chains if c.severity == "CRITICAL")
    lines.append(f"  Total: {len(chains)} chain(s) ({crit} critical)")
    return "\n".join(lines)


def to_dict(chains: list[ExploitChain]) -> list[dict]:
    return [
        {
            "chain_id": c.chain_id,
            "name": c.name,
            "description": c.description,
            "severity": c.severity,
            "combined_impact": c.combined_impact,
            "attack_narrative": c.attack_narrative,
            "mitre_tactics": c.mitre_tactics,
            "links": [
                {
                    "role": l.role,
                    "description": l.description,
                    "file": l.finding.get("path", l.finding.get("file", "")),
                    "line": l.finding.get("line", l.finding.get("line_start", 0)),
                }
                for l in c.links
            ],
        }
        for c in chains
    ]
