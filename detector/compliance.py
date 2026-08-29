#!/usr/bin/env python3
"""Compliance report generator -- maps security findings to compliance frameworks:
OWASP Top 10 (2021), NIST SP 800-53 Rev 5, SOC 2, and PCI-DSS v4.0.
Generates audit-ready reports with control mapping, gap analysis, and remediation."""
from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class ComplianceMapping:
    cwe: str
    frameworks: dict[str, list[str]] = field(default_factory=dict)


@dataclass
class ComplianceGap:
    framework: str
    control_id: str
    control_name: str
    status: str
    finding_count: int
    severity_breakdown: dict[str, int] = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    remediation: str = ""


@dataclass
class ComplianceReport:
    framework: str
    generated_at: str
    total_controls: int
    passing: int
    failing: int
    not_assessed: int
    gaps: list[ComplianceGap] = field(default_factory=list)
    score: float = 0.0


OWASP_TOP_10_2021 = {
    "A01:2021": {
        "name": "Broken Access Control",
        "cwes": ["CWE-22", "CWE-23", "CWE-35", "CWE-59", "CWE-200", "CWE-201",
                 "CWE-219", "CWE-264", "CWE-275", "CWE-276", "CWE-284", "CWE-285",
                 "CWE-352", "CWE-359", "CWE-377", "CWE-402", "CWE-425", "CWE-441",
                 "CWE-497", "CWE-538", "CWE-540", "CWE-548", "CWE-552", "CWE-566",
                 "CWE-601", "CWE-639", "CWE-651", "CWE-668", "CWE-706", "CWE-862",
                 "CWE-863", "CWE-913", "CWE-922", "CWE-1275"],
        "remediation": "Implement proper access controls, deny by default, enforce record ownership",
    },
    "A02:2021": {
        "name": "Cryptographic Failures",
        "cwes": ["CWE-261", "CWE-296", "CWE-310", "CWE-319", "CWE-321", "CWE-322",
                 "CWE-323", "CWE-324", "CWE-325", "CWE-326", "CWE-327", "CWE-328",
                 "CWE-329", "CWE-330", "CWE-331", "CWE-335", "CWE-336", "CWE-337",
                 "CWE-338", "CWE-340", "CWE-347", "CWE-523", "CWE-720", "CWE-757",
                 "CWE-759", "CWE-760", "CWE-780", "CWE-798", "CWE-916"],
        "remediation": "Use strong, up-to-date encryption algorithms; protect data in transit and at rest",
    },
    "A03:2021": {
        "name": "Injection",
        "cwes": ["CWE-20", "CWE-74", "CWE-75", "CWE-77", "CWE-78", "CWE-79",
                 "CWE-80", "CWE-83", "CWE-87", "CWE-88", "CWE-89", "CWE-90",
                 "CWE-91", "CWE-93", "CWE-94", "CWE-95", "CWE-96", "CWE-97",
                 "CWE-98", "CWE-99", "CWE-100", "CWE-113", "CWE-116", "CWE-138",
                 "CWE-184", "CWE-470", "CWE-471", "CWE-564", "CWE-610", "CWE-643",
                 "CWE-644", "CWE-652", "CWE-917"],
        "remediation": "Use parameterized queries, input validation, output encoding",
    },
    "A04:2021": {
        "name": "Insecure Design",
        "cwes": ["CWE-73", "CWE-183", "CWE-209", "CWE-213", "CWE-235", "CWE-256",
                 "CWE-257", "CWE-266", "CWE-269", "CWE-280", "CWE-311", "CWE-312",
                 "CWE-313", "CWE-316", "CWE-419", "CWE-430", "CWE-434", "CWE-444",
                 "CWE-451", "CWE-472", "CWE-501", "CWE-522", "CWE-525", "CWE-539",
                 "CWE-579", "CWE-598", "CWE-602", "CWE-642", "CWE-646", "CWE-650",
                 "CWE-653", "CWE-656", "CWE-657", "CWE-799", "CWE-807", "CWE-840",
                 "CWE-841", "CWE-927", "CWE-1021", "CWE-1173"],
        "remediation": "Implement threat modeling, secure design patterns, and defense-in-depth",
    },
    "A05:2021": {
        "name": "Security Misconfiguration",
        "cwes": ["CWE-2", "CWE-11", "CWE-13", "CWE-15", "CWE-16", "CWE-260",
                 "CWE-315", "CWE-520", "CWE-526", "CWE-537", "CWE-541", "CWE-547",
                 "CWE-611", "CWE-614", "CWE-756", "CWE-776", "CWE-942", "CWE-1004",
                 "CWE-1032", "CWE-1174"],
        "remediation": "Harden configurations, disable unnecessary features, automate config validation",
    },
    "A06:2021": {
        "name": "Vulnerable and Outdated Components",
        "cwes": ["CWE-1104"],
        "remediation": "Maintain component inventory, monitor CVEs, automated dependency updates",
    },
    "A07:2021": {
        "name": "Identification and Authentication Failures",
        "cwes": ["CWE-255", "CWE-259", "CWE-287", "CWE-288", "CWE-290", "CWE-294",
                 "CWE-295", "CWE-297", "CWE-300", "CWE-302", "CWE-304", "CWE-306",
                 "CWE-307", "CWE-346", "CWE-384", "CWE-521", "CWE-613", "CWE-620",
                 "CWE-640", "CWE-798", "CWE-940", "CWE-1216"],
        "remediation": "Implement MFA, strong password policies, secure session management",
    },
    "A08:2021": {
        "name": "Software and Data Integrity Failures",
        "cwes": ["CWE-345", "CWE-353", "CWE-426", "CWE-494", "CWE-502", "CWE-565",
                 "CWE-784", "CWE-829", "CWE-830", "CWE-915"],
        "remediation": "Verify integrity of software/data, use signed updates, review CI/CD pipeline",
    },
    "A09:2021": {
        "name": "Security Logging and Monitoring Failures",
        "cwes": ["CWE-117", "CWE-223", "CWE-532", "CWE-778"],
        "remediation": "Implement comprehensive logging, alerting, and incident response",
    },
    "A10:2021": {
        "name": "Server-Side Request Forgery (SSRF)",
        "cwes": ["CWE-918"],
        "remediation": "Validate/sanitize all client-supplied URLs, use allowlists, block metadata endpoints",
    },
}

NIST_800_53 = {
    "AC-1": {"name": "Access Control Policy and Procedures", "cwes": ["CWE-284", "CWE-862", "CWE-863"]},
    "AC-3": {"name": "Access Enforcement", "cwes": ["CWE-284", "CWE-285", "CWE-862", "CWE-863"]},
    "AC-6": {"name": "Least Privilege", "cwes": ["CWE-250", "CWE-266", "CWE-269"]},
    "AU-2": {"name": "Event Logging", "cwes": ["CWE-778", "CWE-117"]},
    "AU-3": {"name": "Content of Audit Records", "cwes": ["CWE-778", "CWE-223"]},
    "CA-2": {"name": "Control Assessments", "cwes": []},
    "CM-6": {"name": "Configuration Settings", "cwes": ["CWE-16", "CWE-1004"]},
    "IA-2": {"name": "Identification and Authentication", "cwes": ["CWE-287", "CWE-306"]},
    "IA-5": {"name": "Authenticator Management", "cwes": ["CWE-259", "CWE-798", "CWE-521"]},
    "RA-5": {"name": "Vulnerability Monitoring and Scanning", "cwes": ["CWE-1104"]},
    "SA-11": {"name": "Developer Testing and Evaluation", "cwes": []},
    "SC-8": {"name": "Transmission Confidentiality and Integrity", "cwes": ["CWE-319", "CWE-311"]},
    "SC-12": {"name": "Cryptographic Key Establishment", "cwes": ["CWE-321", "CWE-326", "CWE-327"]},
    "SC-13": {"name": "Cryptographic Protection", "cwes": ["CWE-326", "CWE-327", "CWE-328"]},
    "SC-28": {"name": "Protection of Information at Rest", "cwes": ["CWE-311", "CWE-312"]},
    "SI-2": {"name": "Flaw Remediation", "cwes": ["CWE-1104"]},
    "SI-3": {"name": "Malicious Code Protection", "cwes": []},
    "SI-10": {"name": "Information Input Validation", "cwes": ["CWE-20", "CWE-78", "CWE-79", "CWE-89"]},
}

SOC2_TSC = {
    "CC6.1": {"name": "Logical and Physical Access Controls", "cwes": ["CWE-284", "CWE-287", "CWE-862"]},
    "CC6.2": {"name": "System Registration and Authorization", "cwes": ["CWE-287", "CWE-306"]},
    "CC6.3": {"name": "Role-Based Access and Least Privilege", "cwes": ["CWE-250", "CWE-269", "CWE-863"]},
    "CC6.6": {"name": "Boundaries - Network Segmentation", "cwes": ["CWE-918"]},
    "CC6.7": {"name": "Data Transmission Controls", "cwes": ["CWE-319", "CWE-311"]},
    "CC6.8": {"name": "Malicious Software Prevention", "cwes": []},
    "CC7.1": {"name": "Monitoring for Security Events", "cwes": ["CWE-778", "CWE-117"]},
    "CC7.2": {"name": "Anomaly Detection", "cwes": []},
    "CC8.1": {"name": "Change Management", "cwes": []},
    "CC9.1": {"name": "Risk Mitigation", "cwes": []},
}

PCI_DSS_V4 = {
    "1.3": {"name": "Network Access Controls", "cwes": ["CWE-284"]},
    "2.2": {"name": "Secure Configuration Standards", "cwes": ["CWE-16", "CWE-1004"]},
    "3.4": {"name": "Render PAN Unreadable", "cwes": ["CWE-311", "CWE-312"]},
    "4.1": {"name": "Strong Cryptography for Transmission", "cwes": ["CWE-319", "CWE-326", "CWE-327"]},
    "6.2": {"name": "Secure Software Development", "cwes": ["CWE-78", "CWE-79", "CWE-89", "CWE-502"]},
    "6.3": {"name": "Vulnerability Identification and Management", "cwes": ["CWE-1104"]},
    "6.4": {"name": "Public-Facing Web Application Protection", "cwes": ["CWE-79", "CWE-89", "CWE-918"]},
    "6.5": {"name": "Change Control Processes", "cwes": []},
    "7.1": {"name": "Restrict Access by Business Need-to-Know", "cwes": ["CWE-862", "CWE-863"]},
    "8.3": {"name": "Strong Authentication", "cwes": ["CWE-287", "CWE-521", "CWE-798"]},
    "10.2": {"name": "Audit Logs", "cwes": ["CWE-778", "CWE-117"]},
    "11.3": {"name": "Internal and External Vulnerability Scans", "cwes": ["CWE-1104"]},
}


FRAMEWORK_CONTROLS = {
    "owasp": OWASP_TOP_10_2021,
    "nist": NIST_800_53,
    "soc2": SOC2_TSC,
    "pci-dss": PCI_DSS_V4,
}


def _extract_cwes(findings: list[dict]) -> dict[str, list[dict]]:
    cwe_findings: dict[str, list[dict]] = defaultdict(list)
    for f in findings:
        cwe = f.get("cwe", f.get("sink_cwe", ""))
        if cwe:
            cwe_findings[cwe].append(f)
        rule_id = f.get("rule_id", "")
        if "CWE-" in rule_id:
            import re
            for m in re.finditer(r"CWE-\d+", rule_id):
                cwe_findings[m.group(0)].append(f)
    return dict(cwe_findings)


def generate_report(
    findings: list[dict],
    framework: str = "owasp",
    project_name: str = "Project",
) -> ComplianceReport:
    controls = FRAMEWORK_CONTROLS.get(framework.lower(), OWASP_TOP_10_2021)
    cwe_findings = _extract_cwes(findings)

    gaps = []
    passing = 0
    failing = 0

    for control_id, control_info in controls.items():
        name = control_info["name"]
        control_cwes = control_info.get("cwes", [])
        remediation = control_info.get("remediation", "")

        matched_findings = []
        for cwe in control_cwes:
            matched_findings.extend(cwe_findings.get(cwe, []))

        if not control_cwes:
            status = "NOT_ASSESSED"
        elif matched_findings:
            status = "FAILING"
            failing += 1
        else:
            status = "PASSING"
            passing += 1

        sev_breakdown = defaultdict(int)
        for f in matched_findings:
            sev = f.get("severity", "MEDIUM")
            sev_breakdown[sev] += 1

        gaps.append(ComplianceGap(
            framework=framework.upper(),
            control_id=control_id,
            control_name=name,
            status=status,
            finding_count=len(matched_findings),
            severity_breakdown=dict(sev_breakdown),
            findings=matched_findings[:5],
            remediation=remediation,
        ))

    total = passing + failing
    not_assessed = len(controls) - total
    score = (passing / total * 100) if total > 0 else 0

    return ComplianceReport(
        framework=framework.upper(),
        generated_at=datetime.now().isoformat(),
        total_controls=len(controls),
        passing=passing,
        failing=failing,
        not_assessed=not_assessed,
        gaps=gaps,
        score=round(score, 1),
    )


def render(report: ComplianceReport) -> str:
    lines = []
    lines.append(f"\n  {report.framework} Compliance Report")
    lines.append(f"  Generated: {report.generated_at[:19]}")
    lines.append(f"  {'='*55}")
    lines.append(f"  Score: {report.score:.1f}% ({report.passing}/{report.passing + report.failing} controls passing)")
    lines.append(f"  Controls: {report.total_controls} total, {report.passing} passing, "
                 f"{report.failing} failing, {report.not_assessed} not assessed")
    lines.append("")

    failing = [g for g in report.gaps if g.status == "FAILING"]
    if failing:
        lines.append("  FAILING CONTROLS:")
        for g in sorted(failing, key=lambda x: -x.finding_count):
            sev_str = ", ".join(f"{k}:{v}" for k, v in sorted(g.severity_breakdown.items()))
            lines.append(f"    FAIL  {g.control_id}  {g.control_name}")
            lines.append(f"          {g.finding_count} finding(s) [{sev_str}]")
            if g.remediation:
                lines.append(f"          Fix: {g.remediation}")

    passing = [g for g in report.gaps if g.status == "PASSING"]
    if passing:
        lines.append(f"\n  PASSING CONTROLS ({len(passing)}):")
        for g in passing:
            lines.append(f"    PASS  {g.control_id}  {g.control_name}")

    not_assessed = [g for g in report.gaps if g.status == "NOT_ASSESSED"]
    if not_assessed:
        lines.append(f"\n  NOT ASSESSED ({len(not_assessed)}):")
        for g in not_assessed:
            lines.append(f"    N/A   {g.control_id}  {g.control_name}")

    return "\n".join(lines)


def render_all(findings: list[dict], project_name: str = "Project") -> str:
    lines = []
    for fw in ("owasp", "nist", "soc2", "pci-dss"):
        report = generate_report(findings, fw, project_name)
        lines.append(render(report))
        lines.append("")
    return "\n".join(lines)


def to_dict(report: ComplianceReport) -> dict:
    return {
        "framework": report.framework,
        "generated_at": report.generated_at,
        "score": report.score,
        "total_controls": report.total_controls,
        "passing": report.passing,
        "failing": report.failing,
        "not_assessed": report.not_assessed,
        "gaps": [
            {
                "control_id": g.control_id,
                "control_name": g.control_name,
                "status": g.status,
                "finding_count": g.finding_count,
                "severity_breakdown": g.severity_breakdown,
                "remediation": g.remediation,
            }
            for g in report.gaps
        ],
    }
