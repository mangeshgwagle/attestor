#!/usr/bin/env python3
"""Pentest report generator for Owen.

Turns Owen's findings into a professional penetration testing report with
CVSS scores, risk ratings, remediation guidance, and executive summary.

Usage:
    gen = ReportGen()
    gen.add_findings(findings)
    gen.add_chains(chains)        # from exploit_chain42
    gen.add_dep_vulns(dep_vulns)  # from dep_scan42
    report = gen.generate()
    print(report.markdown())
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from typing import Any

VERSION = "4.2"


# =========================================================================== #
#  DATA TYPES                                                                  #
# =========================================================================== #

class Severity(Enum):
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()


class FindingStatus(Enum):
    OPEN = "Open"
    REMEDIATED = "Remediated"
    ACCEPTED = "Risk Accepted"
    FALSE_POSITIVE = "False Positive"


SEVERITY_COLOR = {
    Severity.CRITICAL: "#dc3545",
    Severity.HIGH: "#fd7e14",
    Severity.MEDIUM: "#ffc107",
    Severity.LOW: "#28a745",
    Severity.INFO: "#17a2b8",
}


def severity_from_cvss(cvss: float) -> Severity:
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    if cvss >= 0.1:
        return Severity.LOW
    return Severity.INFO


CWE_CVSS_BASE: dict[int, float] = {
    89: 8.6, 79: 6.1, 78: 9.8, 94: 9.8, 22: 7.5, 23: 7.5,
    502: 9.8, 306: 7.4, 862: 6.5, 798: 7.5, 918: 6.4,
    434: 8.8, 611: 7.5, 113: 6.1, 120: 9.8, 134: 7.5,
    190: 7.5, 250: 4.4, 295: 5.9, 319: 5.9, 327: 5.9,
    338: 5.3, 369: 5.3, 400: 7.5, 476: 5.9, 614: 4.3,
    770: 7.5, 922: 5.3, 1321: 7.3, 90: 7.5, 80: 6.1,
    36: 7.5,
}

CWE_TITLE: dict[int, str] = {
    89: "SQL Injection",
    79: "Cross-Site Scripting (XSS)",
    80: "Basic XSS",
    78: "OS Command Injection",
    94: "Code Injection",
    22: "Path Traversal",
    23: "Relative Path Traversal",
    36: "Absolute Path Traversal",
    90: "LDAP Injection",
    113: "HTTP Response Splitting",
    120: "Buffer Overflow",
    134: "Format String Vulnerability",
    190: "Integer Overflow",
    250: "Unnecessary Privileges",
    295: "Improper Certificate Validation",
    306: "Missing Authentication",
    319: "Cleartext Transmission",
    327: "Broken Cryptography",
    338: "Weak PRNG",
    369: "Divide By Zero",
    400: "Resource Exhaustion",
    434: "Unrestricted File Upload",
    476: "NULL Pointer Dereference",
    502: "Insecure Deserialization",
    611: "XML External Entity (XXE)",
    614: "Missing Secure Cookie Flag",
    770: "Allocation Without Limits",
    798: "Hard-coded Credentials",
    862: "Missing Authorization",
    918: "Server-Side Request Forgery (SSRF)",
    922: "Insecure Storage of Sensitive Data",
    1321: "Prototype Pollution",
}

CWE_REMEDIATION: dict[int, str] = {
    89: "Use parameterized queries or prepared statements. Never concatenate user input into SQL.",
    79: "Encode output contextually (HTML, JS, URL). Use Content-Security-Policy headers.",
    78: "Avoid shell commands with user input. Use safe APIs (subprocess with list args, no shell=True).",
    94: "Never eval() user input. Use sandboxed template engines.",
    22: "Validate and canonicalize file paths. Use allowlists for permitted directories.",
    502: "Never deserialize untrusted data. Use safe formats (JSON) with schema validation.",
    306: "Implement authentication on all sensitive endpoints. Use established auth frameworks.",
    862: "Enforce authorization checks on every request. Use role-based access control.",
    798: "Move credentials to environment variables or a secrets manager. Rotate compromised keys.",
    918: "Validate and allowlist destination URLs. Block internal network ranges.",
    434: "Validate file type, size, and content. Store uploads outside webroot.",
    611: "Disable external entity processing. Use defusedxml or equivalent.",
    113: "Validate and sanitize header values. Reject input with CR/LF characters.",
    120: "Use bounded string functions (strncpy, snprintf). Enable stack protections.",
    134: "Never pass user input as format string. Use printf(\"%s\", user_input).",
    190: "Check arithmetic bounds before operations. Use safe integer libraries.",
    400: "Implement rate limiting, request size limits, and timeouts.",
    770: "Set allocation limits and quotas. Monitor resource consumption.",
    614: "Set Secure and HttpOnly flags on session cookies. Use SameSite attribute.",
    922: "Encrypt sensitive data at rest. Use proper key management.",
    1321: "Freeze prototypes. Validate and sanitize object keys. Use Map instead of plain objects.",
    295: "Validate TLS certificates properly. Do not disable certificate verification.",
    319: "Use TLS/HTTPS for all data transmission. Enforce HSTS.",
    327: "Use modern, vetted cryptographic algorithms (AES-256-GCM, SHA-256+).",
    338: "Use cryptographically secure PRNGs (secrets module, SecureRandom).",
    250: "Follow least privilege principle. Drop unnecessary permissions.",
    369: "Check for zero before division. Handle edge cases in arithmetic.",
    476: "Check pointers before dereferencing. Use static analysis tools.",
    90: "Use parameterized LDAP queries. Escape special characters in filters.",
}


@dataclass
class ReportFinding:
    """A single finding in the pentest report."""
    finding_id: str
    title: str
    cwe: int
    severity: Severity
    cvss: float
    description: str
    file_path: str
    line: int
    evidence: str = ""
    remediation: str = ""
    status: FindingStatus = FindingStatus.OPEN
    references: list[str] = field(default_factory=list)

    @property
    def owasp_category(self) -> str:
        mapping = {
            89: "A03:2021 Injection",
            79: "A03:2021 Injection",
            78: "A03:2021 Injection",
            94: "A03:2021 Injection",
            90: "A03:2021 Injection",
            113: "A03:2021 Injection",
            22: "A01:2021 Broken Access Control",
            862: "A01:2021 Broken Access Control",
            918: "A10:2021 SSRF",
            306: "A07:2021 Auth Failures",
            798: "A07:2021 Auth Failures",
            502: "A08:2021 Integrity Failures",
            434: "A04:2021 Insecure Design",
            611: "A05:2021 Security Misconfiguration",
            327: "A02:2021 Cryptographic Failures",
            295: "A02:2021 Cryptographic Failures",
            319: "A02:2021 Cryptographic Failures",
            338: "A02:2021 Cryptographic Failures",
            614: "A02:2021 Cryptographic Failures",
        }
        return mapping.get(self.cwe, "Other")


@dataclass
class ReportMeta:
    """Report metadata."""
    title: str = "Penetration Test Report"
    target: str = ""
    tester: str = "Owen Attestor 4.2"
    date: str = ""
    scope: str = ""
    methodology: str = "Automated static analysis with Owen Attestor 4.2"
    classification: str = "CONFIDENTIAL"

    def __post_init__(self):
        if not self.date:
            self.date = datetime.now().strftime("%Y-%m-%d")


@dataclass
class PentestReport:
    """Complete pentest report."""
    meta: ReportMeta
    findings: list[ReportFinding]
    chains: list[dict[str, Any]] = field(default_factory=list)
    dep_vulns: list[dict[str, Any]] = field(default_factory=list)

    @property
    def report_id(self) -> str:
        raw = "%s:%s:%s" % (self.meta.target, self.meta.date,
                            len(self.findings))
        return hashlib.sha256(raw.encode()).hexdigest()[:12]

    def by_severity(self) -> dict[str, list[ReportFinding]]:
        groups: dict[str, list[ReportFinding]] = {}
        for f in self.findings:
            name = f.severity.name
            groups.setdefault(name, []).append(f)
        return groups

    def severity_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            name = f.severity.name
            counts[name] = counts.get(name, 0) + 1
        return counts

    def risk_score(self) -> float:
        if not self.findings:
            return 0.0
        weights = {
            Severity.CRITICAL: 10, Severity.HIGH: 7,
            Severity.MEDIUM: 4, Severity.LOW: 1, Severity.INFO: 0,
        }
        total = sum(weights.get(f.severity, 0) for f in self.findings)
        return min(total / max(len(self.findings), 1) * 10, 100)

    def risk_rating(self) -> str:
        score = self.risk_score()
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 40:
            return "MEDIUM"
        if score >= 20:
            return "LOW"
        return "INFORMATIONAL"

    def executive_summary(self) -> str:
        counts = self.severity_counts()
        total = len(self.findings)
        rating = self.risk_rating()
        score = self.risk_score()

        lines = [
            "## Executive Summary",
            "",
            "A penetration test was conducted against **%s** on %s using %s." % (
                self.meta.target or "the target application",
                self.meta.date, self.meta.methodology),
            "",
            "**Overall Risk Rating: %s (%.0f/100)**" % (rating, score),
            "",
            "### Findings Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
        ]

        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            count = counts.get(sev, 0)
            if count > 0:
                lines.append("| %s | %d |" % (sev, count))

        lines.append("| **Total** | **%d** |" % total)
        lines.append("")

        if counts.get("CRITICAL", 0) > 0:
            lines.append(
                "**Immediate action required.** Critical vulnerabilities were "
                "found that could lead to full system compromise.")
        elif counts.get("HIGH", 0) > 0:
            lines.append(
                "**High-priority remediation recommended.** Significant "
                "vulnerabilities exist that could be exploited.")
        else:
            lines.append(
                "The application has moderate security posture with "
                "opportunities for improvement.")

        if self.chains:
            lines.append("")
            lines.append("**%d exploit chain(s)** were identified, showing "
                         "how individual findings can be combined for "
                         "greater impact." % len(self.chains))

        if self.dep_vulns:
            lines.append("")
            lines.append("**%d dependency vulnerability(ies)** were found "
                         "in third-party packages." % len(self.dep_vulns))

        return "\n".join(lines)

    def markdown(self) -> str:
        sections = []

        sections.append("# %s" % self.meta.title)
        sections.append("")
        sections.append("**Classification:** %s" % self.meta.classification)
        sections.append("**Report ID:** %s" % self.report_id)
        sections.append("**Date:** %s" % self.meta.date)
        sections.append("**Target:** %s" % (self.meta.target or "N/A"))
        sections.append("**Tester:** %s" % self.meta.tester)
        if self.meta.scope:
            sections.append("**Scope:** %s" % self.meta.scope)
        sections.append("")
        sections.append("---")
        sections.append("")

        sections.append(self.executive_summary())
        sections.append("")
        sections.append("---")
        sections.append("")

        sections.append("## Detailed Findings")
        sections.append("")

        sorted_findings = sorted(self.findings,
                                 key=lambda f: (-f.cvss, f.cwe))

        for i, f in enumerate(sorted_findings, 1):
            sections.append("### %d. %s" % (i, f.title))
            sections.append("")
            sections.append("| Field | Value |")
            sections.append("|-------|-------|")
            sections.append("| **Severity** | %s |" % f.severity.name)
            sections.append("| **CVSS** | %.1f |" % f.cvss)
            sections.append("| **CWE** | CWE-%d |" % f.cwe)
            sections.append("| **OWASP** | %s |" % f.owasp_category)
            sections.append("| **Location** | `%s:%d` |" % (f.file_path, f.line))
            sections.append("| **Status** | %s |" % f.status.value)
            sections.append("")

            sections.append("**Description:**")
            sections.append(f.description)
            sections.append("")

            if f.evidence:
                sections.append("**Evidence:**")
                sections.append("```")
                sections.append(f.evidence)
                sections.append("```")
                sections.append("")

            sections.append("**Remediation:**")
            sections.append(f.remediation)
            sections.append("")

            if f.references:
                sections.append("**References:**")
                for ref in f.references:
                    sections.append("- %s" % ref)
                sections.append("")

            sections.append("---")
            sections.append("")

        if self.chains:
            sections.append("## Exploit Chains")
            sections.append("")
            for i, chain in enumerate(self.chains, 1):
                sections.append("### Chain %d" % i)
                sections.append("")
                steps = chain.get("steps", [])
                cvss = chain.get("cvss", 0.0)
                impact = chain.get("impact", "Unknown")
                sections.append("**CVSS:** %.1f | **Final Impact:** %s | "
                                "**Steps:** %d" % (cvss, impact, len(steps)))
                sections.append("")
                for j, step in enumerate(steps, 1):
                    sections.append("%d. CWE-%d at `%s:%d` — %s" % (
                        j, step.get("cwe", 0),
                        step.get("file", "?"), step.get("line", 0),
                        step.get("description", "")))
                sections.append("")

        if self.dep_vulns:
            sections.append("## Dependency Vulnerabilities")
            sections.append("")
            sections.append("| CVE | Package | Version | Severity | CVSS | Fix |")
            sections.append("|-----|---------|---------|----------|------|-----|")
            for dv in self.dep_vulns:
                sections.append("| %s | %s | %s | %s | %.1f | %s |" % (
                    dv.get("cve", ""),
                    dv.get("package", ""),
                    dv.get("version", ""),
                    dv.get("severity", ""),
                    dv.get("cvss", 0.0),
                    dv.get("fixed_version", "N/A"),
                ))
            sections.append("")

        sections.append("## Methodology")
        sections.append("")
        sections.append(self.meta.methodology)
        sections.append("")
        sections.append("---")
        sections.append("")
        sections.append("*Generated by Owen Attestor %s*" % VERSION)

        return "\n".join(sections)


# =========================================================================== #
#  REPORT GENERATOR                                                            #
# =========================================================================== #

class ReportGen:
    """Builds a pentest report from Owen findings."""

    def __init__(self, target: str = "", scope: str = ""):
        self._findings: list[ReportFinding] = []
        self._chains: list[dict[str, Any]] = []
        self._dep_vulns: list[dict[str, Any]] = []
        self._meta = ReportMeta(target=target, scope=scope)
        self._counter = 0

    def add_finding(self, cwe: int, file_path: str, line: int,
                    **kwargs) -> ReportFinding:
        self._counter += 1
        if isinstance(cwe, str):
            m = re.search(r"(\d+)", cwe)
            cwe = int(m.group(1)) if m else 0

        cvss = kwargs.get("cvss", CWE_CVSS_BASE.get(cwe, 5.0))
        severity = severity_from_cvss(cvss)
        title = kwargs.get("title", CWE_TITLE.get(cwe, "CWE-%d" % cwe))
        remediation = kwargs.get("remediation",
                                 CWE_REMEDIATION.get(cwe, "Review and remediate."))
        description = kwargs.get("description",
                                 "A %s vulnerability (CWE-%d) was identified "
                                 "at %s:%d." % (title.lower(), cwe, file_path, line))

        finding = ReportFinding(
            finding_id="OWEN-%04d" % self._counter,
            title=title,
            cwe=cwe,
            severity=severity,
            cvss=cvss,
            description=description,
            file_path=file_path,
            line=line,
            evidence=kwargs.get("evidence", kwargs.get("snippet", "")),
            remediation=remediation,
            references=kwargs.get("references", [
                "https://cwe.mitre.org/data/definitions/%d.html" % cwe,
            ]),
        )
        self._findings.append(finding)
        return finding

    def add_findings(self, findings: list[dict[str, Any]]) -> int:
        count = 0
        for f in findings:
            cwe = f.get("cwe", 0)
            if isinstance(cwe, str):
                m = re.search(r"(\d+)", str(cwe))
                cwe = int(m.group(1)) if m else 0
            if cwe <= 0:
                continue
            self.add_finding(
                cwe=cwe,
                file_path=f.get("file_path", f.get("path", "")),
                line=f.get("line", 0),
                evidence=f.get("snippet", f.get("evidence", "")),
                description=f.get("message", ""),
            )
            count += 1
        return count

    def add_chains(self, chains: list[dict[str, Any]]) -> None:
        self._chains.extend(chains)

    def add_dep_vulns(self, dep_vulns: list[dict[str, Any]]) -> None:
        self._dep_vulns.extend(dep_vulns)

    def generate(self) -> PentestReport:
        return PentestReport(
            meta=self._meta,
            findings=self._findings,
            chains=self._chains,
            dep_vulns=self._dep_vulns,
        )

    @property
    def finding_count(self) -> int:
        return len(self._findings)


def from_findings(findings: list[dict[str, Any]],
                  target: str = "") -> PentestReport:
    gen = ReportGen(target=target)
    gen.add_findings(findings)
    return gen.generate()
