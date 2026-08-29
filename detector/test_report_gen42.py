#!/usr/bin/env python3
"""Tests for report_gen42.py — Pentest report generator."""
import unittest

from report_gen42 import (
    Severity, FindingStatus, ReportFinding, ReportMeta, PentestReport,
    ReportGen, severity_from_cvss, from_findings,
    CWE_TITLE, CWE_REMEDIATION, CWE_CVSS_BASE, VERSION,
)


class TestConstants(unittest.TestCase):
    def test_version(self):
        self.assertEqual(VERSION, "4.2")

    def test_cwe_titles(self):
        self.assertGreater(len(CWE_TITLE), 20)
        self.assertEqual(CWE_TITLE[89], "SQL Injection")

    def test_cwe_remediation(self):
        self.assertGreater(len(CWE_REMEDIATION), 20)
        self.assertIn("parameterized", CWE_REMEDIATION[89])

    def test_cwe_cvss(self):
        self.assertGreater(len(CWE_CVSS_BASE), 20)
        self.assertGreater(CWE_CVSS_BASE[89], 7.0)


class TestSeverityFromCvss(unittest.TestCase):
    def test_critical(self):
        self.assertEqual(severity_from_cvss(9.8), Severity.CRITICAL)

    def test_high(self):
        self.assertEqual(severity_from_cvss(7.5), Severity.HIGH)

    def test_medium(self):
        self.assertEqual(severity_from_cvss(5.0), Severity.MEDIUM)

    def test_low(self):
        self.assertEqual(severity_from_cvss(2.0), Severity.LOW)

    def test_info(self):
        self.assertEqual(severity_from_cvss(0.0), Severity.INFO)


class TestReportFinding(unittest.TestCase):
    def test_owasp_category(self):
        f = ReportFinding(
            finding_id="T-001", title="SQLi", cwe=89,
            severity=Severity.HIGH, cvss=8.6,
            description="test", file_path="a.py", line=1)
        self.assertIn("Injection", f.owasp_category)

    def test_unknown_owasp(self):
        f = ReportFinding(
            finding_id="T-002", title="X", cwe=9999,
            severity=Severity.LOW, cvss=2.0,
            description="test", file_path="a.py", line=1)
        self.assertEqual(f.owasp_category, "Other")


class TestReportMeta(unittest.TestCase):
    def test_auto_date(self):
        m = ReportMeta()
        self.assertRegex(m.date, r"\d{4}-\d{2}-\d{2}")

    def test_tester(self):
        m = ReportMeta()
        self.assertIn("Owen", m.tester)


class TestPentestReport(unittest.TestCase):
    def _make_report(self):
        gen = ReportGen(target="TestApp")
        gen.add_finding(89, "app.py", 10)
        gen.add_finding(78, "util.py", 25)
        gen.add_finding(614, "auth.py", 5)
        return gen.generate()

    def test_report_id(self):
        r = self._make_report()
        self.assertEqual(len(r.report_id), 12)

    def test_severity_counts(self):
        r = self._make_report()
        counts = r.severity_counts()
        total = sum(counts.values())
        self.assertEqual(total, 3)

    def test_risk_score(self):
        r = self._make_report()
        self.assertGreater(r.risk_score(), 0)
        self.assertLessEqual(r.risk_score(), 100)

    def test_risk_rating(self):
        r = self._make_report()
        self.assertIn(r.risk_rating(),
                      ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"))

    def test_executive_summary(self):
        r = self._make_report()
        s = r.executive_summary()
        self.assertIn("Executive Summary", s)
        self.assertIn("TestApp", s)
        self.assertIn("Risk Rating", s)

    def test_markdown(self):
        r = self._make_report()
        md = r.markdown()
        self.assertIn("# Penetration Test Report", md)
        self.assertIn("SQL Injection", md)
        self.assertIn("Command Injection", md)
        self.assertIn("CWE-89", md)
        self.assertIn("Remediation", md)
        self.assertIn("Owen Attestor", md)

    def test_empty_report(self):
        r = PentestReport(meta=ReportMeta(), findings=[])
        md = r.markdown()
        self.assertIn("Penetration Test Report", md)
        self.assertEqual(r.risk_score(), 0.0)

    def test_chains_in_report(self):
        gen = ReportGen(target="App")
        gen.add_finding(89, "a.py", 1)
        gen.add_chains([{
            "cvss": 9.5, "impact": "RCE", "steps": [
                {"cwe": 89, "file": "a.py", "line": 1, "description": "SQLi"},
                {"cwe": 78, "file": "b.py", "line": 2, "description": "CMDi"},
            ]
        }])
        r = gen.generate()
        md = r.markdown()
        self.assertIn("Exploit Chains", md)
        self.assertIn("Chain 1", md)

    def test_dep_vulns_in_report(self):
        gen = ReportGen(target="App")
        gen.add_finding(89, "a.py", 1)
        gen.add_dep_vulns([{
            "cve": "CVE-2021-44228", "package": "log4j-core",
            "version": "2.14.1", "severity": "CRITICAL",
            "cvss": 10.0, "fixed_version": "2.17.0",
        }])
        r = gen.generate()
        md = r.markdown()
        self.assertIn("Dependency Vulnerabilities", md)
        self.assertIn("CVE-2021-44228", md)


class TestReportGen(unittest.TestCase):
    def test_add_finding(self):
        gen = ReportGen()
        f = gen.add_finding(89, "app.py", 10)
        self.assertEqual(gen.finding_count, 1)
        self.assertEqual(f.cwe, 89)
        self.assertIn("OWEN-", f.finding_id)

    def test_add_findings_from_dicts(self):
        gen = ReportGen()
        count = gen.add_findings([
            {"cwe": 89, "file_path": "a.py", "line": 1},
            {"cwe": 78, "file_path": "b.py", "line": 2},
        ])
        self.assertEqual(count, 2)
        self.assertEqual(gen.finding_count, 2)

    def test_add_findings_skips_invalid(self):
        gen = ReportGen()
        count = gen.add_findings([
            {"cwe": 0}, {"rule": "x"},
        ])
        self.assertEqual(count, 0)

    def test_cwe_string_parsing(self):
        gen = ReportGen()
        f = gen.add_finding("CWE-89", "a.py", 1)
        self.assertEqual(f.cwe, 89)

    def test_auto_remediation(self):
        gen = ReportGen()
        f = gen.add_finding(89, "a.py", 1)
        self.assertIn("parameterized", f.remediation)

    def test_auto_severity(self):
        gen = ReportGen()
        f = gen.add_finding(78, "a.py", 1)
        self.assertEqual(f.severity, Severity.CRITICAL)


class TestFromFindings(unittest.TestCase):
    def test_basic(self):
        report = from_findings([
            {"cwe": 89, "file_path": "a.py", "line": 1},
        ], target="MyApp")
        self.assertEqual(len(report.findings), 1)
        self.assertIn("MyApp", report.markdown())

    def test_empty(self):
        report = from_findings([])
        self.assertEqual(len(report.findings), 0)


if __name__ == "__main__":
    unittest.main()
