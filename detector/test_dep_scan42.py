#!/usr/bin/env python3
"""Tests for dep_scan42.py — Dependency CVE scanner."""
import unittest

from dep_scan42 import (
    Dependency, Advisory, VulnMatch, Ecosystem, RiskLevel,
    DepScanner, parse_requirements_txt, parse_package_json,
    parse_gemfile, parse_go_mod, parse_cargo_toml, parse_pom_xml,
    parse_csproj, parse_composer_json,
    parse_version, version_lt, version_in_range,
    ADVISORY_DB, VERSION,
)


class TestConstants(unittest.TestCase):
    def test_version(self):
        self.assertEqual(VERSION, "4.2")

    def test_advisory_db_not_empty(self):
        self.assertGreater(len(ADVISORY_DB), 30)

    def test_advisories_have_cve_ids(self):
        for adv in ADVISORY_DB:
            self.assertTrue(adv.cve_id.startswith("CVE-"), adv.cve_id)


class TestVersionParsing(unittest.TestCase):
    def test_simple(self):
        self.assertEqual(parse_version("1.2.3"), (1, 2, 3))

    def test_prefix_stripped(self):
        self.assertEqual(parse_version("v1.2.3"), (1, 2, 3))
        self.assertEqual(parse_version("^1.2.3"), (1, 2, 3))
        self.assertEqual(parse_version("~1.2.3"), (1, 2, 3))
        self.assertEqual(parse_version(">=1.2.3"), (1, 2, 3))

    def test_version_lt(self):
        self.assertTrue(version_lt("1.0.0", "2.0.0"))
        self.assertFalse(version_lt("2.0.0", "1.0.0"))
        self.assertFalse(version_lt("1.0.0", "1.0.0"))

    def test_version_in_range_less_than(self):
        self.assertTrue(version_in_range("1.0.0", "< 2.0.0"))
        self.assertFalse(version_in_range("3.0.0", "< 2.0.0"))

    def test_version_in_range_compound(self):
        self.assertTrue(version_in_range("1.5.0", ">= 1.0.0, < 2.0.0"))
        self.assertFalse(version_in_range("0.5.0", ">= 1.0.0, < 2.0.0"))

    def test_version_in_range_dash(self):
        self.assertTrue(version_in_range("1.5.0", "1.0.0 - 2.0.0"))
        self.assertFalse(version_in_range("3.0.0", "1.0.0 - 2.0.0"))

    def test_version_in_range_star(self):
        self.assertTrue(version_in_range("999.0.0", "*"))


class TestParsers(unittest.TestCase):
    def test_requirements_txt(self):
        content = "flask==2.0.1\nrequests>=2.25.0\ndjango\n# comment\n"
        deps = parse_requirements_txt(content, "requirements.txt")
        self.assertEqual(len(deps), 3)
        self.assertEqual(deps[0].name, "flask")
        self.assertEqual(deps[0].version, "2.0.1")
        self.assertEqual(deps[2].version, "*")

    def test_package_json(self):
        content = '{"dependencies":{"axios":"^0.21.1"},"devDependencies":{"jest":"^27.0.0"}}'
        deps = parse_package_json(content, "package.json")
        self.assertEqual(len(deps), 2)
        self.assertFalse(deps[0].is_dev)
        self.assertTrue(deps[1].is_dev)

    def test_package_json_invalid(self):
        deps = parse_package_json("not json", "package.json")
        self.assertEqual(deps, [])

    def test_gemfile(self):
        content = "gem 'rails', '~> 6.1'\ngem 'puma'\n"
        deps = parse_gemfile(content, "Gemfile")
        self.assertEqual(len(deps), 2)
        self.assertEqual(deps[0].name, "rails")
        self.assertEqual(deps[1].version, "*")

    def test_go_mod(self):
        content = (
            "module example.com/app\n\n"
            "require (\n"
            "\tgolang.org/x/text v0.3.6\n"
            "\tgolang.org/x/net v0.3.0\n"
            ")\n"
        )
        deps = parse_go_mod(content, "go.mod")
        self.assertEqual(len(deps), 2)
        self.assertEqual(deps[0].version, "0.3.6")

    def test_cargo_toml(self):
        content = (
            "[dependencies]\n"
            'serde = "1.0.130"\n'
            'tokio = "1.12.0"\n'
        )
        deps = parse_cargo_toml(content, "Cargo.toml")
        self.assertEqual(len(deps), 2)

    def test_pom_xml(self):
        content = (
            "<dependencies>\n"
            "  <dependency>\n"
            "    <groupId>org.apache.logging.log4j</groupId>\n"
            "    <artifactId>log4j-core</artifactId>\n"
            "    <version>2.14.1</version>\n"
            "  </dependency>\n"
            "</dependencies>\n"
        )
        deps = parse_pom_xml(content, "pom.xml")
        self.assertEqual(len(deps), 1)
        self.assertIn("log4j-core", deps[0].name)
        self.assertEqual(deps[0].version, "2.14.1")

    def test_csproj(self):
        content = '<PackageReference Include="Newtonsoft.Json" Version="13.0.1" />\n'
        deps = parse_csproj(content, "app.csproj")
        self.assertEqual(len(deps), 1)
        self.assertEqual(deps[0].ecosystem, Ecosystem.DOTNET)

    def test_composer_json(self):
        content = '{"require":{"monolog/monolog":"^2.0"},"require-dev":{"phpunit/phpunit":"^9.0"}}'
        deps = parse_composer_json(content, "composer.json")
        self.assertEqual(len(deps), 2)
        self.assertEqual(deps[0].ecosystem, Ecosystem.PHP)


class TestDepScanner(unittest.TestCase):
    def test_scan_content_requirements(self):
        s = DepScanner()
        deps = s.scan_content("requests==2.25.0\n", "requirements.txt")
        self.assertEqual(len(deps), 1)
        self.assertEqual(s.dependencies[0].name, "requests")

    def test_scan_content_package_json_with_vuln(self):
        s = DepScanner()
        s.scan_content('{"dependencies":{"lodash":"4.17.10"}}', "package.json")
        vulns = s.check()
        vuln_cves = [v.advisory.cve_id for v in vulns]
        self.assertIn("CVE-2019-10744", vuln_cves)

    def test_scan_content_log4j(self):
        pom = (
            "<dependency>"
            "<groupId>org.apache.logging.log4j</groupId>"
            "<artifactId>log4j-core</artifactId>"
            "<version>2.14.1</version>"
            "</dependency>"
        )
        s = DepScanner()
        s.scan_content(pom, "pom.xml")
        vulns = s.check()
        cves = [v.advisory.cve_id for v in vulns]
        self.assertIn("CVE-2021-44228", cves)

    def test_no_vulns_for_patched(self):
        s = DepScanner()
        s.scan_content('{"dependencies":{"lodash":"4.17.21"}}', "package.json")
        vulns = s.check()
        self.assertEqual(len(vulns), 0)

    def test_report_format(self):
        s = DepScanner()
        s.scan_content("requests==2.25.0\njinja2==2.10\n", "requirements.txt")
        s.check()
        report = s.report()
        self.assertIn("Dependency CVE Scan", report)
        self.assertIn("Dependencies found: 2", report)

    def test_as_findings(self):
        s = DepScanner()
        s.scan_content("jinja2==2.10\n", "requirements.txt")
        s.check()
        findings = s.as_findings()
        self.assertGreater(len(findings), 0)
        self.assertIn("cve", findings[0])
        self.assertIn("package", findings[0])

    def test_upgrade_action(self):
        dep = Dependency("lodash", "4.17.10", Ecosystem.JAVASCRIPT)
        adv = Advisory("CVE-2021-23337", "lodash", Ecosystem.JAVASCRIPT,
                       "< 4.17.21", "4.17.21", RiskLevel.HIGH, 7.2,
                       "Prototype pollution")
        vm = VulnMatch(dependency=dep, advisory=adv)
        self.assertIn("4.17.21", vm.upgrade_action)

    def test_unfixable(self):
        dep = Dependency("badlib", "1.0.0", Ecosystem.PYTHON)
        adv = Advisory("CVE-9999-0001", "badlib", Ecosystem.PYTHON,
                       "< 999.0", "", RiskLevel.HIGH, 7.0,
                       "No fix")
        vm = VulnMatch(dependency=dep, advisory=adv, is_fixable=False)
        self.assertIn("replacing", vm.upgrade_action)

    def test_unknown_manifest(self):
        s = DepScanner()
        deps = s.scan_content("hello world", "random.txt")
        self.assertEqual(deps, [])


class TestDependency(unittest.TestCase):
    def test_key(self):
        d = Dependency("Flask", "2.0.1", Ecosystem.PYTHON)
        self.assertEqual(d.key, "python:flask")


class TestAdvisory(unittest.TestCase):
    def test_key(self):
        a = ADVISORY_DB[0]
        self.assertIn(":", a.key)


if __name__ == "__main__":
    unittest.main()
