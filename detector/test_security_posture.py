from __future__ import annotations

import json
from datetime import date, timedelta
from pathlib import Path
import tempfile
import unittest

import security_posture


class SecurityPostureTests(unittest.TestCase):
    def test_file_scope_excludes_siblings_but_directory_scope_includes_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.py"
            target.write_text("value = 1\n", encoding="utf-8")
            sibling = root / "sibling.py"
            sibling.write_text(
                "AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE'\n", encoding="utf-8")

            file_report = security_posture.assess(target, jobs=1, use_cache=False)
            directory_report = security_posture.assess(root, jobs=1, use_cache=False)

        self.assertEqual(file_report["root"], str(target.resolve()))
        self.assertEqual(file_report["coverage"]["scope_kind"], "file")
        self.assertEqual(file_report["summary"]["files_scanned"], 1)
        self.assertEqual(file_report["coverage"]["files_discovered"], 1)
        self.assertNotIn("sibling.py", json.dumps(file_report))
        self.assertEqual(directory_report["summary"]["files_scanned"], 2)
        self.assertTrue(any(row["path"] == "sibling.py" and row["rule"] == "hardcoded-secret"
                            for row in directory_report["findings"]))

    def test_fuses_advanced_rules_inventory_and_taxonomy_without_secret_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.php").write_text("<?php eval($source);\n", encoding="utf-8")
            (root / "main.tf").write_text("publicly_accessible = true\n", encoding="utf-8")
            (root / "requirements.txt").write_text("requests==2.32.0\n", encoding="utf-8")
            secret = "sk_live_DO_NOT_ECHO_12345678901234567890"
            (root / ".env").write_text("API_KEY=" + secret + "\n", encoding="utf-8")
            report = security_posture.assess(tmp, jobs=2, use_cache=False)
        rules = {row["rule"] for row in report["findings"]}
        self.assertIn("adv-php-eval", rules)
        self.assertIn("adv-tf-rds-public", rules)
        self.assertGreaterEqual(report["risk"]["score"], 1)
        self.assertEqual(len(report["dependency_inventory"]["dependencies"]), 1)
        rendered = json.dumps(report)
        self.assertNotIn(secret, rendered)
        self.assertTrue(report["assurance_notes"])
        self.assertEqual(report["coverage"]["precision_flow_rules"], 15_000)
        # 15,000 precision-flow rules plus the explicit detector catalog.
        # Bumped by one for py-os-command-injection: os.system/os.popen build a
        # shell command the same way subprocess(shell=True) does and had no
        # Python rule at all -- command-exec only ever covered C/C++.
        # Bumped by five more for the pointer-lifetime rules written against
        # the Juliet CWE-416 and CWE-476 families, both of which the catalog
        # was completely silent on before: c-use-after-free, c-null-deref,
        # c-null-guard-bitwise, c-deref-after-null-check, c-null-check-after-deref.
        # Bumped by three more for the buffer-overflow rules written against the
        # CWE-121/122 families: c-stack-buffer-overflow, c-heap-buffer-overflow,
        # c-struct-member-overrun.  The first two are one analysis split by where
        # the destination lives, because that is what separates the two Top-25
        # classes -- reporting both as the parent CWE-787 would lose them.
        # Bumped by two more for py-route-missing-authorization (CWE-862,
        # rank 4) and py-route-missing-authentication (CWE-306, rank 21).
        # Juliet has no case for either -- it is C/C++ memory safety and never
        # covers web authorisation -- so those two were written from shapes a
        # local model generated to a specification we controlled, and are
        # measured on their negatives rather than on that corpus.
        # Bumped by two more for py-upload-unrestricted (CWE-434, rank 12)
        # and py-unbounded-read (CWE-770, rank 25), written from shapes the
        # local model generated to specification. No CWE-639 rule was added:
        # it is structurally the same defect py-route-missing-authorization
        # already reports, and a near-duplicate written to claim a Top-25 box
        # would be gaming the coverage metric rather than improving detection.
        # Bumped by two more for the allocator-pairing rules,
        # c-mismatched-free (CWE-762) and c-free-not-on-heap (CWE-590).
        # A blind-spot audit found no rule fired on the flawed variant of
        # either class even once, across ~5,000 Juliet cases.
        # Bumped by one for c-command-injection (CWE-78). The pre-existing
        # command-exec reports the presence of a shell, which is true of
        # correct code too; this one tracks taint to the sink, so it separates
        # a fixed program from an attacker-supplied one. Measured on a
        # held-out split: 0% -> 53.5% of CWE-78, with no false positives.
        # Bumped by one more for c-integer-overflow (CWE-190). Both variants
        # of a real case perform the same arithmetic; only the corrected one
        # bounds its operands first, so the guard is the entire discriminator.
        # Held out: 0% -> 58.5% of CWE-190, and 0% -> 50.5% of CWE-191 from
        # the same rule, since underflow is the same shape. No false positives
        # in either class.
        # And one more for c-path-traversal (CWE-23/36), which reuses the
        # command-injection taint walk unchanged -- same sources, same literal
        # assignment as the fix, different sink. Held out: 0% -> 85.7% of
        # CWE-23 and 0% -> 71.2% of CWE-36, no false positives in either.
        # The 4.1.5 source carries three additional explicit detector rules.
        # Keep this assertion exact so accidental inventory drift still fails.
        # 15,341 before six Java rules were added to detect.RULES; 15,348
        # after java-fixed-seed; 15,352 once LDAP, XPath, reflected XSS and
        # response splitting joined them. Five catalogues, not one:
        # detect.RULES (124 -- plus the bounds/arithmetic family:
        # array-index, divide-by-zero, integer-overflow, covering 20,171
        # Juliet files that had no rule at all, java-unbounded-allocation
        # for CWE-789's 2,553 and java-unbounded-loop for CWE-400's 2,412 --
        # and CWE-134/23/36/470/15 via format-string, path-traversal,
        # unsafe-reflection and external-config -- 24 of 112 Java
        # families now. Ten more pattern rules took the crypto, comment,
        # exception and obsolete-API families to 35 of 112 and 92.2%
        # of the corpus. No rule was added for CWE-379/378: the one
        # written fired on both halves of every pair and was deleted.
        # py-return-in-finally replaces the
        # unusable adv-py-return-finally), nativescan (24), multilang (23),
        # advanced_rules (202) and precision_catalog (15,000).
        # +10 for the Go/Rust/C# packs. Twenty rules were written and ten
        # registered: the rest -- weak hashes, InsecureSkipVerify,
        # BinaryFormatter, transmute -- already existed in multilang and
        # advanced_rules, and a second copy in detect.RULES would double-report
        # every one of them rather than cover anything new.
        # +9 for the assembly packs: five x86-64 rules and four IBM High
        # Level Assembler rules. HLASM is the first mainframe dialect in the
        # catalog and shares no masking with anything else -- it is column-
        # sensitive, and `*` is both a comment marker and multiplication.
        self.assertEqual(report["coverage"]["total_explicit_rules"], 15_407)

        # Weakness classes the catalog cannot express are named, not implied.
        top25 = report["coverage"]["cwe_top25"]
        self.assertEqual(top25["taxonomy"], "CWE Top 25:2025")
        self.assertEqual(top25["classes"], 25)
        self.assertEqual(top25["with_rules"] + top25["without_rules"], 25)
        self.assertEqual(len(top25["covered"]), top25["with_rules"])
        self.assertEqual(len(top25["uncovered"]), top25["without_rules"])
        self.assertTrue(top25["with_rules"], "no Top-25 class is claimed at all")
        self.assertTrue(top25["uncovered"], "coverage is not yet complete")
        listed = [row["cwe"] for row in top25["covered"]] + \
                 [row["cwe"] for row in top25["uncovered"]]
        self.assertEqual(len(set(listed)), 25)
        for row in top25["uncovered"]:
            self.assertIn("rank", row)
        # The report must not let a gap read as a clean result.
        self.assertTrue(any("says nothing about it" in line
                            for line in top25["limitations"]))
        self.assertNotIn(secret, json.dumps(top25))

    def test_sarif_and_markdown_are_actionable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "app.js"
            path.write_text("child_process.exec(command);\n", encoding="utf-8")
            report = security_posture.assess(tmp, jobs=1, use_cache=False)
        sarif = security_posture.to_sarif(report)
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])
        markdown = security_posture.render_markdown(report)
        self.assertIn("Fix first", markdown)
        self.assertIn("Coverage and honesty", markdown)

    def test_missing_workspace_fails_honestly(self):
        report = security_posture.assess("definitely-missing-attestor-workspace", use_cache=False)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["risk"]["label"], "unknown")

    def test_baseline_and_reasoned_expiring_suppression_remain_auditable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                "from flask import request\nimport os\n"
                "command = request.args.get('cmd')\nos.system(command)\n",
                encoding="utf-8")
            first = security_posture.assess(root, jobs=1, use_cache=False)
            fingerprint = first["findings"][0]["fingerprint"]
            baseline = root / "baseline.json"
            baseline.write_text(json.dumps(security_posture.baseline_document(first)), encoding="utf-8")
            suppressions = root / "suppressions.json"
            suppressions.write_text(json.dumps({
                "schema": "attestor-security-suppressions/1",
                "suppressions": [{"fingerprint": fingerprint,
                                  "reason": "Risk accepted under SEC-1234",
                                  "expires": (date.today() + timedelta(days=30)).isoformat()}],
            }), encoding="utf-8")
            report = security_posture.assess(root, jobs=1, use_cache=False,
                                              baseline_path=str(baseline),
                                              suppressions_path=str(suppressions))
        selected = next(row for row in report["findings"] if row["fingerprint"] == fingerprint)
        self.assertEqual(selected["baseline_state"], "unchanged")
        self.assertTrue(selected["suppressed"])
        self.assertEqual(report["governance"]["suppressions"]["matched"], 1)
        self.assertGreaterEqual(report["summary"]["suppressed_findings"], 1)
        sarif_result = next(row for row in security_posture.to_sarif(report)["runs"][0]["results"]
                            if row["partialFingerprints"]["attestorFindingFingerprint/v1"] == fingerprint)
        self.assertEqual(sarif_result["suppressions"][0]["status"], "accepted")

    def test_expired_and_invalid_suppressions_do_not_hide_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.js").write_text("child_process.exec(command);\n", encoding="utf-8")
            first = security_posture.assess(root, jobs=1, use_cache=False)
            fingerprint = first["findings"][0]["fingerprint"]
            policy = root / "suppressions.json"
            policy.write_text(json.dumps({"suppressions": [
                {"fingerprint": fingerprint, "reason": "Expired SEC-10 acceptance",
                 "expires": (date.today() - timedelta(days=1)).isoformat()},
                {"fingerprint": "bad", "reason": "too short", "expires": "never"},
            ]}), encoding="utf-8")
            report = security_posture.assess(root, jobs=1, use_cache=False,
                                              suppressions_path=str(policy))
        self.assertFalse(next(row for row in report["findings"]
                              if row["fingerprint"] == fingerprint)["suppressed"])
        governance = report["governance"]["suppressions"]
        self.assertEqual(governance["expired_count"], 1)
        self.assertEqual(governance["invalid_count"], 1)

    def test_versioned_taxonomy_reachability_and_stride_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text(
                "from flask import Flask, request\napp = Flask(__name__)\n"
                "@app.get('/run')\ndef run(command):\n    import os\n    os.system(command)\n",
                encoding="utf-8")
            report = security_posture.assess(root, jobs=1, use_cache=False)
        self.assertEqual(report["standards"]["primary_application_taxonomy"], "OWASP Top 10:2025")
        self.assertEqual(report["threat_model"]["method"], "STRIDE")
        self.assertTrue(report["threat_model"]["trust_boundaries"])
        self.assertTrue(all(isinstance(row.get("reachability"), dict) for row in report["findings"]))
        self.assertTrue(all("fingerprint" in row for row in report["findings"]))


if __name__ == "__main__":
    unittest.main()
