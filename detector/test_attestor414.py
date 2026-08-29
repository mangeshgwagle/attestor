from __future__ import annotations

import copy
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import attestor414
import truth_guard41
import variant414


class Attestor414Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        (cls.root / "app.py").write_text(
            "def calculate(value):\n"
            "    return eval(value)\n",
            encoding="utf-8",
        )
        (cls.root / "requirements.txt").write_text(
            "example-package==1.0\n", encoding="utf-8")
        cls.reports = {
            slug: attestor414.maximum(cls.root, variant=slug)
            for slug in variant414.PROFILE_SLUGS
        }

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def test_all_three_profiles_are_exact_verified_and_effective(self) -> None:
        for slug, report in self.reports.items():
            with self.subTest(slug=slug):
                profile = variant414.profile_for_slug(slug)
                self.assertEqual(report["schema"], attestor414.SCHEMA)
                self.assertEqual(report["version"], attestor414.VERSION)
                self.assertEqual(
                    report["variant_414"]["selected_profile"]["display_name"],
                    profile.display_name,
                )
                self.assertEqual(
                    report["analyzer"]["variant_profile_sha256"],
                    variant414.profile_identity(profile),
                )
                language = variant414.response_language_metadata(profile)
                self.assertEqual(
                    report["analyzer"]["response_language_414"],
                    language,
                )
                self.assertEqual(
                    report["response_414"]["language"],
                    language,
                )
                self.assertTrue(
                    attestor414.verify_report(report, root=self.root)[0],
                    attestor414.verify_report(report, root=self.root)[1],
                )

    def test_api_is_exact_while_the_cli_parser_keeps_aliases(self) -> None:
        self.assertIs(
            variant414.parse_profile("CJP"),
            variant414.COCKROACH_JANTA_PARTY,
        )
        for value in ("CJP", "South Park", "south park", "SOUTH-PARK", " sp "):
            with self.subTest(value=value), self.assertRaises(
                    attestor414.Attestor414Error):
                attestor414.maximum(self.root, variant=value)
        with self.assertRaises(attestor414.Attestor414Error):
            attestor414.maximum(
                self.root,
                variant="south-park",
                variant_profile=variant414.SOUTH_PARK,
            )

    def test_default_is_balanced_south_park(self) -> None:
        report = attestor414.maximum(self.root)
        self.assertEqual(
            report["variant_414"]["selected_profile"]["slug"],
            "south-park",
        )

    def test_light_profile_omissions_are_explicit_not_silent(self) -> None:
        report = self.reports["gruppe-sechs"]
        gaps = "\n".join(report["coverage"]["gaps"])
        self.assertIn("attack-static-413 omitted", gaps)
        self.assertIn("posture-static-413 omitted", gaps)
        self.assertFalse(report["coverage"]["complete"])
        effective = report["analysis_config"]["variant_effective_policy"]
        self.assertEqual(
            effective["selected_worker_actions"],
            ["coding-static", "security-static"],
        )

    def test_adjudication_preserves_uncertainty_and_plans_no_commands(self) -> None:
        report = self.reports["south-park"]
        adjudication = report["adjudication_414"]
        self.assertTrue(adjudication["findings"])
        self.assertEqual(
            adjudication["summary"]["findings"],
            len(report["findings"]),
        )
        self.assertEqual(adjudication["summary"]["supported"], 0)
        self.assertGreater(adjudication["summary"]["insufficient"], 0)
        self.assertFalse(
            report["adjudication_scope_414"][
                "source_binding_alone_counted_as_diagnostic_proof"
            ]
        )
        plan = report["validation_opportunities_414"]
        self.assertTrue(plan["opportunities"])
        self.assertFalse(plan["execution"]["commands_generated"])
        self.assertFalse(plan["execution"]["target_code_executed"])
        self.assertTrue(all(
            row["authorization_required"] is True and
            row["executed"] is False and
            row["commands_generated"] is False
            for row in plan["opportunities"]
        ))

    def test_improvement_delivery_never_claims_static_output_is_verified(self) -> None:
        delivery = self.reports["cockroach-janta-party"][
            "improvement_delivery_414"]
        self.assertFalse(delivery["automatic_apply"])
        self.assertTrue(delivery["review_required"])
        self.assertIn("scanner, build, and test", delivery["limitation"])

    def test_variant_config_and_adjudication_tampering_are_withheld(self) -> None:
        original = self.reports["south-park"]
        for mutate in (
            lambda value: value["analysis_config"].__setitem__(
                "version", "forged"),
            lambda value: value["adjudication_414"]["summary"].__setitem__(
                "supported", 999),
            lambda value: value["variant_finding_boundary_414"].__setitem__(
                "finding_limit", 12_000),
        ):
            tampered = copy.deepcopy(original)
            mutate(tampered)
            self.assertFalse(
                attestor414.verify_report(tampered, root=self.root)[0])
            safe = attestor414.safe_public_report(
                tampered, root=self.root)
            self.assertEqual(safe["status"], "inconsistent")
            self.assertNotIn("variant_414", safe)
            self.assertEqual(
                safe["variant_status_414"], "withheld-unverified")

    def test_re_guarded_derived_forgery_still_fails_semantic_replay(self) -> None:
        forged = copy.deepcopy(self.reports["south-park"])
        forged.pop("truth_guard3")
        delivery = forged["improvement_delivery_414"]
        delivery["automatic_apply"] = True
        delivery["report_sha256"] = attestor414._sha({
            key: value for key, value in delivery.items()
            if key != "report_sha256"
        })
        forged = truth_guard41.guard_document(
            forged,
            root=self.root,
            config=forged["analysis_config"],
            analyzer=forged["analyzer"],
        )
        valid, errors = attestor414.verify_report(
            forged, root=self.root)
        self.assertFalse(valid)
        self.assertIn("improvement delivery is invalid", errors)

    def test_render_and_sarif_use_only_the_verified_variant(self) -> None:
        report = self.reports["south-park"]
        rendered = attestor414.render(report, root=self.root)
        self.assertIn("Attestor 4.1.4 — South Park", rendered)
        self.assertIn("Adjudication:", rendered)
        sarif = attestor414.to_sarif(report, root=self.root)
        run = sarif["runs"][0]
        self.assertEqual(
            run["tool"]["driver"]["semanticVersion"], "4.1.4")
        self.assertEqual(
            run["properties"]["attestorVariantSlug"], "south-park")
        self.assertTrue(run["properties"]["attestorVariantVerified"])
        self.assertEqual(
            run["properties"]["attestorResponseLanguageTier"], "existing")

        tampered = copy.deepcopy(report)
        tampered["analyzer"]["variant_slug"] = "gruppe-sechs"
        withheld = attestor414.render(tampered, root=self.root)
        self.assertIn("variant identity withheld", withheld)
        self.assertNotIn("Attestor 4.1.4 — South Park", withheld)

    def test_c3_language_is_verified_maximum_only_across_outputs(self) -> None:
        maximum = self.reports["cockroach-janta-party"]
        rendered = attestor414.render(maximum, root=self.root)
        self.assertIn(
            "Response language: C3 (Attestor-specific; not CEFR).",
            rendered,
        )
        for slug in ("south-park", "gruppe-sechs"):
            with self.subTest(slug=slug):
                self.assertNotIn(
                    "Response language: C3",
                    attestor414.render(self.reports[slug], root=self.root),
                )

        answer = attestor414.answer(
            maximum, "How many findings?", root=self.root)
        self.assertTrue(answer["response_language"]["verified"])
        self.assertEqual(answer["response_language"]["tier"], "C3")
        self.assertFalse(
            answer["response_language"]["official_cefr_claim"])
        self.assertEqual(
            answer["response_language"]["profile_sha256"],
            variant414.profile_identity(
                variant414.COCKROACH_JANTA_PARTY),
        )

        sarif = attestor414.to_sarif(maximum, root=self.root)
        properties = sarif["runs"][0]["properties"]
        self.assertEqual(properties["attestorResponseLanguageTier"], "C3")
        self.assertTrue(
            properties["attestorResponseLanguageAttestorSpecific"])
        self.assertFalse(
            properties["attestorResponseLanguageOfficialCefrClaim"])

    def test_reguarded_response_language_spoof_is_rejected(self) -> None:
        forged = copy.deepcopy(self.reports["south-park"])
        forged.pop("truth_guard3")
        forged["response_414"]["language"] = (
            variant414.response_language_metadata(
                variant414.COCKROACH_JANTA_PARTY)
        )
        forged["response_414"]["language_sha256"] = attestor414._sha(
            forged["response_414"]["language"])
        forged = truth_guard41.guard_document(
            forged,
            root=self.root,
            config=forged["analysis_config"],
            analyzer=forged["analyzer"],
        )
        valid, errors = attestor414.verify_report(
            forged, root=self.root)
        self.assertFalse(valid)
        self.assertIn(
            "profile-bound response language is invalid", errors)

    def test_profile_finding_boundary_commits_every_omission(self) -> None:
        rows = [{
            "rule": "R",
            "severity": "LOW",
            "path": "app.py",
            "line": 1,
            "message": str(index),
            "fix": "review",
            "fingerprint": ("%064x" % index)[-64:],
        } for index in range(
            variant414.GRUPPE_SECHS.max_findings + 1)]
        report = {
            "findings": rows,
            "summary": {
                "findings_before_public_boundary": len(rows),
            },
            "coverage": {
                "gaps": [],
                "complete": True,
                "completed_components": [],
            },
        }
        attestor414._apply_profile_finding_boundary(
            report, variant414.GRUPPE_SECHS)
        boundary = report["variant_finding_boundary_414"]
        self.assertEqual(
            len(report["findings"]),
            variant414.GRUPPE_SECHS.max_findings,
        )
        self.assertEqual(boundary["profile_omitted_findings"], 1)
        self.assertRegex(
            boundary["omitted_findings_sha256"], r"^[0-9a-f]{64}$")
        self.assertFalse(report["coverage"]["complete"])

    def test_source_change_makes_the_report_stale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "small.py"
            source.write_text("answer = 41\n", encoding="utf-8")
            report = attestor414.maximum(root, variant="gruppe-sechs")
            self.assertTrue(attestor414.verify_report(report, root=root)[0])
            source.write_text("answer = 42\n", encoding="utf-8")
            valid, errors = attestor414.verify_report(report, root=root)
            self.assertFalse(valid)
            self.assertIn("stale", " ".join(errors))

    def test_authenticated_report_requires_the_same_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "small.py").write_text(
                "answer = 42\n", encoding="utf-8")
            key = b"k" * 32
            report = attestor414.maximum(
                root,
                variant="gruppe-sechs",
                truth_key=key,
                truth_key_id="attestor414-test",
            )
            self.assertTrue(
                attestor414.verify_report(
                    report, root=root, truth_key=key)[0])
            self.assertFalse(
                attestor414.verify_report(
                    report, root=root, truth_key=b"x" * 32)[0])

    def test_json_round_trip_retains_verification(self) -> None:
        report = json.loads(json.dumps(
            self.reports["cockroach-janta-party"]))
        self.assertTrue(
            attestor414.verify_report(report, root=self.root)[0])

    def test_cli_json_failure_is_parseable_and_discloses_no_traceback(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
                attestor414, "maximum",
                side_effect=attestor414.Attestor414Error(
                    "sensitive internal failure detail")), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = attestor414.main([
                str(self.root), "--variant", "cockroach-janta-party",
                "--format", "json",
            ])
        self.assertEqual(code, 2)
        failure = json.loads(stdout.getvalue())
        self.assertEqual(failure["status"], "failed")
        self.assertEqual(failure["error"]["type"], "Attestor414Error")
        self.assertFalse(failure["error"]["traceback_disclosed"])
        combined = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn("Traceback", combined)
        self.assertNotIn("sensitive internal failure detail", combined)

    def test_cli_text_failure_uses_stderr_without_traceback(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
                attestor414, "maximum",
                side_effect=attestor414.Attestor414Error("private detail")), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = attestor414.main([
                str(self.root), "--variant", "cockroach-janta-party",
                "--format", "text",
            ])
        self.assertEqual(code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn(
            "Attestor 4.1.4 failed safely: Attestor414Error",
            stderr.getvalue())
        self.assertNotIn("private detail", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())

    def test_cli_failure_output_write_error_falls_back_visibly(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(
                    attestor414, "maximum",
                    side_effect=attestor414.Attestor414Error("private detail")), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            code = attestor414.main([
                str(self.root), "--variant", "cockroach-janta-party",
                "--format", "json", "--out", directory,
            ])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout.getvalue())["status"], "failed")
        self.assertIn(
            "failure report could not be written", stderr.getvalue())
        self.assertNotIn("private detail", stderr.getvalue())
        self.assertNotIn("Traceback", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
