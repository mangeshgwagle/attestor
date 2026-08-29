#!/usr/bin/env python3
"""Tests for attestor_ui.py -- local HTML interface command routing."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import attestor_ui


class AttestorUiTests(unittest.TestCase):
    def assert_mode_args(self, mode, prompt, flag):
        args = attestor_ui.build_args(mode, prompt)
        self.assertIn(flag, args)
        self.assertIn("--", args)
        self.assertEqual(args[-1], prompt)

    def test_polyglot_mode_builds_superattestor_args(self):
        self.assert_mode_args("polyglot", "sample.c", "--polyglot")

    def test_sieve_mode_builds_superattestor_args(self):
        self.assert_mode_args("sieve", "write fibonacci", "--sieve")

    def test_codemax_mode_builds_superattestor_args(self):
        self.assert_mode_args("codemax", "sample.py", "--codemax")

    def test_attestor2_modes_build_superattestor_args(self):
        self.assert_mode_args("codepower", "sample.py", "--codepower")
        self.assert_mode_args("rarebugs", "sample.py", "--rarebugs")
        self.assert_mode_args("securitymax", ".", "--securitymax")
        self.assert_mode_args("attestor2", ".", "--attestor2")

    def test_known_versions_are_reported(self):
        versions = attestor_ui.available_versions()
        self.assertIn(attestor_ui.CURRENT_VERSION, versions)
        self.assertTrue(versions[attestor_ui.CURRENT_VERSION]["available"])
        self.assertEqual(
            versions[attestor_ui.CURRENT_VERSION]["detector"],
            str(attestor_ui.HERE))

    def test_unknown_version_is_rejected(self):
        result = attestor_ui.run_attestor("arena", "", version="../../Windows")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], 2)

    def test_darwin_limit_is_bounded(self):
        args = attestor_ui.build_args("darwin", "graphql", limit=-99)
        self.assertIn("--darwin", args)
        self.assertEqual(args[args.index("--limit") + 1], "1")
        self.assertEqual(args[-2:], ["search", "graphql"])

    def test_prompt_cannot_inject_cli_options(self):
        args = attestor_ui.build_args("cyber", "--out=C:/victim.txt")
        self.assertIn("--", args)
        self.assertGreater(args.index("--out=C:/victim.txt"), args.index("--"))

    def test_factory_count_is_bounded(self):
        with self.assertRaises(ValueError):
            attestor_ui.build_args("factory", "100000000")

    def test_loopback_guard(self):
        self.assertTrue(attestor_ui._loopback_host("127.0.0.1"))
        self.assertTrue(attestor_ui._loopback_host("::1"))
        self.assertFalse(attestor_ui._loopback_host("0.0.0.0"))

    def test_non_loopback_server_bind_is_always_rejected(self):
        with mock.patch.object(attestor_ui, "LimitedThreadingHTTPServer") as server:
            self.assertEqual(
                attestor_ui.main(["--host", "0.0.0.0", "--port", "0"]), 2)
            server.assert_not_called()

    def test_connection_slots_are_bounded_and_ownership_checked(self):
        server = object.__new__(attestor_ui.LimitedThreadingHTTPServer)
        server._maximum_connections = 1
        server._active_connections = 0
        server._connection_lock = attestor_ui.threading.Lock()
        self.assertTrue(server._take_connection_slot())
        self.assertFalse(server._take_connection_slot())
        server._return_connection_slot()
        self.assertTrue(server._take_connection_slot())
        server._return_connection_slot()
        with self.assertRaises(RuntimeError):
            server._return_connection_slot()

    def test_non_text_json_fields_fail_closed(self):
        with self.assertRaises(ValueError):
            attestor_ui.build_args(["cyber"], "sample.py")
        with self.assertRaises(ValueError):
            attestor_ui.build_args("cyber", {"path": "sample.py"})
        result = attestor_ui.run_attestor("arena", "", version={"bad": True})
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], 2)

    def test_mayhem_modes_and_response_style_are_routed(self):
        args = attestor_ui.build_args("mayhem", ".", response_style="direct")
        self.assertIn("--mayhem", args)
        self.assertEqual(args[args.index("--response-style") + 1], "direct")
        self.assertIn("mayhem", attestor_ui._capabilities(attestor_ui.HERE))
        with self.assertRaises(ValueError):
            attestor_ui.build_args("mayhem", ".", response_style="invented")

    def test_attestor41_and_compatibility_modes_are_routed_as_json(self):
        expected = {
            "attestor41": "--attestor414",
            "attestor40": "--attestor40", "attestor35": "--attestor35", "attestor3": "--attestor3",
            "improve": "--attestor414",
            "semantic": "--semantic",
            "supplychain": "--supply-chain", "repositorymemory": "--repository-memory",
        }
        for mode, flag in expected.items():
            with self.subTest(mode=mode):
                args = attestor_ui.build_args(mode, ".")
                self.assertIn(flag, args)
                self.assertEqual(args[args.index("--format") + 1], "json")
                self.assertGreater(args.index("."), args.index("--"))

    def test_escape_lab_is_current_no_input_and_not_a_variant_mode(self):
        args = attestor_ui.build_args("escapelab", "")
        self.assertIn("--escape-lab", args)
        self.assertEqual(args[args.index("--format") + 1], "json")
        self.assertNotIn("--", args)
        self.assertNotIn("--variant", args)
        self.assertIn("escapelab", attestor_ui.REPORT_MODES)
        self.assertIn("escapelab", attestor_ui._capabilities(attestor_ui.HERE))
        self.assertNotIn("escapelab", attestor_ui.VARIANT_MODES)
        with self.assertRaisesRegex(ValueError, "does not accept a prompt or path"):
            attestor_ui.build_args("escapelab", "C:/Windows")
        with self.assertRaisesRegex(ValueError, "only in Attestor 4.1.4"):
            attestor_ui.build_args("escapelab", "", version="Attestor 4.1.3")
        with self.assertRaises(ValueError):
            attestor_ui.build_args(
                "escapelab", "", variant="cockroach-janta-party")

    def test_current_variant_uses_exact_slug_before_target_terminator(self):
        for slug in attestor_ui.variant414.PROFILE_SLUGS:
            with self.subTest(slug=slug):
                args = attestor_ui.build_args(
                    "attestor41", "--variant cockroach-janta-party",
                    variant=slug)
                self.assertEqual(args[args.index("--variant") + 1], slug)
                self.assertLess(args.index("--attestor414"), args.index("--"))
                self.assertLess(args.index("--variant"), args.index("--"))
                self.assertGreater(
                    args.index("--variant cockroach-janta-party"),
                    args.index("--"))

    def test_variant_boundary_rejects_aliases_types_and_other_modes(self):
        invalid = (
            "South Park", "SP", "south_park", " SOUTH-PARK ",
            True, 1, {}, ["south-park"],
        )
        for value in invalid:
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                attestor_ui.build_args("attestor41", ".", variant=value)
        with self.assertRaises(ValueError):
            attestor_ui.build_args(
                "research", "Question", variant="south-park")
        with self.assertRaises(ValueError):
            attestor_ui.build_args(
                "attestor40", ".", variant="south-park")

    def test_historical_41_keeps_legacy_flag_and_has_no_variant(self):
        args = attestor_ui.build_args(
            "attestor41", ".", version="Attestor 4.1.3")
        self.assertIn("--attestor41", args)
        self.assertNotIn("--attestor414", args)
        self.assertNotIn("--variant", args)
        with self.assertRaises(ValueError):
            attestor_ui.build_args(
                "attestor41", ".", version="Attestor 4.1.3",
                variant="south-park")

    def test_variant_catalog_is_safe_canonical_metadata(self):
        descriptors = attestor_ui.available_variants()
        self.assertEqual(
            [row["slug"] for row in descriptors],
            list(attestor_ui.variant414.PROFILE_SLUGS))
        self.assertEqual(attestor_ui.DEFAULT_VARIANT, "south-park")
        for row in descriptors:
            self.assertEqual(
                set(row),
                {"slug", "display_name", "mode", "profile_sha256",
                 "timeout_seconds", "worker_timeout_seconds",
                 "max_output_bytes", "response_language"})
            self.assertRegex(row["profile_sha256"], r"^[0-9a-f]{64}$")
            profile = attestor_ui.variant414.profile_for_slug(row["slug"])
            self.assertEqual(
                row["worker_timeout_seconds"],
                profile.max_worker_seconds)
            self.assertEqual(
                row["timeout_seconds"],
                attestor_ui._variant_process_timeout(profile))
            self.assertEqual(
                row["response_language"],
                attestor_ui.variant414.response_language_metadata(profile))
        self.assertEqual(
            descriptors[0]["response_language"]["tier"], "C3")
        self.assertTrue(all(
            row["response_language"]["tier"] == "existing"
            for row in descriptors[1:]))

    def test_research_is_offline_by_default_and_machine_readable(self):
        args = attestor_ui.build_args("research", "What changed in battery recycling?")
        self.assertIn("--research", args)
        self.assertEqual(args[args.index("--format") + 1], "json")
        self.assertNotIn("--online", args)
        self.assertNotIn("--fetch-pages", args)
        self.assertEqual(args[-2:], ["--", "What changed in battery recycling?"])

    def test_research_network_controls_require_exact_explicit_permission(self):
        args = attestor_ui.build_args(
            "research", "Compare two public policies",
            research_online=True, research_fetch_pages=True)
        self.assertLess(args.index("--online"), args.index("--"))
        self.assertLess(args.index("--fetch-pages"), args.index("--"))
        malformed = attestor_ui.build_args(
            "research", "Question", research_online="true",  # type: ignore[arg-type]
            research_fetch_pages=1)  # type: ignore[arg-type]
        self.assertNotIn("--online", malformed)
        self.assertNotIn("--fetch-pages", malformed)
        with self.assertRaises(ValueError):
            attestor_ui.build_args("research", "Question", research_fetch_pages=True)
        with self.assertRaises(ValueError):
            attestor_ui.build_args("attestor41", ".", research_online=True)

    def test_research_requires_a_nonempty_question(self):
        with self.assertRaisesRegex(ValueError, "non-coding question"):
            attestor_ui.build_args("research", "   ")

    def test_cjp_control_is_exact_profile_and_permission_bound(self):
        preview_digest = "a" * 64
        args = attestor_ui.build_args(
            "cjpcontrol", "permission.json",
            variant="cockroach-janta-party",
            cjp_permission_confirmed=True,
            cjp_apply=True,
            cjp_apply_confirmed=True,
            cjp_preview_evidence_sha256=preview_digest)
        self.assertIn("--cjp-control", args)
        self.assertIn("--confirm-cjp-permission", args)
        self.assertIn("--apply-cjp-edit", args)
        self.assertIn("--confirm-cjp-apply", args)
        self.assertIn("--cjp-preview-evidence-sha256", args)
        self.assertIn(preview_digest, args)
        self.assertNotIn("--variant", args)
        self.assertEqual(args[-2:], ["--", "permission.json"])
        for invalid in ("south-park", "gruppe-sechs"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                attestor_ui.build_args(
                    "cjpcontrol", "permission.json", variant=invalid)
        with self.assertRaises(ValueError):
            attestor_ui.build_args(
                "cjpcontrol", "permission.json", version="Attestor 4.1.3")

    def test_cjp_ui_booleans_are_literal_and_apply_is_separate(self):
        malformed = attestor_ui.build_args(
            "cjpcontrol", "permission.json",
            variant="cockroach-janta-party",
            cjp_permission_confirmed="true",  # type: ignore[arg-type]
            cjp_apply=1,  # type: ignore[arg-type]
            cjp_apply_confirmed="true")  # type: ignore[arg-type]
        self.assertNotIn("--confirm-cjp-permission", malformed)
        self.assertNotIn("--apply-cjp-edit", malformed)
        self.assertNotIn("--confirm-cjp-apply", malformed)
        with self.assertRaises(ValueError):
            attestor_ui.build_args(
                "cjpcontrol", "permission.json",
                cjp_apply=True)
        with self.assertRaises(ValueError):
            attestor_ui.build_args(
                "cjpcontrol", "permission.json",
                cjp_permission_confirmed=True,
                cjp_apply=True,
                cjp_apply_confirmed=True,
                cjp_preview_evidence_sha256="not-a-digest")
        with self.assertRaises(ValueError):
            attestor_ui.build_args(
                "cjpcontrol", "permission.json",
                cjp_preview_evidence_sha256="a" * 64)
        with self.assertRaises(ValueError):
            attestor_ui.build_args(
                "cjpcontrol", "permission.json",
                cjp_permission_confirmed=True,
                cjp_apply_confirmed=True)
        with self.assertRaises(ValueError):
            attestor_ui.build_args(
                "attestor41", ".",
                cjp_permission_confirmed=True)

    def test_cjp_denied_output_is_profile_verified_but_not_authorized(self):
        profile = attestor_ui.variant414.COCKROACH_JANTA_PARTY
        report = {
            "schema": "attestor-cjp-local-control/4.1.4",
            "version": "4.1.4",
            "profile": "cockroach-janta-party",
            "response_language": {
                **attestor_ui.variant414.response_language_metadata(profile),
                "profile_sha256":
                    attestor_ui.variant414.profile_identity(profile),
                "verified": True,
            },
            "status": "authorization-required",
            "authorization": attestor_ui.cjp_authorization414.denied_status(),
        }
        descriptor = attestor_ui._verified_cjp_output_variant(
            json.dumps(report))
        self.assertEqual(
            descriptor["slug"], "cockroach-janta-party")
        report["profile"] = "south-park"
        self.assertIsNone(
            attestor_ui._verified_cjp_output_variant(json.dumps(report)))

    def test_cjp_authorized_output_requires_a_valid_content_free_audit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "file.txt").write_text("bounded", encoding="utf-8")
            operation = "1" * 64
            registry = attestor_ui.cjp_authorization414.AuthorizationRegistry()
            manifest = registry.issue_preview_authorization(
                root, ("file.txt",), organization="TCS",
                issuer="Authorized custodian",
                owner_statement="I authorize this exact local inspection.",
                purpose="Inspect supplied file",
                allowed_actions=("inspect-files",),
                operation_sha256=operation, confirmed=True)
            audit = registry.consume(
                manifest, root=root,
                requested_actions=("inspect-files",),
                operation_sha256=operation)
        profile = attestor_ui.variant414.COCKROACH_JANTA_PARTY
        report = {
            "schema": "attestor-cjp-local-control/4.1.4",
            "version": "4.1.4",
            "profile": "cockroach-janta-party",
            "response_language": {
                **attestor_ui.variant414.response_language_metadata(profile),
                "profile_sha256":
                    attestor_ui.variant414.profile_identity(profile),
                "verified": True,
            },
            "status": "inspected",
            "operation_sha256": operation,
            "authorization": audit,
        }
        self.assertIsNotNone(
            attestor_ui._verified_cjp_output_variant(json.dumps(report)))
        report["operation_sha256"] = "2" * 64
        self.assertIsNone(
            attestor_ui._verified_cjp_output_variant(json.dumps(report)))

    def test_workbench_defaults_to_attestor41_without_removing_compatibility(self):
        self.assertEqual(attestor_ui.UI_VERSION, "4.1.4")
        self.assertEqual(attestor_ui.CURRENT_VERSION, "Attestor 4.1.4")
        self.assertEqual(attestor_ui.DEFAULT_VARIANT, "south-park")
        self.assertIn("Attestor 4.1.3", attestor_ui.VERSION_LABELS)
        self.assertIn("Attestor 4.0", attestor_ui.VERSION_LABELS)
        self.assertIn("Attestor 3.5", attestor_ui.VERSION_LABELS)
        self.assertIn("Attestor 3.0", attestor_ui.VERSION_LABELS)

    def test_patchguard_prompt_becomes_non_injectable_cli_values(self):
        args = attestor_ui.build_args("patchguard", "src/app.py :: C:/tmp/candidate.py")
        self.assertIn("--patchguard", args)
        self.assertIn("--candidate-file=C:/tmp/candidate.py", args)
        self.assertEqual(args[-2:], ["--", "src/app.py"])
        with self.assertRaises(ValueError):
            attestor_ui.build_args("patchguard", "only-one-path")

    def test_finding_exit_is_a_completed_report_not_job_failure(self):
        self.assertTrue(attestor_ui._completed_returncode("workspace", 1))
        self.assertTrue(attestor_ui._completed_returncode("qualitygate", 1))
        self.assertFalse(attestor_ui._completed_returncode("workspace", 7))
        self.assertFalse(attestor_ui._completed_returncode("chat", 7))
        self.assertFalse(attestor_ui._completed_returncode("mayhem", 2))

    def test_report_json_is_not_corrupted_by_stderr_diagnostics(self):
        output, diagnostics = attestor_ui._process_output(
            "attestor3", b'{"findings":[{"rule":"r"}]}\n',
            b"app.py:2: SyntaxWarning: review this line\n")
        self.assertEqual(json.loads(output)["findings"][0]["rule"], "r")
        self.assertIn("SyntaxWarning", diagnostics)

    def test_secret_like_stderr_is_withheld_from_ui_diagnostics(self):
        output, diagnostics = attestor_ui._process_output(
            "attestor3", b'{"findings":[]}\n',
            b"API_KEY='sk_live_1234567890abcdefghijklmnop'\n")
        self.assertEqual(json.loads(output)["findings"], [])
        self.assertEqual(
            diagnostics,
            "[diagnostics withheld: credential-like material detected]")

    def test_subprocess_output_is_forced_to_utf8_even_in_isolated_mode(self):
        captured = {}

        class FakeProcess:
            pid = 1
            returncode = 0
            def poll(self): return 0
            def wait(self, timeout=None): return 0

        def fake_popen(command, **_kwargs):
            captured["command"] = command
            return FakeProcess()

        with mock.patch.object(attestor_ui.subprocess, "Popen", side_effect=fake_popen):
            result = attestor_ui.run_attestor("arena", "")
        self.assertTrue(result["ok"])
        command = captured["command"]
        self.assertEqual(command[command.index("-X") + 1], "utf8")

    def test_oversized_machine_report_fails_without_accepting_partial_json(self):
        class FakeProcess:
            pid = 1
            returncode = 0
            def poll(self): return 0
            def wait(self, timeout=None): return 0

        def fake_popen(_command, **kwargs):
            limit = attestor_ui.variant414.GRUPPE_SECHS.max_ui_output_bytes
            kwargs["stdout"].write(b"{" + b"x" * limit)
            return FakeProcess()

        with mock.patch.object(attestor_ui.subprocess, "Popen", side_effect=fake_popen):
            result = attestor_ui.run_attestor(
                "attestor41", ".", variant="gruppe-sechs")
        self.assertFalse(result["ok"])
        self.assertEqual(result["code"], 125)
        self.assertEqual(result["outcome"], "output-boundary-exceeded")
        self.assertTrue(result["partial"])
        self.assertFalse(result["output_boundary"]["machine_report_accepted"])
        self.assertIn("partial JSON was rejected", result["output"])
        self.assertEqual(
            result["output_boundary"]["maximum_bytes"],
            attestor_ui.variant414.GRUPPE_SECHS.max_ui_output_bytes)

    def test_variant_process_limits_ignore_request_timeout_and_budget_fields(self):
        captured = {}

        class FakeProcess:
            pid = 1
            returncode = 0
            def poll(self): return 0
            def wait(self, timeout=None): return 0

        def fake_popen(command, **_kwargs):
            captured["command"] = command
            return FakeProcess()

        with mock.patch.object(
                attestor_ui.subprocess, "Popen", side_effect=fake_popen), \
                mock.patch.object(
                    attestor_ui, "_read_bounded",
                    side_effect=[(b"{}", False), (b"", False)]) as bounded:
            result = attestor_ui.run_attestor(
                "attestor41", ".", timeout=600, variant="gruppe-sechs")
        profile = attestor_ui.variant414.GRUPPE_SECHS
        self.assertTrue(result["ok"])
        self.assertEqual(
            result["execution_limits"],
            {"source": "compiled-variant",
             "timeout_seconds": attestor_ui._variant_process_timeout(profile),
             "stdout_bytes": profile.max_ui_output_bytes})
        self.assertEqual(bounded.call_args_list[0].args[1],
                         profile.max_ui_output_bytes)
        self.assertEqual(bounded.call_args_list[1].args[1],
                         attestor_ui.MAX_OUTPUT_BYTES)
        self.assertEqual(
            captured["command"][
                captured["command"].index("--variant") + 1],
            "gruppe-sechs")

    def test_verified_result_variant_comes_from_guarded_report(self):
        profile = attestor_ui.variant414.COCKROACH_JANTA_PARTY
        selection = attestor_ui.variant414.selection_report(profile)
        report = {
            "root": ".",
            "variant_414": selection,
            "analysis_config": {"variant_414": selection},
            "analyzer": {
                "variant_slug": profile.slug,
                "variant_profile_sha256":
                    attestor_ui.variant414.profile_identity(profile)},
        }
        with mock.patch.object(
                attestor_ui.attestor414, "verify_report",
                return_value=(True, [])) as verify_report:
            descriptor = attestor_ui._verified_report_variant(report)
        verify_report.assert_called_once_with(report, root=".")
        self.assertEqual(descriptor["slug"], "cockroach-janta-party")
        self.assertEqual(descriptor["display_name"],
                         "Cockroach Janta Party")
        self.assertEqual(
            descriptor["response_language"]["tier"], "C3")
        report["analyzer"]["variant_slug"] = "south-park"
        with mock.patch.object(
                attestor_ui.attestor414, "verify_report",
                return_value=(True, [])):
            self.assertIsNone(attestor_ui._verified_report_variant(report))

    def test_result_variant_rejects_failed_or_inconsistent_full_report(self):
        profile = attestor_ui.variant414.SOUTH_PARK
        selection = attestor_ui.variant414.selection_report(profile)
        report = {
            "root": ".",
            "variant_414": selection,
            "analysis_config": {"variant_414": selection},
            "analyzer": {
                "variant_slug": profile.slug,
                "variant_profile_sha256":
                    attestor_ui.variant414.profile_identity(profile)},
        }
        with mock.patch.object(
                attestor_ui.attestor414, "verify_report",
                return_value=(False, ["effective policy mismatch"])):
            self.assertIsNone(attestor_ui._verified_report_variant(report))

        report["analysis_config"]["variant_414"] = (
            attestor_ui.variant414.selection_report(
                attestor_ui.variant414.GRUPPE_SECHS))
        with mock.patch.object(
                attestor_ui.attestor414, "verify_report",
                return_value=(True, [])):
            self.assertIsNone(attestor_ui._verified_report_variant(report))

    def test_requested_label_cannot_replace_verified_result_variant(self):
        actual = attestor_ui._variant_descriptor(
            attestor_ui.variant414.COCKROACH_JANTA_PARTY)

        class FakeProcess:
            pid = 1
            returncode = 0
            def poll(self): return 0
            def wait(self, timeout=None): return 0

        with mock.patch.object(
                attestor_ui.subprocess, "Popen", return_value=FakeProcess()), \
                mock.patch.object(
                    attestor_ui, "_read_bounded",
                    side_effect=[(b"{}", False), (b"", False)]), \
                mock.patch.object(
                    attestor_ui, "_verified_output_variant",
                    return_value=actual):
            result = attestor_ui.run_attestor(
                "attestor41", ".", variant="south-park")
        self.assertEqual(
            result["verified_variant"]["display_name"],
            "Cockroach Janta Party")
        self.assertFalse(result["variant_consistent"])

    def test_online_research_history_requires_explicit_provider_retention(self):
        store = mock.Mock()
        manager = attestor_ui.JobManager(workers=1, max_pending=1, evidence_store=store)
        report = {"schema": "attestor-research/4.1", "status": "complete",
                  "execution": {"network_accessed": False}, "retention": {}}
        result = {"ok": True, "code": 0, "output": json.dumps(report), "elapsed_ms": 1}
        try:
            with mock.patch.object(attestor_ui, "run_attestor", return_value=result):
                submitted = manager.submit({"mode": "research", "prompt": "Question",
                                            "research_online": True})
                self.assertIsNotNone(submitted)
                manager._jobs[submitted["id"]]["future"].result(timeout=5)
                finished = manager.get(submitted["id"])["result"]
            self.assertIn("session-only", finished["history_skipped"])
            store.store_report.assert_not_called()
        finally:
            manager.shutdown()

    def test_online_research_can_archive_when_provider_explicitly_allows_it(self):
        store = mock.Mock()
        store.store_report.return_value = {"run_id": "allowed"}
        manager = attestor_ui.JobManager(workers=1, max_pending=1, evidence_store=store)
        result = {"ok": True, "code": 0, "output": json.dumps({
            "schema": "attestor-research/4.1", "execution": {"network_accessed": True},
            "retention": {"provider_declared_retention_allowed": True}}), "elapsed_ms": 1}
        try:
            manager._archive_result(result, mode="research", research_online=True)
            self.assertEqual(result["history"]["run_id"], "allowed")
            store.store_report.assert_called_once()
        finally:
            manager.shutdown()

    def test_cjp_control_history_is_always_session_only(self):
        store = mock.Mock()
        manager = attestor_ui.JobManager(
            workers=1, max_pending=1, evidence_store=store)
        result = {
            "ok": True, "code": 0,
            "output": json.dumps({
                "schema": "attestor-cjp-local-control/4.1.4",
                "status": "inspected"}),
            "elapsed_ms": 1,
        }
        try:
            with mock.patch.object(
                    attestor_ui, "run_attestor", return_value=result):
                submitted = manager.submit({
                    "mode": "cjpcontrol",
                    "prompt": "permission.json",
                    "variant": "cockroach-janta-party",
                    "cjp_permission_confirmed": True,
                })
                self.assertIsNotNone(submitted)
                manager._jobs[submitted["id"]]["future"].result(timeout=5)
                finished = manager.get(submitted["id"])["result"]
            self.assertIn("session-only", finished["history_skipped"])
            store.store_report.assert_not_called()
        finally:
            manager.shutdown()

    def test_escape_lab_history_is_always_session_only(self):
        store = mock.Mock()
        manager = attestor_ui.JobManager(
            workers=1, max_pending=1, evidence_store=store)
        result = {
            "ok": True, "code": 1,
            "output": json.dumps({
                "schema": "attestor-private-escape-report/4.1.4",
                "status": "completed"}),
            "elapsed_ms": 1,
        }
        try:
            with mock.patch.object(
                    attestor_ui, "run_attestor", return_value=result):
                submitted = manager.submit({
                    "mode": "escapelab", "prompt": "",
                })
                self.assertIsNotNone(submitted)
                manager._jobs[submitted["id"]]["future"].result(timeout=5)
                finished = manager.get(submitted["id"])["result"]
            self.assertIn("session-only", finished["history_skipped"])
            store.store_report.assert_not_called()
        finally:
            manager.shutdown()


if __name__ == "__main__":
    unittest.main(verbosity=2)
