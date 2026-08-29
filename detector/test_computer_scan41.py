from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import computer_scan41


class ComputerScan41Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    @staticmethod
    def report(root: Path) -> dict:
        return {
            "schema": "attestor-maximum/4.1",
            "version": "4.1.3",
            "status": "action-required",
            "root": str(root),
            "summary": {"findings": 1},
            "findings": [{
                "rule": "unsafe-eval", "severity": "HIGH", "path": "app.py",
                "line": 1, "message": "Dynamic evaluation is unsafe.",
                "fix": "Use a constrained parser.", "source_engine": "test",
                "secret_value": "NEVER-RETURN-SECRET",
            }],
            "improvements": [{
                "id": "legacy-fix", "status": "review-only",
                "summary": "Replace eval.", "path": "app.py",
                "improved_source": "NEVER-RETURN-LEGACY-SOURCE",
            }],
            "repair_director_41": {
                "status": "candidate-ready",
                "candidates": [{
                    "candidate_id": "candidate-1", "status": "review-only",
                    "summary": "Replace dynamic evaluation.",
                    "files": [{"path": "app.py",
                               "candidate_source": "NEVER-RETURN-CANDIDATE-SOURCE"}],
                    "provider_secret": "NEVER-RETURN-PROVIDER-SECRET",
                }],
            },
            "coverage": {"complete": True, "gaps": []},
            "analysis_config": {"apply_improvements_authorized": False},
            "execution": {
                "attestor41_target_code_executed": False,
                "attestor41_network_accessed": False,
                "attestor41_target_files_written": False,
                "repair_apply_performed": False,
            },
            "report_sha256": "a" * 64,
        }

    def make_project(self, parent: Path | None = None, name: str = "project") -> Path:
        project = (parent or self.root) / name
        project.mkdir(parents=True)
        (project / "package.json").write_text('{"name":"test"}', encoding="utf-8")
        (project / "app.py").write_text("print('static')\n", encoding="utf-8")
        return project

    def test_denial_returns_before_root_enumeration_or_analyzer(self) -> None:
        analyzer = mock.Mock(side_effect=AssertionError("must not run"))
        with mock.patch.object(computer_scan41, "_scope_roots",
                               side_effect=AssertionError("must not enumerate")):
            report = computer_scan41.scan_computer(
                authorized=False, roots_override=[self.root], analyzer=analyzer,
                review_improvements=True)
        self.assertEqual(report["status"], "authorization-required")
        self.assertFalse(report["authorization"]["authorized"])
        self.assertEqual(report["authorization"]["permission_kind"],
                         "application-level-read-consent")
        self.assertFalse(report["authorization"]["os_privilege_elevation_requested"])
        self.assertFalse(report["authorization"]["access_control_bypass_requested"])
        self.assertFalse(report["execution"]["discovery_started"])
        self.assertFalse(report["execution"]["analysis_started"])
        self.assertEqual(report["summary"]["projects_analyzed"], 0)
        analyzer.assert_not_called()

    def test_discovers_project_and_forces_static_read_only_analysis(self) -> None:
        project = self.make_project()
        calls: list[tuple[Path, dict]] = []

        def analyzer(path: Path, **kwargs):
            calls.append((path, kwargs))
            return self.report(path)

        report = computer_scan41.scan_computer(
            authorized=True, roots_override=[self.root], analyzer=analyzer,
            review_improvements=True)

        self.assertEqual([item[0] for item in calls], [project.resolve()])
        options = calls[0][1]
        self.assertTrue(options["improve"])
        self.assertFalse(options["apply_improvements"])
        self.assertFalse(options["include_candidate_source"])
        self.assertFalse(options["use_cache"])
        self.assertFalse(options["compiler_checks"])
        self.assertIsNone(options["test_command"])
        self.assertFalse(options["authorize_tests"])
        self.assertEqual(report["summary"]["projects_analyzed"], 1)
        self.assertEqual(report["summary"]["findings_returned"], 1)
        self.assertFalse(report["execution"]["target_code_executed"])
        self.assertFalse(report["execution"]["target_files_written"])
        self.assertFalse(report["execution"]["improvements_applied"])
        self.assertFalse(report["execution"]["os_privilege_elevation_requested"])
        self.assertFalse(report["execution"]["access_control_bypass_requested"])
        encoded = json.dumps(report, sort_keys=True)
        self.assertNotIn("NEVER-RETURN-SECRET", encoded)
        self.assertNotIn("NEVER-RETURN-LEGACY-SOURCE", encoded)
        self.assertNotIn("NEVER-RETURN-CANDIDATE-SOURCE", encoded)
        self.assertNotIn("NEVER-RETURN-PROVIDER-SECRET", encoded)

    def test_excludes_sensitive_dependency_and_cache_directories(self) -> None:
        project = self.make_project()
        for relative in (Path(".ssh") / "private.py",
                         Path("node_modules") / "dependency.js",
                         Path(".cache") / "cached.py"):
            path = project / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("do_not_scan = True\n", encoding="utf-8")

        report = computer_scan41.scan_computer(
            authorized=True, roots_override=[project],
            analyzer=lambda path, **kwargs: self.report(path))
        discovery = report["discovery"]
        samples = "\n".join(discovery["sample_source_files"]).casefold()
        self.assertGreaterEqual(discovery["excluded_directories"], 3)
        self.assertNotIn(".ssh", samples)
        self.assertNotIn("node_modules", samples)
        self.assertNotIn(".cache", samples)
        self.assertIn("app.py", samples)
        self.assertFalse(report["coverage"]["complete"])
        self.assertTrue(any("excluded by sensitive" in gap
                            for gap in report["coverage"]["gaps"]))

    def test_traversal_file_and_depth_bounds_are_reported(self) -> None:
        (self.root / "a.py").write_text("a = 1\n", encoding="utf-8")
        (self.root / "b.py").write_text("b = 2\n", encoding="utf-8")
        # Lexically before source files so both independent boundaries are hit.
        deep = self.root / "0child"
        deep.mkdir()
        (deep / "c.py").write_text("c = 3\n", encoding="utf-8")

        report = computer_scan41.scan_computer(
            authorized=True, roots_override=[self.root], max_files=1,
            max_directories=2, max_depth=0,
            analyzer=lambda path, **kwargs: self.report(path))
        discovery = report["discovery"]
        self.assertLessEqual(discovery["files_seen"], 1)
        self.assertTrue(discovery["limit_hits"]["files"])
        self.assertTrue(discovery["limit_hits"]["depth"])
        self.assertFalse(report["coverage"]["complete"])
        self.assertTrue(any("boundary" in gap for gap in report["coverage"]["gaps"]))

    def test_project_selection_is_bounded_and_deterministic(self) -> None:
        alpha = self.make_project(name="alpha")
        self.make_project(name="beta")
        self.make_project(name="gamma")
        seen: list[Path] = []

        def analyzer(path: Path, **kwargs):
            seen.append(path)
            return self.report(path)

        report = computer_scan41.scan_computer(
            authorized=True, roots_override=[self.root], max_projects=1,
            analyzer=analyzer)
        self.assertEqual(seen, [alpha.resolve()])
        self.assertEqual(report["summary"]["projects_selected"], 1)
        self.assertTrue(any("project-selection boundary" in gap
                            for gap in report["coverage"]["gaps"]))

    def test_fixed_drive_scope_works_with_test_roots_without_enumeration(self) -> None:
        project = self.make_project()
        with mock.patch.object(computer_scan41, "_fixed_drive_roots",
                               side_effect=AssertionError("override must win")):
            report = computer_scan41.scan_computer(
                authorized=True, scope="fixed-drives", roots_override=[self.root],
                analyzer=lambda path, **kwargs: self.report(path))
        self.assertEqual(report["authorization"]["scope"], "fixed-drives")
        self.assertEqual(report["projects"][0]["root"], str(project.resolve()))

    def test_links_are_not_followed_when_platform_allows_creation(self) -> None:
        project = self.make_project()
        external = self.root / "external"
        external.mkdir()
        (external / "outside.py").write_text("outside = True\n", encoding="utf-8")
        link = project / "linked"
        try:
            link.symlink_to(external, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("directory symlinks are not available to this user")
        report = computer_scan41.scan_computer(
            authorized=True, roots_override=[project],
            analyzer=lambda path, **kwargs: self.report(path))
        self.assertGreaterEqual(report["discovery"]["linked_or_reparse_paths_skipped"], 1)
        self.assertNotIn("outside.py", "\n".join(report["discovery"]["sample_source_files"]))
        self.assertFalse(report["coverage"]["complete"])
        self.assertTrue(any("linked, reparse" in gap
                            for gap in report["coverage"]["gaps"]))

    def test_cross_filesystem_skip_is_an_explicit_coverage_gap(self) -> None:
        project = self.make_project()
        foreign = project / "0foreign"
        foreign.mkdir()
        (foreign / "outside.py").write_text("outside = True\n", encoding="utf-8")
        target = os.path.normcase(os.path.abspath(os.fspath(foreign)))
        real_stat = os.stat

        def boundary_stat(path, *args, **kwargs):
            metadata = real_stat(path, *args, **kwargs)
            current = os.path.normcase(os.path.abspath(os.fspath(path)))
            if current == target:
                return mock.Mock(st_dev=metadata.st_dev + 1)
            return metadata

        with mock.patch.object(computer_scan41.os, "stat", side_effect=boundary_stat):
            report = computer_scan41.scan_computer(
                authorized=True, roots_override=[project],
                analyzer=lambda path, **kwargs: self.report(path))
        self.assertGreaterEqual(report["discovery"]["cross_filesystem_paths_skipped"], 1)
        self.assertFalse(report["coverage"]["complete"])
        self.assertTrue(any("cross-filesystem" in gap
                            for gap in report["coverage"]["gaps"]))

    def test_analyzer_error_does_not_expose_exception_message(self) -> None:
        self.make_project()

        def fail(_path: Path, **_kwargs):
            raise RuntimeError("NEVER-RETURN-EXCEPTION-SECRET")

        report = computer_scan41.scan_computer(
            authorized=True, roots_override=[self.root], analyzer=fail)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["errors"][0]["error"], "RuntimeError")
        self.assertNotIn("NEVER-RETURN-EXCEPTION-SECRET", json.dumps(report))

    def test_malformed_mapping_keyerror_fails_closed_without_message_leak(self) -> None:
        self.make_project()

        class BrokenReport(dict):
            def get(self, *_args, **_kwargs):
                raise KeyError("NEVER-RETURN-KEYERROR-SECRET")

        report = computer_scan41.scan_computer(
            authorized=True, roots_override=[self.root],
            analyzer=lambda _path, **_kwargs: BrokenReport())
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["errors"][0]["error"], "KeyError")
        self.assertTrue(any("failed closed" in gap for gap in report["coverage"]["gaps"]))
        self.assertNotIn("NEVER-RETURN-KEYERROR-SECRET", json.dumps(report))

    def test_reported_effect_violation_is_inconsistent(self) -> None:
        self.make_project()

        def unsafe(path: Path, **_kwargs):
            report = self.report(path)
            report["execution"]["selected_tests_executed"] = True
            report["execution"]["changes_applied"] = True
            return report

        report = computer_scan41.scan_computer(
            authorized=True, roots_override=[self.root], analyzer=unsafe)
        self.assertEqual(report["status"], "inconsistent")
        self.assertTrue(report["execution"]["target_code_executed"])
        self.assertTrue(report["execution"]["target_files_written"])
        self.assertTrue(report["execution"]["improvements_applied"])
        self.assertFalse(report["coverage"]["complete"])

    def test_failed_report_is_not_counted_as_completed_analysis(self) -> None:
        self.make_project()

        def failed(path: Path, **_kwargs):
            report = self.report(path)
            report["status"] = "failed"
            report["coverage"] = {"complete": True, "gaps": []}
            return report

        report = computer_scan41.scan_computer(
            authorized=True, roots_override=[self.root], analyzer=failed)
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["summary"]["projects_analyzed"], 0)
        self.assertEqual(report["summary"]["analysis_errors"], 1)
        self.assertFalse(report["projects"][0]["analysis_completed"])
        self.assertFalse(report["projects"][0]["coverage"]["complete"])
        self.assertTrue(any("non-success project status" in gap
                            for gap in report["coverage"]["gaps"]))

    def test_mixed_success_and_failed_project_reports_are_partial(self) -> None:
        self.make_project(name="alpha")
        self.make_project(name="beta")

        def mixed(path: Path, **_kwargs):
            report = self.report(path)
            if path.name == "alpha":
                report["status"] = "stale"
            else:
                report["status"] = "complete"
                report["findings"] = []
                report["summary"]["findings"] = 0
            return report

        report = computer_scan41.scan_computer(
            authorized=True, roots_override=[self.root], analyzer=mixed)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["summary"]["projects_analyzed"], 1)
        self.assertEqual(report["summary"]["analysis_errors"], 1)

    def test_invalid_limits_and_scope_fail_closed(self) -> None:
        for kwargs in ({"scope": "network"}, {"max_projects": 0},
                       {"max_projects": computer_scan41.MAX_PROJECTS + 1},
                       {"max_depth": -1}, {"authorized": 1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(computer_scan41.ComputerScanError):
                computer_scan41.scan_computer(**kwargs)

    def test_text_renderer_is_compact(self) -> None:
        report = computer_scan41.scan_computer(authorized=False)
        rendered = computer_scan41.render_text(report)
        self.assertIn("authorization-required", rendered)
        self.assertIn("no discovery performed", rendered)
        self.assertNotIn("None", rendered)

    def test_text_renderer_escapes_terminal_and_bidi_controls(self) -> None:
        report = computer_scan41.scan_computer(authorized=False)
        report["coverage"]["gaps"] = ["bad\x1b[31m\x85\u202efile"]
        rendered = computer_scan41.render_text(report)
        self.assertNotIn("\x1b", rendered)
        self.assertNotIn("\x85", rendered)
        self.assertNotIn("\u202e", rendered)
        self.assertIn("\\x1b[31m\\x85\\u202efile", rendered)


if __name__ == "__main__":
    unittest.main()
