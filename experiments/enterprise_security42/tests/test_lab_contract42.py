"""Acceptance contracts for the isolated, no-cost enterprise security lab.

These tests intentionally exercise the experiment through its public module and
CLI surfaces.  They do not import or alter any production Attestor component.
"""
from __future__ import annotations

import ast
import copy
from contextlib import ExitStack, redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
import ntpath
import os
from pathlib import Path, PurePosixPath
import re
import socket
import subprocess
import sys
import tempfile
import types
import unittest
from unittest import mock


LAB_ROOT = Path(__file__).resolve().parent.parent
LAB_PATH = LAB_ROOT / "lab.py"
PRODUCT_ROOT = LAB_ROOT.parent.parent
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CWE = re.compile(r"^CWE-[1-9][0-9]*$")
FORBIDDEN_REPORT_KEYS = {
    "absolute_path",
    "code",
    "content",
    "line_text",
    "raw_source",
    "snippet",
    "source_text",
}


def _load_lab():
    if not LAB_PATH.is_file():
        raise AssertionError("the experiment entrypoint is missing: %s" % LAB_PATH)
    module_name = "enterprise_security42_lab_contract_target"
    sys.modules.pop(module_name, None)
    spec = importlib.util.spec_from_file_location(module_name, LAB_PATH)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load %s" % LAB_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _invoke(lab, argv):
    stdout = io.StringIO()
    stderr = io.StringIO()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            result = lab.main(list(argv))
        except SystemExit as exc:  # main(argv), unlike __main__, is a return API.
            raise AssertionError("main(argv) raised SystemExit(%r)" % exc.code) from exc
    if type(result) is not int:
        raise AssertionError("main(argv) must return an integer exit status")
    return result, stdout.getvalue(), stderr.getvalue()


def _json_command(lab, command):
    code, output, error = _invoke(lab, [command, "--format", "json"])
    if error:
        raise AssertionError("successful JSON command wrote stderr: %s" % error)
    try:
        report = json.loads(output)
    except json.JSONDecodeError as exc:
        raise AssertionError("command did not emit one JSON document") from exc
    return code, output, report


def _walk(value):
    yield value
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from _walk(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk(child)


def _dicts(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _dicts(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _dicts(child)


def _is_absolute_text(value):
    if not isinstance(value, str) or not value:
        return False
    return PurePosixPath(value).is_absolute() or ntpath.isabs(value)


def _production_python_files():
    excluded = {"tests", "fixtures", "fixture", "corpus", "targets", "samples"}
    return [
        path for path in LAB_ROOT.rglob("*.py")
        if not any(part.casefold() in excluded for part in path.relative_to(LAB_ROOT).parts)
    ]


def _qualified_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _qualified_name(node.value)
        return (prefix + "." if prefix else "") + node.attr
    return ""


def _leaf_paths(value, prefix=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _leaf_paths(child, prefix + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _leaf_paths(child, prefix + (index,))
    else:
        yield prefix


def _mutated(value):
    if type(value) is bool:
        return not value
    if type(value) is int:
        return value + 1
    if type(value) is float:
        return value + 0.125
    if isinstance(value, str):
        return value + "-mutated"
    if value is None:
        return "mutated"
    return {"mutated": True}


def _mutate_at(value, path):
    target = value
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = _mutated(target[path[-1]])


def _reseal(lab, report):
    result = copy.deepcopy(report)
    result.pop("report_sha256", None)
    result["report_sha256"] = lab.digest_json(result)
    return result


class LabContractCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lab = _load_lab()
        cls.engine = sys.modules[cls.lab.SourceUnit.__module__]
        cls.fixtures = sys.modules[cls.engine.BenchmarkFixture.__module__]

    def assert_report_envelope(self, report, command):
        self.assertIsInstance(report, dict)
        for key in (
                "schema", "command", "status", "complete", "cost_profile",
                "report_sha256"):
            self.assertIn(key, report)
        self.assertEqual(report["command"], command)
        self.assertIs(type(report["complete"]), bool)
        self.assertRegex(report["report_sha256"], SHA256)
        self.assertTrue(self.lab.verify_report(report))

    def assert_minimal_safe_report(self, report):
        serialized = self.lab.canonical_json(report)
        if isinstance(serialized, bytes):
            serialized = serialized.decode("utf-8")
        self.assertNotIn(str(LAB_ROOT.resolve()), serialized)
        for item in _dicts(report):
            self.assertFalse(
                FORBIDDEN_REPORT_KEYS.intersection(
                    str(key).casefold() for key in item), item)
        absolute_values = [value for value in _walk(report)
                           if _is_absolute_text(value)]
        self.assertEqual(absolute_values, [])


class StaticBoundaryTests(LabContractCase):
    def test_implementation_is_standard_library_only(self):
        stdlib = set(sys.stdlib_module_names) | {"__future__"}
        local = {path.stem for path in _production_python_files()}
        violations = []
        for path in _production_python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    names = [alias.name.split(".", 1)[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    names = [(node.module or "").split(".", 1)[0]]
                else:
                    continue
                for name in names:
                    if name and name not in stdlib and name not in local:
                        violations.append("%s imports %s" % (path.name, name))
        self.assertEqual(violations, [])

    def test_implementation_has_no_process_network_or_target_execution_surface(self):
        forbidden_imports = {
            "asyncio", "ctypes", "ftplib", "http", "importlib",
            "multiprocessing", "runpy", "smtplib", "socket", "subprocess",
            "telnetlib", "urllib", "webbrowser",
        }
        forbidden_calls = {
            "compile", "eval", "exec", "os.popen", "os.system",
            "runpy.run_module", "runpy.run_path", "subprocess.call",
            "subprocess.check_call", "subprocess.check_output",
            "subprocess.Popen", "subprocess.run",
        }
        violations = []
        for path in _production_python_files():
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots = {alias.name.split(".", 1)[0] for alias in node.names}
                    violations.extend(
                        "%s imports %s" % (path.name, root)
                        for root in sorted(roots & forbidden_imports))
                elif isinstance(node, ast.ImportFrom) and node.level == 0:
                    root = (node.module or "").split(".", 1)[0]
                    if root in forbidden_imports:
                        violations.append("%s imports %s" % (path.name, root))
                elif isinstance(node, ast.Call):
                    name = _qualified_name(node.func)
                    if (name in forbidden_calls or name.startswith("os.exec")
                            or name.startswith("os.spawn")):
                        violations.append("%s calls %s" % (path.name, name))
        self.assertEqual(violations, [])

    def test_all_commands_run_with_network_and_subprocess_calls_blocked(self):
        def blocked(*_args, **_kwargs):
            raise AssertionError("network or subprocess use is forbidden")

        targets = [
            "socket.socket", "socket.create_connection", "subprocess.Popen",
            "subprocess.run", "subprocess.call", "subprocess.check_call",
            "subprocess.check_output", "os.system", "os.popen",
        ]
        with ExitStack() as stack:
            for target in targets:
                stack.enter_context(mock.patch(target, side_effect=blocked))
            for command in ("benchmark", "isolation", "self-test"):
                code, _output, _error = _invoke(
                    self.lab, [command, "--format", "json"])
                self.assertIn(code, (0, 1, 3), command)


class JsonAndCliTests(LabContractCase):
    def test_json_is_byte_for_byte_deterministic(self):
        for command in ("benchmark", "isolation", "self-test"):
            with self.subTest(command=command):
                first_code, first, first_report = _json_command(self.lab, command)
                second_code, second, second_report = _json_command(self.lab, command)
                self.assertEqual(first_code, 0)
                self.assertEqual(second_code, first_code)
                self.assertEqual(second, first)
                self.assertEqual(second_report, first_report)
                self.assert_report_envelope(first_report, command)
                self.assert_minimal_safe_report(first_report)

    def test_cost_profile_is_exactly_offline_and_no_cost(self):
        expected = {
            "network": False,
            "subprocess": False,
            "external_tools": False,
            "target_execution": False,
            "incremental_cost_usd": 0,
            "provider_cost_usd": 0,
        }
        for command in ("benchmark", "isolation", "self-test"):
            with self.subTest(command=command):
                _code, _output, report = _json_command(self.lab, command)
                self.assertEqual(report["cost_profile"], expected)

    def test_report_digest_is_recomputed_and_every_leaf_is_bound(self):
        for command in ("benchmark", "isolation", "self-test"):
            with self.subTest(command=command):
                _code, _output, report = _json_command(self.lab, command)
                unsigned = copy.deepcopy(report)
                expected = unsigned.pop("report_sha256")
                self.assertEqual(self.lab.digest_json(unsigned), expected)
                for path in _leaf_paths(report):
                    changed = copy.deepcopy(report)
                    _mutate_at(changed, path)
                    self.assertFalse(
                        self.lab.verify_report(changed),
                        "%s was not bound to report_sha256" % (path,))

    def test_invalid_cli_inputs_return_two_without_traceback(self):
        cases = (
            [],
            ["unknown"],
            ["benchmark", "--format", "yaml"],
            ["benchmark", "unexpected-target"],
            ["isolation", "--out"],
        )
        for argv in cases:
            with self.subTest(argv=argv):
                code, stdout, stderr = _invoke(self.lab, argv)
                self.assertEqual(code, 2)
                self.assertNotIn("Traceback", stdout + stderr)

    def test_stable_exit_mapping(self):
        expected = {
            "success": 0,
            "quality_gate_miss": 1,
            "invalid_input": 2,
            "incomplete": 3,
            "operational_failure": 4,
        }
        observed = {status: self.lab.exit_for_status(status) for status in expected}
        self.assertEqual(observed, expected)

    def test_real_command_maps_quality_incomplete_and_operational_statuses(self):
        class SilentDetector:
            RULE_CWE = {}

            @staticmethod
            def scan_project(_sources, deep=True):
                self.assertTrue(deep)
                return ()

        class OutOfScopeDetector:
            RULE_CWE = {"injected-unknown": "CWE-999"}

            @staticmethod
            def scan_project(_sources, deep=True):
                self.assertTrue(deep)
                return (types.SimpleNamespace(
                    path="outside.py", line=1, rule="injected-unknown"),)

        reports = (
            (self.lab.run_benchmark(detector_module=SilentDetector), 3),
            (self.lab.run_benchmark(detector_module=OutOfScopeDetector), 3),
        )
        for report, expected in reports:
            with self.subTest(status=report["status"]), mock.patch.object(
                    self.lab, "run_benchmark", return_value=report):
                self.assertTrue(self.lab.verify_report(report))
                code, stdout, stderr = _invoke(
                    self.lab, ["benchmark", "--format", "json"])
                self.assertEqual(code, expected)
                self.assertNotIn("Traceback", stdout + stderr)

        # Quality routing is a CLI dispatch contract. Keep report-integrity
        # enforcement independently covered by the verifier tests above.
        quality_report = copy.deepcopy(self.lab.run_benchmark())
        quality_report["status"] = "quality_gate_miss"
        with mock.patch.object(
                self.lab, "run_benchmark", return_value=quality_report), \
                mock.patch.object(self.lab, "verify_report", return_value=True):
            code, stdout, stderr = _invoke(
                self.lab, ["benchmark", "--format", "json"])
            self.assertEqual(code, 1)
            self.assertNotIn("Traceback", stdout + stderr)

        with mock.patch.object(
                self.lab, "run_benchmark", side_effect=OSError("injected")):
            code, stdout, stderr = _invoke(
                self.lab, ["benchmark", "--format", "json"])
            self.assertEqual(code, 4)
            self.assertNotIn("Traceback", stdout + stderr)


class EngineBoundaryTests(LabContractCase):
    def test_detector_receives_sources_but_never_benchmark_labels(self):
        class SpyDetector:
            RULE_CWE = {}

            def __init__(self):
                self.calls = []

            def scan_project(self, sources, deep=True):
                self.calls.append((copy.deepcopy(sources), deep))
                return ()

        detector = SpyDetector()
        report = self.lab.run_benchmark(detector_module=detector)
        self.assertEqual(len(detector.calls), len(self.fixtures.BENCHMARK_FIXTURES))
        self.assertTrue(self.lab.verify_report(report))
        for case, (received, deep) in zip(
                self.fixtures.BENCHMARK_FIXTURES, detector.calls):
            with self.subTest(case=case.case_id):
                expected = {item.path: item.content for item in case.sources}
                self.assertEqual(received, expected)
                self.assertTrue(deep)
                boundary = repr((received, {"deep": deep}))
                for secret_label in (
                        case.case_id, case.group_id, case.cwe, case.rule_id,
                        "expected_vulnerable", "vulnerable"):
                    self.assertNotIn(secret_label, boundary)

    def test_preloaded_detect_module_cannot_spoof_reviewed_detector(self):
        planted = types.ModuleType("detect")
        planted.RULE_CWE = {}
        planted.called = False

        def planted_scan(_sources, deep=True):
            planted.called = True
            return ()

        planted.scan_project = planted_scan
        source = self.lab.SourceUnit("src/handler.py", "return_value = 1\n")
        with mock.patch.dict(sys.modules, {"detect": planted}):
            try:
                report = self.lab.analyze_tenant("identity-check", (source,))
            except self.engine.LabOperationalError:
                report = None
        self.assertFalse(planted.called)
        if report is not None:
            self.assertTrue(self.lab.verify_report(report))

    def test_forged_detector_origin_metadata_cannot_spoof_reviewed_module(self):
        expected = (PRODUCT_ROOT / "detector" / "detect.py").resolve(strict=True)
        rule_canary = "FORGED-ORIGIN-RULE-CANARY"
        planted = types.ModuleType("detect")
        planted.__file__ = str(expected)
        planted.__spec__ = types.SimpleNamespace(origin=str(expected))
        planted.RULE_CWE = {rule_canary: "CWE-94"}
        planted.called = False

        def planted_scan(_sources, deep=True):
            planted.called = True
            return (types.SimpleNamespace(
                path="src/handler.py", line=1, rule=rule_canary),)

        planted.scan_project = planted_scan
        source = self.lab.SourceUnit("src/handler.py", "value = 1\n")
        with mock.patch.dict(sys.modules, {"detect": planted}):
            try:
                report = self.lab.analyze_tenant("forged-origin", (source,))
            except self.engine.LabOperationalError as exc:
                report = None
                self.assertNotIn(rule_canary, str(exc))
        self.assertFalse(planted.called, "untrusted module code was executed")
        if report is not None:
            self.assertTrue(self.lab.verify_report(report))
            self.assertNotIn(rule_canary, self.lab.canonical_json(report))

    def test_reviewed_detector_file_must_be_contained_and_not_a_symlink(self):
        detector_path = PRODUCT_ROOT / "detector" / "detect.py"
        self.assertTrue(detector_path.is_file())
        self.assertFalse(
            detector_path.is_symlink(),
            "the checked-in detector itself must not be a symbolic link")
        outside_path = PRODUCT_ROOT.parent / "external-detector" / "detect.py"
        real_import = __import__
        real_is_symlink = Path.is_symlink
        real_resolve = Path.resolve

        def symlink_fact(candidate):
            if candidate == detector_path:
                return True
            return real_is_symlink(candidate)

        def outside_resolve(candidate, strict=False):
            if candidate == detector_path:
                return outside_path
            return real_resolve(candidate, strict=strict)

        scenarios = (
            ("detector-file-symlink", "is_symlink", symlink_fact),
            ("detector-resolves-outside-release", "resolve", outside_resolve),
        )
        for name, method_name, replacement in scenarios:
            with self.subTest(name=name):
                state = {"imported": False, "scanned": False}
                planted = types.ModuleType("detect")
                planted.__file__ = str(detector_path)
                planted.__spec__ = types.SimpleNamespace(
                    origin=str(detector_path))
                planted.RULE_CWE = {}

                def planted_scan(_sources, deep=True):
                    state["scanned"] = True
                    return ()

                def guarded_import(module_name, *args, **kwargs):
                    if module_name == "detect":
                        state["imported"] = True
                        return planted
                    return real_import(module_name, *args, **kwargs)

                planted.scan_project = planted_scan
                rejected = False
                with mock.patch.object(
                        self.engine, "_TRUSTED_DETECTOR", None), \
                        mock.patch.dict(sys.modules), \
                        mock.patch.object(
                            self.engine.Path, method_name, new=replacement), \
                        mock.patch("builtins.__import__", new=guarded_import):
                    sys.modules.pop("detect", None)
                    try:
                        self.lab.analyze_tenant(
                            "dependency-boundary",
                            (self.lab.SourceUnit(
                                "src/handler.py", "value = 1\n"),),
                        )
                    except self.engine.LabOperationalError:
                        rejected = True
                self.assertEqual(
                    (state["imported"], state["scanned"], rejected),
                    (False, False, True),
                    "detector dependency was not rejected before execution",
                )

    def test_injected_detector_cannot_claim_production_provenance_or_leak_rule_id(self):
        source = self.lab.SourceUnit(
            "src/provenance.py", "def identity(value):\n    return value\n")
        production = self.lab.analyze_tenant(
            "provenance-baseline", (source,))
        self.assertTrue(self.lab.verify_report(production))
        production_sha256 = production["detector_sha256"]
        rule_canary = "RULE-ID-CANARY-DO-NOT-LEAK"

        class InjectedDetector:
            RULE_CWE = {rule_canary: "CWE-94"}

            @staticmethod
            def scan_project(_sources, deep=True):
                return (types.SimpleNamespace(
                    path="src/provenance.py", line=1, rule=rule_canary),)

        try:
            report = self.lab.analyze_tenant(
                "provenance-injected", (source,),
                detector_module=InjectedDetector)
        except self.engine.LabOperationalError as exc:
            self.assertNotIn(rule_canary, str(exc))
            return

        self.assertTrue(
            self.lab.verify_report(report),
            "a report returned by the producer must verify itself")
        rendered = self.lab.canonical_json(report)
        self.assertNotIn(rule_canary, rendered)
        self.assertFalse(
            report["complete"]
            and report["detector_sha256"] == production_sha256,
            "injected code claimed a complete reviewed-detector analysis")

    def test_out_of_range_finding_line_fails_closed_with_a_valid_report(self):
        source = self.lab.SourceUnit(
            "src/line-boundary.java", "class Boundary {}\n")
        expected_rule = self.fixtures.BENCHMARK_FIXTURES[0].rule_id
        expected_cwe = self.fixtures.BENCHMARK_FIXTURES[0].cwe

        class ImpossibleLineDetector:
            RULE_CWE = {expected_rule: expected_cwe}

            @staticmethod
            def scan_project(_sources, deep=True):
                return (types.SimpleNamespace(
                    path="src/line-boundary.java",
                    line=999_999,
                    rule=expected_rule,
                ),)

        try:
            report = self.lab.analyze_tenant(
                "line-boundary", (source,),
                detector_module=ImpossibleLineDetector)
        except self.engine.LabOperationalError as exc:
            self.assertNotIn("Traceback", str(exc))
            return

        self.assertTrue(
            self.lab.verify_report(report),
            "the producer sealed a report its verifier rejects")
        self.assertFalse(report["complete"])
        self.assertEqual(report["status"], "incomplete")
        line_counts = {
            item["path"]: item["line_count"]
            for item in report["manifest"]["files"]
        }
        self.assertTrue(report["coverage_gaps"])
        self.assertTrue(all(
            finding["line"] <= line_counts[finding["path"]]
            for finding in report["findings"]
        ))

    def test_target_source_is_never_executed_or_returned(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "target-executed.txt"
            source_text = (
                "from pathlib import Path\n"
                "Path(%r).write_text('executed', encoding='utf-8')\n"
                % str(marker)
            )
            report = self.lab.analyze_tenant(
                "execution-check",
                (self.lab.SourceUnit("src/do-not-run.py", source_text),),
            )
            self.assertFalse(marker.exists())
        self.assertTrue(self.lab.verify_report(report))
        serialized = self.lab.canonical_json(report)
        self.assertNotIn(source_text, serialized)
        self.assertNotIn(str(marker), serialized)

    def test_nonlogical_and_external_paths_are_rejected(self):
        for path in (
                "/tmp/input.py", "../input.py", "src/../input.py",
                "C:/input.py", "src\\input.py", Path("src/input.py")):
            with self.subTest(path=path), self.assertRaises(
                    self.engine.LabInputError):
                self.lab.analyze_tenant(
                    "path-check", (self.lab.SourceUnit(path, "value = 1\n"),))

    def test_symlink_or_reparse_target_cannot_enter_the_input_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            target = directory / "outside.py"
            target.write_text("raise RuntimeError('must not execute')\n", encoding="utf-8")
            link = directory / "linked.py"
            try:
                link.symlink_to(target)
            except OSError as exc:
                self.skipTest("symbolic links unavailable: %s" % exc)
            with self.assertRaises(self.engine.LabInputError):
                self.lab.analyze_tenant(
                    "link-check",
                    (self.lab.SourceUnit(str(link), "value = 1\n"),),
                )
            self.assertEqual(
                target.read_text(encoding="utf-8"),
                "raise RuntimeError('must not execute')\n")


class BenchmarkEvidenceTests(LabContractCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.report = cls.lab.run_benchmark()

    def test_metrics_include_confusion_matrix_per_cwe(self):
        self.assert_report_envelope(self.report, "benchmark")
        per_cwe = self.report["metrics"]["per_cwe"]
        self.assertIsInstance(per_cwe, dict)
        self.assertTrue(per_cwe)
        for cwe, values in per_cwe.items():
            with self.subTest(cwe=cwe):
                self.assertRegex(cwe, CWE)
                for key in ("tp", "tn", "fp", "fn"):
                    self.assertIs(type(values[key]), int)
                    self.assertGreaterEqual(values[key], 0)
                self.assertGreater(values["tp"] + values["fn"], 0)
                self.assertGreater(values["tn"] + values["fp"], 0)
                precision = values["tp"] / (values["tp"] + values["fp"])
                recall = values["tp"] / (values["tp"] + values["fn"])
                f1 = 2 * precision * recall / (precision + recall)
                self.assertEqual(values["precision"], round(precision, 6))
                self.assertEqual(values["recall"], round(recall, 6))
                self.assertEqual(values["f1"], round(f1, 6))

    def test_every_bundled_case_is_scored_once_and_totals_cover_the_corpus(self):
        expected = {case.case_id: case for case in self.fixtures.BENCHMARK_FIXTURES}
        observations = self.report["cases"]
        observed_ids = [item["case_id"] for item in observations]
        self.assertEqual(len(observed_ids), len(set(observed_ids)))
        self.assertEqual(set(observed_ids), set(expected))
        self.assertEqual(self.report["dataset"]["case_count"], len(expected))

        aggregate = self.report["metrics"]["aggregate"]
        self.assertEqual(
            sum(aggregate[key] for key in ("tp", "tn", "fp", "fn")),
            len(expected))
        for cwe, metrics in self.report["metrics"]["per_cwe"].items():
            expected_count = sum(case.cwe == cwe for case in expected.values())
            self.assertEqual(
                sum(metrics[key] for key in ("tp", "tn", "fp", "fn")),
                expected_count)

        dataset_rows = []
        for item in observations:
            case = expected[item["case_id"]]
            self.assertEqual(item["group_id"], case.group_id)
            self.assertEqual(item["cwe"], case.cwe)
            self.assertEqual(item["expected_rule_id"], case.rule_id)
            self.assertIs(item["expected_vulnerable"], case.vulnerable)
            self.assertTrue(self.lab.verify_report(item["analysis"]))
            dataset_rows.append({
                "case_id": case.case_id,
                "group_id": case.group_id,
                "cwe": case.cwe,
                "rule_id": case.rule_id,
                "vulnerable": case.vulnerable,
                "input_manifest_sha256": item["analysis"]["manifest"][
                    "manifest_sha256"],
            })
        self.assertEqual(
            self.report["dataset"]["cases_sha256"],
            self.lab.digest_json(dataset_rows))

    def test_custom_or_missing_cases_cannot_claim_bundled_success(self):
        one_case = self.lab.run_benchmark(
            cases=(self.fixtures.BENCHMARK_FIXTURES[0],))
        missing_case = self.lab.run_benchmark(
            cases=self.fixtures.BENCHMARK_FIXTURES[:-1])
        for report in (one_case, missing_case):
            self.assertTrue(self.lab.verify_report(report))
            self.assertNotEqual(report["status"], "success")
            self.assertFalse(report["quality_gate"]["passed"])

    def test_bundled_exact_verification_pins_fixture_bytes(self):
        source_type = self.fixtures.FixtureSource
        case_type = self.fixtures.BenchmarkFixture
        altered_cases = []
        for index, case in enumerate(self.fixtures.BENCHMARK_FIXTURES):
            sources = list(case.sources)
            if index == 0:
                original = sources[0]
                sources[0] = source_type(
                    original.path,
                    original.content + "\n// altered fixture bytes\n",
                )
            altered_cases.append(case_type(
                case_id=case.case_id,
                group_id=case.group_id,
                cwe=case.cwe,
                rule_id=case.rule_id,
                vulnerable=case.vulnerable,
                sources=tuple(sources),
            ))

        custom = self.lab.run_benchmark(cases=tuple(altered_cases))
        self.assertTrue(self.lab.verify_report(custom))
        self.assertEqual(custom["dataset"]["fixture_set"], "custom-unverified")
        expected_manifest = self.lab.build_manifest(
            "benchmark-%s" % self.fixtures.BENCHMARK_FIXTURES[0].case_id,
            tuple(self.lab.SourceUnit(item.path, item.content)
                  for item in self.fixtures.BENCHMARK_FIXTURES[0].sources),
        )
        self.assertNotEqual(
            custom["cases"][0]["analysis"]["manifest"]["manifest_sha256"],
            expected_manifest["manifest_sha256"],
        )

        forged = copy.deepcopy(custom)
        forged["dataset"]["name"] = (
            "Attestor bundled paired synthetic smoke corpus")
        forged["dataset"]["fixture_set"] = "bundled-exact-v1"
        forged["complete"] = all(
            item["analysis"]["complete"] for item in forged["cases"])
        quality_ok = all(
            item["outcome"] in {"tp", "tn"}
            and not item["unexpected_rule_ids"]
            and item["analysis"]["complete"]
            for item in forged["cases"]
        )
        forged["status"] = (
            "incomplete" if not forged["complete"] else
            ("success" if quality_ok else "quality_gate_miss")
        )
        forged["quality_gate"]["passed"] = forged["status"] == "success"
        forged = _reseal(self.lab, forged)
        self.assertFalse(
            self.lab.verify_report(forged),
            "bundled-exact accepted altered fixture bytes")

    def test_incomplete_coverage_outranks_a_real_finding(self):
        source_type = self.fixtures.FixtureSource
        case_type = self.fixtures.BenchmarkFixture
        case = case_type(
            case_id="injected-incomplete",
            group_id="injected-pair",
            cwe="CWE-94",
            rule_id="dangerous-eval",
            vulnerable=True,
            sources=(
                source_type("src/handler.py", "def f(value):\n    return eval(value)\n"),
                source_type("notes/unsupported.txt", "coverage gap\n"),
            ),
        )

        class FindingDetector:
            RULE_CWE = {"dangerous-eval": "CWE-94"}

            @staticmethod
            def scan_project(_sources, deep=True):
                return (types.SimpleNamespace(
                    path="src/handler.py", line=2, rule="dangerous-eval"),)

        report = self.lab.run_benchmark(
            cases=(case,), detector_module=FindingDetector)
        analysis = report["cases"][0]["analysis"]
        self.assertTrue(analysis["findings"])
        self.assertTrue(analysis["coverage_gaps"])
        self.assertFalse(report["complete"])
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(self.lab.exit_for_status(report["status"]), 3)
        self.assertTrue(self.lab.verify_report(report))

    def test_evidence_is_hashed_minimal_and_relative(self):
        evidence = [
            item for item in _dicts(self.report)
            if {"path", "input_sha256", "manifest_sha256", "rule_id",
                "rule_version", "cwe", "line", "evidence_sha256",
                "finding_sha256"}.issubset(item)
        ]
        self.assertTrue(evidence, "benchmark emitted no evidence records")
        for item in evidence:
            with self.subTest(path=item["path"], rule=item["rule_id"]):
                self.assertIs(type(item["path"]), str)
                self.assertFalse(_is_absolute_text(item["path"]))
                self.assertNotIn("\\", item["path"])
                self.assertNotIn("..", PurePosixPath(item["path"]).parts)
                for key in (
                        "input_sha256", "manifest_sha256", "evidence_sha256",
                        "finding_sha256"):
                    self.assertRegex(item[key], SHA256)
                self.assertTrue(item["rule_id"])
                self.assertTrue(item["rule_version"])
                self.assertRegex(item["cwe"], CWE)
                self.assertIs(type(item["line"]), int)
                self.assertGreaterEqual(item["line"], 1)

    def test_manifest_input_evidence_and_finding_hashes_recompute(self):
        cases = {case.case_id: case for case in self.fixtures.BENCHMARK_FIXTURES}
        for observation in self.report["cases"]:
            case = cases[observation["case_id"]]
            source_by_path = {item.path: item.content for item in case.sources}
            analysis = observation["analysis"]
            manifest = analysis["manifest"]
            unsigned_manifest = copy.deepcopy(manifest)
            supplied_manifest_hash = unsigned_manifest.pop("manifest_sha256")
            self.assertEqual(
                self.lab.digest_json(unsigned_manifest), supplied_manifest_hash)
            for file_record in manifest["files"]:
                expected_hash = hashlib.sha256(
                    source_by_path[file_record["path"]].encode("utf-8"))
                self.assertEqual(file_record["sha256"], expected_hash.hexdigest())
            for evidence in analysis["findings"]:
                core = {
                    key: evidence[key]
                    for key in (
                        "cwe", "input_sha256", "line", "manifest_sha256",
                        "path", "rule_id", "rule_version")
                }
                self.assertEqual(
                    evidence["evidence_sha256"], self.lab.digest_json(core))
                binding = {
                    "evidence_sha256": evidence["evidence_sha256"],
                    "manifest_sha256": manifest["manifest_sha256"],
                    "tenant_id": analysis["tenant_id"],
                }
                self.assertEqual(
                    evidence["finding_sha256"], self.lab.digest_json(binding))

    def test_resealed_derived_claim_tampering_is_rejected(self):
        mutations = (
            (("dataset", "case_count"), len(self.report["cases"]) + 1),
            (("dataset", "cases_sha256"), "0" * 64),
            (("quality_gate", "passed"), False),
            (("metrics", "aggregate", "tp"), 0),
            (("complete",), False),
            (("status",), "quality_gate_miss"),
        )
        for path, replacement in mutations:
            with self.subTest(path=path):
                changed = copy.deepcopy(self.report)
                target = changed
                for component in path[:-1]:
                    target = target[component]
                target[path[-1]] = replacement
                changed = _reseal(self.lab, changed)
                self.assertFalse(self.lab.verify_report(changed))

    def test_reports_contain_no_raw_source_or_absolute_paths(self):
        self.assert_minimal_safe_report(self.report)


class IsolationTests(LabContractCase):
    def test_tenant_reports_are_disjoint_and_tokens_do_not_cross(self):
        report = self.lab.run_isolation_self_test()
        self.assert_report_envelope(report, "isolation")
        tenants = report["tenants"]
        self.assertIsInstance(tenants, dict)
        self.assertEqual(len(tenants), 2)
        names = sorted(tenants)
        first, second = tenants[names[0]], tenants[names[1]]
        first_tokens = set(first["finding_tokens"])
        second_tokens = set(second["finding_tokens"])
        self.assertTrue(first_tokens)
        self.assertTrue(second_tokens)
        self.assertTrue(first_tokens.isdisjoint(second_tokens))
        first_json = json.dumps(first, sort_keys=True)
        second_json = json.dumps(second, sort_keys=True)
        for token in second_tokens:
            self.assertNotIn(token, first_json)
        for token in first_tokens:
            self.assertNotIn(token, second_json)
        self.assertTrue(all(report["checks"].values()))

    def test_canaries_source_and_exact_manifests_never_cross_or_leak(self):
        report = self.lab.run_isolation_self_test()
        rendered = self.lab.canonical_json(report)
        for tenant, sources in self.fixtures.TENANT_FIXTURES.items():
            canary = self.fixtures.TENANT_CANARIES[tenant]
            self.assertNotIn(canary, rendered)
            for source in sources:
                self.assertNotIn(source.content, rendered)
                for line in source.content.splitlines():
                    if len(line.strip()) >= 10:
                        self.assertNotIn(line.strip(), rendered)

            summary = report["tenants"][tenant]
            analysis = summary["analysis"]
            expected_manifest = self.lab.build_manifest(
                tenant,
                tuple(self.lab.SourceUnit(item.path, item.content)
                      for item in sources),
            )
            self.assertEqual(analysis["tenant_id"], tenant)
            self.assertEqual(analysis["manifest"], expected_manifest)
            self.assertEqual(
                summary["manifest_sha256"],
                expected_manifest["manifest_sha256"])
            self.assertEqual(
                summary["finding_tokens"],
                [item["finding_sha256"] for item in analysis["findings"]])
            self.assertEqual(
                summary["path_hashes"],
                [hashlib.sha256(item["path"].encode("utf-8")).hexdigest()
                 for item in expected_manifest["files"]])

    def test_resealed_replacement_tenant_cannot_claim_bundled_isolation(self):
        report = self.lab.run_isolation_self_test()
        replacement = self.lab.analyze_tenant(
            "tenant-alpha",
            (self.lab.SourceUnit(
                "src/replacement.py",
                "def f(x):\n    return eval(x)\n",
            ),),
        )
        self.assertTrue(self.lab.verify_report(replacement))
        expected_alpha_manifest = self.lab.build_manifest(
            "tenant-alpha",
            tuple(self.lab.SourceUnit(item.path, item.content)
                  for item in self.fixtures.TENANT_FIXTURES["tenant-alpha"]),
        )
        self.assertNotEqual(replacement["manifest"], expected_alpha_manifest)

        forged = copy.deepcopy(report)
        forged["tenants"]["tenant-alpha"] = {
            "analysis": replacement,
            "finding_tokens": [
                item["finding_sha256"] for item in replacement["findings"]
            ],
            "manifest_sha256": replacement["manifest"]["manifest_sha256"],
            "path_hashes": [
                hashlib.sha256(item["path"].encode("utf-8")).hexdigest()
                for item in replacement["manifest"]["files"]
            ],
        }

        alpha = forged["tenants"]["tenant-alpha"]["analysis"]
        beta = forged["tenants"]["tenant-beta"]["analysis"]
        alpha_json = self.lab.canonical_json(alpha)
        beta_json = self.lab.canonical_json(beta)
        alpha_tokens = {
            item["finding_sha256"] for item in alpha["findings"]
        }
        beta_tokens = {
            item["finding_sha256"] for item in beta["findings"]
        }
        forged["checks"] = {
            "alpha_canary_redacted": (
                self.fixtures.TENANT_CANARIES["tenant-alpha"]
                not in alpha_json),
            "beta_canary_redacted": (
                self.fixtures.TENANT_CANARIES["tenant-beta"]
                not in beta_json),
            "alpha_canary_absent_from_beta": (
                self.fixtures.TENANT_CANARIES["tenant-alpha"]
                not in beta_json),
            "beta_canary_absent_from_alpha": (
                self.fixtures.TENANT_CANARIES["tenant-beta"]
                not in alpha_json),
            "different_input_manifests": (
                alpha["manifest"]["manifest_sha256"]
                != beta["manifest"]["manifest_sha256"]),
            "finding_tokens_disjoint": alpha_tokens.isdisjoint(beta_tokens),
            "tenant_ids_not_crossed": (
                "tenant-beta" not in alpha_json
                and "tenant-alpha" not in beta_json),
            "both_tenants_have_independent_findings": bool(
                alpha_tokens and beta_tokens),
            "tenant_reports_verify": (
                self.lab.verify_report(alpha)
                and self.lab.verify_report(beta)),
        }
        forged["complete"] = bool(alpha["complete"] and beta["complete"])
        forged["status"] = (
            "incomplete" if not forged["complete"] else
            ("success" if all(forged["checks"].values())
             else "quality_gate_miss")
        )
        forged = _reseal(self.lab, forged)
        self.assertFalse(
            self.lab.verify_report(forged),
            "isolation accepted a tenant outside the exact bundled fixtures")

    def test_resealed_tenant_swap_and_derived_tampering_are_rejected(self):
        report = self.lab.run_isolation_self_test()
        names = sorted(report["tenants"])

        swapped = copy.deepcopy(report)
        swapped["tenants"][names[0]]["analysis"], swapped["tenants"][names[1]][
            "analysis"] = (
                swapped["tenants"][names[1]]["analysis"],
                swapped["tenants"][names[0]]["analysis"],
            )
        self.assertFalse(self.lab.verify_report(_reseal(self.lab, swapped)))

        mutations = []
        changed_check = copy.deepcopy(report)
        check_name = sorted(changed_check["checks"])[0]
        changed_check["checks"][check_name] = False
        mutations.append(changed_check)

        changed_manifest = copy.deepcopy(report)
        changed_manifest["tenants"][names[0]]["manifest_sha256"] = (
            changed_manifest["tenants"][names[1]]["manifest_sha256"])
        mutations.append(changed_manifest)

        changed_tokens = copy.deepcopy(report)
        changed_tokens["tenants"][names[0]]["finding_tokens"].append("0" * 64)
        mutations.append(changed_tokens)

        changed_complete = copy.deepcopy(report)
        changed_complete["complete"] = False
        changed_complete["status"] = "incomplete"
        mutations.append(changed_complete)

        for changed in mutations:
            self.assertFalse(self.lab.verify_report(_reseal(self.lab, changed)))


class SelfTestDerivationTests(LabContractCase):
    def test_self_test_children_and_status_are_derived_and_bound(self):
        report = self.lab.run_self_test()
        self.assertTrue(self.lab.verify_report(report))
        self.assertEqual(report["benchmark"], self.lab.run_benchmark())
        self.assertEqual(report["isolation"], self.lab.run_isolation_self_test())
        self.assertIs(report["children_verify"], True)

        mutations = []
        changed_child_flag = copy.deepcopy(report)
        changed_child_flag["children_verify"] = False
        mutations.append(changed_child_flag)
        changed_complete = copy.deepcopy(report)
        changed_complete["complete"] = False
        changed_complete["status"] = "incomplete"
        mutations.append(changed_complete)
        changed_status = copy.deepcopy(report)
        changed_status["status"] = "quality_gate_miss"
        mutations.append(changed_status)
        for changed in mutations:
            self.assertFalse(self.lab.verify_report(_reseal(self.lab, changed)))


class RootCliTests(LabContractCase):
    def test_root_cli_is_cwd_independent_and_ignores_caller_module_planting(self):
        entrypoint = PRODUCT_ROOT / "attestor_cli.py"
        self.assertTrue(entrypoint.is_file())
        with tempfile.TemporaryDirectory() as temporary:
            planted = Path(temporary) / "lab.py"
            planted.write_text(
                "raise RuntimeError('caller module was imported')\n",
                encoding="utf-8")
            completed = subprocess.run(
                [sys.executable, "-I", "-B", "-X", "utf8", str(entrypoint),
                 "lab", "benchmark", "--format", "json"],
                cwd=temporary,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
                check=False,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertNotIn("Traceback", completed.stdout + completed.stderr)
        report = json.loads(completed.stdout)
        self.assert_report_envelope(report, "benchmark")


if __name__ == "__main__":
    unittest.main()
