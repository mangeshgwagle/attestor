from __future__ import annotations

import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import repair_director41 as director
import scanengine


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class RepairDirector41Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def write(self, name: str, value: str) -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8", newline="")
        return path

    def candidate_document(self, path: Path, content: str) -> dict:
        return {
            "schema": director.CANDIDATE_SCHEMA,
            "candidate_id": "provider-1",
            "producer": "offline-test",
            "changes": [{
                "path": path.relative_to(self.root).as_posix(),
                "before_sha256": sha(path.read_bytes()),
                "content": content,
            }],
            "target_rules": ["dangerous-eval"],
            "target_fingerprints": [],
            "rationale": "replace dynamic expression evaluation",
            "producer_evidence": {"response_sha256": "a" * 64},
        }

    def test_provider_candidate_is_exact_json_and_stale_guarded(self) -> None:
        path = self.write("app.py", "def parse(value):\n    return eval(value)\n")
        document = self.candidate_document(
            path, "import ast\ndef parse(value):\n    return ast.literal_eval(value)\n")
        candidate = director.candidate_from_provider_text(
            json.dumps(document), self.root)
        self.assertEqual(candidate.candidate_id, "provider-1")
        self.assertEqual(candidate.changes[0].operation, "update")
        with self.assertRaises(director.RepairDirectorError):
            director.candidate_from_provider_text(
                "```json\n" + json.dumps(document) + "\n```", self.root)
        duplicated = json.dumps(document).replace(
            '"candidate_id": "provider-1"',
            '"candidate_id": "provider-1", "candidate_id": "provider-2"')
        with self.assertRaisesRegex(director.RepairDirectorError, "duplicate JSON key"):
            director.candidate_from_provider_text(duplicated, self.root)
        with mock.patch.object(director.json, "loads", side_effect=RecursionError):
            with self.assertRaisesRegex(director.RepairDirectorError, "exactly one JSON"):
                director.candidate_from_provider_text("{}", self.root)
        path.write_text("changed\n", encoding="utf-8")
        with self.assertRaises(director.RepairDirectorError):
            director.candidate_from_document(document, self.root)

    def test_path_traversal_and_duplicate_candidates_fail_closed(self) -> None:
        path = self.write("app.py", "value = eval(data)\n")
        document = self.candidate_document(path, "value = data\n")
        document["changes"][0]["path"] = "../outside.py"
        with self.assertRaises(director.RepairDirectorError):
            director.candidate_from_document(document, self.root)

        valid = self.candidate_document(path, "value = data\n")
        candidate = director.candidate_from_document(valid, self.root)
        with self.assertRaises(director.RepairDirectorError):
            director.direct(self.root, candidates=[candidate, candidate], mechanical=False)

    def test_candidate_paths_share_the_portable_transaction_boundary(self) -> None:
        invalid = [
            "nul.txt", "folder/AUX", "COM3.py", "LPT\u00b2.txt",
            "bad<name.py", "bad>name.py", 'bad"name.py', "bad|name.py",
            "bad?name.py", "bad*name.py", "bad:name.py", "bad\x1fname.py",
            "bad\u202ename.py", "bad\ud800name.py", "trailing. ",
            "cafe\u0301.py", ".ATTESTOR35-REPAIR.LOCK", "\u00e9" * 128,
            "\U0001f600" * 128, "x" * 256,
        ]
        for value in invalid:
            with self.subTest(value=ascii(value)), self.assertRaises(director.RepairDirectorError):
                director._relative(value)

    def test_oversized_baselines_are_rejected_before_full_read(self) -> None:
        path = self.write("large.py", "value = 1\n")
        document = self.candidate_document(path, "value = 2\n")
        with path.open("wb") as stream:
            stream.truncate(director.MAX_FILE_BYTES + 1)
        with mock.patch.object(Path, "read_bytes",
                               side_effect=AssertionError("unbounded read attempted")):
            with self.assertRaisesRegex(director.RepairDirectorError, "baseline.*size"):
                director.candidate_from_document(document, self.root)

        path.write_text("value = 1\n", encoding="utf-8")
        document = self.candidate_document(path, "value = 2\n")
        candidate = director.candidate_from_document(document, self.root)
        with path.open("wb") as stream:
            stream.truncate(director.MAX_FILE_BYTES + 1)
        with mock.patch.object(Path, "read_bytes",
                               side_effect=AssertionError("unbounded read attempted")):
            with self.assertRaisesRegex(director.RepairDirectorError, "baseline.*size"):
                director.static_evaluate(self.root, candidate)

        path.write_text("value = 1\n", encoding="utf-8")
        finding = {"rule": "dangerous-eval", "path": str(path),
                   "message": "fixture", "line": 1}
        with mock.patch.object(
                director, "_read_baseline",
                side_effect=director.RepairDirectorError("bounded baseline rejected")) as bounded, \
                mock.patch.object(Path, "read_bytes",
                                  side_effect=AssertionError("unbounded read attempted")):
            self.assertEqual(director.mechanical_candidates(self.root, [finding]), [])
        bounded.assert_called_once()

    def test_candidate_json_cli_checks_size_before_read_bytes(self) -> None:
        provider = self.root / "candidate.json"
        provider.write_bytes(b"x" * 9)
        with mock.patch.object(director, "MAX_PROVIDER_BYTES", 8), \
                mock.patch.object(Path, "read_bytes",
                                  side_effect=AssertionError("unbounded read attempted")), \
                mock.patch.object(
                    director.argparse.ArgumentParser, "error",
                    side_effect=director.RepairDirectorError(
                        "candidate file exceeds the size boundary")):
            with self.assertRaisesRegex(director.RepairDirectorError, "candidate file.*size"):
                director.main([str(self.root), "--candidate-json", str(provider)])

    def test_candidate_paths_refuse_linked_parent_directories(self) -> None:
        real = self.root / "real"
        real.mkdir()
        path = real / "app.py"
        path.write_text("value = eval(data)\n", encoding="utf-8")
        linked = self.root / "linked"
        try:
            linked.symlink_to(real, target_is_directory=True)
        except OSError as exc:
            self.skipTest("directory symlink privilege unavailable: %s" % type(exc).__name__)
        document = self.candidate_document(path, "value = data\n")
        document["changes"][0]["path"] = "linked/app.py"
        with self.assertRaisesRegex(director.RepairDirectorError, "link|reparse"):
            director.candidate_from_document(document, self.root)

    def test_mechanical_candidate_is_qualified_but_never_called_verified(self) -> None:
        path = self.write("app.py", "def parse(value):\n    return eval(value)\n")
        scan = scanengine.scan([str(path)], jobs=1, deep=True, tools=False,
                               use_cache=False)
        self.assertIn("dangerous-eval", {item.rule for item in scan.issues})
        candidates = director.mechanical_candidates(self.root, scan.issues)
        self.assertEqual(len(candidates), 1)
        self.assertIn(b"ast.literal_eval", candidates[0].changes[0].content or b"")

        report = director.direct(self.root, issue="remove unsafe evaluation",
                                 findings=scan.issues, mechanical=True)
        self.assertEqual(report["status"], "candidates-qualified")
        self.assertEqual(report["summary"]["static_qualified"], 1)
        self.assertEqual(report["summary"]["verified"], 0)
        self.assertFalse(report["evaluations"][0]["verified"])
        self.assertFalse(report["execution"]["target_code_executed"])
        self.assertFalse(report["execution"]["workspace_written"])
        self.assertIn("static qualification is not verification",
                      " ".join(report["coverage"]["gaps"]).lower())

    def test_static_regression_is_refused(self) -> None:
        path = self.write("app.py", "def parse(value):\n    return eval(value)\n")
        document = self.candidate_document(
            path,
            "PASSWORD = \"this-is-a-very-secret-password\"\n"
            "def parse(value):\n    return value\n",
        )
        candidate = director.candidate_from_document(document, self.root)
        result = director.static_evaluate(self.root, candidate)
        self.assertEqual(result["status"], "refused")
        self.assertTrue(any("high-severity" in reason for reason in result["reasons"]))

    def test_stale_candidate_is_revalidated_at_evaluation_time(self) -> None:
        path = self.write("app.py", "def parse(value):\n    return eval(value)\n")
        scan = scanengine.scan([str(path)], jobs=1, deep=True, tools=False,
                               use_cache=False)
        candidate = director.mechanical_candidates(self.root, scan.issues)[0]
        path.write_text("value = 999\n", encoding="utf-8")
        with self.assertRaisesRegex(director.RepairDirectorError, "stale"):
            director.static_evaluate(self.root, candidate)
        report = director.direct(self.root, findings=scan.issues,
                                 candidates=[candidate], mechanical=False)
        self.assertEqual(report["evaluations"][0]["status"], "refused")
        self.assertTrue(any("boundary refused" in reason
                            for reason in report["evaluations"][0]["reasons"]))

    def test_fingerprint_only_or_unrelated_targets_never_auto_qualify(self) -> None:
        path = self.write("safe.py", "value = 1\n")
        candidate = director.RepairCandidate(
            "fake-fingerprint", "test",
            (director.CandidateChange("safe.py", sha(path.read_bytes()),
                                      b"value = 2\n"),),
            (), ("a" * 64,), "unrelated change")
        static = director.static_evaluate(self.root, candidate)
        self.assertEqual(static["status"], "refused")
        self.assertTrue(any("fingerprint-only" in reason
                            for reason in static["reasons"]))
        direct = director.direct(
            self.root, findings=[{"rule": "some-rule", "path": "safe.py",
                                  "fingerprint": "b" * 64}],
            candidates=[candidate], mechanical=False)
        self.assertEqual(direct["evaluations"][0]["status"], "refused")
        self.assertTrue(any("do not intersect" in reason
                            for reason in direct["evaluations"][0]["reasons"]))
        mixed = director.RepairCandidate(
            "fake-mixed-target", "test",
            (director.CandidateChange("safe.py", sha(path.read_bytes()),
                                      b"value = 3\n"),),
            ("not-observed",), ("b" * 64,), "still unrelated")
        mixed_report = director.direct(
            self.root, findings=[{"rule": "different-rule", "path": "safe.py",
                                  "fingerprint": "b" * 64}],
            candidates=[mixed], mechanical=False)
        self.assertEqual(mixed_report["evaluations"][0]["status"], "refused")
        self.assertTrue(any("not observed" in reason
                            for reason in mixed_report["evaluations"][0]["reasons"]))

    def test_complete_improved_result_is_explicit_and_labeled_unverified(self) -> None:
        path = self.write("app.py", "def parse(value):\n    return eval(value)\n")
        scan = scanengine.scan([str(path)], jobs=1, deep=True, tools=False,
                               use_cache=False)
        hidden = director.direct(self.root, findings=scan.issues)
        self.assertIsNone(hidden["selected_candidate_output"])
        shown = director.direct(self.root, findings=scan.issues,
                                include_candidate_source=True)
        output = shown["selected_candidate_output"]
        self.assertTrue(output["complete"])
        self.assertEqual(output["state"], "unverified-review-candidate")
        self.assertIn("ast.literal_eval", output["changes"][0]["content"])
        self.assertFalse(shown["evaluations"][0]["verified"])
        self.assertEqual(path.read_text(encoding="utf-8"),
                         "def parse(value):\n    return eval(value)\n")

    def test_reports_are_deterministic_for_identical_inputs(self) -> None:
        path = self.write("app.py", "def parse(value):\n    return eval(value)\n")
        scan = scanengine.scan([str(path)], jobs=1, deep=True, tools=False,
                               use_cache=False)
        first = director.direct(self.root, findings=scan.issues)
        second = director.direct(self.root, findings=scan.issues)
        self.assertEqual(first, second)
        self.assertRegex(first["report_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
