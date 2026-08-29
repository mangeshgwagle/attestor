#!/usr/bin/env python3
"""Adversarial tests for Attestor 3.5 proof-gated multi-file repair."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path

import execution_fabric35 as fabric35
import transactional_repair35 as repair35


IMAGE = "registry.example/attestor/python-checks@sha256:" + "b" * 64
EXEC_AUTH = fabric35.ExecutionAuthorization(True, "verify full repair transaction", "tests")
APPLY_AUTH = repair35.ApplyAuthorization(True, "apply verified repair transaction", "tests")


def digest(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def result(stdout="", returncode=0, status="completed"):
    return fabric35.ExecutionResult(
        status=status, returncode=returncode, stdout=stdout, stderr="",
        timed_out=status == "timed-out", truncated=False, runtime="mock-rootless",
        request_sha256="1" * 64, argv_sha256="2" * 64, transcript=(), reason="",
    )


class FakeFabric:
    """Evidence-producing fabric double; it never invokes a host command."""

    def __init__(self, *, new_finding=False, keep_target=False, malformed=False,
                 fail_after_kind="", callback=None, transcript_valid=True):
        self.calls = []
        self.new_finding = new_finding
        self.keep_target = keep_target
        self.malformed = malformed
        self.fail_after_kind = fail_after_kind
        self.callback = callback
        self.transcript_valid = transcript_valid

    def verify_transcript(self, _transcript):
        return self.transcript_valid

    def run(self, request, authorization):
        self.calls.append((request, authorization))
        phase = Path(request.workspace).name
        kind = request.label.split("-")[1]
        if self.callback:
            self.callback(len(self.calls), request)
        if kind == "scanner":
            if self.malformed and phase == "after":
                return result("not-json")
            findings = []
            if phase == "before" or self.keep_target:
                findings.append({"rule": "SEC001", "path": "app.py",
                                 "message": "unsafe evaluation"})
            if phase == "after" and self.new_finding:
                findings.append({"rule": "SEC999", "path": "app.py",
                                 "message": "new regression"})
            return result(json.dumps({"findings": findings}))
        if phase == "after" and kind == self.fail_after_kind:
            return result("failed", returncode=2)
        return result("ok")

    def run_disposable(self, request, authorization):
        return self.run(request, authorization)


class TransactionalRepair35Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.old = "def public(value):\n    return eval(value)\n"
        self.new = "def public(value):\n    return int(value)\n"
        # Bytes keep the expected digest independent of host newline translation.
        (self.root / "app.py").write_bytes(self.old.encode("utf-8"))

    def tearDown(self):
        self.temporary.cleanup()

    def plan(self, changes=None, target_rules=("SEC001",)):
        changes = changes or (
            repair35.FileChange("app.py", digest(self.old), self.new),
        )
        return repair35.ChangeSet(tuple(changes), target_rules=target_rules,
                                  rationale="replace unsafe evaluation")

    @staticmethod
    def hooks():
        return (
            repair35.VerificationHook("scan", "scanner", IMAGE,
                                      ("attestor-scan", "--json"), (0, 1)),
            repair35.VerificationHook("build", "build", IMAGE,
                                      ("python", "-m", "compileall", "-q", ".")),
            repair35.VerificationHook("tests", "test", IMAGE,
                                      ("python", "-m", "unittest", "discover")),
        )

    def test_default_is_verified_dry_run_and_all_hooks_use_disposable_fabric(self):
        fake = FakeFabric()
        engine = repair35.TransactionalRepair(self.root, fake)
        outcome = engine.repair(self.plan(), self.hooks(),
                                execution_authorization=EXEC_AUTH)
        self.assertEqual(outcome.status, "verified-dry-run")
        self.assertTrue(outcome.verified)
        self.assertFalse(outcome.applied)
        self.assertEqual((self.root / "app.py").read_text(), self.old)
        self.assertEqual(len(fake.calls), 6)
        phases = [Path(call[0].workspace).name for call in fake.calls]
        self.assertEqual(phases, ["before"] * 3 + ["after"] * 3)
        self.assertTrue(all(Path(call[0].workspace) != self.root for call in fake.calls))
        self.assertTrue(all(call[1] is EXEC_AUTH for call in fake.calls))
        self.assertEqual(outcome.evidence["scanner"]["target_before"], 1)
        self.assertEqual(outcome.evidence["scanner"]["target_after"], 0)

    def test_apply_requires_separate_explicit_authorization(self):
        fake = FakeFabric()
        engine = repair35.TransactionalRepair(self.root, fake)
        outcome = engine.repair(self.plan(), self.hooks(),
                                execution_authorization=EXEC_AUTH, apply=True)
        self.assertEqual(outcome.status, "refused")
        self.assertIn("separate apply authorization", outcome.reasons[0])
        self.assertFalse(fake.calls)
        self.assertEqual((self.root / "app.py").read_text(), self.old)

    def test_verified_change_set_applies_with_stale_guards(self):
        fake = FakeFabric()
        engine = repair35.TransactionalRepair(self.root, fake)
        outcome = engine.repair(
            self.plan(), self.hooks(), execution_authorization=EXEC_AUTH,
            apply=True, apply_authorization=APPLY_AUTH)
        self.assertEqual(outcome.status, "applied", outcome)
        self.assertTrue(outcome.applied)
        self.assertEqual((self.root / "app.py").read_text(), self.new)
        self.assertFalse((self.root / repair35.LOCK_NAME).exists())

    def test_stale_input_hash_is_rejected_before_any_execution(self):
        fake = FakeFabric()
        stale = repair35.FileChange("app.py", "0" * 64, self.new)
        outcome = repair35.TransactionalRepair(self.root, fake).repair(
            self.plan((stale,)), self.hooks(), execution_authorization=EXEC_AUTH)
        self.assertEqual(outcome.status, "refused")
        self.assertIn("stale", outcome.reasons[0])
        self.assertFalse(fake.calls)

    def test_workspace_change_after_verification_blocks_apply(self):
        def mutate_after_last_hook(call_number, _request):
            if call_number == 6:
                (self.root / "external.txt").write_text("human edit", encoding="utf-8")

        fake = FakeFabric(callback=mutate_after_last_hook)
        outcome = repair35.TransactionalRepair(self.root, fake).repair(
            self.plan(), self.hooks(), execution_authorization=EXEC_AUTH,
            apply=True, apply_authorization=APPLY_AUTH)
        self.assertEqual(outcome.status, "rejected")
        self.assertIn("changed during", " ".join(outcome.reasons))
        self.assertEqual((self.root / "app.py").read_text(), self.old)
        self.assertEqual((self.root / "external.txt").read_text(), "human edit")

    def test_path_escape_and_case_collision_are_rejected(self):
        with self.assertRaises(repair35.RepairError):
            repair35.FileChange("../outside.py", None, "x = 1\n")
        with self.assertRaises(repair35.RepairError):
            repair35.FileChange("C:\\outside.py", None, "x = 1\n")
        one = repair35.FileChange("new.py", None, "x = 1\n")
        two = repair35.FileChange("NEW.py", None, "x = 2\n")
        with self.assertRaises(repair35.RepairError):
            repair35.ChangeSet((one, two), target_rules=("SEC001",))

    def test_portable_path_boundary_rejects_windows_and_unicode_aliases(self):
        invalid = [
            "CON", "con.txt", "folder/PRN.py", "COM1.py", "Lpt9",
            "COM\u00b9.txt", "CONIN$.log", "bad<name.py", "bad>name.py",
            'bad"name.py', "bad|name.py", "bad?name.py", "bad*name.py",
            "bad:name.py", "bad\x1fname.py", "bad\u202ename.py",
            "bad\ud800name.py", "trailing./file.py", "trailing /file.py",
            "cafe\u0301.py", ".ATTESTOR35-REPAIR.LOCK", "\u00e9" * 128,
            "\U0001f600" * 128, "a" * 256,
        ]
        for value in invalid:
            with self.subTest(value=ascii(value)), self.assertRaises(repair35.RepairError):
                repair35.normalize_relative_path(value)
        self.assertEqual(repair35.normalize_relative_path("safe\\dir\\file.py"),
                         "safe/dir/file.py")
        self.assertEqual(repair35.normalize_relative_path("a" * 255), "a" * 255)

    def test_symlink_workspace_is_refused_instead_of_followed(self):
        outside = self.root.parent / (self.root.name + "-outside.txt")
        outside.write_text("outside", encoding="utf-8")
        link = self.root / "link.txt"
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest("symbolic links are unavailable to this test account")
        fake = FakeFabric()
        outcome = repair35.TransactionalRepair(self.root, fake).repair(
            self.plan(), self.hooks(), execution_authorization=EXEC_AUTH)
        self.assertEqual(outcome.status, "refused")
        self.assertIn("symbolic-link", outcome.reasons[0])
        self.assertFalse(fake.calls)
        self.assertEqual(outside.read_text(), "outside")
        outside.unlink(missing_ok=True)

    def test_source_deletion_and_public_api_removal_are_refused(self):
        fake = FakeFabric()
        delete = repair35.FileChange("app.py", digest(self.old), None)
        deleted = repair35.TransactionalRepair(self.root, fake).repair(
            self.plan((delete,)), self.hooks(), execution_authorization=EXEC_AUTH)
        self.assertIn("source-file deletion", deleted.reasons[0])
        remove_api = repair35.FileChange("app.py", digest(self.old), "x = 1\n")
        removed = repair35.TransactionalRepair(self.root, fake).repair(
            self.plan((remove_api,)), self.hooks(), execution_authorization=EXEC_AUTH)
        self.assertIn("removes public API", removed.reasons[0])
        self.assertFalse(fake.calls)

    def test_replacement_size_boundary_is_enforced_before_execution(self):
        fake = FakeFabric()
        policy = repair35.RepairPolicy(
            max_file_bytes=1_024, max_change_bytes=2_048,
            max_workspace_bytes=16 * 1024 * 1024)
        huge = repair35.FileChange("app.py", digest(self.old),
                                   "def public(value):\n    return value\n#" + "x" * 1_024)
        outcome = repair35.TransactionalRepair(self.root, fake, policy).repair(
            self.plan((huge,)), self.hooks(), execution_authorization=EXEC_AUTH)
        self.assertEqual(outcome.status, "refused")
        self.assertIn("size boundary", outcome.reasons[0])
        self.assertFalse(fake.calls)

    def test_new_scanner_finding_rejects_otherwise_clean_patch(self):
        fake = FakeFabric(new_finding=True)
        outcome = repair35.TransactionalRepair(self.root, fake).repair(
            self.plan(), self.hooks(), execution_authorization=EXEC_AUTH)
        self.assertEqual(outcome.status, "rejected")
        self.assertIn("new finding", " ".join(outcome.reasons))
        self.assertEqual((self.root / "app.py").read_text(), self.old)

    def test_target_must_be_observed_and_reduced(self):
        fake = FakeFabric(keep_target=True)
        outcome = repair35.TransactionalRepair(self.root, fake).repair(
            self.plan(), self.hooks(), execution_authorization=EXEC_AUTH)
        self.assertEqual(outcome.status, "rejected")
        self.assertIn("did not reduce", " ".join(outcome.reasons))

    def test_malformed_scanner_evidence_and_failed_tests_reject(self):
        malformed = repair35.TransactionalRepair(self.root, FakeFabric(malformed=True)).repair(
            self.plan(), self.hooks(), execution_authorization=EXEC_AUTH)
        self.assertEqual(malformed.status, "rejected")
        self.assertIn("not one JSON", " ".join(malformed.reasons))
        failed = repair35.TransactionalRepair(
            self.root, FakeFabric(fail_after_kind="test")).repair(
                self.plan(), self.hooks(), execution_authorization=EXEC_AUTH)
        self.assertEqual(failed.status, "rejected")
        self.assertIn("after test", " ".join(failed.reasons))

    def test_unsigned_or_tampered_hook_evidence_is_rejected(self):
        outcome = repair35.TransactionalRepair(
            self.root, FakeFabric(transcript_valid=False)).repair(
                self.plan(), self.hooks(), execution_authorization=EXEC_AUTH)
        self.assertEqual(outcome.status, "rejected")
        self.assertIn("invalid signed transcript", " ".join(outcome.reasons))

    def test_missing_build_or_test_hook_cannot_downgrade_policy(self):
        fake = FakeFabric()
        outcome = repair35.TransactionalRepair(self.root, fake).repair(
            self.plan(), self.hooks()[:1], execution_authorization=EXEC_AUTH)
        self.assertEqual(outcome.status, "refused")
        self.assertIn("mandatory", outcome.reasons[0])
        self.assertFalse(fake.calls)

    def test_second_file_failure_rolls_back_first_file(self):
        util_old = "def helper(value):\n    return eval(value)\n"
        util_new = "def helper(value):\n    return int(value)\n"
        (self.root / "util.py").write_bytes(util_old.encode("utf-8"))
        changes = (
            repair35.FileChange("app.py", digest(self.old), self.new),
            repair35.FileChange("util.py", digest(util_old), util_new),
        )
        replace_calls = []

        def fail_once_on_second(source, target):
            replace_calls.append((Path(source), Path(target)))
            if len(replace_calls) == 2:
                raise OSError("simulated disk failure")
            os.replace(source, target)

        outcome = repair35.TransactionalRepair(
            self.root, FakeFabric(), replace_file=fail_once_on_second).repair(
                self.plan(changes), self.hooks(), execution_authorization=EXEC_AUTH,
                apply=True, apply_authorization=APPLY_AUTH)
        self.assertEqual(outcome.status, "rolled-back", outcome)
        self.assertTrue(outcome.rolled_back)
        self.assertEqual((self.root / "app.py").read_text(), self.old)
        self.assertEqual((self.root / "util.py").read_text(), util_old)
        self.assertFalse((self.root / repair35.LOCK_NAME).exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
