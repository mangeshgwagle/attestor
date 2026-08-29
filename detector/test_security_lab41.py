#!/usr/bin/env python3
from __future__ import annotations

import dataclasses
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import execution_fabric35 as fabric35
import security_lab41 as lab41
import security_validation413 as validation413


IMAGE = "registry.example/attestor/lab@sha256:" + "d" * 64


class FakeProcess:
    def __init__(self):
        self.stdout = io.BytesIO(b"lab complete\n")
        self.stderr = io.BytesIO()
        self.returncode = 0

    def wait(self, timeout=None):
        return self.returncode

    def kill(self):
        self.returncode = -9


class CapturingFactory:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        return FakeProcess()


def capabilities(eligible: bool = True) -> fabric35.FabricCapabilities:
    runtime = fabric35.RuntimeCapability(
        "podman", "/mock/podman", True, eligible, "linux",
        eligible, False, "fixture")
    return fabric35.FabricCapabilities((runtime,), False)


def workspace() -> tuple[tempfile.TemporaryDirectory, Path]:
    temporary = tempfile.TemporaryDirectory()
    root = Path(temporary.name)
    (root / "tests").mkdir()
    (root / "tests" / "fuzz_target.py").write_text("def test_target():\n    assert True\n",
                                                     encoding="utf-8")
    return temporary, root


def authorization(plan: lab41.LabPlan, **overrides) -> lab41.LabAuthorization:
    values = {"granted": True, "workspace_sha256": plan.workspace_sha256,
              "experiments": (plan.experiment,), "purpose": "verify a local test target",
              "actor": "test-suite", "plan_sha256": plan.plan_sha256}
    values.update(overrides)
    return lab41.LabAuthorization(**values)


class SecurityLab41Tests(unittest.TestCase):
    def make_lab(self, *, eligible=True, images=None):
        factory = CapturingFactory()
        fabric = fabric35.ExecutionFabric(
            capabilities(eligible), process_factory=factory, signing_key=b"k" * 32)
        configured = {"fuzz": IMAGE} if images is None else images
        return lab41.SecurityLab(fabric, configured), factory

    def test_unconfigured_adapter_is_explicitly_unavailable_and_never_executes(self):
        temporary, root = workspace()
        self.addCleanup(temporary.cleanup)
        lab, factory = self.make_lab(images={})
        plan = lab.plan("fuzz", root, "tests/fuzz_target.py")
        result = lab.execute(plan)
        self.assertEqual(plan.status, "unavailable")
        self.assertTrue(lab.verify_plan(plan))
        self.assertEqual(result["status"], "refused")
        self.assertIn("adapter", result["reason"])
        self.assertFalse(factory.calls)

    def test_only_explicit_test_fuzz_and_crash_targets_are_eligible(self):
        temporary, root = workspace()
        self.addCleanup(temporary.cleanup)
        (root / "production.py").write_text("print('live')", encoding="utf-8")
        lab, _factory = self.make_lab()
        for target in ("production.py", "../outside.py"):
            with self.subTest(target=target), self.assertRaises(lab41.SecurityLabError):
                lab.plan("fuzz", root, target)
        with self.assertRaises(lab41.SecurityLabError):
            lab.plan("crash-minimize", root, "tests/fuzz_target.py")
        (root / "crashes").mkdir()
        (root / "crashes" / "case-1").write_bytes(b"boom")
        self.assertEqual(lab.plan("crash-minimize", root, "crashes/case-1").status, "unavailable")

    def test_workspace_attestation_is_deterministic_and_changes_with_any_file(self):
        temporary, root = workspace()
        self.addCleanup(temporary.cleanup)
        one = lab41.workspace_scope_sha256(root)
        two = lab41.workspace_scope_sha256(root)
        self.assertEqual(one, two)
        (root / ".git").mkdir()
        (root / ".git" / "config").write_text("changed", encoding="utf-8")
        self.assertNotEqual(one, lab41.workspace_scope_sha256(root))

    def test_authorized_plan_executes_only_the_fixed_command_in_disposable_fabric(self):
        temporary, root = workspace()
        self.addCleanup(temporary.cleanup)
        lab, factory = self.make_lab()
        plan = lab.plan("fuzz", root, "tests/fuzz_target.py", duration_seconds=17)
        with mock.patch.dict(os.environ, {}, clear=True):
            result = lab.execute(plan, authorization(plan))
        self.assertEqual(result["status"], "completed", result)
        self.assertEqual(result["controls"], {"host_execution": False, "network": False,
                                               "workspace": "disposable-copy",
                                               "image_pull": False})
        self.assertEqual(len(factory.calls), 1)
        argv, kwargs = factory.calls[0]
        self.assertIn("--pull=never", argv)
        self.assertIn("--network=none", argv)
        image_index = argv.index(IMAGE)
        self.assertEqual(argv[image_index + 1:], list(plan.command))
        self.assertEqual(plan.command, ("attestor-security-lab", "fuzz", "--target",
                                        "tests/fuzz_target.py", "--duration", "17",
                                        "--artifacts", "/tmp/attestor-artifacts"))
        self.assertFalse(kwargs["shell"])

    def test_one_use_gateway_consumes_patch_and_plan_bound_permission(self):
        temporary, root = workspace()
        self.addCleanup(temporary.cleanup)
        lab, factory = self.make_lab()
        plan = lab.plan("fuzz", root, "tests/fuzz_target.py")
        registry = validation413.ApprovalRegistry(
            b"a" * 32, clock=lambda: 1_800_000_000)
        token = registry.issue(
            root_identity_sha256=plan.workspace_sha256,
            patch_sha256=plan.workspace_sha256,
            plan_sha256=plan.plan_sha256,
            purpose="sandbox-execution",
            confirmed=True,
            nonce="f" * 48,
        )
        result = validation413.execute_security_lab_once(
            lab, plan, registry, token)
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["permission_retained"])
        self.assertFalse(result["authorization_reusable"])
        self.assertEqual(len(factory.calls), 1)
        with self.assertRaises(validation413.ValidationError):
            validation413.execute_security_lab_once(
                lab, plan, registry, token)
        self.assertEqual(len(factory.calls), 1)

    def test_omitted_wrong_workspace_or_wrong_plan_authorization_refuses(self):
        temporary, root = workspace()
        self.addCleanup(temporary.cleanup)
        lab, factory = self.make_lab()
        plan = lab.plan("fuzz", root, "tests/fuzz_target.py")
        candidates = [None,
                      authorization(plan, workspace_sha256="a" * 64),
                      authorization(plan, plan_sha256="b" * 64),
                      authorization(plan, experiments=("mutation",))]
        for candidate in candidates:
            with self.subTest(candidate=candidate):
                result = lab.execute(plan, candidate)
                self.assertEqual(result["status"], "refused")
                self.assertIn("plan-bound", result["reason"])
        self.assertFalse(factory.calls)

    def test_caller_rehashed_arbitrary_command_is_still_rejected(self):
        temporary, root = workspace()
        self.addCleanup(temporary.cleanup)
        lab, factory = self.make_lab()
        plan = lab.plan("fuzz", root, "tests/fuzz_target.py")
        forged = dataclasses.replace(plan, command=("sh", "-c", "id"), plan_sha256="")
        forged = dataclasses.replace(
            forged, plan_sha256=lab41._sha(lab41._plan_digest_body(forged)))
        self.assertFalse(lab.verify_plan(forged))
        result = lab.execute(forged, authorization(forged))
        self.assertEqual(result["status"], "refused")
        self.assertIn("integrity", result["reason"])
        self.assertFalse(factory.calls)

    def test_plan_field_or_digest_tampering_is_detected(self):
        temporary, root = workspace()
        self.addCleanup(temporary.cleanup)
        lab, _factory = self.make_lab()
        plan = lab.plan("fuzz", root, "tests/fuzz_target.py")
        self.assertTrue(lab.verify_plan(plan))
        self.assertFalse(lab.verify_plan(dataclasses.replace(plan, duration_seconds=99)))
        self.assertFalse(lab.verify_plan(dataclasses.replace(plan, plan_sha256="0" * 64)))

    def test_workspace_change_after_plan_is_refused_before_container_start(self):
        temporary, root = workspace()
        self.addCleanup(temporary.cleanup)
        lab, factory = self.make_lab()
        plan = lab.plan("fuzz", root, "tests/fuzz_target.py")
        auth = authorization(plan)
        (root / "new-file.txt").write_text("changed", encoding="utf-8")
        result = lab.execute(plan, auth)
        self.assertEqual(result["status"], "refused")
        self.assertIn("workspace changed", result["reason"])
        self.assertFalse(factory.calls)

    def test_ineligible_fabric_refuses_even_with_valid_plan_and_authorization(self):
        temporary, root = workspace()
        self.addCleanup(temporary.cleanup)
        lab, factory = self.make_lab(eligible=False)
        plan = lab.plan("fuzz", root, "tests/fuzz_target.py")
        result = lab.execute(plan, authorization(plan))
        self.assertEqual(result["status"], "refused")
        self.assertIn("eligible local rootless", result["reason"])
        self.assertFalse(factory.calls)

    def test_ambient_remote_daemon_selector_is_rechecked_at_execution_time(self):
        temporary, root = workspace()
        self.addCleanup(temporary.cleanup)
        lab, factory = self.make_lab()
        plan = lab.plan("fuzz", root, "tests/fuzz_target.py")
        with mock.patch.dict(os.environ, {"DOCKER_HOST": "tcp://attacker:2375"}, clear=True):
            result = lab.execute(plan, authorization(plan))
        self.assertEqual(result["status"], "refused")
        self.assertIn("ambient runtime endpoint", result["reason"])
        self.assertFalse(factory.calls)

    def test_capabilities_never_claim_host_remote_network_or_arbitrary_commands(self):
        lab, _factory = self.make_lab(images={"fuzz": IMAGE, "mutation": "latest"})
        report = lab.capabilities()
        self.assertTrue(report["adapters"]["fuzz"]["available"])
        self.assertFalse(report["adapters"]["mutation"]["available"])
        self.assertIn("host execution", report["unavailable_adapters"])
        self.assertIn("arbitrary command execution", report["unavailable_adapters"])
        self.assertIn("live targets", report["unavailable_adapters"])

    def test_invalid_image_duration_experiment_and_deleted_target_fail_closed(self):
        temporary, root = workspace()
        self.addCleanup(temporary.cleanup)
        lab, factory = self.make_lab(images={"fuzz": "attestor/lab:latest"})
        self.assertEqual(lab.plan("fuzz", root, "tests/fuzz_target.py").status, "unavailable")
        for duration in (0, 601):
            with self.assertRaises(lab41.SecurityLabError):
                lab.plan("fuzz", root, "tests/fuzz_target.py", duration_seconds=duration)
        with self.assertRaises(lab41.SecurityLabError):
            lab.plan("unknown", root, "tests/fuzz_target.py")

        ready_lab, _ = self.make_lab()
        plan = ready_lab.plan("fuzz", root, "tests/fuzz_target.py")
        auth = authorization(plan)
        (root / "tests" / "fuzz_target.py").unlink()
        result = ready_lab.execute(plan, auth)
        self.assertEqual(result["status"], "refused")
        self.assertFalse(factory.calls)

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links unavailable")
    def test_workspace_links_are_outside_the_authorization_contract(self):
        temporary, root = workspace()
        self.addCleanup(temporary.cleanup)
        target = root / "tests" / "fuzz_target.py"
        link = root / "tests" / "linked.py"
        try:
            link.symlink_to(target)
        except OSError as exc:
            self.skipTest("symbolic-link privilege unavailable: " + str(exc))
        with self.assertRaises(lab41.SecurityLabError):
            lab41.workspace_scope_sha256(root)


if __name__ == "__main__":
    unittest.main(verbosity=2)
