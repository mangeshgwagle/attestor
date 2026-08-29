#!/usr/bin/env python3
"""Adversarial tests for Attestor 3.5's fail-closed execution fabric."""
from __future__ import annotations

import copy
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import execution_fabric35 as fabric35


IMAGE = "registry.example/attestor/verify@sha256:" + "a" * 64
AUTH = fabric35.ExecutionAuthorization(True, "verify an untrusted repair", "test-suite")


def secure_capabilities(executable: str = "/mock/podman") -> fabric35.FabricCapabilities:
    capability = fabric35.RuntimeCapability(
        "podman", executable, True, True, "linux", True, False,
        "eligible rootless Linux runtime",
    )
    return fabric35.FabricCapabilities((capability,), False)


class FakeProcess:
    def __init__(self, stdout: bytes = b"ok\n", stderr: bytes = b"",
                 returncode: int = 0, timeout: bool = False):
        self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = returncode
        self.timeout = timeout
        self.killed = False

    def wait(self, timeout=None):
        if self.timeout and not self.killed:
            raise subprocess.TimeoutExpired("podman", timeout)
        return -9 if self.killed else self.returncode

    def kill(self):
        self.killed = True


class CapturingFactory:
    def __init__(self, process: FakeProcess | None = None):
        self.process = process or FakeProcess()
        self.calls = []

    def __call__(self, argv, **kwargs):
        self.calls.append((list(argv), dict(kwargs)))
        return self.process


class ExecutionFabric35Tests(unittest.TestCase):
    def request(self, workspace: Path, **overrides):
        values = {
            "image": IMAGE,
            "command": ("python", "-m", "unittest"),
            "workspace": workspace,
        }
        values.update(overrides)
        return fabric35.ExecutionRequest(**values)

    def test_execution_refuses_by_default_without_spawning(self):
        with tempfile.TemporaryDirectory() as temporary:
            factory = CapturingFactory()
            runner = fabric35.ExecutionFabric(
                secure_capabilities(), process_factory=factory, signing_key=b"k" * 32)
            result = runner.run(self.request(Path(temporary)))
        self.assertEqual(result.status, "refused")
        self.assertIn("authorization", result.reason)
        self.assertEqual(factory.calls, [])
        self.assertTrue(runner.verify_transcript(result.transcript))

    def test_hardened_argv_is_a_list_and_user_options_cannot_escape_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            factory = CapturingFactory()
            runner = fabric35.ExecutionFabric(
                secure_capabilities(), process_factory=factory, signing_key=b"k" * 32)
            command = ("--privileged", "echo; touch /host/pwn", "$(id)")
            result = runner.run(self.request(Path(temporary), command=command), AUTH)
        self.assertTrue(result.ok, result)
        argv, kwargs = factory.calls[0]
        for option in ("--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
                       "--security-opt=no-new-privileges"):
            self.assertIn(option, argv)
        self.assertTrue(any(item.startswith("--pids-limit=") for item in argv))
        self.assertTrue(any(item.startswith("--cpus=") for item in argv))
        self.assertTrue(any(item.startswith("--memory=") for item in argv))
        self.assertTrue(any(item.startswith("--tmpfs=/tmp:rw,noexec,nosuid,nodev")
                            for item in argv))
        image_index = argv.index(IMAGE)
        self.assertEqual(argv[image_index + 1:], list(command))
        self.assertFalse(kwargs["shell"])
        self.assertNotIn("sh", argv[:image_index])
        self.assertNotIn("/bin/sh", argv[:image_index])
        mount = argv[argv.index("--mount") + 1]
        self.assertTrue(mount.endswith(",ro"), mount)

    def test_writable_execution_uses_only_a_bounded_disposable_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "original.txt").write_text("unchanged", encoding="utf-8")
            mounts = []

            def mutating_factory(argv, **_kwargs):
                mount = argv[argv.index("--mount") + 1]
                mounts.append(mount)
                source = mount.split(",src=", 1)[1].split(",dst=", 1)[0]
                Path(source, "container-write.txt").write_text("temporary", encoding="utf-8")
                return FakeProcess()

            runner = fabric35.ExecutionFabric(
                secure_capabilities(), process_factory=mutating_factory,
                signing_key=b"d" * 32)
            result = runner.run_disposable(self.request(root), AUTH)
        self.assertTrue(result.ok, result)
        self.assertEqual(len(mounts), 1)
        self.assertTrue(mounts[0].endswith(",rw"), mounts[0])
        self.assertNotIn(str(root), mounts[0])
        self.assertFalse((root / "container-write.txt").exists())
        controls = result.transcript[-2]["payload"]["controls"]
        self.assertIn("disposable-workspace", controls)

    def test_disposable_copy_fails_closed_at_workspace_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "one.txt").write_text("1", encoding="utf-8")
            (root / "two.txt").write_text("2", encoding="utf-8")
            factory = CapturingFactory()
            policy = fabric35.ExecutionPolicy(max_workspace_files=1)
            runner = fabric35.ExecutionFabric(
                secure_capabilities(), policy, process_factory=factory)
            result = runner.run_disposable(self.request(root), AUTH)
        self.assertEqual(result.status, "refused")
        self.assertIn("file-count boundary", result.reason)
        self.assertFalse(factory.calls)

    def test_option_shaped_image_and_mount_delimiter_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            comma = root / "has,comma"
            comma.mkdir()
            factory = CapturingFactory()
            runner = fabric35.ExecutionFabric(secure_capabilities(), process_factory=factory)
            bad_image = runner.run(self.request(root, image="--privileged"), AUTH)
            bad_mount = runner.run(self.request(comma), AUTH)
        self.assertEqual(bad_image.status, "refused")
        self.assertIn("pinned", bad_image.reason)
        self.assertEqual(bad_mount.status, "refused")
        self.assertIn("delimiter", bad_mount.reason)
        self.assertFalse(factory.calls)

    def test_malformed_typed_fields_fail_closed_instead_of_crashing(self):
        with tempfile.TemporaryDirectory() as temporary:
            factory = CapturingFactory()
            runner = fabric35.ExecutionFabric(secure_capabilities(), process_factory=factory)
            malformed = fabric35.ExecutionRequest(
                image=IMAGE, command=("python", object()), workspace=Path(temporary))
            result = runner.run(malformed, AUTH)
        self.assertEqual(result.status, "refused")
        self.assertIn("invalid argv", result.reason)
        self.assertFalse(factory.calls)

    def test_named_ineligible_runtime_never_falls_back_to_eligible_one(self):
        windows = fabric35.RuntimeCapability(
            "docker", "C:/docker.exe", True, False, "windows", False, True,
            "Windows controls are not equivalent")
        podman = secure_capabilities().runtimes[0]
        capabilities = fabric35.FabricCapabilities((windows, podman), True)
        with tempfile.TemporaryDirectory() as temporary:
            factory = CapturingFactory()
            runner = fabric35.ExecutionFabric(capabilities, process_factory=factory)
            result = runner.run(self.request(Path(temporary), runtime="docker"), AUTH)
        self.assertEqual(result.status, "refused")
        self.assertIn("requested runtime", result.reason)
        self.assertFalse(factory.calls)

    def test_secret_named_environment_is_refused_and_output_is_redacted(self):
        with tempfile.TemporaryDirectory() as temporary:
            rejected_factory = CapturingFactory()
            runner = fabric35.ExecutionFabric(
                secure_capabilities(), process_factory=rejected_factory,
                signing_key=b"s" * 32)
            rejected = runner.run(self.request(
                Path(temporary), environment={"API_TOKEN": "do-not-leak"}), AUTH)
            self.assertEqual(rejected.status, "refused")
            self.assertFalse(rejected_factory.calls)

            secret = "unusual-value-7931"
            factory = CapturingFactory(FakeProcess(
                stdout=("answer=" + secret + " password=hunter2\n").encode(),
                stderr=("Bearer abcdefghijkl token=xyzxyzxyz\n").encode()))
            runner = fabric35.ExecutionFabric(
                secure_capabilities(), process_factory=factory,
                signing_key=b"s" * 32)
            result = runner.run(self.request(
                Path(temporary), environment={"ATTESTOR_VALUE": secret}), AUTH)
        serialized = json.dumps(result.transcript, sort_keys=True)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn("hunter2", result.stdout)
        self.assertNotIn("abcdefghijkl", result.stderr)
        self.assertNotIn("xyzxyzxyz", result.stderr)
        self.assertNotIn(secret, serialized)
        argv, _kwargs = factory.calls[0]
        self.assertNotIn(secret, " ".join(argv))

    def test_timeout_kills_process_and_does_not_retry_with_weaker_options(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = FakeProcess(timeout=True)
            factory = CapturingFactory(process)
            cleanup = []
            def cleanup_runner(executable, name, environment, timeout):
                cleanup.append((executable, name, environment, timeout))
                return True
            policy = fabric35.ExecutionPolicy(timeout_seconds=0.1)
            runner = fabric35.ExecutionFabric(
                secure_capabilities(), policy, process_factory=factory,
                cleanup_runner=cleanup_runner)
            result = runner.run(self.request(Path(temporary)), AUTH)
        self.assertEqual(result.status, "timed-out")
        self.assertTrue(result.timed_out)
        self.assertTrue(process.killed)
        self.assertEqual(len(factory.calls), 1)
        self.assertEqual(len(cleanup), 1)
        self.assertEqual(cleanup[0][0], "/mock/podman")

    def test_runtime_control_environment_cannot_switch_the_probed_daemon(self):
        with tempfile.TemporaryDirectory() as temporary:
            factory = CapturingFactory()
            runner = fabric35.ExecutionFabric(
                secure_capabilities(), process_factory=factory)
            result = runner.run(self.request(
                Path(temporary), environment={"DOCKER_HOST": "tcp://attacker:2375"}), AUTH)
        self.assertEqual(result.status, "refused")
        self.assertIn("runtime-control", result.reason)
        self.assertFalse(factory.calls)

    def test_ambient_remote_daemon_selection_is_rejected_and_not_inherited(self):
        def which(name):
            return "/mock/" + name

        with mock.patch.dict("os.environ", {"DOCKER_HOST": "tcp://attacker:2375"}, clear=True):
            capabilities = fabric35.detect_capabilities(which=which)
            environment = fabric35.ExecutionFabric._host_environment({})
        self.assertFalse(capabilities.eligible)
        self.assertTrue(all("forbidden" in item.reason for item in capabilities.runtimes))
        self.assertNotIn("DOCKER_HOST", environment)

    def test_ambient_remote_selector_added_after_detection_is_rechecked_before_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            factory = CapturingFactory()
            runner = fabric35.ExecutionFabric(
                secure_capabilities(), process_factory=factory)
            request = self.request(Path(temporary))
            with mock.patch.dict("os.environ", {"CONTAINER_HOST": "ssh://attacker/run"},
                                 clear=True):
                result = runner.run(request, AUTH)
        self.assertEqual(result.status, "refused")
        self.assertIn("ambient runtime endpoint", result.reason)
        self.assertFalse(factory.calls)

    def test_combined_output_is_bounded_and_marked_truncated(self):
        with tempfile.TemporaryDirectory() as temporary:
            factory = CapturingFactory(FakeProcess(b"A" * 4_000, b"B" * 4_000))
            policy = fabric35.ExecutionPolicy(max_output_bytes=1_024)
            runner = fabric35.ExecutionFabric(
                secure_capabilities(), policy, process_factory=factory)
            result = runner.run(self.request(Path(temporary)), AUTH)
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.stdout.encode()) + len(result.stderr.encode()), 1_024)

    def test_hash_chain_and_signature_detect_any_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = fabric35.ExecutionFabric(
                secure_capabilities(), process_factory=CapturingFactory(),
                signing_key=b"z" * 32, clock_ns=lambda: 42)
            result = runner.run(self.request(Path(temporary)), AUTH)
        self.assertTrue(runner.verify_transcript(result.transcript))
        tampered = copy.deepcopy(list(result.transcript))
        tampered[-1]["payload"]["returncode"] = 99
        self.assertFalse(runner.verify_transcript(tampered))
        reordered = list(reversed(result.transcript))
        self.assertFalse(runner.verify_transcript(reordered))

    def test_capability_probe_distinguishes_rootless_linux_and_windows(self):
        def which(name):
            return "/mock/" + name

        def probe(argv, _timeout):
            if argv[0].endswith("podman"):
                return SimpleNamespace(returncode=0, stdout="true|linux", stderr="")
            return SimpleNamespace(returncode=0, stdout="windows|[]", stderr="")

        capabilities = fabric35.detect_capabilities(which=which, probe=probe)
        self.assertTrue(capabilities.by_name("podman").eligible)
        self.assertFalse(capabilities.by_name("docker").eligible)
        self.assertTrue(capabilities.windows_isolation_available)


if __name__ == "__main__":
    unittest.main(verbosity=2)
