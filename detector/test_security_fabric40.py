#!/usr/bin/env python3
"""Adversarial contracts for Attestor 4.0's defensive security fabric."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import security_fabric40


def write(root: Path, relative: str, text: str) -> Path:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8", newline="\n")
    return target


def rules(report: dict) -> set[str]:
    return {row["rule"] for row in report["findings"]}


class SecurityFabricContractTests(unittest.TestCase):
    def test_schema_determinism_integrity_and_assurance(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "app.py", "def add(left, right):\n    return left + right\n")
            first = security_fabric40.analyze(root)
            second = security_fabric40.analyze(root)
        self.assertEqual(first, second)
        self.assertEqual(first["schema"], "attestor-security-fabric/4.0")
        self.assertEqual(first["version"], "4.0.0")
        self.assertEqual(first["status"], "clean")
        body = {key: value for key, value in first.items() if key != "report_sha256"}
        expected = hashlib.sha256(json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False).encode("utf-8")).hexdigest()
        self.assertEqual(first["report_sha256"], expected)
        assurance = first["assurance"]
        self.assertFalse(assurance["target_code_executed"])
        self.assertFalse(assurance["network_accessed"])
        self.assertFalse(assurance["target_files_written"])
        self.assertFalse(assurance["automatic_remediation_applied"])

    def test_invalid_root_and_invalid_limits_fail_closed(self):
        report = security_fabric40.analyze("this-path-does-not-exist-40")
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["findings"], [])
        with self.assertRaises(security_fabric40.SecurityFabric40Error):
            security_fabric40.Limits(max_files=0)
        with self.assertRaises(security_fabric40.SecurityFabric40Error):
            security_fabric40.Limits(max_total_bytes=security_fabric40.MAX_TOTAL_BYTES_HARD + 1)
        with self.assertRaises(security_fabric40.SecurityFabric40Error):
            security_fabric40.analyze(Path.cwd(), limits={})
        with tempfile.TemporaryDirectory() as folder, mock.patch.object(
                security_fabric40, "_linklike", return_value=True):
            refused = security_fabric40.analyze(folder)
        self.assertEqual(refused["status"], "failed")
        self.assertIn("reparse point", refused["coverage"]["gaps"][0])

    def test_total_byte_and_file_limits_are_explicit_partial_coverage(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first_path = write(root, "a.py", "def first():\n    return 1\n")
            write(root, "b.py", "def second():\n    return 2\n")
            byte_limit = first_path.stat().st_size
            by_bytes = security_fabric40.analyze(
                root, limits=security_fabric40.Limits(max_total_bytes=byte_limit))
            by_files = security_fabric40.analyze(
                root, limits=security_fabric40.Limits(max_files=1))
        self.assertEqual(by_bytes["status"], "partial")
        self.assertIn("max_total_bytes", by_bytes["limits"]["hit"])
        self.assertEqual(by_bytes["coverage"]["files_loaded"], 1)
        self.assertEqual(by_bytes["coverage"]["bytes_consumed"], byte_limit)
        self.assertTrue(any(row["reason"] == "max_total_bytes reached"
                            for row in by_bytes["coverage"]["skipped"]))
        self.assertEqual(by_files["status"], "partial")
        self.assertIn("max_files", by_files["limits"]["hit"])
        self.assertEqual(by_files["coverage"]["files_considered"], 1)

    def test_single_file_scope_is_supported_without_reading_siblings(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = write(root, "app.js", "eval(req.query.code);\n")
            sibling_marker = "SIBLING-" + "MUST-NOT-BE-READ"
            write(root, "sibling.py", "marker = %r\n" % sibling_marker)
            report = security_fabric40.analyze(target)
        self.assertEqual(report["status"], "findings")
        self.assertEqual(report["root"], str(target.resolve()))
        self.assertEqual(report["coverage"]["scope_kind"], "file")
        self.assertEqual(report["coverage"]["files_considered"], 1)
        self.assertEqual(report["coverage"]["files_loaded"], 1)
        self.assertIn("fabric40-generic-code-injection", rules(report))
        self.assertTrue(all(row["path"] == "app.js" for row in report["findings"]))
        self.assertNotIn(sibling_marker, json.dumps(report))
        self.assertTrue(any("single-file scope" in gap
                            for gap in report["coverage"]["gaps"]))

    def test_unsupported_exact_file_is_partial_not_clean(self):
        with tempfile.TemporaryDirectory() as folder:
            target = write(Path(folder), "archive.bin", "not an allowlisted type")
            report = security_fabric40.analyze(target)
        self.assertEqual(report["status"], "partial")
        self.assertEqual(report["coverage"]["files_loaded"], 0)
        self.assertTrue(any(
            "no analyzable files" in gap for gap in report["coverage"]["gaps"]))

    def test_global_top_k_keeps_late_critical_finding(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for index in range(40):
                write(
                    root, "a%02d.tf" % index,
                    'resource "x" "y" { storage_encrypted = false }\n')
            write(root, "z.js", "eval(req.query.code);\n")
            report = security_fabric40.analyze(
                root, limits=security_fabric40.Limits(max_findings=1))
        self.assertEqual(report["status"], "partial")
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(report["findings"][0]["severity"], "CRITICAL")
        self.assertEqual(
            report["findings"][0]["rule"],
            "fabric40-generic-code-injection")

    def test_symlinks_are_not_followed_and_root_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            parent = Path(folder)
            root = parent / "root"; root.mkdir()
            outside_marker = "OUTSIDE-" + "BOUNDARY-40"
            outside = write(parent, "outside.py", "marker = %r\n" % outside_marker)
            link = root / "linked.py"
            root_link = parent / "root-link"
            try:
                os.symlink(outside, link)
                os.symlink(root, root_link, target_is_directory=True)
            except (OSError, NotImplementedError) as exc:
                self.skipTest("symlink creation unavailable: %s" % exc)
            report = security_fabric40.analyze(root)
            refused = security_fabric40.analyze(root_link)
        self.assertEqual(report["coverage"]["files_loaded"], 0)
        self.assertTrue(any("symlink" in row["reason"]
                            for row in report["coverage"]["skipped"]))
        self.assertNotIn(outside_marker, json.dumps(report))
        self.assertEqual(refused["status"], "failed")
        self.assertIn("symbolic link", refused["coverage"]["gaps"][0])

    def test_python_auth_injection_ssrf_deserialization_path_and_crypto(self):
        source = (
            "from flask import request\nimport hashlib, os, pickle, random, requests\n"
            "@app.route('/admin/<item>')\n"
            "def handler(item):\n"
            "    command = request.args.get('command')\n"
            "    role = request.args.get('role')\n"
            "    if role == 'admin':\n        privileged_action()\n"
            "    os.system(command)\n"
            "    cursor.execute(f'SELECT * FROM users WHERE id={command}')\n"
            "    requests.get(command, verify=False)\n"
            "    pickle.loads(command)\n"
            "    open(command)\n"
            "    eval(command)\n"
            "    response.set_cookie('session', command)\n"
            "    reset_token = random.random()\n"
            "    password_hash = hashlib.md5(command.encode())\n"
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); write(root, "app.py", source)
            report = security_fabric40.analyze(root)
        expected = {
            "fabric40-client-controlled-authorization", "fabric40-command-injection",
            "fabric40-sql-injection", "fabric40-ssrf",
            "fabric40-unsafe-deserialization", "fabric40-path-traversal",
            "fabric40-code-injection", "fabric40-session-cookie-hardening",
            "fabric40-tls-verification-disabled",
            "fabric40-insecure-security-token-randomness", "fabric40-weak-security-hash",
        }
        self.assertTrue(expected <= rules(report), expected - rules(report))
        self.assertEqual(report["status"], "findings")
        self.assertGreater(report["summary"]["risk_score"], 0)
        self.assertGreaterEqual(len(report["threat_model"]["attack_paths"]), 1)
        self.assertTrue(all(row["state"] == "static-hypothesis"
                            for row in report["threat_model"]["attack_paths"]))

    def test_inherited_auth_and_crypto_checks_are_reused(self):
        source = (
            "options = {'verify_signature': False}\n"
            "algorithms = ['none']\n"
            "redirect_uri = '*'\n"
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); write(root, "auth.py", source)
            report = security_fabric40.analyze(root)
        self.assertIn("secctx-jwt-signature-disabled", rules(report))
        self.assertIn("secctx-jwt-none-algorithm", rules(report))
        engines = report["coverage"]["engines"]
        self.assertEqual(engines["security-intelligence"]["mode"],
                         "bounded-in-memory-scanners")
        self.assertGreaterEqual(engines["security-intelligence"]["raw_findings"], 2)

    def test_container_kubernetes_and_cloud_misconfigurations(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "Dockerfile", "FROM ubuntu:latest\nUSER root\nCOPY . .\n")
            write(root, "k8s/deployment.yaml", (
                "kind: Deployment\nspec:\n  hostNetwork: true\n  template:\n"
                "    spec:\n      containers:\n      - securityContext:\n"
                "          privileged: true\n          runAsNonRoot: false\n"
                "          readOnlyRootFilesystem: false\n          capabilities:\n"
                "            add:\n            - ALL\n"))
            write(root, "infra/main.tf", (
                "from_port = 22\nto_port = 22\ncidr_blocks = ['0.0.0.0/0']\n"
                "acl = 'public-read'\nstorage_encrypted = false\n"))
            report = security_fabric40.analyze(root)
        expected = {
            "secctx-container-mutable-base", "secctx-container-explicit-root",
            "fabric40-container-broad-context-copy", "secctx-container-privileged",
            "secctx-k8s-host-namespace", "fabric40-k8s-root-allowed",
            "fabric40-k8s-writable-rootfs", "fabric40-k8s-add-all-capabilities",
            "secctx-tf-public-admin-service", "secctx-cloud-public-storage",
            "fabric40-cloud-encryption-disabled",
        }
        self.assertTrue(expected <= rules(report), expected - rules(report))
        kinds = {row["kind"] for row in report["threat_model"]["attack_surface"]["components"]}
        self.assertIn("container", kinds)
        self.assertIn("infrastructure-as-code", kinds)

    def test_api_headers_mass_assignment_and_privacy_checks(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "openapi.yaml", (
                "openapi: 3.1.0\npaths:\n  /public:\n    get:\n      security: []\n"
                "      responses:\n        '200': {description: ok}\n"))
            write(root, "nginx.conf", (
                "server {\n add_header Strict-Transport-Security 'max-age=0';\n"
                " add_header X-Frame-Options DENY;\n}\n"))
            write(root, "api.js", (
                "console.log(req.body.password);\nuser.update(req.body);\n"))
            report = security_fabric40.analyze(root)
        expected = {
            "fabric40-openapi-security-scheme-missing",
            "fabric40-openapi-operation-auth-disabled", "fabric40-hsts-disabled",
            "fabric40-nginx-security-headers-incomplete", "fabric40-api-mass-assignment",
            "fabric40-sensitive-data-logging",
        }
        self.assertTrue(expected <= rules(report), expected - rules(report))
        self.assertTrue(any(row["control"] == "strict-transport-security"
                            for row in report["security_controls"]))
        self.assertTrue(any("rate-limit" in gap for gap in report["coverage"]["gaps"]))

    def test_openapi_detector_does_not_treat_program_source_literals_as_a_contract(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "parser.py", 'marker = "openapi"\nsecurity_label = "securitySchemes"\n')
            report = security_fabric40.analyze(root)
        self.assertNotIn("fabric40-openapi-security-scheme-missing", rules(report))

    def test_non_python_lexical_attack_classes(self):
        source = (
            "eval(req.query.code);\nchild_process.exec(req.body.cmd);\n"
            "fetch(req.query.url);\nunserialize(req.body.data);\n"
            "sendFile(req.query.path);\n"
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); write(root, "api.js", source)
            report = security_fabric40.analyze(root)
        expected = {
            "fabric40-generic-code-injection", "fabric40-generic-command-injection",
            "fabric40-generic-ssrf", "fabric40-generic-unsafe-deserialization",
            "fabric40-generic-path-traversal",
        }
        self.assertTrue(expected <= rules(report), expected - rules(report))

    def test_secret_evidence_is_redacted_without_value_or_value_hash(self):
        token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); write(root, ".env", "GITHUB_TOKEN=" + token + "\n")
            report = security_fabric40.analyze(root)
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn(token, serialized)
        self.assertNotIn(hashlib.sha256(token.encode()).hexdigest(), serialized)
        secret_rows = [row for row in report["findings"]
                       if "secret" in row["category"] or "credential" in row["category"]]
        self.assertTrue(secret_rows)
        self.assertTrue(all(item["secret_material_redacted"]
                            for row in secret_rows for item in row["evidence"]))
        self.assertTrue(all("source_sha256" not in item
                            for row in secret_rows for item in row["evidence"]))
        self.assertFalse(report["assurance"]["raw_secret_material_in_report"])

    def test_supply_chain_lock_integrity_and_exact_snapshot_graph(self):
        lock = {
            "name": "fixture", "version": "1.0.0", "lockfileVersion": 3,
            "packages": {
                "": {"name": "fixture", "version": "1.0.0",
                     "dependencies": {"dep": "1.2.3"}},
                "node_modules/dep": {"name": "dep", "version": "1.2.3",
                                     "integrity": "sha512-" + "A" * 64},
            },
        }
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "package.json", json.dumps({"name": "fixture", "dependencies": {"dep": "1.2.3"}}))
            lock_path = write(root, "package-lock.json", json.dumps(lock, sort_keys=True))
            original = lock_path.read_bytes()
            report = security_fabric40.analyze(root)
            unchanged = lock_path.read_bytes()
        supply = report["supply_chain"]
        self.assertEqual(original, unchanged)
        self.assertEqual(supply["lockfile_integrity"][0]["sha256"],
                         hashlib.sha256(original).hexdigest())
        self.assertEqual(supply["exact_graph"]["status"], "complete")
        # The package-lock workspace root is an emitted node, not a dangling
        # synthetic edge endpoint.
        self.assertEqual(supply["exact_graph"]["nodes"], 2)
        self.assertEqual(supply["exact_graph"]["edges"], 1)
        self.assertTrue(report["assurance"]["temporary_snapshot_files_written"])
        self.assertFalse(report["assurance"]["target_files_written"])
        self.assertNotIn("attestor40-lock-snapshot-", json.dumps(report))

    def test_missing_lockfile_is_observation_not_advisory_claim(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "package.json", json.dumps({"name": "fixture", "dependencies": {"dep": "1.2.3"}}))
            report = security_fabric40.analyze(root)
        self.assertIn("fabric40-lockfile-not-observed", rules(report))
        self.assertFalse(report["supply_chain"]["sbom"]["generated"])

    def test_dependency_free_package_does_not_invent_a_lockfile_requirement(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "package.json", json.dumps({
                "name": "dependency-free-extension", "private": True,
                "engines": {"vscode": "^1.90.0"},
            }))
            report = security_fabric40.analyze(root)
        self.assertNotIn("fabric40-lockfile-not-observed", rules(report))
        manifest = report["supply_chain"]["manifest_lock_coverage"][0]
        self.assertEqual(manifest["status"], "not-required-no-dependencies")
        self.assertFalse(manifest["lock_required"])
        self.assertFalse(report["supply_chain"]["execution"]["network"])
        self.assertTrue(any("advisories were not queried" in gap
                            for gap in report["coverage"]["gaps"]))

    def test_no_network_process_execution_or_target_mutation(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            target = write(root, "app.py", "def ready():\n    return True\n")
            before = target.read_bytes()
            with mock.patch("socket.socket", side_effect=AssertionError("network used")), \
                    mock.patch("subprocess.Popen", side_effect=AssertionError("process used")), \
                    mock.patch("os.system", side_effect=AssertionError("shell used")):
                report = security_fabric40.analyze(root)
            after = target.read_bytes()
        self.assertEqual(before, after)
        self.assertFalse(report["assurance"]["network_accessed"])
        self.assertFalse(report["assurance"]["external_processes_spawned"])
        self.assertFalse(report["assurance"]["target_code_executed"])

    def test_finding_and_remediation_contract_is_normalized_and_manual(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            write(root, "app.py", "from flask import request\nimport os\ndef f():\n os.system(request.args.get('x'))\n")
            report = security_fabric40.analyze(root)
        self.assertTrue(report["findings"])
        required = {"rule", "severity", "path", "line", "message", "remediation",
                    "fingerprint", "confidence", "risk_score", "priority", "evidence"}
        for row in report["findings"]:
            self.assertTrue(required <= set(row), required - set(row))
            self.assertFalse(row["remediation_metadata"]["automatic_apply"])
            self.assertFalse(Path(row["path"]).is_absolute())
        self.assertTrue(report["remediation_plan"])
        self.assertTrue(all(not row["automatic_apply"]
                            for row in report["remediation_plan"]))

    def test_finding_limit_is_enforced_after_deduplication(self):
        source = "\n".join("print(request.body.password_%d)" % index for index in range(8)) + "\n"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); write(root, "api.py", source)
            report = security_fabric40.analyze(
                root, limits=security_fabric40.Limits(max_findings=2))
        self.assertEqual(report["status"], "partial")
        self.assertEqual(len(report["findings"]), 2)
        self.assertIn("max_findings", report["limits"]["hit"])

    def test_per_scanner_and_raw_finding_amplification_are_bounded(self):
        source = "\n".join(
            "print(request.body.password_%d)" % index for index in range(200)) + "\n"
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder); write(root, "amplified.py", source)
            report = security_fabric40.analyze(
                root, limits=security_fabric40.Limits(max_findings=1))
        boundary = report["coverage"]["raw_finding_boundary"]
        self.assertLessEqual(boundary["retained"], boundary["limit"])
        self.assertEqual(len(report["findings"]), 1)
        self.assertIn("max_findings", report["limits"]["hit"])
        self.assertTrue(any("per-scanner boundary" in gap or
                            "pre-deduplication limit" in gap or
                            "severity-ranked top-K" in gap
                            for gap in report["coverage"]["gaps"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
