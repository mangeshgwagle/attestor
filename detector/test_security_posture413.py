#!/usr/bin/env python3
"""Focused security and contract tests for Attestor 4.1.3 posture analysis."""
from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import security_posture413 as posture


def _rules(report: dict) -> set[str]:
    return {row["rule_id"] for row in report["findings"]}


def _all_strings(value):
    pending = [value]
    while pending:
        current = pending.pop()
        if isinstance(current, str):
            yield current
        elif type(current) is dict:
            pending.extend(current.keys())
            pending.extend(current.values())
        elif type(current) is list:
            pending.extend(current)


class SecurityPosture413Tests(unittest.TestCase):
    def test_empty_report_is_bounded_explicit_and_verifiable(self):
        report = posture.scan_security_posture([])
        self.assertTrue(posture.verify_report(report))
        self.assertEqual(report["schema"], posture.SCHEMA)
        self.assertEqual(report["version"], "4.1.3")
        self.assertEqual(report["status"], "partial")
        self.assertEqual(
            {
                "findings", "cloud_iac", "sbom", "provenance",
                "secret_history", "crypto", "binary", "coverage", "execution",
            } - set(report),
            set(),
        )
        capabilities = {row["capability"] for row in report["gaps"]}
        self.assertIn("signature-provenance", capabilities)
        self.assertIn("git-secret-history", capabilities)
        self.assertIn("lockfile-drift", capabilities)
        self.assertEqual(report["execution"], {
            "target_code_executed": False,
            "network_accessed": False,
            "files_written": False,
            "git_invoked": False,
            "binary_mode": "metadata-and-bounded-printable-strings-only",
        })

    def test_cloud_iac_docker_kubernetes_terraform_actions_and_iam(self):
        artifacts = [
            posture.Artifact("Dockerfile", "FROM ubuntu:latest\nRUN chmod 777 /app\n"),
            posture.Artifact(
                "deploy/pod.yaml",
                "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n"
                "  containers:\n  - image: demo:latest\n"
                "    securityContext:\n      privileged: true\n      runAsUser: 0\n",
            ),
            posture.Artifact(
                "infra/main.tf",
                'cidr_blocks = ["0.0.0.0/0"]\npublicly_accessible = true\n'
                'acl = "public-read"\nstorage_encrypted = false\n',
            ),
            posture.Artifact(
                ".github/workflows/ci.yml",
                "on:\n  pull_request_target:\npermissions: write-all\njobs:\n"
                "  test:\n    steps:\n    - uses: vendor/action@main\n"
                "    - run: echo ${{ github.event.issue.title }}\n",
            ),
            posture.Artifact(
                "iam/admin-policy.json",
                json.dumps({
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": ["*", "iam:PassRole"],
                        "Resource": "*",
                    }]
                }),
            ),
        ]
        report = posture.scan_security_posture(artifacts)
        rules = _rules(report)
        expected = {
            "IAC-DOCKER-UNPINNED-BASE", "IAC-DOCKER-DEFAULT-ROOT",
            "IAC-DOCKER-WORLD-WRITABLE", "IAC-K8S-PRIVILEGED",
            "IAC-K8S-HOST-NAMESPACE", "IAC-K8S-ROOT-UID",
            "IAC-K8S-UNPINNED-IMAGE", "IAC-TF-PUBLIC-IPV4",
            "IAC-TF-PUBLIC-DATABASE", "IAC-TF-PUBLIC-ACL",
            "IAC-TF-ENCRYPTION-DISABLED", "CI-PR-TARGET",
            "CI-TOKEN-WRITE-ALL", "CI-ACTION-MUTABLE-REF",
            "CI-UNTRUSTED-EXPRESSION-IN-SHELL", "IAM-WILDCARD-ACTION",
            "IAM-WILDCARD-RESOURCE", "IAM-PASSROLE-WILDCARD",
        }
        self.assertEqual(expected - rules, set())
        self.assertGreaterEqual(report["cloud_iac"]["artifacts_considered"], 4)
        self.assertGreaterEqual(report["cloud_iac"]["finding_count"], len(expected))
        self.assertTrue(posture.verify_report(report))

    def test_sbom_dual_formats_lock_drift_typosquat_and_private_name(self):
        package_json = json.dumps({
            "dependencies": {
                "lodash": "4.17.21",
                "lodas": "^2.0.0",
                "corp-auth": "1.0.0",
            },
            "devDependencies": {"typescript": "5.6.0"},
        })
        package_lock = json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "version": "1.0.0"},
                "node_modules/lodash": {"name": "lodash", "version": "4.17.20"},
                "node_modules/typescript": {"name": "typescript", "version": "5.6.0"},
            },
        })
        digest = hashlib.sha256(package_json.encode()).hexdigest()
        report = posture.scan_security_posture(
            [
                posture.Artifact("package.json", package_json),
                posture.Artifact("package-lock.json", package_lock),
            ],
            private_namespaces=["corp-"],
            provenance_evidence=[{
                "subject_path": "package.json",
                "subject_sha256": digest,
                "signature_verified": True,
                "provenance_verified": True,
                "signer": "trusted-builder",
                "source": "caller-attestation",
            }],
        )
        rules = _rules(report)
        self.assertIn("SC-LOCK-VERSION-DRIFT", rules)
        self.assertIn("SC-LOCK-MISSING-DEPENDENCY", rules)
        self.assertIn("SC-TYPOSQUAT-SIMILAR-NAME", rules)
        self.assertIn("SC-UNSCOPED-PRIVATE-NAME", rules)
        self.assertGreaterEqual(report["sbom"]["component_count"], 4)
        self.assertEqual(
            len(report["sbom"]["spdx"]["packages"]),
            report["sbom"]["component_count"],
        )
        self.assertEqual(
            len(report["sbom"]["cyclonedx"]["components"]),
            report["sbom"]["component_count"],
        )
        self.assertEqual(report["provenance"]["state"], "verified")
        record = report["provenance"]["records"][0]
        self.assertTrue(record["digest_matches_snapshot"])
        self.assertEqual(record["state"], "reported-verified")
        self.assertEqual(record["evidence_state"], "inferred")
        self.assertFalse(report["provenance"]["verification_performed_by_attestor"])

    def test_provenance_digest_mismatch_is_proven_and_a_gap(self):
        report = posture.scan_security_posture(
            [posture.Artifact("package.json", '{"dependencies":{}}')],
            provenance_evidence=[{
                "subject_path": "package.json",
                "subject_sha256": "0" * 64,
                "signature_verified": True,
                "provenance_verified": True,
                "signer": "builder",
                "source": "attestation",
            }],
        )
        record = report["provenance"]["records"][0]
        self.assertEqual(record["state"], "digest-mismatch")
        self.assertEqual(record["evidence_state"], "proven")
        self.assertFalse(record["digest_matches_snapshot"])
        self.assertTrue(any(
            gap["capability"] == "signature-provenance" for gap in report["gaps"]
        ))

    def test_secrets_and_history_are_lifecycle_only_and_never_disclosed(self):
        synthetic = "AK" + "IA" + "Q" * 16
        content = "credential = " + synthetic + "\n"
        history = [{
            "path": "config/old.env",
            "line": 8,
            "rule_id": "credential-pattern",
            "severity": "high",
            "removed": True,
            "rotation_verified": False,
            "revocation_verified": False,
        }]
        report = posture.scan_security_posture(
            [posture.Artifact("config/current.env", content)],
            history_evidence=history,
        )
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn(synthetic, serialized)
        self.assertNotIn(hashlib.sha256(synthetic.encode()).hexdigest(), serialized)
        self.assertIn("secret-aws-access-key", _rules(report))
        self.assertIn("SECRET-LIFECYCLE-INCOMPLETE", _rules(report))
        self.assertEqual(report["secret_history"]["state"], "available")
        self.assertFalse(report["secret_history"]["raw_values"])
        self.assertFalse(report["secret_history"]["value_hashes"])
        self.assertFalse(report["secret_history"]["git_invoked"])
        self.assertTrue(all(event["raw_value_present"] is False
                            for event in report["secret_history"]["events"]))
        self.assertTrue(posture.verify_report(report))

    def test_history_raw_or_extra_fields_are_rejected(self):
        row = {
            "path": "old.env",
            "line": 1,
            "rule_id": "secret",
            "severity": "high",
            "removed": True,
            "rotation_verified": True,
            "revocation_verified": True,
            "value": "not-accepted",
        }
        with self.assertRaises(posture.SecurityPostureError):
            posture.scan_security_posture([], history_evidence=[row])

    def test_crypto_tls_and_script_backdoor_indicators(self):
        code = (
            "digest = hashlib.md5(data)\n"
            "client.get(url, verify=False)\n"
            "ssl_context.check_hostname = False\n"
            "token = random.choice(alphabet)\n"
            "nonce = b'fixed-value'\n"
        )
        script = (
            "#!/bin/sh\n"
            "curl https://example.invalid/file | sh\n"
            "history -c\n"
        )
        report = posture.scan_security_posture([
            posture.Artifact("src/auth.py", code),
            posture.Artifact("tools/setup.sh", script, executable=True),
        ])
        rules = _rules(report)
        self.assertEqual({
            "CRYPTO-WEAK-DIGEST", "TLS-CERTIFICATE-VERIFY-DISABLED",
            "TLS-HOST-VERIFY-DISABLED", "CRYPTO-NONCRYPTO-RANDOM",
            "CRYPTO-STATIC-NONCE-INDICATOR", "SCRIPT-DOWNLOAD-EXECUTE",
            "SCRIPT-AUDIT-ERASURE",
        } - rules, set())
        self.assertGreaterEqual(report["crypto"]["finding_count"], 5)
        self.assertTrue(posture.verify_report(report))

    def test_binary_analysis_is_metadata_and_strings_only(self):
        data = b"MZ" + bytes(range(256)) * 32 + b"FromBase64String"
        report = posture.scan_security_posture([
            posture.Artifact("assets/document.dat", data, executable=False),
        ])
        rules = _rules(report)
        self.assertIn("BINARY-EXECUTABLE-EXTENSION-MISMATCH", rules)
        self.assertIn("BINARY-HIGH-ENTROPY-EXECUTABLE", rules)
        self.assertIn("BINARY-ENCODED-COMMAND-INDICATOR", rules)
        self.assertEqual(report["binary"]["artifact_count"], 1)
        row = report["binary"]["artifacts"][0]
        self.assertEqual(row["analysis"], "metadata-and-bounded-printable-strings-only")
        self.assertNotIn("strings", row)
        self.assertFalse(report["binary"]["target_code_executed"])

    def test_dynamic_nonce_assignments_are_not_static_nonce_findings(self):
        code = (
            "nonce = value.get('nonce')\n"
            "nonce = manifest['nonce']\n"
            "nonce = token_nonce\n"
            "iv = make_iv()\n"
        )
        report = posture.scan_security_posture([
            posture.Artifact("src/auth.py", code),
        ])
        self.assertNotIn("CRYPTO-STATIC-NONCE-INDICATOR", _rules(report))
        self.assertTrue(posture.verify_report(report))

    def test_regex_rule_catalog_text_is_not_executable_behavior(self):
        code = (
            "        (r\"(?i)\\b(?:DES|MODE_ECB)\\b\", 'cipher-rule'),\n"
            "        (r\"(?i)\\bTLSv1\\b\", 'tls-rule'),\n"
            "        (r\"(?i)\\bDisableAntiSpyware\\b\", 'control-rule'),\n"
            "        (r\"(?i)\\bhistory\\s+-c\\b\", 'history-rule'),\n"
        )
        report = posture.scan_security_posture([
            posture.Artifact("src/detector_rules.py", code),
        ])
        self.assertTrue({
            "CRYPTO-LEGACY-CIPHER", "TLS-LEGACY-PROTOCOL",
            "SCRIPT-SECURITY-CONTROL-DISABLE", "SCRIPT-AUDIT-ERASURE",
        }.isdisjoint(_rules(report)))
        self.assertTrue(posture.verify_report(report))

    def test_control_characters_are_escaped_in_every_output_string(self):
        report = posture.scan_security_posture([
            posture.Artifact(
                "deploy/\u202eevil.yaml",
                "apiVersion: v1\nkind: Pod\nprivileged: true\n",
            ),
        ])
        rendered = json.dumps(report, ensure_ascii=False)
        self.assertNotIn("\u202e", rendered)
        self.assertIn("\\\\u202e", rendered)
        for value in _all_strings(report):
            self.assertFalse(any(
                ord(character) < 32 or 0x7F <= ord(character) <= 0x9F
                or ord(character) in posture._BIDI
                for character in value
            ))
        self.assertTrue(posture.verify_report(report))

    def test_determinism_and_digest_tamper_detection(self):
        artifacts = [
            posture.Artifact("b.py", "verify = False\n"),
            posture.Artifact("a.tf", 'acl = "public-read"\n'),
        ]
        first = posture.scan_security_posture(artifacts)
        second = posture.scan_security_posture(reversed(artifacts))
        self.assertEqual(first, second)
        altered = copy.deepcopy(first)
        altered["coverage"]["complete"] = not altered["coverage"]["complete"]
        self.assertFalse(posture.verify_report(altered))
        altered = copy.deepcopy(first)
        altered["report_sha256"] = "0" * 64
        self.assertFalse(posture.verify_report(altered))

    def test_strict_artifact_and_metadata_budgets(self):
        with mock.patch.object(posture, "MAX_ARTIFACTS", 1):
            with self.assertRaises(posture.SecurityPostureError):
                posture.scan_security_posture([
                    posture.Artifact("a.txt", ""),
                    posture.Artifact("b.txt", ""),
                ])
        with mock.patch.object(posture, "MAX_FILE_BYTES", 3):
            with self.assertRaises(posture.SecurityPostureError):
                posture.scan_security_posture([posture.Artifact("a.txt", "four")])
        with self.assertRaises(posture.SecurityPostureError):
            posture.scan_security_posture([
                posture.Artifact("../escape.txt", "data"),
            ])
        with self.assertRaises(posture.SecurityPostureError):
            posture.scan_security_posture([
                {"path": "x.txt", "content": "", "unexpected": True},
            ])

    def test_duplicate_json_keys_fail_closed_without_crashing_scan(self):
        report = posture.scan_security_posture([
            posture.Artifact(
                "iam/policy.json",
                '{"Statement":[],"Statement":[{"Effect":"Allow","Action":"*"}]}',
            ),
        ])
        self.assertNotIn("IAM-WILDCARD-ACTION", _rules(report))
        self.assertTrue(any(
            row["capability"] == "iam-policy" for row in report["gaps"]
        ))
        self.assertTrue(posture.verify_report(report))

    def test_workspace_collector_skips_links_and_analyze_accepts_metadata_json(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Dockerfile").write_text("FROM demo:latest\n", encoding="utf-8")
            (root / "ignored.bin").write_bytes(b"plain")
            linked = root / "linked.py"
            link_supported = True
            try:
                linked.symlink_to(root / "Dockerfile")
            except (OSError, NotImplementedError):
                link_supported = False
            history = json.dumps([{
                "path": "old.env",
                "line": 2,
                "rule_id": "credential-pattern",
                "severity": "high",
                "removed": True,
                "rotation_verified": True,
                "revocation_verified": True,
            }])
            report = posture.analyze(
                root,
                staged_diff="api_key = placeholder\n",
                history_export=history,
            )
            self.assertTrue(posture.verify_report(report))
            self.assertIn("IAC-DOCKER-UNPINNED-BASE", _rules(report))
            self.assertEqual(report["secret_history"]["event_count"], 1)
            if link_supported:
                self.assertTrue(any(
                    row["path"] == "linked.py" and "linked" in row["reason"]
                    for row in report["gaps"]
                ))
            with self.assertRaises(posture.SecurityPostureError):
                posture.analyze(root, history_export="unstructured history")

    def test_workspace_entry_and_per_directory_budgets_are_explicit_and_deterministic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "b.py").write_text("b = 2\n", encoding="utf-8")
            (root / "a.py").write_text("a = 1\n", encoding="utf-8")
            with (
                mock.patch.object(posture, "MAX_DIRECTORY_ENTRIES", 2),
                mock.patch.object(posture, "MAX_ENTRIES_PER_DIRECTORY", 10),
            ):
                first = posture.collect_workspace_artifacts(root)
                second = posture.collect_workspace_artifacts(root)
            self.assertEqual(first, second)
            self.assertEqual(first[0], [])
            self.assertTrue(any(
                "total directory-entry" in row["reason"] for row in first[1]))

            with (
                mock.patch.object(posture, "MAX_DIRECTORY_ENTRIES", 100),
                mock.patch.object(posture, "MAX_ENTRIES_PER_DIRECTORY", 1),
            ):
                artifacts, gaps = posture.collect_workspace_artifacts(root)
            self.assertEqual(artifacts, [])
            self.assertTrue(any(
                "per-directory entry" in row["reason"] for row in gaps))

    def test_workspace_depth_and_directory_count_boundaries_are_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            nested = root / "first" / "second"
            nested.mkdir(parents=True)
            (nested / "deep.py").write_text("value = 1\n", encoding="utf-8")
            with mock.patch.object(posture, "MAX_DIRECTORY_DEPTH", 1):
                artifacts, gaps = posture.collect_workspace_artifacts(root)
            self.assertEqual(artifacts, [])
            self.assertTrue(any(
                row["path"] == "first/second"
                and "depth boundary" in row["reason"]
                for row in gaps
            ))

            with mock.patch.object(posture, "MAX_DIRECTORIES", 1):
                artifacts, gaps = posture.collect_workspace_artifacts(root)
            self.assertEqual(artifacts, [])
            self.assertTrue(any(
                row["path"] == "first"
                and "directory count boundary" in row["reason"]
                for row in gaps
            ))

    def test_workspace_reparse_cross_device_and_nonregular_metadata_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("reparse.py", "foreign.py", "special.py"):
                (root / name).write_text("value = 1\n", encoding="utf-8")
            real_lstat = os.lstat

            def changed_stat(path):
                original = real_lstat(path)
                name = Path(path).name
                fields = {
                    "st_mode": original.st_mode,
                    "st_dev": original.st_dev,
                    "st_ino": original.st_ino,
                    "st_size": original.st_size,
                    "st_mtime": original.st_mtime,
                    "st_ctime": original.st_ctime,
                    "st_mtime_ns": original.st_mtime_ns,
                    "st_ctime_ns": original.st_ctime_ns,
                    "st_file_attributes": int(
                        getattr(original, "st_file_attributes", 0)),
                }
                if name == "reparse.py":
                    fields["st_file_attributes"] |= 0x400
                elif name == "foreign.py":
                    fields["st_dev"] = int(original.st_dev) + 1
                elif name == "special.py":
                    fields["st_mode"] = posture.stat.S_IFIFO
                return SimpleNamespace(**fields)

            with mock.patch.object(posture.os, "lstat", side_effect=changed_stat):
                artifacts, gaps = posture.collect_workspace_artifacts(root)
        self.assertEqual(artifacts, [])
        reasons = {row["path"]: row["reason"] for row in gaps}
        self.assertIn("reparse", reasons["reparse.py"])
        self.assertIn("cross-device", reasons["foreign.py"])
        self.assertIn("non-regular", reasons["special.py"])

    def test_verified_file_reader_rejects_metadata_and_content_races(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "race.py"
            target.write_bytes(b"x")
            initial = os.lstat(target)
            fields = {
                "st_mode": initial.st_mode,
                "st_dev": initial.st_dev,
                "st_ino": initial.st_ino,
                "st_size": initial.st_size,
                "st_mtime": initial.st_mtime,
                "st_ctime": initial.st_ctime,
                "st_mtime_ns": initial.st_mtime_ns + 1,
                "st_ctime_ns": initial.st_ctime_ns,
                "st_file_attributes": int(
                    getattr(initial, "st_file_attributes", 0)),
            }
            changed = SimpleNamespace(**fields)
            with (
                mock.patch.object(
                    posture.os, "fstat", side_effect=[initial, changed, changed]),
                mock.patch.object(posture, "_read_fd_pass", return_value=b"x"),
            ):
                data, reason = posture._read_verified_regular_file(
                    target, initial, int(initial.st_dev), posture.MAX_FILE_BYTES)
            self.assertIsNone(data)
            self.assertIn("metadata changed while", reason)

            with (
                mock.patch.object(
                    posture.os, "fstat", side_effect=[initial, initial, initial]),
                mock.patch.object(
                    posture, "_read_fd_pass", side_effect=[b"x", b"y"]),
            ):
                data, reason = posture._read_verified_regular_file(
                    target, initial, int(initial.st_dev), posture.MAX_FILE_BYTES)
            self.assertIsNone(data)
            self.assertIn("content changed", reason)

            real_close = os.close

            def close_then_fail(descriptor):
                real_close(descriptor)
                raise OSError("simulated close failure")

            with mock.patch.object(
                    posture.os, "close", side_effect=close_then_fail):
                data, reason = posture._read_verified_regular_file(
                    target, initial, int(initial.st_dev), posture.MAX_FILE_BYTES)
            self.assertIsNone(data)
            self.assertIn("became unavailable", reason)

    def test_workspace_scan_exposes_traversal_limits_and_stays_verifiable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "app.py").write_text("value = 1\n", encoding="utf-8")
            (root / "image.png").write_bytes(b"not-an-analyzed-image")
            report = posture.scan_workspace(root)
        limits = report["scope"]["limits"]
        self.assertEqual(limits["max_directory_entries"], posture.MAX_DIRECTORY_ENTRIES)
        self.assertEqual(
            limits["max_entries_per_directory"], posture.MAX_ENTRIES_PER_DIRECTORY)
        self.assertEqual(limits["max_directory_depth"], posture.MAX_DIRECTORY_DEPTH)
        self.assertEqual(limits["max_directories"], posture.MAX_DIRECTORIES)
        self.assertTrue(any(
            row["path"] == "image.png" and "allowlist" in row["reason"]
            for row in report["gaps"]
        ))
        self.assertTrue(posture.verify_report(report))

    def test_module_has_only_stdlib_imports_and_no_active_io_primitives(self):
        source_path = Path(posture.__file__)
        source = source_path.read_text(encoding="utf-8")
        tree = ast.parse(source)
        imports = {
            alias.name.split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        imports |= {
            (node.module or "").split(".", 1)[0]
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
        }
        imports.discard("__future__")
        self.assertEqual(
            imports - {
                "dataclasses", "hashlib", "hmac", "json", "math", "os", "pathlib",
                "re", "stat", "tomllib", "typing", "unicodedata", "urllib", "xml",
            },
            set(),
        )
        self.assertNotIn("sub" + "process", source)
        self.assertNotIn("os." + "system", source)
        self.assertNotIn("socket" + ".", source)
        self.assertNotIn("url" + "open", source)
        self.assertNotIn("os." + "walk", source)


if __name__ == "__main__":
    unittest.main()
