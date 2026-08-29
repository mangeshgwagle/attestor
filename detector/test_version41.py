from __future__ import annotations

import json
from pathlib import Path
import unittest

import analysis_snapshot41
import computer_scan41
import cjp_authorization414
import cjp_control414
import database_intelligence414
import deep_correctness41
import evidence_store41
import attack_surface413
import attestor414
import attestor41
import attestor_lsp41
import attestorbench41
import release_hardening
import repair_director41
import research_engine41
import response41
import secret_lifecycle41
import security_lab41
import security_posture413
import security_validation413
import semantic_graph41
import semantic_rule_sdk41
import supply_chain_trust41
import truth_guard41
import variant414


ROOT = Path(__file__).resolve().parent.parent


class Attestor41VersionContractTests(unittest.TestCase):
    def test_42_distribution_preserves_414_analysis_protocols(self) -> None:
        expected = "4.1.4"
        observed = {
            "evidence_store41": evidence_store41.VERSION,
            "cjp_authorization414": cjp_authorization414.VERSION,
            "cjp_control414": cjp_control414.VERSION,
            "database_intelligence414": database_intelligence414.VERSION,
            "attestor414": attestor414.VERSION,
            "variant414": variant414.VERSION,
        }
        self.assertEqual(
            (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
            "4.2",
        )
        self.assertEqual(release_hardening.PRODUCT_VERSION, "4.2")
        for surface, value in observed.items():
            with self.subTest(surface=surface):
                self.assertEqual(value, expected)

    def test_inherited_413_engines_keep_their_producer_versions(self) -> None:
        expected = "4.1.3"
        observed = {
            "attack_surface413": attack_surface413.VERSION,
            "analysis_snapshot41": analysis_snapshot41.VERSION,
            "computer_scan41": computer_scan41.VERSION,
            "deep_correctness41": deep_correctness41.VERSION,
            "attestor41": attestor41.VERSION,
            "attestor_lsp41": attestor_lsp41.SERVER_VERSION,
            "attestorbench41": attestorbench41.VERSION,
            "repair_director41": repair_director41.VERSION,
            "research_engine41": research_engine41.VERSION,
            "response41": response41.VERSION,
            "secret_lifecycle41": secret_lifecycle41.VERSION,
            "security_lab41": security_lab41.VERSION,
            "security_posture413": security_posture413.VERSION,
            "security_validation413": security_validation413.VERSION,
            "semantic_graph41": semantic_graph41.VERSION,
            "semantic_rule_sdk41": semantic_rule_sdk41.VERSION,
            "supply_chain_trust41": supply_chain_trust41.VERSION,
            "truth_guard41": truth_guard41.VERSION,
        }
        for surface, value in observed.items():
            with self.subTest(surface=surface):
                self.assertEqual(value, expected)

    def test_vscode_bundle_and_server_manifest_are_41(self) -> None:
        extension = ROOT / "integrations" / "vscode"
        package = json.loads((extension / "package.json").read_text(encoding="utf-8"))
        manifest = json.loads((extension / "server" / "server-manifest.json").read_text(
            encoding="utf-8"))
        self.assertEqual(package["version"], "4.1.3")
        self.assertEqual(manifest["version"], "4.1.3")
        self.assertEqual(manifest["entrypoint"], "attestor_lsp41.py")
        bundled = {row["path"] for row in manifest["files"]}
        self.assertIn("attestor_lsp41.py", bundled)

    def test_legacy_editor_branding_does_not_change_41_protocol_schemas(self) -> None:
        initialized = attestor_lsp41.AttestorLanguageServer41().handle({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"workspaceFolders": []},
        })[0]["result"]
        self.assertEqual(initialized["serverInfo"],
                         {"name": "Attestor 4.1.3", "version": "4.1.3"})
        self.assertEqual(
            initialized["capabilities"]["experimental"]["attestor"]["presentationVersion"],
            "4.1.3",
        )
        self.assertEqual(research_engine41.USER_AGENT,
                          "AttestorResearch/4.1.3 evidence-client")
        self.assertEqual(attestor41.SCHEMA, "attestor-maximum/4.1")
        self.assertEqual(computer_scan41.SCHEMA, "attestor-computer-scan/4.1")
        self.assertEqual(research_engine41.SCHEMA, "attestor-research/4.1")
        self.assertEqual(attack_surface413.SCHEMA, "attestor.attack-surface/4.1")
        self.assertEqual(security_validation413.SCHEMA, "attestor-security-validation/4.1")


if __name__ == "__main__":
    unittest.main()
