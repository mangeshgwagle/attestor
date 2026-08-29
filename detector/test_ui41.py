from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

import evidence_store41
import attestor_ui
import truth_guard41


class Workbench41StaticTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = attestor_ui.INDEX.read_text(encoding="utf-8")
        cls.js = attestor_ui.UI_SCRIPT.read_text(encoding="utf-8")
        cls.css = attestor_ui.UI_STYLES.read_text(encoding="utf-8")

    def test_camera_is_completely_replaced_by_evidence_explorer(self):
        combined = self.html + self.js + self.css
        self.assertNotIn("camera", combined.lower())
        self.assertIn("view-evidence", self.html)
        self.assertIn("function renderEvidenceExplorer", self.js)
        self.assertIn("sourceEvidence", self.js)

    def test_posture_is_unrated_or_partial_without_complete_coverage(self):
        self.assertIn("function postureAssessment", self.js)
        self.assertIn("state: 'Unrated'", self.js)
        self.assertIn("state: 'Partial'", self.js)
        self.assertIn("Partial coverage · not a posture verdict", self.js)

    def test_history_and_exports_are_authoritative_server_operations(self):
        self.assertNotIn("sessionStorage", self.js)
        self.assertIn("/api/history?limit=100", self.js)
        self.assertIn("/api/history/compare?baseline=", self.js)
        self.assertIn("/export/' + format", self.js)
        self.assertNotIn("function sarifFor", self.js)
        self.assertNotIn("exportMarkdown", self.js)
        self.assertIn("id=\"triageOwner\"", self.html)
        self.assertIn("id=\"suppressionExpiry\"", self.html)

    def test_legacy_truth_ledgers_are_not_misrouted_to_truth_guard3(self):
        verification = attestor_ui._history_verification({"truth_guard2": {"schema": "legacy"}})
        self.assertFalse(verification["applicable"])
        self.assertFalse(verification["checked"])
        self.assertEqual(verification["status"], "not-applicable")

    def test_42_distribution_branding_preserves_414_analysis_contract(self):
        self.assertEqual(attestor_ui.DISTRIBUTION_VERSION, "Attestor 4.2")
        self.assertEqual(attestor_ui.CURRENT_VERSION, "Attestor 4.1.4")
        self.assertEqual(attestor_ui.UI_VERSION, "4.1.4")
        self.assertIn(
            "<title>Attestor 4.2 distribution · "
            "4.1.4 analysis engine/protocol</title>",
            self.html,
        )
        self.assertIn("<strong>Attestor 4.2 distribution</strong>", self.html)
        self.assertIn("<span>4.1.4 analysis engine/protocol</span>", self.html)
        self.assertIn('<option selected>Attestor 4.1.4</option>', self.html)
        self.assertNotIn('<option>Attestor 4.2</option>', self.html)
        self.assertIn("Attestor 4.1.4 Maximum", self.html)
        self.assertIn("script-src 'self'", attestor_ui.CONTENT_SECURITY_POLICY)
        self.assertIn("media-src 'none'", attestor_ui.CONTENT_SECURITY_POLICY)
        self.assertTrue(attestor_ui._loopback_host("::1"))
        self.assertFalse(attestor_ui._loopback_host("0.0.0.0"))
        args = attestor_ui.build_args("attestor41", ".")
        self.assertIn("--attestor414", args)
        self.assertEqual(args[args.index("--variant") + 1], "south-park")
        self.assertEqual(args[args.index("--format") + 1], "json")

    def test_research_mode_is_explicit_offline_and_public_web_only(self):
        self.assertIn('id="view-research"', self.html)
        self.assertIn('<option value="research">Deep public-web research</option>', self.html)
        self.assertIn('id="researchOnline" type="checkbox"', self.html)
        self.assertNotIn('id="researchOnline" type="checkbox" checked', self.html)
        self.assertIn('id="researchFetchPages" type="checkbox" disabled', self.html)
        self.assertIn("normal public web", self.html.lower())
        self.assertIn("no logins, paywalls, private networks, dark web, or form submissions", self.html.lower())
        self.assertIn("function normalizedResearch", self.js)
        self.assertIn("function renderResearch", self.js)
        self.assertIn("document.schema !== 'attestor-research/4.1'", self.js)
        self.assertIn("research_online: mode === 'research'", self.js)
        self.assertIn("research_fetch_pages: mode === 'research'", self.js)
        self.assertIn("possible-disagreement-not-adjudicated", self.js)
        self.assertIn("providerKeyReported", self.js)

    def test_research_ui_has_no_credential_input_or_browser_web_fetch(self):
        combined = (self.html + self.js).lower()
        self.assertNotIn('type="password"', combined)
        self.assertNotIn("api_key", combined)
        self.assertNotIn("brave_api_key", combined)
        self.assertIn("connect-src 'self'", attestor_ui.CONTENT_SECURITY_POLICY)
        static_args = attestor_ui.build_args("attestor41", ".")
        self.assertNotIn("--online", static_args)
        self.assertNotIn("--fetch-pages", static_args)

    def test_research_normalization_and_public_link_boundary_in_javascript(self):
        node = os.environ.get("ATTESTOR_NODE") or shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable for the research UI boundary check")
        integer = self.js[self.js.index("function safeInteger("):self.js.index("function delay(")]
        text_helpers = self.js[self.js.index("function safeText("):self.js.index("function firstDefined(")]
        normalization = self.js[self.js.index("function triState("):self.js.index("function parseStructuredOutput(")]
        link_boundary = self.js[self.js.index("function publicSourceUrl("):self.js.index("function researchRow(")]
        fixture = {
            "schema": "attestor-research/4.1", "status": "evidence-collected-with-gaps",
            "question": "fixture", "summary": {"queries": 2, "sources": 1, "claims": 1},
            "sources": [{"source_id": "S1", "url": "https://example.com/a", "title": "Example"}],
            "answer": {"claims": [{"text": "Bounded claim", "citations": ["S1"]}],
                       "gaps": ["limited evidence"], "limitations": ["not proof"]},
            "coverage": {"complete": False, "gaps": ["limited evidence"],
                         "page_fetch_enabled": False, "robots_respected": True},
            "execution": {"network_accessed": True, "private_network_accessed": False,
                          "credentials_bypassed": False, "forms_submitted": False,
                          "dark_web_accessed": False, "provider_key_reported": False},
        }
        program = (
            "const MAX_RESEARCH_CLAIMS=50,MAX_RESEARCH_SOURCES=100,MAX_RESEARCH_GAPS=100;\n" +
            integer + text_helpers + normalization + link_boundary +
            "\nconst report=" + json.dumps(fixture) + ";\n" +
            "const parsed=normalizedResearch(report);\n" +
            "if(!parsed||parsed.claims.length!==1||parsed.sources.length!==1||parsed.gaps.length!==1)process.exit(2);\n" +
            "if(publicSourceUrl('https://example.com/a')!=='https://example.com/a')process.exit(3);\n" +
            "for(const value of ['javascript:alert(1)','https://localhost/x','https://127.0.0.1/x','https://u:p@example.com/x'])" +
            "if(publicSourceUrl(value)!=='')process.exit(4);\n"
        )
        completed = subprocess.run([node, "-e", program], capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)

    def test_project_root_and_historical_truth_normalization_in_javascript(self):
        node = os.environ.get("ATTESTOR_NODE") or shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable for the UI normalization check")
        integer = self.js[self.js.index("function safeInteger("):self.js.index("function delay(")]
        helpers = self.js[self.js.index("function safeText("):self.js.index("function firstDefined(")]
        normalization = self.js[self.js.index("function normalizedFinding("):self.js.index("function normalizedResearch(")]
        program = (
            "const SEVERITY_RANK={CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFO:1};\n" +
            integer + helpers + normalization +
            "\nconst f=normalizedFinding({rule:'r',severity:'HIGH',project_root:'C:/one',path:'src/a.py'},0);" +
            "const stale=historicalTruthPresentation({historyVerification:" +
            "normalizedHistoryVerification({applicable:true,verified:false,fresh:false,status:'stale'})});" +
            "const invalid=historicalTruthPresentation({historyVerification:" +
            "normalizedHistoryVerification({applicable:true,verified:false,fresh:false,status:'invalid'})});" +
            "if(f.projectRoot!=='C:/one'||!f.id.includes('C:/one')||" +
            "stale.label!=='Stale historical evidence'||stale.label.includes('Verified')||" +
            "invalid.label!=='Unverified historical evidence')process.exit(2);"
        )
        completed = subprocess.run([node, "-e", program], capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)

    def test_computer_review_improvement_normalization_in_javascript(self):
        node = os.environ.get("ATTESTOR_NODE") or shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable for the UI improvement check")
        integer = self.js[self.js.index("function safeInteger("):self.js.index("function delay(")]
        helpers = self.js[self.js.index("function safeText("):self.js.index("function firstDefined(")]
        normalization = self.js[self.js.index("function normalizedFinding("):self.js.index("function normalizedResearch(")]
        fixture = {"id": "candidate-1", "status": "review-only", "project_root": "C:/one",
                   "summary": "Candidate summary", "paths": ["src/a.py"],
                   "rule": "rule.one", "digest": "abc123"}
        program = (
            "const SEVERITY_RANK={CRITICAL:5,HIGH:4,MEDIUM:3,LOW:2,INFO:1};\n" +
            integer + helpers + normalization + "\nconst item=normalizedImprovement(" +
            json.dumps(fixture) + ",0);" +
            "if(!item.reviewOnly||item.accepted||item.projectRoot!=='C:/one'||" +
            "item.summary!=='Candidate summary'||item.paths[0]!=='src/a.py'||" +
            "item.target!=='src/a.py'||item.rule!=='rule.one'||item.digest!=='abc123')process.exit(2);"
        )
        completed = subprocess.run([node, "-e", program], capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)
        for label in ("Review only", "Project root: ", "Candidate path: ", "Rule: ", "Digest: "):
            self.assertIn(label, self.js)


class Workbench41HistoryApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base_root = Path(self.temp.name)
        self.root = self.base_root / "project"
        self.root.mkdir()
        self.source = self.root / "app.py"
        self.source.write_text("x = input()\nprint(x)\n", encoding="utf-8")
        report = {"schema": "fixture/4.1", "status": "verified", "root": str(self.root),
                  "coverage": {"complete": True, "gaps": []},
                  "findings": [{"rule": "fixture", "path": "app.py", "line": 2,
                                "severity": "HIGH"}], "sarif": {"version": "2.1.0", "runs": []}}
        self.store = evidence_store41.EvidenceStore(self.base_root / "history.sqlite3")
        self.saved = self.store.store_report(truth_guard41.guard_document(report, root=self.root))

        class QuietHandler(attestor_ui.Handler):
            def log_message(self, _format, *_args):
                return

        self.server = attestor_ui.LimitedThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        port = self.server.server_address[1]
        self.server.allowed_hosts = {"127.0.0.1:%d" % port, "localhost:%d" % port}
        self.server.session_token = "test-token"
        self.server.evidence_store = self.store
        self.server.jobs = attestor_ui.JobManager(1, evidence_store=self.store)
        self.server.max_active_jobs = 1
        self.base = "http://127.0.0.1:%d" % port
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown(); self.server.server_close(); self.server.jobs.shutdown()
        self.thread.join(timeout=3); self.temp.cleanup()

    def request(self, path: str, *, token: bool = True):
        headers = {"X-Attestor-Token": "test-token"} if token else {}
        # Fresh Truth Guard replay intentionally re-reads bounded evidence before
        # export; allow enough time for slower Windows/OneDrive CI filesystems.
        return urllib.request.urlopen(urllib.request.Request(self.base + path, headers=headers), timeout=10)

    def test_history_requires_token_and_returns_canonical_report(self):
        with self.assertRaises(urllib.error.HTTPError) as denied:
            self.request("/api/history", token=False)
        self.assertEqual(denied.exception.code, 403)
        with self.request("/api/history") as response:
            rows = json.loads(response.read())["runs"]
        self.assertEqual(rows[0]["run_id"], self.saved["run_id"])
        with self.request("/api/history/%s" % self.saved["run_id"]) as response:
            opened = json.loads(response.read())
        self.assertEqual(opened["report"]["truth_guard3"]["schema"], truth_guard41.SCHEMA)
        self.assertTrue(opened["verification"]["verified"])
        self.assertTrue(opened["verification"]["fresh"])
        self.assertEqual(opened["verification"]["status"], "fresh-verified")

    def test_health_separates_distribution_from_analysis_versions(self):
        with self.request("/health", token=False) as response:
            health = json.loads(response.read())
        self.assertEqual(health["distribution_version"], "Attestor 4.2")
        self.assertEqual(health["version"], "Attestor 4.1.4")
        self.assertEqual(health["ui_version"], "4.1.4")

    def test_history_get_marks_changed_source_evidence_stale(self):
        self.source.write_text("changed = True\n", encoding="utf-8")
        with self.request("/api/history/%s" % self.saved["run_id"]) as response:
            opened = json.loads(response.read())
        self.assertFalse(opened["verification"]["verified"])
        self.assertFalse(opened["verification"]["fresh"])
        self.assertEqual(opened["verification"]["status"], "stale")

    def test_export_is_server_verified(self):
        with self.request("/api/history/%s/export/json" % self.saved["run_id"]) as response:
            self.assertIn("application/json", response.headers["Content-Type"])
            document = json.loads(response.read())
        self.assertEqual(document["schema"], "fixture/4.1")


if __name__ == "__main__":
    unittest.main()
