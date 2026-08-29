#!/usr/bin/env python3
"""Static integration checks for the Attestor 4.1 evidence workbench."""
from __future__ import annotations

import collections
import json
import os
import re
import shutil
import subprocess
import threading
import unittest
import urllib.request
from html.parser import HTMLParser

import attestor_ui


class UiParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.ids = []
        self.scripts = []
        self.links = []
        self.inline_handlers = []
        self.inline_styles = []
        self.tags = collections.Counter()
        self.aria_live = 0

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        self.tags[tag] += 1
        if values.get("id"):
            self.ids.append(values["id"])
        if tag == "script":
            self.scripts.append(values.get("src", ""))
        if tag == "link":
            self.links.append(values.get("href", ""))
        for name, _value in attrs:
            if name.lower().startswith("on"):
                self.inline_handlers.append(name)
            if name.lower() == "style":
                self.inline_styles.append(tag)
            if name.lower() == "aria-live":
                self.aria_live += 1


class WorkbenchMarkupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = attestor_ui.INDEX.read_text(encoding="utf-8")
        cls.css = attestor_ui.UI_STYLES.read_text(encoding="utf-8")
        cls.js = attestor_ui.UI_SCRIPT.read_text(encoding="utf-8")
        cls.parser = UiParser()
        cls.parser.feed(cls.html)

    def test_assets_are_external_and_markup_has_no_inline_behavior(self):
        self.assertEqual(self.parser.scripts, ["/ui23.js"])
        self.assertIn("/ui23.css", self.parser.links)
        self.assertEqual(self.parser.inline_handlers, [])
        self.assertEqual(self.parser.inline_styles, [])
        self.assertNotIn("<script type=", self.html)

    def test_required_workbench_landmarks_and_unique_ids(self):
        self.assertGreaterEqual(self.parser.tags["nav"], 2)
        self.assertEqual(self.parser.tags["main"], 1)
        self.assertGreaterEqual(self.parser.tags["aside"], 2)
        self.assertGreaterEqual(self.parser.aria_live, 2)
        counts = collections.Counter(self.parser.ids)
        self.assertEqual([name for name, count in counts.items() if count > 1], [])
        required = {
            "view-overview", "view-scan", "view-findings", "view-compare", "view-history",
            "view-attacks", "view-improvements", "attackPathList", "improvementList",
            "attackPathCount", "verifiedImprovementCount", "truthGuardMetric",
            "calibrationMetric", "fabricMetric", "evidenceMetric", "symbolicState",
            "polyglotState", "dependencyState", "gitState",
            "engineeringMetric", "securityFabricMetric", "fabricDashboardTitle",
            "engineeringSummary", "engineeringStatus", "engineeringEvidenceBadge",
            "engineeringCoverageBadge", "engineeringVerificationBadge",
            "engineeringEvidenceCount", "engineeringGapCount", "engineeringVerifiedCount",
            "engineeringCapabilities", "securityFabricSummary", "securityFabricStatus",
            "securityFabricEvidenceBadge", "securityFabricCoverageBadge",
            "securityFabricVerificationBadge", "securityFabricEvidenceCount",
            "securityFabricGapCount", "securityFabricVerifiedCount", "securityFabricCapabilities",
            "engineeringLimitations", "securityFabricLimitations",
            "scanForm", "sendBtn", "cancelBtn", "jobProgress", "findingList",
            "findingDrawer", "resultSearch", "severityFilter", "groupSelect", "sortSelect",
            "compareNotice", "historyList", "exportSarifBtn", "themeBtn", "view-evidence",
            "evidenceExplorerList", "triageOwner", "triageReason", "suppressionExpiry",
            "view-research", "researchControls", "researchOnline", "researchFetchPages",
            "researchClaims", "researchSources", "researchDisagreements", "researchCoverage",
            "cjpControls", "cjpPermissionConfirmed", "cjpApply",
            "cjpApplyConfirmed", "cjpSatire", "escapeLabControls",
            "variantControls", "variantSelect", "variantHint", "resultVariantLabel",
        }
        self.assertTrue(required.issubset(set(self.parser.ids)))

    def test_large_catalog_controls_are_bounded_and_discoverable(self):
        self.assertIn("15,000", self.html)
        self.assertIn('id="installedRules"', self.html)
        self.assertIn("data.precision_rules", self.js)
        self.assertRegex(self.html, r'<option>50</option>\s*<option selected>100</option>\s*<option>200</option>')
        self.assertIn("const MAX_FINDINGS = 15000", self.js)
        self.assertIn("rows.slice(start, start + pageSize)", self.js)
        self.assertIn("function filteredFindings()", self.js)
        self.assertIn("function openFinding(", self.js)

    def test_accessibility_and_responsive_contracts(self):
        self.assertIn("Skip to workbench", self.html)
        self.assertIn('aria-modal="true"', self.html)
        self.assertIn(":focus-visible", self.css)
        self.assertIn("prefers-reduced-motion", self.css)
        self.assertIn("@media (max-width: 620px)", self.css)
        self.assertIn(".fabric-domain-grid", self.css)
        self.assertIn('aria-labelledby="fabricDashboardTitle"', self.html)
        self.assertIn("event.altKey", self.js)
        self.assertIn("event.key === '/'", self.js)
        self.assertIn("focusable", self.js)

    def test_camera_is_removed_and_evidence_explorer_is_routed(self):
        self.assertNotIn("camera", (self.html + self.js + self.css).lower())
        self.assertIn("function renderEvidenceExplorer(", self.js)
        self.assertIn("sourceEvidence", self.js)

    def test_non_coding_research_is_separate_explicit_and_source_resolved(self):
        self.assertIn("Deep public-web research", self.html)
        self.assertIn("Online access is off by default", self.html)
        self.assertIn("normal public web", self.html)
        self.assertIn("function normalizedResearch(", self.js)
        self.assertIn("function renderResearch(", self.js)
        self.assertIn("function publicSourceUrl(", self.js)
        self.assertIn("noopener noreferrer", self.js)
        self.assertIn("Coverage and gaps", self.html)
        self.assertNotIn('type="password"', self.html)

    def test_history_and_semantic_compare_are_server_authoritative(self):
        self.assertNotIn("sessionStorage", self.js)
        self.assertIn("/api/history?limit=100", self.js)
        self.assertIn("/api/history/compare?baseline=", self.js)
        self.assertIn("Authoritative semantic delta", self.js)

    def test_dom_writes_and_exports_escape_untrusted_output(self):
        self.assertNotIn(".innerHTML", self.js)
        self.assertNotRegex(self.js, r"\beval\s*\(")
        self.assertNotIn("new Function", self.js)
        self.assertNotIn("document.write", self.js)
        self.assertIn("textContent", self.js)
        self.assertNotIn("function sarifFor", self.js)
        self.assertIn("canonicalExport", self.js)

    def test_theme_and_chart_have_no_external_dependency(self):
        self.assertIn('data-theme="dark"', self.html)
        self.assertIn('body[data-theme="light"]', self.css)
        self.assertIn("riskRingValue", self.html)
        self.assertNotRegex(self.html.lower(), r"https?://")

    def test_structured_results_are_safely_presented(self):
        self.assertIn("function parseStructuredOutput(", self.js)
        self.assertIn("function renderAttackPaths(", self.js)
        self.assertIn("function renderImprovements(", self.js)
        self.assertIn("Complete improved source", self.js)
        self.assertIn("No result was labeled improved", self.js)
        self.assertIn("improved_source_withheld", self.js)
        self.assertIn("document.truth_guard", self.js)
        self.assertIn("grounded", self.js)
        self.assertIn("separate diagnostics", self.js)

    def test_attestor41_and_compatibility_assurance_states_are_visible(self):
        self.assertIn("Attestor 4.1.4 assurance matrix", self.html)
        self.assertIn("document.truth_guard3", self.js)
        self.assertIn("document.truth_guard2", self.js)
        self.assertIn("confidence_calibration_35", self.js)
        self.assertIn("execution_fabric_35", self.js)
        self.assertIn("supply_chain_graph_35", self.js)

    def test_attestor41_fabrics_are_bounded_and_missing_data_is_not_inferred(self):
        self.assertIn("document.engineering", self.js)
        self.assertIn("document.security_fabric", self.js)
        self.assertIn("function normalizedFabric(", self.js)
        self.assertIn("function renderFabricDashboards(", self.js)
        self.assertIn("No top-level ", self.js)
        self.assertIn("capabilities.length ? capabilities", self.js)
        self.assertIn("const MAX_FABRIC_LIMITATIONS = 8", self.js)
        self.assertIn("function fabricLimitations(", self.js)
        self.assertIn("coverageObject.gaps", self.js)
        self.assertIn("raw.assurance_notes", self.js)
        self.assertIn("not proof of complete coverage", self.js)
        self.assertIn("Reported limitations &amp; gaps", self.html)
        self.assertIn('<option value="attestor41" selected>', self.html)

    def test_414_variant_selector_is_exact_and_result_label_is_verified(self):
        for slug in (
                "cockroach-janta-party", "south-park", "gruppe-sechs"):
            self.assertIn('value="%s"' % slug, self.html)
        self.assertIn(
            '<option value="south-park" selected>', self.html)
        self.assertIn("const DEFAULT_VARIANT = 'south-park'", self.js)
        self.assertIn("function installVariantCatalog(", self.js)
        self.assertIn("function verifiedResultVariant(", self.js)
        self.assertIn("function verifiedVariantLabel(", self.js)
        self.assertIn(
            "language.schema !== 'attestor-response-language/4.1.4'",
            self.js)
        self.assertIn(
            "'C3 (Attestor-specific; not CEFR)'", self.js)
        self.assertIn("record.result && record.result.verified_variant", self.js)
        record_body = self.js[
            self.js.index("function setRecord("):
            self.js.index("function hydrateAnnotations(")]
        self.assertNotIn("record.request.variant", record_body)
        submit_body = self.js[
            self.js.index("async function submitScan("):
            self.js.index("async function pollJob(")]
        self.assertIn("request.variant = elements.variantSelect.value", submit_body)
        self.assertIn("request.timeout =", submit_body)
        self.assertLess(
            submit_body.index("if (variantSelectionApplies())"),
            submit_body.index("request.timeout ="))

    def test_cjp_local_control_is_explicit_one_run_and_cockroach_only(self):
        self.assertIn('value="cjpcontrol"', self.html)
        self.assertIn(
            "Cockroach one-run local-file authorization", self.html)
        self.assertIn(
            "family relationship is not authority", self.html)
        self.assertIn(
            "no TCS account, network, credential, administrator", self.html)
        self.assertIn('id="cjpPreviewEvidence"', self.html)
        self.assertIn(
            "fails closed unless this exact digest still matches", self.html)
        self.assertIn(
            "new Set(['attestor41', 'improve', 'cjpcontrol'])", self.js)
        self.assertIn(
            "elements.variantSelect.value = 'cockroach-janta-party'",
            self.js)
        submit_body = self.js[
            self.js.index("async function submitScan("):
            self.js.index("async function pollJob(")]
        self.assertIn("cjp_permission_confirmed", submit_body)
        self.assertIn("cjp_apply_confirmed", submit_body)
        self.assertIn("cjp_preview_evidence_sha256", submit_body)
        self.assertIn("/^[0-9a-f]{64}$/", submit_body)
        self.assertIn(
            "resetCjpAuthorization()", submit_body)
        self.assertIn("Actual automatic deletion authority: 0%", self.html)
        self.assertIn("the joke changes no permission or behavior", self.html)
        self.assertIn(
            "profile.slug !== 'cockroach-janta-party'", self.js)

    def test_private_escape_lab_is_no_input_session_only_simulation(self):
        self.assertIn('value="escapelab"', self.html)
        self.assertIn(
            "Private sandbox escape lab - simulation only", self.html)
        self.assertIn(
            "never attempts to escape the real Windows host", self.html)
        self.assertIn(
            "No prompt, path, caller code, caller-controlled shell/process",
            self.html)
        self.assertIn("Actual automatic deletion authority: 0%", self.html)
        self.assertIn(
            "escapelab: 'Private Sandbox Escape Lab (Simulation Only)'",
            self.js)
        variant_declaration = self.js[
            self.js.index("const VARIANT_MODES"):
            self.js.index("const VARIANT_LABELS")]
        self.assertNotIn("escapelab", variant_declaration)
        set_mode = self.js[
            self.js.index("function setMode("):
            self.js.index("function variantSelectionApplies(")]
        self.assertIn("const isEscapeLab = mode === 'escapelab'", set_mode)
        self.assertIn("elements.prompt.value = ''", set_mode)
        self.assertIn("elements.escapeLabControls.hidden = !isEscapeLab", set_mode)
        submit_body = self.js[
            self.js.index("async function submitScan("):
            self.js.index("async function pollJob(")]
        self.assertIn("if (mode === 'escapelab') prompt = ''", submit_body)

    def test_compatibility_identity_precedes_server_canonical_export(self):
        self.assertIn("function declaredReportIdentity(", self.js)
        self.assertIn("schema === 'attestor-maximum/4.1'", self.js)
        self.assertIn("schema === 'attestor-maximum/4.0'", self.js)
        self.assertIn("schema === 'attestor-maximum/3.5'", self.js)
        self.assertIn("schema === 'attestor-maximum/3.0'", self.js)
        body = self.js[self.js.index("function recordIdentity("):self.js.index("async function canonicalExport(")]
        self.assertLess(body.index("declaredReportIdentity(record)"), body.index("record.mode === 'attestor35'"))
        self.assertLess(body.index("record.mode === 'attestor35'"), body.index("record.version"))
        self.assertLess(body.index("record.mode === 'attestor3'"), body.index("record.version"))
        self.assertIn("return 'Attestor 3.5'", body)
        self.assertIn("return 'Attestor 3.0'", body)
        exports = self.js[self.js.index("async function canonicalExport("):self.js.index("async function copyText(")]
        self.assertIn("/api/history/", exports)
        self.assertIn("/export/' + format", exports)
        self.assertNotIn("JSON.stringify({...record", exports)

    def test_compatibility_export_identity_behavior_in_javascript(self):
        node = os.environ.get("ATTESTOR_NODE") or shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable for the pure export-identity check")
        helpers = self.js[self.js.index("function safeText("):self.js.index("function boundedCollectionSize(")]
        identity = self.js[self.js.index("function declaredReportIdentity("):self.js.index("async function canonicalExport(")]
        cases = [
            [{"mode": "attestor41", "version": "Attestor 4.1.2", "result": {"output": "plain"}}, "Attestor 4.1.2"],
            [{"mode": "attestor35", "version": "Attestor 4.0", "result": {"output": "plain"}}, "Attestor 3.5"],
            [{"mode": "attestor3", "version": "Attestor 4.0", "result": {"output": "plain"}}, "Attestor 3.0"],
            [{"mode": "attestor40", "version": "Attestor 3.5", "result": {"output": "plain"}}, "Attestor 4.0"],
            [{"mode": "attestor40", "version": "Attestor 4.0", "result": {
                "output": json.dumps({"schema": "attestor-maximum/3.5", "version": "3.5.0"})}}, "Attestor 3.5"],
            [{"mode": "attestor35", "version": "Attestor 3.5", "result": {
                "output": json.dumps({"schema": "attestor-maximum/4.0", "version": "4.0.0"})}}, "Attestor 4.0"],
            [{"mode": "chat", "version": "Attestor 4.1.2", "result": {
                "output": json.dumps({"schema": "unrelated/1.0", "version": "3.0.0"})}}, "Attestor 4.1.2"],
        ]
        program = (
            "const MAX_STRUCTURED_OUTPUT = 32 * 1024 * 1024;\n" +
            helpers + identity + "\nconst cases = " + json.dumps(cases) + ";\n" + (
            "for (const [record, expected] of cases) { const actual = recordIdentity(record); "
            "if (actual !== expected) { console.error(JSON.stringify({record, expected, actual})); process.exit(1); } }"
            )
        )
        completed = subprocess.run([node, "-e", program], capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)

    def test_fabric_limitations_are_render_bounded_in_javascript(self):
        node = os.environ.get("ATTESTOR_NODE") or shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable for the pure limitations-boundary check")
        helpers = self.js[self.js.index("function safeText("):self.js.index("function boundedCollectionSize(")]
        limitation_function = self.js[self.js.index("function fabricLimitations("):self.js.index("function normalizedFabric(")]
        program = "const MAX_FABRIC_LIMITATIONS = 8;\n" + helpers + limitation_function + r"""
const coverage = {gaps: Array.from({length: 12}, (_, index) => ({message: 'gap-' + index, path: 'p' + index}))};
const rows = fabricLimitations({limitations: ['static-only'], assurance: ['no execution']}, coverage);
if (rows.length !== 8 || rows[0] !== 'gap-0 (p0)' || !rows[7].includes('omitted by the UI boundary')) {
  console.error(JSON.stringify(rows)); process.exit(1);
}
"""
        completed = subprocess.run([node, "-e", program], capture_output=True, text=True, timeout=10)
        self.assertEqual(completed.returncode, 0, completed.stderr or completed.stdout)


class WorkbenchServerContractTests(unittest.TestCase):
    def test_ui_version_and_assets_are_current(self):
        self.assertEqual(attestor_ui.UI_VERSION, "4.1.4")
        self.assertEqual(attestor_ui.CURRENT_VERSION, "Attestor 4.1.4")
        self.assertTrue(attestor_ui.INDEX.is_file())
        self.assertTrue(attestor_ui.UI_SCRIPT.is_file())
        self.assertTrue(attestor_ui.UI_STYLES.is_file())
        self.assertEqual(attestor_ui.STATIC_ASSETS["/ui23.js"][0], attestor_ui.UI_SCRIPT)
        self.assertEqual(attestor_ui.STATIC_ASSETS["/ui23.css"][0], attestor_ui.UI_STYLES)
        self.assertEqual(attestor_ui.STATIC_ASSETS["/ui22.js"][0], attestor_ui.UI_SCRIPT)

    def test_csp_allows_only_external_ui_code_and_styles(self):
        policy = attestor_ui.CONTENT_SECURITY_POLICY
        self.assertIn("script-src 'self'", policy)
        self.assertIn("style-src 'self'", policy)
        self.assertIn("object-src 'none'", policy)
        self.assertIn("form-action 'none'", policy)
        self.assertNotIn("unsafe-inline", policy)
        self.assertNotIn("unsafe-eval", policy)

    def test_client_uses_existing_secured_job_api(self):
        js = attestor_ui.UI_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("fetch('/health'", js)
        self.assertIn("api('/api/jobs'", js)
        self.assertRegex(js, r"api\('/api/jobs/' \+ encodeURIComponent\(jobId\)\)")
        self.assertIn("{method: 'DELETE'}", js)
        self.assertIn("X-Attestor-Token", js)

    def test_server_serves_workbench_assets_with_strict_csp(self):
        class QuietHandler(attestor_ui.Handler):
            def log_message(self, _format, *_args):
                return

        server = attestor_ui.LimitedThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        port = server.server_address[1]
        server.allowed_hosts = {"127.0.0.1:%d" % port, "localhost:%d" % port}
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            for path, content_type in (("/", "text/html"), ("/ui23.css", "text/css"),
                                       ("/ui23.js", "text/javascript"), ("/ui22.js", "text/javascript")):
                with self.subTest(path=path):
                    with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=3) as response:
                        self.assertEqual(response.status, 200)
                        self.assertIn(content_type, response.headers["Content-Type"])
                        self.assertEqual(response.headers["Content-Security-Policy"],
                                         attestor_ui.CONTENT_SECURITY_POLICY)
                        self.assertTrue(response.read())
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
