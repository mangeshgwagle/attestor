#!/usr/bin/env python3
"""Attestor REST API server -- enterprise deployment wrapper.

Wraps every Attestor engine as HTTP endpoints. Zero external dependencies
(stdlib http.server). TCS / enterprise CI/CD hits this instead of the CLI.

    attestor serve --port 8844
    curl -X POST http://localhost:8844/api/check -d '{"root": "/app/src"}'
"""
from __future__ import annotations

import io
import json
import os
import sys
import time
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from threading import Lock
from urllib.parse import urlparse, parse_qs

_DETECTOR = Path(__file__).resolve().parent
if os.fspath(_DETECTOR) not in sys.path:
    sys.path.insert(0, os.fspath(_DETECTOR))

VERSION = "4.3"
API_KEY_HEADER = "X-Attestor-Key"
_scan_lock = Lock()


def _require_auth(handler) -> bool:
    expected = os.environ.get("ATTESTOR_API_KEY", "")
    if not expected:
        return True
    provided = handler.headers.get(API_KEY_HEADER, "")
    if provided != expected:
        handler.send_json({"error": "unauthorized"}, status=401)
        return False
    return True


def _json_body(handler) -> dict:
    length = int(handler.headers.get("Content-Length", 0))
    if length == 0:
        return {}
    raw = handler.rfile.read(length)
    return json.loads(raw.decode("utf-8"))


def _run_check(body: dict) -> dict:
    import triage
    import autofix
    import memory as mem_mod

    root = body.get("root", ".")
    effort = body.get("effort", "medium")

    from cli import _run_effort, EFFORT_SCANNERS
    mem = mem_mod.Memory(root)
    t0 = int(time.time() * 1000)

    triage.load_overrides()
    findings = _run_effort(root, effort)

    pre_filter = len(findings)
    findings = mem.filter_findings(findings)
    mem_suppressed = pre_filter - len(findings)

    triaged = triage.triage_all(findings)
    counts = triage.counts(triaged)

    actionable = [t for t in triaged if t.action != "suppress"]
    autofixable = sum(1 for t in actionable
                      if t.finding.get("rule_id", "") in autofix.SAFE_FIXERS)

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for t in actionable:
        s = t.finding.get("severity", "MEDIUM")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    elapsed = int(time.time() * 1000) - t0
    mem.record_scan([t.finding for t in triaged], scan_type="check",
                    paths=[root], duration_ms=elapsed)

    return {
        "version": VERSION,
        "root": root,
        "effort": effort,
        "scanner_groups": len(EFFORT_SCANNERS.get(effort, [])),
        "raw_findings": pre_filter,
        "memory_suppressed": mem_suppressed,
        "actionable": len(actionable),
        "autofixable": autofixable,
        "severity": sev_counts,
        "findings": triage.to_dict(triaged),
        "duration_ms": elapsed,
    }


def _run_secrets(body: dict) -> dict:
    import secret_scanner
    root = body.get("root", ".")
    findings = []
    if os.path.isdir(root):
        findings = secret_scanner.scan_directory(root)
    else:
        findings = secret_scanner.scan_file(root)
    return {"findings": secret_scanner.to_dict(findings),
            "count": len(findings)}


def _run_exploits(body: dict) -> dict:
    import exploit_detector
    root = body.get("root", ".")
    findings = []
    if os.path.isdir(root):
        findings = exploit_detector.scan_directory(root)
    else:
        findings = exploit_detector.scan_file(root)
    return {"findings": exploit_detector.to_dict(findings),
            "count": len(findings)}


def _run_compliance(body: dict) -> dict:
    import compliance
    root = body.get("root", ".")
    framework = body.get("framework", "owasp")
    from cli import _run_effort
    findings = _run_effort(root, body.get("effort", "high"))
    report = compliance.generate(findings, framework=framework, root=root)
    return compliance.to_dict(report)


def _run_sca(body: dict) -> dict:
    import sca_scanner
    root = body.get("root", ".")
    deps, findings = sca_scanner.scan(root, offline=body.get("offline", False))
    return sca_scanner.to_dict(deps, findings)


def _run_iac(body: dict) -> dict:
    import iac_scanner
    root = body.get("root", ".")
    findings = []
    if os.path.isdir(root):
        findings = iac_scanner.scan_directory(root)
    else:
        findings = iac_scanner.scan_file(root)
    return {"findings": iac_scanner.to_dict(findings),
            "count": len(findings)}


def _run_taint(body: dict) -> dict:
    import taint_tracker
    root = body.get("root", ".")
    flows = []
    if os.path.isdir(root):
        flows = taint_tracker.scan_directory(root)
    else:
        flows = taint_tracker.scan_file(root)
    return {"flows": taint_tracker.to_dict(flows),
            "count": len(flows)}


def _run_dataflow(body: dict) -> dict:
    import dataflow
    paths = body.get("paths", [body.get("root", ".")])
    findings = dataflow.scan_paths(paths)
    return {"findings": dataflow.to_dict(findings),
            "count": len(findings)}


def _run_sbom(body: dict) -> dict:
    import sbom_generator
    root = body.get("root", ".")
    fmt = body.get("format", "cyclonedx")
    sbom = sbom_generator.generate(root, fmt=fmt)
    return sbom_generator.to_dict(sbom)


def _run_threat_model(body: dict) -> dict:
    import threat_model
    root = body.get("root", ".")
    model = threat_model.analyze(root)
    return threat_model.to_dict(model)


def _run_surface(body: dict) -> dict:
    import attack_surface
    root = body.get("root", ".")
    entries = []
    if os.path.isdir(root):
        entries = attack_surface.scan_directory(root)
    else:
        entries = attack_surface.scan_file(root)
    return {"entries": attack_surface.to_dict(entries),
            "count": len(entries)}


def _run_hybrid(body: dict) -> dict:
    import hybrid_engine
    root = body.get("root", ".")
    effort = body.get("effort", "high")
    model = body.get("model", None)
    analyzer = hybrid_engine.HybridAnalyzer(root, model=model)
    results = analyzer.analyze(effort=effort, batch=True)
    return {"results": hybrid_engine.to_dict(results),
            "exploitable": sum(1 for r in results if r.verdict == "EXPLOITABLE"),
            "count": len(results)}


def _run_memory_stats(body: dict) -> dict:
    import memory as mem_mod
    root = body.get("root", ".")
    mem = mem_mod.Memory(root)
    return mem.get_stats()


def _run_memory_feedback(body: dict) -> dict:
    import memory as mem_mod
    root = body.get("root", ".")
    mem = mem_mod.Memory(root)
    verdict = body.get("verdict", "tp")
    path = body.get("file", "")
    line = body.get("line", 0)
    rule_id = body.get("rule_id", "")
    mem.feedback(verdict, path=path, line=line, rule_id=rule_id,
                 note=body.get("note", ""))
    return {"status": "recorded", "verdict": verdict,
            "file": path, "line": line}


def _run_sales_ingest(body: dict) -> dict:
    import sales_engine
    data_dir = body.get("data_dir", ".")
    sa = sales_engine.SalesAnalyzer(data_dir)
    results = []
    for csv_path in body.get("files", []):
        result = sa.ingest(csv_path, source=body.get("source", ""))
        results.append(result)
    return {"results": results}


def _run_sales_analyze(body: dict) -> dict:
    import sales_engine
    data_dir = body.get("data_dir", ".")
    sa = sales_engine.SalesAnalyzer(data_dir)
    report = sa.analyze(days=body.get("days", 30))
    return sales_engine.to_dict(report)


def _run_inventory_check(body: dict) -> dict:
    import inventory_engine
    data_dir = body.get("data_dir", ".")
    mon = inventory_engine.InventoryMonitor(data_dir)
    if body.get("stock"):
        mon.load_stock(body["stock"])
    if not mon._thresholds:
        mon.set_default_threshold(
            min_qty=body.get("min_qty", 10),
            reorder_qty=body.get("reorder_qty", 50))
    alerts = mon.check_thresholds()
    result = {"alerts": inventory_engine.alerts_to_dict(alerts),
              "count": len(alerts)}
    if body.get("generate_po") and alerts:
        po = mon.generate_po(alerts, vendor=body.get("vendor", ""))
        if po:
            result["po"] = inventory_engine.po_to_dict(po)
    return result


def _run_schedule_solve(body: dict) -> dict:
    import scheduler_engine
    s = scheduler_engine.Scheduler()
    if body.get("employees_csv"):
        s.load_employees_csv(body["employees_csv"])
    if body.get("shifts_csv"):
        s.load_shifts_csv(body["shifts_csv"])
    if body.get("labour_cap"):
        s.set_labour_cap(body["labour_cap"])
    schedule = s.solve(week_start=body.get("week", ""))
    result = scheduler_engine.to_dict(schedule)
    if body.get("gcal"):
        result["gcal_events"] = scheduler_engine.to_gcal_events(schedule)
    return result


def _run_novel(body: dict) -> dict:
    import novel_detector
    root = body.get("root", ".")
    threshold = body.get("threshold", 2.0)
    nd = novel_detector.NovelDetector(z_threshold=threshold)
    if os.path.isdir(root):
        findings = nd.scan_directory(root)
    else:
        findings = nd.scan_file(root)
    return {"findings": novel_detector.to_dict(findings),
            "count": len(findings)}


def _run_explain(body: dict) -> dict:
    import explainer
    from cli import _run_effort
    root = body.get("root", ".")
    effort = body.get("effort", "medium")
    findings = _run_effort(root, effort)
    top_n = body.get("top", 10)
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: sev_order.get(f.get("severity", "LOW"), 4))
    findings = findings[:top_n]
    exp = explainer.Explainer(context_lines=body.get("context", 5))
    explanations = exp.explain_batch(findings)
    return {"explanations": explainer.to_dict(explanations),
            "count": len(explanations)}


ROUTES: dict[str, callable] = {
    "/api/check": _run_check,
    "/api/secrets": _run_secrets,
    "/api/exploits": _run_exploits,
    "/api/compliance": _run_compliance,
    "/api/sca": _run_sca,
    "/api/iac": _run_iac,
    "/api/taint": _run_taint,
    "/api/dataflow": _run_dataflow,
    "/api/sbom": _run_sbom,
    "/api/threat-model": _run_threat_model,
    "/api/surface": _run_surface,
    "/api/hybrid": _run_hybrid,
    "/api/memory/stats": _run_memory_stats,
    "/api/memory/feedback": _run_memory_feedback,
    "/api/sales/ingest": _run_sales_ingest,
    "/api/sales/analyze": _run_sales_analyze,
    "/api/inventory/check": _run_inventory_check,
    "/api/schedule/solve": _run_schedule_solve,
    "/api/novel": _run_novel,
    "/api/explain": _run_explain,
}


class AttestorHandler(BaseHTTPRequestHandler):
    server_version = f"Attestor/{VERSION}"

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[attestor-api] {fmt % args}\n")

    def send_json(self, data: dict, status: int = 200):
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Attestor-Version", VERSION)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlparse(self.path).path.rstrip("/")

        if path == "/api/health":
            self.send_json({"status": "ok", "version": VERSION})
            return

        if path == "/api/version":
            import platform
            self.send_json({
                "version": VERSION,
                "branding": "for AI's, by AI",
                "python": platform.python_version(),
                "platform": platform.platform(),
                "endpoints": sorted(ROUTES.keys()),
            })
            return

        if path == "/api/routes":
            self.send_json({"routes": sorted(ROUTES.keys())})
            return

        self.send_json({"error": "not found", "available": "/api/health, /api/version, /api/routes"},
                       status=404)

    def do_POST(self):
        if not _require_auth(self):
            return

        path = urlparse(self.path).path.rstrip("/")
        handler_fn = ROUTES.get(path)
        if not handler_fn:
            self.send_json({"error": f"unknown endpoint: {path}",
                           "available": sorted(ROUTES.keys())}, status=404)
            return

        try:
            body = _json_body(self)
        except (json.JSONDecodeError, ValueError) as e:
            self.send_json({"error": f"invalid JSON: {e}"}, status=400)
            return

        t0 = time.time()
        try:
            with _scan_lock:
                result = handler_fn(body)
            result["_meta"] = {
                "endpoint": path,
                "duration_ms": int((time.time() - t0) * 1000),
                "version": VERSION,
            }
            self.send_json(result)
        except FileNotFoundError as e:
            self.send_json({"error": f"path not found: {e}"}, status=404)
        except Exception as e:
            tb = traceback.format_exc()
            sys.stderr.write(f"[attestor-api] ERROR on {path}: {tb}\n")
            self.send_json({"error": str(e), "endpoint": path}, status=500)


def serve(host: str = "0.0.0.0", port: int = 8844):
    server = HTTPServer((host, port), AttestorHandler)
    key_status = "enabled" if os.environ.get("ATTESTOR_API_KEY") else "disabled"
    sys.stderr.write(
        f"\n  Attestor API Server v{VERSION}\n"
        f"  Listening on {host}:{port}\n"
        f"  Auth: {key_status}\n"
        f"  Endpoints: {len(ROUTES)}\n\n"
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\nShutting down.\n")
        server.server_close()


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Attestor API Server")
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=8844)
    a = p.parse_args()
    serve(a.host, a.port)
