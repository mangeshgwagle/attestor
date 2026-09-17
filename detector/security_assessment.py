#!/usr/bin/env python3
"""Small, preview-first service assessment with portable evidence reports.

Only TCP connections and HTTP HEAD requests are issued. Plans name exact
targets, expire after one hour, and are confirmed before any network activity.
"""
from __future__ import annotations

import argparse
import hashlib
import html
import http.client
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import shutil
import socket
import ssl
import sys
import threading
import time
from urllib.parse import urlsplit, urlunsplit

PLAN_SCHEMA = "attestor.assessment-plan.v1"
REPORT_SCHEMA = "attestor.assessment-report.v1"
MAX_CHECKS = 128
MAX_SECONDS = 60
MAX_FILE_BYTES = 4 * 1024 * 1024


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("utf-8")


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _integer(value, low, high, name):
    if type(value) is not int or not low <= value <= high:
        raise ValueError(f"{name} must be an integer from {low} to {high}")
    return value


def _target(value):
    if not isinstance(value, str) or not value or len(value) > 2048:
        raise ValueError("Each target must be one exact host, IP address, or HTTP(S) URL")
    if any(ord(c) < 33 or ord(c) == 127 for c in value) or "\\" in value:
        raise ValueError("Targets cannot contain spaces, control characters, or backslashes")
    is_url = "://" in value
    try:
        address = ipaddress.ip_address(value) if not is_url else None
    except ValueError:
        address = None
    if address is not None:
        if "%" in value:
            raise ValueError("IPv6 zone identifiers are not supported")
        return {"value": str(address), "host": str(address), "url": None}
    try:
        parsed = urlsplit(value if is_url else "//" + value)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid target address") from exc
    if not host or parsed.username is not None or parsed.password is not None:
        raise ValueError("Targets need an exact hostname and cannot contain credentials")
    if parsed.query or parsed.fragment:
        raise ValueError("Use a URL without query parameters or a fragment")
    if not is_url and (parsed.path or port is not None):
        raise ValueError("For a port or path, use an HTTP(S) URL or the ports option")
    if is_url and parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported")
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            host = host.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ValueError("Invalid hostname") from exc
        if len(host) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                                      for part in host.split(".")):
            raise ValueError("Use exact hostnames; ranges and wildcards are not supported")
    if "%" in host:
        raise ValueError("IPv6 zone identifiers are not supported")
    if port is not None:
        _integer(port, 1, 65535, "URL port")
    if is_url:
        authority = "[" + host + "]" if ":" in host else host
        if port is not None:
            authority += ":" + str(port)
        path = parsed.path or "/"
        try:
            path.encode("ascii")
        except UnicodeError as exc:
            raise ValueError("URL paths must use percent encoding for non-ASCII characters") from exc
        value = urlunsplit((parsed.scheme, authority, path, "", ""))
        return {"value": value, "host": host, "url": value}
    return {"value": host, "host": host, "url": None}


def _checks(targets, ports):
    checks = []
    for value in targets:
        target = _target(value)
        for port in ports:
            checks.append({"kind": "tcp", "target": value, "host": target["host"],
                           "port": port, "description": f"TCP connection to {target['host']}:{port}"})
        if target["url"]:
            parsed = urlsplit(target["url"])
            checks.append({"kind": "http", "target": value, "host": target["host"],
                           "port": parsed.port or (443 if parsed.scheme == "https" else 80),
                           "url": value, "description": f"HTTP HEAD headers for {value}"})
    return checks


def create_plan(targets, ports=None, timeout_seconds=3, max_requests=64, label=""):
    if not isinstance(targets, list) or not 1 <= len(targets) <= 8:
        raise ValueError("Choose between 1 and 8 exact targets")
    ports = [80, 443] if ports is None else ports
    if not isinstance(ports, list) or not 1 <= len(ports) <= 16:
        raise ValueError("Choose between 1 and 16 TCP ports")
    ports = sorted(set(_integer(p, 1, 65535, "Port") for p in ports))
    timeout_seconds = _integer(timeout_seconds, 1, 10, "Check timeout")
    max_requests = _integer(max_requests, 1, MAX_CHECKS, "Request budget")
    if not isinstance(label, str) or len(label) > 80 or any(ord(c) < 32 for c in label):
        raise ValueError("Report name must be at most 80 characters without control characters")
    targets = list(dict.fromkeys(_target(t)["value"] for t in targets))
    checks = _checks(targets, ports)
    if len(checks) > max_requests:
        raise ValueError(f"Plan needs {len(checks)} checks but its budget is {max_requests}")
    created = int(time.time())
    plan = {"schema": PLAN_SCHEMA, "label": label.strip() or "Security assessment",
            "targets": targets, "ports": ports, "checks": checks,
            "timeout_seconds": timeout_seconds, "max_requests": max_requests,
            "max_seconds": MAX_SECONDS, "created_at": created, "expires_at": created + 3600}
    plan["sha256"] = _digest(plan)
    return plan


def validate_plan(plan):
    if not isinstance(plan, dict):
        raise ValueError("Plan must be a JSON object")
    expected = {"schema", "label", "targets", "ports", "checks", "timeout_seconds",
                "max_requests", "max_seconds", "created_at", "expires_at", "sha256"}
    if set(plan) != expected or plan.get("schema") != PLAN_SCHEMA:
        raise ValueError("Unsupported or incomplete assessment plan")
    unsigned = {k: v for k, v in plan.items() if k != "sha256"}
    if plan["sha256"] != _digest(unsigned):
        raise ValueError("Plan changed after preview; create a fresh preview")
    created = _integer(plan["created_at"], 0, 2**53, "Creation time")
    if type(plan["expires_at"]) is not int or plan["expires_at"] != created + 3600:
        raise ValueError("Invalid plan expiration")
    if not created - 60 <= time.time() < plan["expires_at"]:
        raise ValueError("Plan expired or has a future creation time; create a fresh preview")
    rebuilt = create_plan(plan["targets"], plan["ports"], plan["timeout_seconds"],
                          plan["max_requests"], plan["label"])
    for key in ("targets", "ports", "checks", "timeout_seconds", "max_requests", "max_seconds", "label"):
        if plan[key] != rebuilt[key]:
            raise ValueError("Plan contains unsupported checks or options")
    return json.loads(_canonical(plan))


def _resolve(host, timeout):
    """Bound resolver waiting; use one address consistently for this run."""
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    answers = queue.Queue(maxsize=1)
    def lookup():
        try:
            answers.put((socket.getaddrinfo(host, None, type=socket.SOCK_STREAM), None))
        except OSError as exc:
            answers.put((None, exc))
    threading.Thread(target=lookup, daemon=True).start()
    try:
        addresses, error = answers.get(timeout=timeout)
    except queue.Empty as exc:
        raise TimeoutError("Hostname resolution timed out") from exc
    if error:
        raise error
    if not addresses:
        raise OSError("Hostname has no address")
    return addresses[0][4][0]


def _open_socket(address, port, timeout):
    ip = ipaddress.ip_address(address)
    if ip.is_multicast or ip.is_unspecified or ip.is_link_local:
        raise ValueError("Multicast, unspecified, and link-local addresses are not supported")
    connection = socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.settimeout(timeout)
        connection.connect((address, port))
        return connection
    except BaseException:
        connection.close()
        raise


class _PinnedHTTP(http.client.HTTPConnection):
    def __init__(self, host, port, address, timeout, secure=False):
        super().__init__(host, port, timeout=timeout)
        self.address = address
        self.secure = secure
        self.deadline = time.monotonic() + timeout

    def _remaining(self):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("HTTP check reached its time limit")
        return remaining

    def connect(self):
        self.sock = _open_socket(self.address, self.port, self.timeout)
        self.sock.settimeout(self._remaining())
        if self.secure:
            try:
                self.sock = ssl.create_default_context().wrap_socket(self.sock, server_hostname=self.host)
            except BaseException:
                self.sock.close()
                raise


def _perform(check, address, timeout):
    if check["kind"] == "tcp":
        with _open_socket(address, check["port"], timeout):
            return {"outcome": "open", "evidence": "TCP connection accepted"}
    parsed = urlsplit(check["url"])
    connection = _PinnedHTTP(check["host"], check["port"], address, timeout, parsed.scheme == "https")
    # An idle socket timeout alone does not bound a slowly trickling response.
    expired = threading.Event()
    def stop_response():
        expired.set()
        sock = connection.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
    timer = threading.Timer(timeout, stop_response)
    timer.daemon = True
    timer.start()
    try:
        connection.request("HEAD", parsed.path or "/", headers={"User-Agent": "Attestor-Assessment/1.0",
                                                               "Connection": "close"})
        response = connection.getresponse()
        if expired.is_set():
            raise TimeoutError("HTTP check reached its time limit")
        # Do not retain cookies, authentication headers, redirects, or bodies.
        wanted = {"content-type", "server", "strict-transport-security", "content-security-policy",
                  "x-content-type-options", "x-frame-options", "referrer-policy"}
        headers = {name.lower(): value[:1024] for name, value in response.getheaders()
                   if name.lower() in wanted}
        return {"outcome": "responded", "http_status": response.status, "headers": headers,
                "evidence": f"HTTP {response.status}; HEAD only; redirects not followed"}
    finally:
        timer.cancel()
        connection.close()


def _findings(check, result):
    target = check["target"]
    if result["outcome"] == "open":
        return [{"severity": "info", "title": f"TCP port {check['port']} is reachable", "target": target,
                 "evidence": result["evidence"], "recommendation": "Confirm this service is intended to be exposed."}]
    if result["outcome"] != "responded":
        return []
    rows = []
    if check["url"].startswith("http://"):
        rows.append({"severity": "info", "title": "HTTP endpoint responded without TLS", "target": target,
                     "evidence": result["evidence"], "recommendation": "Review HTTPS and redirect configuration; redirects were not followed."})
    if 200 <= result["http_status"] < 300 and "html" in result["headers"].get("content-type", "").lower():
        for name, description in (("content-security-policy", "Content Security Policy"),
                                  ("x-content-type-options", "MIME type sniffing protection")):
            if name not in result["headers"]:
                rows.append({"severity": "info", "title": description + " header not observed", "target": target,
                             "evidence": f"{name} was absent from this HEAD response",
                             "recommendation": "Review the full application response and deployment policy; this observation alone does not establish a vulnerability."})
    return rows


def run_plan(plan, confirm_sha256, authorized=False, cancel_event=None):
    plan = validate_plan(plan)
    if authorized is not True:
        raise ValueError("Confirm that you are authorized to assess these targets")
    if confirm_sha256 != plan["sha256"]:
        raise ValueError("Confirmation must match the preview's sha256")
    started = time.monotonic()
    deadline = started + plan["max_seconds"]
    report = {"schema": REPORT_SCHEMA, "label": plan["label"], "plan": plan,
              "started_at": int(time.time()), "status": "completed", "checks": [], "findings": [], "audit": [],
              "limitations": ["Connection and HEAD observations only; no vulnerability exploitation or authentication tests.",
                              "One resolved address per hostname is used; other addresses may behave differently.",
                              "Hashes check internal consistency, not author identity or independent proof of origin."]}
    def record(event, data):
        item = {"sequence": len(report["audit"]), "event": event, "data": data,
                "previous_sha256": report["audit"][-1]["sha256"] if report["audit"] else "0" * 64}
        item["sha256"] = _digest(item)
        report["audit"].append(item)
    record("start", {"plan_sha256": plan["sha256"]})
    addresses = {}
    for check in plan["checks"]:
        if cancel_event is not None and cancel_event.is_set():
            report["status"] = "cancelled"
            break
        if time.monotonic() >= deadline:
            report["status"] = "partial"
            break
        result = dict(check)
        try:
            host = check["host"]
            if host not in addresses:
                try:
                    addresses[host] = _resolve(host, min(plan["timeout_seconds"], max(.01, deadline - time.monotonic())))
                except (OSError, ValueError) as exc:
                    addresses[host] = exc
            if isinstance(addresses[host], Exception):
                raise addresses[host]
            result["resolved_address"] = addresses[host]
            if cancel_event is not None and cancel_event.is_set():
                report["status"] = "cancelled"
                break
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                report["status"] = "partial"
                break
            result.update(_perform(check, addresses[host], min(plan["timeout_seconds"], remaining)))
        except ConnectionRefusedError:
            result.update(outcome="closed", evidence="TCP connection refused")
        except (OSError, ValueError, http.client.HTTPException) as exc:
            result.update(outcome="error", evidence=str(exc)[:500])
            report["status"] = "partial"
        report["checks"].append(result)
        report["findings"].extend(_findings(check, result))
        record("check", {"index": len(report["checks"]) - 1, "sha256": _digest(result)})
    report["finished_at"] = int(time.time())
    report["duration_seconds"] = round(time.monotonic() - started, 3)
    record("finish", {"status": report["status"], "checks": len(report["checks"]),
                      "findings_sha256": _digest(report["findings"])})
    report["sha256"] = _digest(report)
    return report


def verify_report(report):
    if not isinstance(report, dict) or report.get("schema") != REPORT_SCHEMA:
        raise ValueError("Unsupported assessment report")
    if report.get("sha256") != _digest({k: v for k, v in report.items() if k != "sha256"}):
        raise ValueError("Report digest mismatch")
    plan = report.get("plan", {})
    events = report.get("audit", [])
    checks = report.get("checks", [])
    findings = report.get("findings", [])
    if (not isinstance(plan, dict) or not isinstance(events, list) or
            not isinstance(checks, list) or not isinstance(findings, list) or
            not all(isinstance(item, dict) for item in events + checks + findings) or
            not all(isinstance(item.get("data"), dict) for item in events) or
            report.get("status") not in ("completed", "cancelled", "partial") or
            not isinstance(report.get("label"), str) or
            not isinstance(report.get("limitations"), list)):
        raise ValueError("Malformed report fields")
    if plan.get("sha256") != _digest({k: v for k, v in plan.items() if k != "sha256"}):
        raise ValueError("Embedded plan digest mismatch")
    previous = "0" * 64
    if len(events) != len(checks) + 2:
        raise ValueError("Audit record count mismatch")
    for index, item in enumerate(events):
        if (item.get("sequence") != index or item.get("previous_sha256") != previous or
                item.get("sha256") != _digest({k: v for k, v in item.items() if k != "sha256"})):
            raise ValueError(f"Audit chain mismatch at record {index}")
        previous = item["sha256"]
    if events[0].get("event") != "start" or events[0]["data"] != {"plan_sha256": plan["sha256"]}:
        raise ValueError("Audit start mismatch")
    for index, check in enumerate(checks):
        if events[index + 1]["event"] != "check" or events[index + 1]["data"] != {"index": index, "sha256": _digest(check)}:
            raise ValueError("Check evidence mismatch")
    if events[-1]["event"] != "finish" or events[-1]["data"] != {
            "status": report["status"], "checks": len(checks), "findings_sha256": _digest(report["findings"])}:
        raise ValueError("Audit finish mismatch")
    return {"ok": True, "records": len(events), "report_sha256": report["sha256"]}


def render_html(report):
    verify_report(report)
    esc = lambda value: html.escape(str(value), quote=True)
    findings = "".join("<tr>" + "".join("<td>" + esc(row.get(key, "")) + "</td>" for key in
                        ("severity", "title", "target", "evidence", "recommendation")) + "</tr>"
                       for row in report["findings"])
    checks = "".join("<tr>" + "".join("<td>" + esc(row.get(key, "")) + "</td>" for key in
                     ("description", "resolved_address", "outcome", "evidence")) + "</tr>" for row in report["checks"])
    return ("<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
            "<title>Attestor assessment</title><style>body{font:16px system-ui;margin:3rem auto;padding:0 1rem;max-width:1100px;color:#172b32}"
            "table{border-collapse:collapse;width:100%;margin:1rem 0}td,th{text-align:left;vertical-align:top;padding:.7rem;border:1px solid #ccd8db;overflow-wrap:anywhere}"
            "th{background:#edf4f3}code{overflow-wrap:anywhere}li{margin:.5rem 0}@media print{body{margin:0}}</style>"
            "<h1>" + esc(report["label"]) + "</h1><p>Status: " + esc(report["status"]) + " · " + str(len(report["checks"])) +
            " checks · " + str(len(report["findings"])) + " observations</p><h2>Findings</h2>" +
            ("<table><tr><th>Severity</th><th>Observation</th><th>Target</th><th>Evidence</th><th>Follow-up</th></tr>" + findings + "</table>"
             if findings else "<p>No observations were produced. Review check outcomes below for coverage and errors.</p>") +
            "<h2>Checks</h2><table><tr><th>Check</th><th>Address</th><th>Outcome</th><th>Evidence</th></tr>" + checks +
            "</table><h2>Evidence</h2><p>Audit chain: verified internally (" + str(len(report["audit"])) + " records).</p><p>Report SHA-256: <code>" +
            esc(report["sha256"]) + "</code></p><h2>Scope and limits</h2><ul>" +
            "".join("<li>" + esc(item) + "</li>" for item in report["limitations"]) + "</ul></html>")


def status():
    candidates = []
    executable = shutil.which("msfconsole")
    if executable:
        candidates.append(Path(executable))
    for name in ("ATTESTOR_METASPLOIT_HOME", "METASPLOIT_HOME", "MSF_HOME"):
        if os.environ.get(name):
            root = Path(os.environ[name])
            candidates.extend(root / item for item in ("bin/msfconsole.bat", "bin/msfconsole", "msfconsole"))
    if os.name == "nt":
        candidates.append(Path("C:/metasploit-framework/bin/msfconsole.bat"))
    install = {"available": False, "version": None, "executable_path": None,
               "execution_enabled": False}
    for candidate in candidates:
        if not candidate.is_file():
            continue
        install.update(available=True, executable_path=str(candidate.resolve()))
        for root in (candidate.parent, candidate.parent.parent):
            manifest = root / "version-manifest.json"
            try:
                data = _read_json(manifest)
                install["version"] = data.get("build_version") or data.get("software", {}).get("metasploit-framework", {}).get("described_version")
                if install["version"]:
                    install["version_source"] = str(manifest)
                    break
            except (OSError, ValueError):
                pass
        break
    return {"available": True, "checks": ["tcp-connect", "http-head"], "metasploit": install}


def _read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key: " + key)
            result[key] = value
        return result
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("JSON file exceeds 4 MiB")
    return json.loads(raw, object_pairs_hook=unique)


def _write_new(path, content):
    with Path(path).open("x", encoding="utf-8") as stream:
        stream.write(content)


def _emit(value, as_json=False):
    if as_json:
        print(json.dumps(value, indent=2, ensure_ascii=True))
    else:
        print(value)


def main(argv=None):
    parser = argparse.ArgumentParser(prog="attestor security", description="Preview connection and web-header checks, then export an evidence report.")
    commands = parser.add_subparsers(dest="command")
    state = commands.add_parser("status", help="show supported checks and local Metasploit detection")
    state.add_argument("--json", action="store_true")
    msf = commands.add_parser("metasploit", help="inspect the local Metasploit installation")
    msf.add_argument("action", choices=("status",))
    msf.add_argument("--json", action="store_true")
    preview = commands.add_parser("plan", help="create a preview without contacting targets")
    preview.add_argument("--target", action="append", required=True, help="exact host, IP or HTTP(S) URL; repeat for several targets")
    preview.add_argument("--ports", default="80,443", help="comma-separated TCP ports (default: 80,443)")
    preview.add_argument("--label", default="")
    preview.add_argument("--out", help="save the plan to a new JSON file")
    preview.add_argument("--json", action="store_true")
    execute = commands.add_parser("run", help="execute a confirmed plan and save HTML/JSON evidence")
    execute.add_argument("--plan", required=True)
    execute.add_argument("--confirm", required=True, help="SHA-256 shown in the preview")
    execute.add_argument("--authorized", action="store_true", help="confirm permission to assess the listed targets")
    execute.add_argument("--out", required=True, help="new output directory")
    execute.add_argument("--json", action="store_true")
    export = commands.add_parser("report", help="export an existing report as HTML")
    export.add_argument("--input", required=True)
    export.add_argument("--out", required=True)
    audit = commands.add_parser("audit-verify", help="check report digests and audit consistency")
    audit.add_argument("--input", required=True)
    audit.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0
    as_json = getattr(args, "json", False)
    try:
        if args.command in ("status", "metasploit"):
            info = status()
            if as_json:
                _emit(info if args.command == "status" else info["metasploit"], True)
            else:
                print("Checks: TCP connections and HTTP HEAD headers")
                msf_info = info["metasploit"]
                print("Metasploit: " + (str(msf_info["version"] or "detected") if msf_info["available"] else "not found"))
                if msf_info["executable_path"]:
                    print("Location: " + msf_info["executable_path"])
                print("Next: attestor security plan --target https://your-host --out plan.json")
        elif args.command == "plan":
            plan = create_plan(args.target, [int(p.strip()) for p in args.ports.split(",")], label=args.label)
            if args.out:
                _write_new(args.out, json.dumps(plan, indent=2))
            if as_json:
                _emit(plan, True)
            else:
                print(plan["label"] + f" | {len(plan['checks'])} checks | expires in 1 hour")
                for check in plan["checks"]:
                    print("  " + check["description"])
                print("\nConfirmation: " + plan["sha256"])
                print("Plan saved: " + args.out if args.out else "Use --out plan.json to save this preview.")
                if args.out:
                    print(f'Next: attestor security run --plan "{args.out}" --confirm {plan["sha256"]} --authorized --out assessment-results')
        elif args.command == "run":
            plan = validate_plan(_read_json(args.plan))
            if not args.authorized or args.confirm != plan["sha256"]:
                raise ValueError("Run requires --authorized and --confirm matching the preview's sha256")
            output = Path(args.out)
            output.mkdir(parents=True, exist_ok=False)
            cancelled = threading.Event()
            import signal
            previous = signal.signal(signal.SIGINT, lambda *_: cancelled.set())
            try:
                report = run_plan(plan, args.confirm, True, cancelled)
            finally:
                signal.signal(signal.SIGINT, previous)
            _write_new(output / "report.json", json.dumps(report, indent=2))
            _write_new(output / "report.html", render_html(report))
            result = {"status": report["status"], "checks": len(report["checks"]),
                      "findings": len(report["findings"]), "output": str(output.resolve())}
            _emit(result if as_json else f"{result['status']}: {result['checks']} checks, {result['findings']} observations\nReports: {result['output']}", as_json)
            return 0 if report["status"] == "completed" else 3
        elif args.command == "report":
            _write_new(args.out, render_html(_read_json(args.input)))
            print("Report saved: " + args.out)
        elif args.command == "audit-verify":
            result = verify_report(_read_json(args.input))
            _emit(result if as_json else f"Verified {result['records']} audit records and report digest.", as_json)
        return 0
    except (OSError, ValueError, TypeError, KeyError) as exc:
        if as_json:
            _emit({"ok": False, "error": str(exc)}, True)
        else:
            print("attestor security: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
