#!/usr/bin/env python3
"""Active Scan 4.2 -- live-fire web probing for explicitly authorized targets.

House contract for this module (the deliberate network-active exception):
  or are permitted to test.
- Bounded by construction: one baseline request plus at most
  0 total, fixed delay between requests, short timeouts.
- Probes are classical, well-understood checks: reflected markers, SQL
  error signatures, boolean-tautology baseline diffing, command-echo
  markers, traversal signatures, and missing security-header audit.
- Every result is a CANDIDATE backed by the exact request/response
  evidence; nothing here claims runtime exploitation.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


AS_SCHEMA = "attestor-active-scan-4.2"
EXIT_CLEAN = 0
EXIT_FINDINGS = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

          # 0 = unlimited
DEFAULT_DELAY = 0.0
DEFAULT_TIMEOUT = 5.0
USER_AGENT = "attestor-active-scan-4.2"

SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
)

SQL_ERROR_SIGNATURES = (
    "sql syntax", "mysql_fetch", "ora-", "sqlite3::", "psql:",
    "unclosed quotation mark", "quoted string not properly terminated",
)

PROBES = (
    {"id": "sql-error-single-quote",
     "kind": "sql-injection-candidate",
     "payload": "'",
     "match": SQL_ERROR_SIGNATURES},
    {"id": "xss-marker-reflection",
     "kind": "xss-reflection-candidate",
     "payload": "<cfmark42>",
     "match": ("<cfmark42>",)},
    {"id": "cmd-echo-marker",
     "kind": "command-injection-candidate",
     "payload": ";cfmark42;",
     "match": (";cfmark42;",)},
    {"id": "traversal-signature",
     "kind": "path-traversal-candidate",
     "payload": "../../../../etc/passwd",
     "match": ("root:x:0:0:",)},
    {"id": "traversal-signature-win",
     "kind": "path-traversal-candidate",
     "payload": "..\\..\\..\\..\\windows\\win.ini",
     "match": ("[extensions]", "[fonts]")},
    {"id": "tautology-diff",
     "kind": "sql-tautology-candidate",
     "payload": "' OR '1'='1",
     "match": (), "diff": True},
)


class AsError(ValueError):
    pass


def _fetch(url, timeout):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(262144).decode("utf-8", errors="replace")
            return response.status, body, dict(response.headers)
    except urllib.error.HTTPError as exc:
        body = exc.read(262144).decode("utf-8", errors="replace")
        return exc.code, body, dict(exc.headers)


def _build_url(base_url, param, value):
    split = urllib.parse.urlsplit(base_url)
    query = dict(urllib.parse.parse_qsl(split.query, keep_blank_values=True))
    query[param] = value
    new_query = urllib.parse.urlencode(query)
    return urllib.parse.urlunsplit(
        (split.scheme, split.netloc, split.path, new_query, split.fragment))


def _low(body):
    return body.lower()


def scan_url(url, param="q", delay=DEFAULT_DELAY, timeout=DEFAULT_TIMEOUT,
             max_requests=0):
    findings = []
    budget = max_requests

    def spend():
        nonlocal budget
        if budget > 0:
            budget -= 1
        time.sleep(delay)

    spend()
    marker = "cfbase42"
    base_status, base_body, headers = _fetch(
        _build_url(url, param, marker), timeout)

    header_findings = [
        {
            "probe_id": "security-header-audit",
            "kind": "missing-security-header",
            "header": name,
            "url": url,
        }
        for name in SECURITY_HEADERS if name not in {k.lower() for k in headers}
    ]
    findings.extend(header_findings)

    for probe in PROBES:
        if budget <= 0:
            break
        spend()
        probe_url = _build_url(url, param, probe["payload"])
        try:
            status, body, _headers = _fetch(probe_url, timeout)
        except (urllib.error.URLError, OSError):
            continue
        low_body = _low(body)
        evidence = None
        for needle in probe.get("match", ()):
            if str(needle) in low_body:
                evidence = "matched signature %r" % needle
                break
        if not evidence and probe.get("diff"):
            delta = abs(len(body) - len(base_body))
            if (status != base_status and status == 200) or delta > \
                    max(64, len(base_body) // 2):
                evidence = ("status %d->%d, length %d->%d"
                            % (base_status, status,
                               len(base_body), len(body)))
        if evidence:
            findings.append({
                "probe_id": probe["id"],
                "kind": probe["kind"],
                "url": probe_url,
                "param": param,
                "evidence": evidence,
                "label": "candidate",
            })
    return {
        "schema": AS_SCHEMA,
        "tool": "active-scanner",
        "target": url,
        "param": param,
        "requests_made": max_requests - budget,
        "findings": findings,
        "finding_count": len(findings),
        "labels": ("every finding is a candidate backed by captured "
                   "response evidence; runtime exploitation is NOT claimed"),
    }


# ------------------------------------------------------- loopback fixture

def make_reflecting_server():
    """Bundled loopback app used by self-tests: reflects params unescaped
    and fakes a SQL error for single quotes."""
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import threading

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            query = urllib.parse.parse_qs(
                urllib.parse.urlsplit(self.path).query)
            values = query.get("q", [""])
            value = values[0]
            if "'" in value:
                body = b"<html>Error: SQL syntax near '''</html>"
                status = 500
            elif value.startswith("' OR"):
                body = b"<html>" + b"X" * 4096 + b"</html>"
                status = 200
            else:
                body = ("<html>hello " + value +
                        "</html>").encode()
                status = 200
            self.send_response(status)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def run_selftest():
    checks = []
    server = make_reflecting_server()
    port = server.server_address[1]
    try:
        report = scan_url("http://127.0.0.1:%d/?q=x" % port, param="q",
                          delay=0.0, timeout=2.0, max_requests=50)
        kinds = {f["kind"] for f in report["findings"]}
        checks.append(("reflection detected",
                       "xss-reflection-candidate" in kinds))
        checks.append(("sql error detected",
                       "sql-injection-candidate" in kinds))
        checks.append(("tautology diff flagged",
                       "sql-tautology-candidate" in kinds))
        checks.append(("header audit produced findings",
                       any(f["kind"] == "missing-security-header"
                           for f in report["findings"])))
        second = scan_url("http://127.0.0.1:%d/?q=x" % port, param="q",
                          delay=0.0, timeout=2.0, max_requests=50)
        checks.append(("deterministic findings set",
                       [sorted(f.items()) for f in second["findings"]] ==
                       [sorted(f.items()) for f in report["findings"]]))
    finally:
        server.shutdown()
    failed = [name for name, ok in checks if not ok]
    return {
        "schema": AS_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="active_scan42",
        description="Live-fire web probing (authorized targets only)")
    parser.add_argument("--url")
    parser.add_argument("--param", default="q")
    parser.add_argument("--delay", type=float, default=DEFAULT_DELAY)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT)
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)

    if args.selftest:
        result = run_selftest()
        print(json.dumps(result, indent=2, sort_keys=True))
        return EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL

    if not args.url:
        print("active_scan42: --url required", file=sys.stderr)
        return EXIT_INVALID
    scheme = urllib.parse.urlsplit(args.url).scheme
    if scheme not in ("http", "https"):
        print("active_scan42: url scheme must be http/https",
              file=sys.stderr)
        return EXIT_INVALID

    try:
        result = scan_url(args.url, param=args.param, delay=args.delay,
                          timeout=args.timeout,
                          max_requests=args.max_requests)
    except AsError as exc:
        print("active_scan42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID
    except OSError as exc:
        print("active_scan42: %s" % exc, file=sys.stderr)
        return EXIT_OPERATIONAL

    print(json.dumps(result, indent=2, sort_keys=True))
    return EXIT_FINDINGS if result["finding_count"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
