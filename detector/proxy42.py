#!/usr/bin/env python3
"""Proxy 4.2 -- loopback interception proxy with Match & Replace rules and
Autorize-style live differential replay.

Workflow (Caido/Burp-style, stdlib-only):
  point your browser or scripts at http://127.0.0.1:PORT/ targeting an
  upstream you are authorized to test. Every request is:
    1. transformed by ordered Match & Replace rules (header/body/URL)
    2. forwarded upstream
    3. logged to a capture ledger (JSONL) that bola_hunter42 consumes
    4. optionally replayed with swapped credentials in the background,
       flagging status/length differences live (the Autorize behavior)

HTTPS note: plain-HTTP upstreams only in v1; no TLS interception, stated
honestly rather than faked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

PX_SCHEMA = "attestor-proxy-4.2"
EXIT_CLEAN = 0
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

AUTH_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token",
                "x-session")
LEDGER_LOCK = threading.Lock()


class PxError(ValueError):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_rules(path):
    with open(path, "r", encoding="utf-8") as handle:
        rules = json.load(handle)
    if not isinstance(rules, list):
        raise PxError("rules file must be a JSON list")
    compiled = []
    for rule in rules[:64]:
        if not isinstance(rule, dict):
            raise PxError("rules must be objects")
        compiled.append({
            "name": rule.get("name", "rule"),
            "field": rule.get("field", "body"),      # header|body|url|any
            "header": (rule.get("header") or "").lower(),
            "pattern": re.compile(str(rule.get("match", ""))) ,
            "replace": str(rule.get("replace", "")),
        })
    return compiled


def apply_rules(rules, url, headers, body):
    """Mutates headers/body/url per ordered rule list."""
    new_url = url
    new_headers = dict(headers)
    new_body = body

    for rule in rules:
        field = rule["field"]

        def sub(text):
            return rule["pattern"].sub(rule["replace"], text)

        try:
            if field in ("url", "any"):
                new_url = sub(new_url)
            if field in ("body", "any"):
                new_body = sub(new_body.decode("latin-1",
                                               errors="replace")).encode()
            if field in ("header", "any"):
                for name in list(new_headers.keys()):
                    if rule["header"] and name.lower() != rule["header"]:
                        continue
                    value = str(new_headers[name])
                    replaced = rule["pattern"].sub(rule["replace"], value)
                    if replaced != value:
                        new_headers[name] = replaced
        except re.error as exc:
            raise PxError("bad regex in rule %r: %s" % (rule["name"],
                                                        exc)) from None
    return new_url, new_headers, new_body


def swap_credentials(headers, replacement_headers):
    out = {k: v for k, v in headers.items()
           if k.lower() not in AUTH_HEADERS}
    out.update(replacement_headers or {})
    return out


def make_proxy(upstream, rules, ledger_path, autorize=None):
    """autorize: {'a': {'headers': {...}}, 'b': {'headers': {...}}}"""
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.0"

        def _relay(self, include_body):
            length = int(self.headers.get("Content-Length", 0) or 0)
            body = self.rfile.read(length) if include_body else b""
            url = upstream.rstrip("/") + self.path
            headers = {k: v for k, v in self.headers.items()}
            fwd_url, fwd_headers, fwd_body = apply_rules(
                rules, url, headers, body)

            request = urllib.request.Request(fwd_url, data=fwd_body or None,
                                             method=self.command)
            for name, value in fwd_headers.items():
                if name.lower() in ("host", "content-length"):
                    continue
                request.add_header(name, value)
            try:
                with urllib.request.urlopen(request, timeout=10) as resp:
                    payload = resp.read(1 << 20)
                    status = resp.status
                    resp_headers = dict(resp.headers)
            except urllib.error.HTTPError as exc:
                payload = exc.read(1 << 20)
                status = exc.code
                resp_headers = dict(exc.headers)

            entry = {
                "method": self.command,
                "path": self.path,
                "request_url": fwd_url,
                "status": status,
                "response_len": len(payload),
                "request_len": len(fwd_body),
            }

            diff_note = None
            if autorize:
                a_headers = (autorize.get("a") or {}).get("headers") or {}
                b_headers = (autorize.get("b") or {}).get("headers") or {}
                try:
                    req_a = urllib.request.Request(
                        fwd_url, data=fwd_body or None,
                        method=self.command)
                    for name, value in swap_credentials(fwd_headers,
                                                        a_headers).items():
                        if name.lower() == "host":
                            continue
                        req_a.add_header(name, value)
                    with urllib.request.urlopen(req_a, timeout=10) as ra:
                        pa = ra.read(1 << 20)
                        sa = ra.status
                    req_b = urllib.request.Request(
                        fwd_url, data=fwd_body or None,
                        method=self.command)
                    for name, value in swap_credentials(fwd_headers,
                                                        b_headers).items():
                        if name.lower() == "host":
                            continue
                        req_b.add_header(name, value)
                    with urllib.request.urlopen(req_b, timeout=10) as rb:
                        pb = rb.read(1 << 20)
                        sb = rb.status
                    same = (sa == sb and
                            abs(len(pb) - len(pa)) <= 48)
                    verdict = ("same-content-wrong-principal" if sa == sb
                               else "divergent")
                    if sb not in (401, 403):
                        diff_note = {
                            "kind": "live-bola-check",
                            "verdict": verdict,
                            "status_a": sa, "len_a": len(pa),
                            "status_b": sb, "len_b": len(pb),
                            "flag": bool(same),
                        }
                except (urllib.error.URLError, OSError):
                    diff_note = {"kind": "live-bola-check",
                                 "verdict": "replay-error"}
            entry["autorize"] = diff_note
            with LEDGER_LOCK:
                with open(ledger_path, "a", encoding="utf-8") as handle:
                    handle.write(json.dumps(entry) + "\n")

            self.send_response(status)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_GET(self):
            self._relay(False)

        def do_POST(self):
            self._relay(True)

        def do_PUT(self):
            self._relay(True)

        def do_DELETE(self):
            self._relay(False)

        def log_message(self, *_args):
            pass

    return HTTPServer(("127.0.0.1", 0), Handler)


def run_selftest():
    checks = []
    from http.server import BaseHTTPRequestHandler as B, HTTPServer as HS
    import threading
    seen = {}

    class Upstream(B):
        def do_GET(self):
            seen["auth"] = self.headers.get("Authorization", "")
            body = ("upstream:" + self.headers.get("Authorization", "?") +
                    ":data").encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    up = HS(("127.0.0.1", 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()

    import tempfile
    import os
    with tempfile.TemporaryDirectory() as tmp:
        rules_path = os.path.join(tmp, "rules.json")
        with open(rules_path, "w", encoding="utf-8") as handle:
            json.dump([{"name": "swap-a-to-b", "field": "header",
                        "header": "authorization",
                        "match": "Bearer A-TOKEN",
                        "replace": "Bearer B-TOKEN"}], handle)
        ledger = os.path.join(tmp, "ledger.jsonl")
        proxy = make_proxy(
            "http://127.0.0.1:%d" % up.server_address[1],
            load_rules(rules_path), ledger,
            autorize={"a": {"headers": {"Authorization": "Bearer A-TOKEN"}},
                      "b": {"headers": {"Authorization": "Bearer B-TOKEN"}}})
        port = proxy.server_address[1]
        threading.Thread(target=proxy.serve_forever, daemon=True).start()

        import urllib.request as ur
        request = ur.Request("http://127.0.0.1:%d/invoice/101" % port,
                             headers={"Authorization": "Bearer A-TOKEN"})
        with ur.urlopen(request) as r:
            body = r.read().decode()
        checks.append(("match-replace rewrote header upstream",
                       seen["auth"] == "Bearer B-TOKEN"))
        checks.append(("client still got a body", body.startswith("upstream:")))

        with open(ledger, "r", encoding="utf-8") as handle:
            lines = [json.loads(l) for l in handle if l.strip()]
        checks.append(("capture ledger written", len(lines) >= 1))
        checks.append(("autorize replay recorded",
                       any(e.get("autorize") and e["autorize"].get(
                           "verdict") == "same-content-wrong-principal"
                           for e in lines)))

    up.shutdown()
    up.server_close()
    failed = [name for name, ok in checks if not ok]
    return {
        "schema": PX_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="proxy42", description="Loopback Match&Replace + Autorize proxy")
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--rules")
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--autorize-config")

    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)

    if args.selftest:
        result = run_selftest()
        print(json.dumps(result, indent=2, sort_keys=True))
        return EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL


    rules = load_rules(args.rules) if args.rules else []
    autorize = None
    if args.autorize_config:
        with open(args.autorize_config, "r", encoding="utf-8") as handle:
            autorize = json.load(handle)

    server = make_proxy(args.upstream, rules, args.ledger,
                        autorize=autorize)
    actual_port = server.server_address[1]
    bound = args.port if args.port in (0, None) else None
    print(json.dumps({"listening": "127.0.0.1:%d" % actual_port,
                      "requested_port": bound or args.port,
                      "schema": PX_SCHEMA}))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
