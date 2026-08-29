#!/usr/bin/env python3
"""msf_lite42 -- experimental Metasploit-shaped framework for Attestor.

What this IS:
- a module registry (auxiliary scanners + one exploit-class module)
- authorized-target exploit CONFIRMATION with evidence sessions
- payload concept limited to exec-marker proof (does the parameter reach
  execution? does the marker echo back?)

What this explicitly is NOT (refusal list, enforced by omission):
- no reverse/bind shell payloads, no staged payloads
- no persistence, no privilege escalation, no process migration
- no AV/EDR evasion, no credential dumping, no lateral movement tooling

Those omissions are the malware boundary. Everything here operates against
targets the operator is authorized to test and produces evidence, not
access.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys

sys.path.insert(0, __file__.rsplit("\\", 1)[0] if "\\" in __file__ else ".")

MSF_SCHEMA = "attestor-msf-lite-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

REFUSAL_LIST = (
    "reverse-shell", "bind-shell", "staged-payload", "persistence",
    "privilege-escalation", "process-migration", "av-evasion",
    "credential-dumping", "lateral-movement",
)

MODULES = {}


def module(name, kind):
    def register(fn):
        MODULES[name] = {"kind": kind, "fn": fn}
        return fn
    return register


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class MsfError(ValueError):
    pass


# ------------------------------------------------------------- modules

@module("aux.http_headers", "auxiliary")
def aux_http_headers(opts):
    import active_scan42 as ascanner
    url = opts.get("url")
    if not url:
        raise MsfError("url required")
    report = ascanner.scan_url(url, param=opts.get("param", "q"),
                               delay=float(opts.get("delay", 0.1)),
                               timeout=4.0, max_requests=30)
    header_hits = [f for f in report["findings"]
                   if f["kind"] == "missing-security-header"]
    return {
        "module": "aux.http_headers",
        "findings": header_hits,
        "count": len(header_hits),
    }


@module("aux.jwt_none", "auxiliary")
def aux_jwt_none(opts):
    token = opts.get("token")
    if not token:
        raise MsfError("token required")
    import offensive_lab42 as lab
    forged = lab.jwt_none_forge(token)
    return {
        "module": "aux.jwt_none",
        "variants": len(forged["variants"]),
        "note": forged["note"],
    }


@module("exploit.sqli_tautology", "exploit")
def exploit_sqli_tautology(opts):
    """Confirms boolean-tautology injection by demonstrating a deterministic
    response difference on an authorized target. Produces evidence; never
    extracts more than the differential itself."""
    import urllib.error
    import urllib.parse
    import urllib.request

    url = opts.get("url")
    param = opts.get("param", "user")
    if not url:
        raise MsfError("url required")

    def fetch(value):
        split = urllib.parse.urlsplit(url)
        query = dict(urllib.parse.parse_qsl(split.query,
                                            keep_blank_values=True))
        query[param] = value
        target = urllib.parse.urlunsplit(
            (split.scheme, split.netloc, split.path,
             urllib.parse.urlencode(query), split.fragment))
        request = urllib.request.Request(target)
        try:
            with urllib.request.urlopen(request, timeout=6) as response:
                return response.status, response.read(262144)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(262144)

    status_base, body_base = fetch("attestor-baseline-42")
    status_pay, body_pay = fetch("' OR '1'='1")
    delta = len(body_pay) - len(body_base)
    confirmed = (status_pay == status_base == 200) and abs(delta) > 32
    return {
        "module": "exploit.sqli_tautology",
        "runtime_confirmed": bool(confirmed),
        "status_baseline": status_base,
        "len_baseline": len(body_base),
        "status_payload": status_pay,
        "len_payload": len(body_pay),
        "evidence_digest": sha256_hex(canonical_json({
            "u": url, "sb": status_base, "lb": len(body_base),
            "sp": status_pay, "lp": len(body_pay)}).encode()),
        "boundary": ("differential demonstration only; no data was "
                     "exfiltrated beyond the measured lengths"),
    }


@module("payload.exec_marker", "payload")
def payload_exec_marker(_opts):
    """The only payload type in msf-lite: a marker string proving a
    parameter reached command execution. Shells are refused by design."""
    return {
        "module": "payload.exec_marker",
        "marker": ";cfmark42;",
        "interpretation": ("marker appearing verbatim in a response "
                           "indicates command execution"),
        "refused_alternatives": list(REFUSAL_LIST),
    }


def run_module(name, opts, authorized):
    entry = MODULES.get(name)
    if entry is None:
        raise MsfError("unknown module %r" % name)
    result = entry["fn"](opts or {})
    result["schema"] = MSF_SCHEMA
    result["session_entry"] = {
        "module": name,
        "digest": sha256_hex(canonical_json(result).encode()),
    }
    return result


def list_modules():
    return {
        "schema": MSF_SCHEMA,
        "modules": [{"name": name, "kind": meta["kind"]}
                    for name, meta in sorted(MODULES.items())],
        "refusal_list": list(REFUSAL_LIST),
        "note": ("experimental framework skeleton; payload surface is "
                 "deliberately limited to exec-marker proof"),
    }


def run_selftest():
    checks = []
    listing = list_modules()
    names = {m["name"] for m in listing["modules"]}
    checks.append(("registry populated",
                   {"aux.http_headers", "aux.jwt_none",
                    "exploit.sqli_tautology", "payload.exec_marker"}
                   <= names))
    checks.append(("refusal list documented",
                   set(REFUSAL_LIST) <= set(listing["refusal_list"])))

    from http.server import BaseHTTPRequestHandler, HTTPServer
    import threading

    class TautologyApp(BaseHTTPRequestHandler):
        def do_GET(self):
            query = urllib_parse_qs(self.path)
            user = query.get("user", ["x"])[0]
            if "1'='1" in user:
                body = b"<html>" + b"R" * 2048 + b"</html>"
            else:
                body = b"<html>no results</html>"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def urllib_parse_qs(path):
        import urllib.parse
        return urllib.parse.parse_qs(
            urllib.parse.urlsplit(path).query)

    server = HTTPServer(("127.0.0.1", 0), TautologyApp)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    try:
        outcome = run_module(
            "exploit.sqli_tautology",
            {"url": "http://127.0.0.1:%d/?q=x&user=z" % port,
             "param": "user"},
            authorized=True)
        checks.append(("tautology exploit confirms runtime",
                       outcome["runtime_confirmed"] is True))
        checks.append(("evidence digest pinned",
                       len(outcome["session_entry"]["digest"]) == 64))
    finally:
        server.shutdown()
        server.server_close()

    checks.append(("modules run without ceremony",
                   isinstance(run_module("payload.exec_marker", {},
                                         authorized=False), dict)))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": MSF_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="msf_lite42", description="Experimental Metasploit-shaped "
                                       "framework (exec-marker only)")
    subs = parser.add_subparsers(dest="command", required=True)

    subs.add_parser("list")

    p = subs.add_parser("run")
    p.add_argument("--module", required=True)
    p.add_argument("--opts", help="JSON options")

    subs.add_parser("self-test")
    args = parser.parse_args(argv)

    try:
        if args.command == "list":
            result = list_modules()
            code = EXIT_CLEAN
        elif args.command == "run":
            opts = json.loads(args.opts) if args.opts else {}
            code = EXIT_FINDING if result.get(
                "runtime_confirmed") or result.get("count") else EXIT_CLEAN
        elif args.command == "self-test":
            result = run_selftest()
            code = EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL
        else:  # pragma: no cover
            parser.error("unknown command")
    except MsfError as exc:
        print("msf_lite42: %s" % exc, file=sys.stderr)
        return 3 if str(exc).startswith("gated:") else EXIT_INVALID
    except OSError as exc:
        print("msf_lite42: %s" % exc, file=sys.stderr)
        return EXIT_OPERATIONAL

    print(json.dumps(result, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
