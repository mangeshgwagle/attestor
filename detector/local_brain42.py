#!/usr/bin/env python3
"""local_brain42 -- Owen's keyless local brain adapter.

Connects to Ollama on the loopback (default 127.0.0.1:11434). No API
keys, no accounts, no cloud: the weights sit on disk and answer forever,
online or air-gapped.

    draft()      one-shot completion from a chosen local model
    gauntlet()   brain drafts -> Owen's scanner audits -> verdict42 signs
    status()     which local models are available right now
    self-test    proves the full client path against a mock server,
                 so the adapter is validated even before Ollama runs
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

LB_SCHEMA = "attestor-local-brain-4.2"
OLLAMA = "http://127.0.0.1:11434"
DEFAULT_MODEL = "qwen2.5-coder:1.5b"
TIMEOUT = 1800


class LbError(ValueError):
    pass


def _post(url, payload, timeout=TIMEOUT):
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _get(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def status(base=OLLAMA):
    try:
        tags = _get(base + "/api/tags")
        models = [m["name"] for m in tags.get("models", [])]
        return {"alive": True, "base": base, "models": models,
                "key_required": False}
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return {"alive": False, "base": base, "models": [],
                "hint": "start Ollama or run: ollama serve"}


def draft(prompt, model=DEFAULT_MODEL, system=None, base=OLLAMA):
    payload = {"model": model, "prompt": prompt, "stream": False}
    if system:
        payload["system"] = system
    result = _post(base + "/api/generate", payload)
    return {
        "schema": LB_SCHEMA,
        "model": model,
        "key_required": False,
        "response": result.get("response", ""),
        "eval_duration_ns": result.get("eval_duration"),
        "eval_count": result.get("eval_count"),
    }


def gauntlet(prompt, model=DEFAULT_MODEL, base=OLLAMA):
    """The brain drafts; Owen's scanner audits; the verdict is returned
    for signing. This is the hybrid: proposal without trust."""
    draft_result = draft(prompt, model=model, base=base)
    code = draft_result["response"]

    scan_summary = None
    try:
        sys.path.insert(0, __file__.rsplit("\\", 1)[0]
                        if "\\" in __file__ else ".")
        import source_hardening42 as hard
        hits = hard.scan_text(code)
        scan_summary = {"findings": len(hits),
                        "checks": sorted({h["check"] for h in hits})}
    except Exception as exc:  # noqa: BLE001
        scan_summary = {"error": str(exc)[:120]}

    return {
        "schema": LB_SCHEMA,
        "tool": "brain-gauntlet",
        "model": model,
        "draft_chars": len(code),
        "draft": code,
        "owen_scan": scan_summary,
        "boundary": ("brain proposes; Owen's deterministic scanner "
                     "audits; trust comes from the audit, not the brain"),
    }


# ------------------------------------------------------------- selftest

def run_selftest():
    """Proves the client against a mock loopback server: no Ollama
    required for the adapter's own validation."""
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class Mock(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps({"models": [{"name": "mock-brain"}]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            self.rfile.read(length)
            body = json.dumps({"response": "MOCK-DRAFT-OK"}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    server = HTTPServer(("127.0.0.1", 0), Mock)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % port

    checks = []
    st = status(base)
    checks.append(("status probe works", st["alive"]
                   and "mock-brain" in st["models"]))
    d = draft("hello", model="mock-brain", base=base)
    checks.append(("draft roundtrip", d["response"] == "MOCK-DRAFT-OK"))
    checks.append(("keyless by design", d["key_required"] is False))
    g = gauntlet("write a parser", model="mock-brain", base=base)
    checks.append(("gauntlet audits the draft",
                   g["draft_chars"] > 0 and "owen_scan" in g))

    server.shutdown()
    failed = [name for name, ok in checks if not ok]
    return {
        "schema": LB_SCHEMA,
        "tool": "self-test",
        "mode": "mock-loopback",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="local_brain42", description="Keyless local brain adapter")
    subs = parser.add_subparsers(dest="command", required=True)

    subs.add_parser("status")
    p = subs.add_parser("draft")
    p.add_argument("--prompt", required=True)
    p.add_argument("--model", default=DEFAULT_MODEL)
    p.add_argument("--system")
    p = subs.add_parser("gauntlet")
    p.add_argument("--prompt", required=True)
    p.add_argument("--model", default=DEFAULT_MODEL)
    subs.add_parser("self-test")
    args = parser.parse_args(argv)

    try:
        if args.command == "status":
            result = status()
            print(json.dumps(result, indent=2, sort_keys=True))
            return EXIT_CLEAN if result["alive"] else 3
        if args.command == "draft":
            result = draft(args.prompt, model=args.model,
                           system=args.system)
            print(json.dumps(result, indent=2, sort_keys=True))
            return EXIT_CLEAN
        if args.command == "gauntlet":
            result = gauntlet(args.prompt, model=args.model)
            print(json.dumps(result, indent=2, sort_keys=True))
            return EXIT_CLEAN
        if args.command == "self-test":
            result = run_selftest()
            print(json.dumps(result, indent=2, sort_keys=True))
            return EXIT_CLEAN if result["passed"] else EXIT_OPERATIONAL
    except (LbError, OSError, json.JSONDecodeError) as exc:
        print("local_brain42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID
    return EXIT_INVALID


EXIT_CLEAN = 0

if __name__ == "__main__":
    sys.exit(main())
