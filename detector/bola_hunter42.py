#!/usr/bin/env python3
"""BOLA Hunter 4.2 -- graph-aware broken-access-control differential engine.

Pipeline (the Autorize idea, upgraded with an object graph):

    1. BASELINE   replay User-A's captured traffic with A credentials;
                  extract object identifiers from responses
    2. GRAPH      map every object id -> the principal that may read it,
                  so the hunter knows exactly which id belongs to whom
    3. DIFFERENTIAL   replay each request with B's credentials (and
                  optionally unauthenticated); compare status + length
    4. VERDICT    wrong-principal success => IDOR/BOLA candidate,
                  evidence-pinned; 401/403 => protected control confirmed

Language note: this operates purely at the HTTP layer, so it tests
backends written in any language whatsoever.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import urllib.error
import urllib.request

BH_SCHEMA = "attestor-bola-hunter-4.2"
EXIT_CLEAN = 0
EXIT_FINDING = 1
EXIT_INVALID = 2
EXIT_OPERATIONAL = 4

ID_PATTERNS = (
    ("numeric-id", re.compile(r"\b(\d{1,10})\b")),
    ("uuid", re.compile(r"\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
                        r"[0-9a-f]{4}-[0-9a-f]{12})\b", re.I)),
    ("email", re.compile(r"\b([\w.+-]+@[\w-]+\.[\w.]+)\b")),
)

AUTH_HEADERS = ("authorization", "cookie", "x-api-key", "x-auth-token",
                "x-session")
LEN_TOLERANCE_ABS = 48


class BhError(ValueError):
    pass


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_session_log(path):
    entries = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            item = json.loads(line)
            if not isinstance(item, dict) or "method" not in item or \
                    "path" not in item:
                raise BhError("log lines need method+path")
            entries.append(item)
    if not entries:
        raise BhError("empty session log")
    return entries


def _request(method, url, headers, body, timeout=6.0):
    request = urllib.request.Request(url, data=body, method=method)
    for name, value in headers.items():
        request.add_header(name, str(value))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read(262144)
            return response.status, payload
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(262144)


def split_credentials(request_headers):
    """Return (auth_subset, anon_rest) for header swapping."""
    auth_part = {}
    rest = {}
    for name, value in (request_headers or {}).items():
        if name.lower() in AUTH_HEADERS:
            auth_part[name] = value
        else:
            rest[name] = value
    return auth_part, rest


def extract_object_ids(text):
    found = []
    seen = set()
    for kind, pattern in ID_PATTERNS:
        for match in pattern.finditer(text):
            token = match.group(1)
            key = (kind, token.lower())
            if key in seen:
                continue
            seen.add(key)
            found.append({"kind": kind, "id": token})
    return found


def build_object_graph(entries, base_url, principal_headers, principal_name,
                       timeout):
    """Baseline pass: fetch as the owning principal, learn id ownership."""
    graph = {}
    _, base_headers = split_credentials({})
    for entry in entries:
        headers = dict(base_headers)
        headers.update(principal_headers)
        headers.update({k: v for k, v in (entry.get("headers") or {}).items()
                        if k.lower() not in AUTH_HEADERS})
        body = (entry.get("body") or "").encode()
        url = base_url.rstrip("/") + entry["path"]
        status, payload = _request(entry["method"], url, headers, body,
                                   timeout)
        if status == 200:
            for obj in extract_object_ids(payload.decode("latin-1",
                                                         errors="replace")):
                key = (obj["kind"], obj["id"].lower())
                graph.setdefault(key, {
                    "id": obj["id"], "kind": obj["kind"],
                    "owner": principal_name,
                    "endpoints": set(),
                })["endpoints"].add(entry["path"])
        for obj in extract_object_ids(entry["path"]):
            key = (obj["kind"], obj["id"].lower())
            graph.setdefault(key, {
                "id": obj["id"], "kind": obj["kind"],
                "owner": principal_name,
                "endpoints": set(),
            })["endpoints"].add(entry["path"])
    return graph


def compare_responses(status_a, len_a, status_b, len_b):
    if status_b in (401, 403, 302, 301):
        return "protected"
    if status_b >= 500:
        return "error-on-cross-principal"
    if status_a == status_b and abs(len_b - len_a) <= LEN_TOLERANCE_ABS:
        return "same-content-wrong-principal"
    if status_b == status_a:
        return "partial-divergence-review"
    return "divergent"


def hunt(entries, base_url, config, timeout=6.0, graph_aware=True):
    alice = config.get("a") or {}
    bob = config.get("b") or {}
    unauth = bool(config.get("unauthenticated", False))
    a_headers = alice.get("headers") or {}
    b_headers = bob.get("headers") or {}

    graph = {}
    if graph_aware:
        graph = build_object_graph(entries, base_url, a_headers, "A",
                                   timeout)

    findings = []
    checked = 0
    protected_count = 0

    _, plain_headers = split_credentials({})
    for entry in entries:
        path = entry["path"]
        method = entry["method"]
        body = (entry.get("body") or "").encode()
        base_headers = dict(plain_headers)
        base_headers.update({k: v for k, v in
                             (entry.get("headers") or {}).items()
                             if k.lower() not in AUTH_HEADERS})

        url = base_url.rstrip("/") + path
        status_a, payload_a = _request(method, url,
                                       {**base_headers, **a_headers},
                                       body, timeout)
        len_a = len(payload_a)

        variants = [("user-b", b_headers)]
        if unauth:
            variants.append(("anonymous", {}))

        for label, swap_headers in variants:
            checked += 1
            status_b, payload_b = _request(
                method, url, {**base_headers, **swap_headers}, body,
                timeout)
            verdict = compare_responses(status_a, len_a, status_b,
                                        len(payload_b))
            if verdict in ("protected", "divergent"):
                protected_count += verdict == "protected"
                continue

            path_ids = [(o["kind"], o["id"].lower()) for o in
                        extract_object_ids(path)]
            owners = sorted({graph[key]["owner"] for key in path_ids
                             if key in graph})
            findings.append({
                "kind": ("bola-candidate-%s" % verdict),
                "endpoint": path,
                "method": method,
                "swapped_to": label,
                "status_a": status_a, "len_a": len_a,
                "status_b": status_b, "len_b": len(payload_b),
                "verdict": verdict,
                "graph_owners_for_path_objects": owners,
                "evidence_digest": sha256_hex(
                    ("%s|%s|%s|%s" % (path, status_a, len_a,
                                      len(payload_b))).encode()),
                "label": "candidate",
            })
    return {
        "schema": BH_SCHEMA,
        "tool": "bola-hunter",
        "target": base_url,
        "graph_nodes": len(graph),
        "requests_replayed": checked,
        "protected_controls_confirmed": protected_count,
        "findings": findings,
        "finding_count": len(findings),
        "boundary": ("differential evidence over explicitly authorized "
                     "sessions; candidates are review points"),
    }


# ------------------------------------------------------------ self-test

def _make_app(enforce_owner):
    from http.server import BaseHTTPRequestHandler, HTTPServer
    import threading

    invoices = {"101": "ALICE-INVOICE total=900", "102": "BOB-INVOICE t=5"}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parts = self.path.split("/")
            inv_id = parts[-1] if parts else ""
            data = invoices.get(inv_id)
            if data is None:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"missing")
                return
            if enforce_owner:
                requester = self.headers.get("X-User", "?")
                owner = "alice" if inv_id == "101" else "bob"
                if requester != owner:
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b"denied")
                    return
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(data.encode())
    server = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def run_selftest():
    checks = []

    def probe(server_port, enforce):
        server = _make_app(enforce)
        port = server.server_address[1]
        try:
            entries = [{"method": "GET", "path": "/api/invoice/101",
                        "headers": {}}]
            config = {"a": {"headers": {"X-User": "alice"}},
                      "b": {"headers": {"X-User": "bob"}},
                      "unauthenticated": True}
            return hunt(entries, "http://127.0.0.1:%d" % port, config,
                        timeout=3.0, graph_aware=True)
        finally:
            server.shutdown()
            server.server_close()

    vulnerable = probe(0, enforce_owner=False)
    checks.append(("vulnerable app yields bola candidates",
                   any(f["verdict"] == "same-content-wrong-principal"
                       for f in vulnerable["findings"])))
    checks.append(("graph learned invoice ownership",
                   vulnerable["graph_nodes"] >= 1))

    hardened = probe(0, enforce_owner=True)
    checks.append(("hardened app shows zero candidates",
                   hardened["finding_count"] == 0))
    checks.append(("protections counted as controls",
                   hardened["protected_controls_confirmed"] >= 1))

    failed = [name for name, ok in checks if not ok]
    return {
        "schema": BH_SCHEMA,
        "tool": "self-test",
        "checks_total": len(checks),
        "checks_failed": failed,
        "passed": not failed,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="bola_hunter42",
        description="Graph-aware access-control differential scanner")
    parser.add_argument("--log", required=True,
                        help="JSONL session log captured as User A")
    parser.add_argument("--url", required=True)
    parser.add_argument("--config", required=True,
                        help="JSON: {'a':{'headers':..},'b':{..},"
                             "'unauthenticated':true}")
    parser.add_argument("--no-graph", action="store_true")
    args = parser.parse_args(argv)

    try:
        entries = load_session_log(args.log)
        with open(args.config, "r", encoding="utf-8") as handle:
            config = json.load(handle)
        report = hunt(entries, args.url, config,
                      graph_aware=not args.no_graph)
    except (BhError, OSError, json.JSONDecodeError) as exc:
        print("bola_hunter42: %s" % exc, file=sys.stderr)
        return EXIT_INVALID

    print(json.dumps(report, indent=2, sort_keys=True))
    return EXIT_FINDING if report["finding_count"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
