#!/usr/bin/env python3
"""
darwin.py -- Attestor's bundled Darwin payload library.

Darwin adds a large web-application security payload dataset to Attestor. The
original archive shipped useful data but brittle tools: hard-coded F:\\temp paths,
a syntax error in export_tools.py, and CLI options that did not match the README.
This wrapper makes it portable and testable inside Attestor.

Examples:
    python darwin.py stats
    python darwin.py list
    python darwin.py search "sql injection" --limit 10
    python darwin.py show "XSS Injection" --limit 20
    python darwin.py export "SQL Injection" --format csv --out sql_payloads.csv
    python darwin.py serve --port 8080
"""
from __future__ import annotations

import argparse
import csv
import http.server
import json
import re
import socketserver
import xml.etree.ElementTree as ET
from pathlib import Path
from xml.dom import minidom

HERE = Path(__file__).resolve().parent
DATA_DIR = HERE / "darwin_payloads"
PAYLOADS_FILE = DATA_DIR / "payloads.json"


def load(path: Path = PAYLOADS_FILE) -> dict:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def stats(data: dict | None = None) -> dict:
    data = data or load()
    cats = data.get("categories", [])
    readme_payloads = sum(len(c.get("payloads", [])) for c in cats)
    intruder_payloads = sum(
        sum(len(v) for v in c.get("intruders", {}).values()) for c in cats)
    return {
        "categories": len(cats),
        "readme_payloads": readme_payloads,
        "intruder_payloads": intruder_payloads,
        "total_payloads": readme_payloads + intruder_payloads,
    }


def list_categories(data: dict | None = None) -> list[str]:
    data = data or load()
    return sorted(c["category"] for c in data.get("categories", []))


def find_category(name: str, data: dict | None = None) -> dict | None:
    data = data or load()
    low = name.lower()
    exact = [c for c in data.get("categories", []) if c["category"].lower() == low]
    if exact:
        return exact[0]
    partial = [c for c in data.get("categories", []) if low in c["category"].lower()]
    return partial[0] if partial else None


def iter_payloads(category: dict):
    for payload in category.get("payloads", []):
        yield "README", payload
    for name, payloads in category.get("intruders", {}).items():
        for payload in payloads:
            yield name, payload


def search(query: str, category: str | None = None, limit: int = 50,
           data: dict | None = None) -> list[dict]:
    data = data or load()
    q = query.lower()
    out = []
    for cat in data.get("categories", []):
        if category and category.lower() not in cat["category"].lower():
            continue
        for source, payload in iter_payloads(cat):
            if q in payload.lower():
                out.append({"category": cat["category"], "source": source,
                            "payload": payload})
                if limit and len(out) >= limit:
                    return out
    return out


def _safe_name(text: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_.-]+", "_", text.strip()).strip("_").lower()
    return name or "payloads"


def _escape_lua(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _escape_ruby(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _escape_python(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def export(category: str, fmt: str = "burp", out: str | None = None,
           data: dict | None = None) -> str:
    data = data or load()
    cat = find_category(category, data)
    if not cat:
        raise ValueError("category not found: " + category)
    payloads = list(iter_payloads(cat))
    base = _safe_name(cat["category"])
    ext = {"burp": "txt", "csv": "csv", "json": "json", "burp-project": "xml",
           "nmap": "nse", "sqlmap": "py", "metasploit": "rb"}.get(fmt)
    if not ext:
        raise ValueError("unknown export format: " + fmt)
    path = out or ("%s.%s" % (base, ext))

    if fmt == "burp":
        with open(path, "w", encoding="utf-8") as fh:
            for _source, payload in payloads:
                fh.write(payload + "\n")
    elif fmt == "csv":
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["Category", "Source", "Payload"])
            for source, payload in payloads:
                writer.writerow([cat["category"], source, payload])
    elif fmt == "json":
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"category": cat["category"], "payloads": [
                {"source": source, "payload": payload} for source, payload in payloads
            ]}, fh, indent=2)
            fh.write("\n")
    elif fmt == "burp-project":
        root = ET.Element("burpProject")
        group = ET.SubElement(root, "intruderPayloads", category=cat["category"])
        for source, payload in payloads:
            node = ET.SubElement(group, "payload", source=source)
            node.text = payload
        xml = minidom.parseString(ET.tostring(root)).toprettyxml(indent="  ")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(xml)
    elif fmt == "nmap":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("-- Nmap payload list for %s\n" % cat["category"])
            fh.write("local payloads = {\n")
            for _source, payload in payloads[:500]:
                fh.write('  "%s",\n' % _escape_lua(payload))
            fh.write("}\n\nreturn payloads\n")
    elif fmt == "sqlmap":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# sqlmap tamper payload list for %s\n" % cat["category"])
            fh.write("from lib.core.enums import PRIORITY\n\n")
            fh.write("__priority__ = PRIORITY.NORMAL\n\n")
            fh.write("DARWIN_PAYLOADS = [\n")
            for _source, payload in payloads[:200]:
                fh.write('    "%s",\n' % _escape_python(payload))
            fh.write("]\n\n")
            fh.write("def tamper(payload, **kwargs):\n")
            fh.write("    return payload\n")
    elif fmt == "metasploit":
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# Metasploit payload list for %s\n" % cat["category"])
            fh.write("DARWIN_PAYLOADS = [\n")
            for _source, payload in payloads[:500]:
                fh.write('  "%s",\n' % _escape_ruby(payload))
            fh.write("]\n")
    return path


def render_stats(data: dict | None = None) -> str:
    s = stats(data)
    return ("Darwin payloads: {categories} categories, {total_payloads} payloads "
            "({readme_payloads} README, {intruder_payloads} intruder)").format(**s)


def render_categories(data: dict | None = None) -> str:
    data = data or load()
    lines = ["Darwin categories", "=" * 17]
    for name in list_categories(data):
        cat = find_category(name, data)
        count = sum(1 for _ in iter_payloads(cat)) if cat else 0
        lines.append("  %-42s %5d" % (name, count))
    return "\n".join(lines)


def render_search(results: list[dict], query: str) -> str:
    lines = ["Darwin search for %r: %d result(s)" % (query, len(results))]
    for i, row in enumerate(results, 1):
        payload = row["payload"].replace("\n", "\\n")
        if len(payload) > 180:
            payload = payload[:177] + "..."
        lines.append("%3d. [%s] [%s] %s" % (
            i, row["category"], row["source"], payload))
    return "\n".join(lines)


def render_category(category: str, limit: int = 50, data: dict | None = None) -> str:
    data = data or load()
    cat = find_category(category, data)
    if not cat:
        return "Darwin category not found: " + category
    rows = list(iter_payloads(cat))
    lines = ["%s: %d payload(s)" % (cat["category"], len(rows)), "=" * 64]
    for i, (source, payload) in enumerate(rows[:limit], 1):
        shown = payload.replace("\n", "\\n")
        if len(shown) > 180:
            shown = shown[:177] + "..."
        lines.append("%3d. [%s] %s" % (i, source, shown))
    if len(rows) > limit:
        lines.append("... %d more" % (len(rows) - limit))
    return "\n".join(lines)


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def serve(port: int = 8080, directory: Path = DATA_DIR) -> None:
    class Handler(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(directory), **kwargs)

        def end_headers(self):
            self.send_header("Access-Control-Allow-Origin", "*")
            super().end_headers()

    with ReusableTCPServer(("127.0.0.1", port), Handler) as httpd:
        print("Darwin payload browser: http://127.0.0.1:%d" % port)
        httpd.serve_forever()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("stats")
    sub.add_parser("list")

    p_search = sub.add_parser("search")
    p_search.add_argument("query")
    p_search.add_argument("--category")
    p_search.add_argument("--limit", type=int, default=50)

    p_show = sub.add_parser("show")
    p_show.add_argument("category")
    p_show.add_argument("--limit", type=int, default=50)

    p_export = sub.add_parser("export")
    p_export.add_argument("category")
    p_export.add_argument("--format", default="burp",
                          choices=["burp", "csv", "json", "burp-project",
                                   "nmap", "sqlmap", "metasploit"])
    p_export.add_argument("--out")

    p_serve = sub.add_parser("serve")
    p_serve.add_argument("--port", type=int, default=8080)

    args = ap.parse_args(argv)
    data = load()
    if args.cmd == "stats":
        print(render_stats(data))
    elif args.cmd == "list":
        print(render_categories(data))
    elif args.cmd == "search":
        print(render_search(search(args.query, args.category, args.limit, data), args.query))
    elif args.cmd == "show":
        print(render_category(args.category, args.limit, data))
    elif args.cmd == "export":
        path = export(args.category, args.format, args.out, data)
        print("wrote Darwin export -> " + path)
    elif args.cmd == "serve":
        serve(args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
