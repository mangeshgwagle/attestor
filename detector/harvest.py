#!/usr/bin/env python3
"""
harvest.py -- Attestor goes to GitHub, reads real code, and improves it.

Give it EITHER a direct GitHub file link OR a code-search query. Flow: fetch the
file -> review it with BOTH engines (the regex detector, and for Python the
deepscan AST analyzer) -> apply the handful of *safe, mechanical* fixes
automatically and flag the rest for a human -> write the improved copy, citing the
source repository and license.

Uses only the GitHub API (reachable here; auth via GITHUB_TOKEN). No Anthropic key
required. This is a linter-with-autofix over public code, not a code *generator* --
it reads and improves what already exists.

    # paste a link -- reviews and improves that exact file
    python3 harvest.py https://github.com/owner/repo/blob/main/app.py
    python3 harvest.py https://raw.githubusercontent.com/owner/repo/main/x.py --print

    # or search, and it picks a matching file
    python3 harvest.py "verify=False" --lang python
    python3 harvest.py "strcpy(" --lang c --pick 1 --print
    python3 harvest.py "app.run(debug=True)" --lang python --out ./fixed.py

Respect the source license (printed for every file). This tool fetches at runtime
and writes locally; it does not redistribute anyone's code.
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse

import detect
import online

LANG_EXT = {
    "python": ".py", "c": ".c", "cpp": ".cpp", "c++": ".cpp",
    "javascript": ".js", "typescript": ".ts", "haskell": ".hs",
}
COMMENT = {".py": "#", ".c": "//", ".cpp": "//", ".js": "//", ".ts": "//", ".hs": "--"}

# Mechanical fixes that are safe to apply without understanding the code.
# (rule_id, pattern, replacement, human note)
SAFE_FIXES = [
    ("py-eq-none", re.compile(r"==\s*None\b"), "is None", "== None -> is None"),
    ("py-eq-none", re.compile(r"!=\s*None\b"), "is not None", "!= None -> is not None"),
    ("py-bare-except", re.compile(r"except\s*:"), "except Exception:", "bare except -> except Exception"),
    ("tls-verify-disabled", re.compile(r"verify\s*=\s*False"), "verify=True", "verify=False -> verify=True"),
    ("weak-hash", re.compile(r"\bhashlib\.md5\b"), "hashlib.sha256", "md5 -> sha256"),
    ("weak-hash", re.compile(r"\bhashlib\.sha1\b"), "hashlib.sha256", "sha1 -> sha256"),
    ("debug-enabled", re.compile(r"\b(debug|DEBUG)\s*=\s*True\b"), r"\1=False", "debug=True -> debug=False"),
]


# Direct-link support: a github.com blob URL or a raw.githubusercontent.com URL.
BLOB_URL = re.compile(
    r"https?://(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/blob/"
    r"(?P<ref>[^/]+)/(?P<path>.+)")
RAW_URL = re.compile(
    r"https?://raw\.githubusercontent\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/"
    r"(?P<ref>[^/]+)/(?P<path>.+)")


def parse_github_url(text: str):
    """Return (repo, ref, path) from a github blob/raw URL, or None if not a URL."""
    m = BLOB_URL.match(text.strip()) or RAW_URL.match(text.strip())
    if not m:
        return None
    path = m.group("path").split("?")[0].split("#")[0]
    return f"{m.group('owner')}/{m.group('repo')}", m.group("ref"), path


def _repo_license(repo: str):
    """Best-effort SPDX license id for a repo (the file-contents API omits it)."""
    try:
        data = online.github_json(f"/repos/{repo}/license")
    except Exception:                           # noqa: BLE001 -- license is optional
        return None
    lic = data.get("license")
    return lic.get("spdx_id") if isinstance(lic, dict) else None


def fetch_url(repo: str, ref: str, path: str):
    """Fetch one exact file by repo/ref/path via the contents API."""
    meta = online.github_json(
        f"/repos/{repo}/contents/{urllib.parse.quote(path)}?ref={urllib.parse.quote(ref)}")
    content = base64.b64decode(meta.get("content", "")).decode("utf-8", "replace")
    lic = None
    if isinstance(meta.get("license"), dict):
        lic = meta["license"].get("spdx_id")
    return content, repo, path, meta.get("html_url"), lic or _repo_license(repo)


def search(query: str, lang: str | None, per_page: int = 5):
    q = query + (f" language:{lang}" if lang else "")
    data = online.github_json("/search/code?q=" + urllib.parse.quote(q) + f"&per_page={per_page}")
    return data.get("items", []), data.get("total_count", 0)


def fetch(item: dict):
    repo = item["repository"]["full_name"]
    path = item["path"]
    meta = online.github_json(f"/repos/{repo}/contents/{urllib.parse.quote(path)}")
    content = base64.b64decode(meta.get("content", "")).decode("utf-8", "replace")
    lic = None
    if isinstance(meta.get("license"), dict):
        lic = meta["license"].get("spdx_id")
    url = item.get("html_url") or meta.get("html_url")
    return content, repo, path, url, lic


_TAINT_RULE = {
    "CWE-78": ("py-os-command-injection", "HIGH"),
    "CWE-95": ("dangerous-eval", "HIGH"),
    "CWE-502": ("py-insecure-deserialize", "MEDIUM"),
    "CWE-22": ("py-path-traversal", "HIGH"),
    "CWE-918": ("py-ssrf", "MEDIUM"),
}


def _argument_taint(content: str, label: str):
    """Findings for taint that reached a sink through a function argument.

    semantic_graph41 already covers taint returned *from* a callee; this covers
    the opposite direction, which is the common shape in real code -- a handler
    taking user input and passing it down into a helper.  Kept behind a broad
    except so a new engine can never take the whole scan down with it.
    """
    try:
        import interprocedural41
        report = interprocedural41.analyze(content, label)
    except Exception:                          # noqa: BLE001 -- advisory engine
        return []
    out = []
    for witness in report.get("witnesses", []):
        rule, severity = _TAINT_RULE.get(witness["cwe"],
                                         ("py-tainted-argument", "MEDIUM"))
        entered = witness["entered_via"]
        origin = entered.get("callee") or entered.get("from", "an untrusted value")
        out.append(detect.Finding(
            label, int(witness["sink"]["line"]), rule, severity,
            "'%s' arrives tainted from %s at line %d and reaches %s here; no "
            "single line contains both halves." % (
                witness["parameter"], origin, entered["line"],
                witness["sink"]["callee"]),
            "validate or encode the value at the trust boundary, before it is "
            "passed on.", ""))
    return out


def scan_content(content: str, ext: str, *, deep: bool = False):
    """Scan in-memory source; `deep` also runs detect's deep-only rules.

    The default stays shallow so existing callers are unchanged.  A caller that
    compares results against a rule id declared `deep=True` must opt in, or that
    rule can never fire and the comparison is meaningless.
    """
    with tempfile.NamedTemporaryFile("w", suffix=ext, delete=False, encoding="utf-8") as fh:
        fh.write(content)
        tmp = fh.name
    try:
        found = detect.scan_file(tmp, deep=deep)
        if ext == ".py":                      # Python gets both AST engines' read
            import deepscan
            import rarebugs
            found += deepscan.scan_path(tmp)
            found += rarebugs.scan_path(tmp)
            found += _argument_taint(content, "harvested" + ext)
        for f in found:                       # relabel path to something readable
            f.path = "harvested" + ext
        found.sort(key=detect.Finding.sort_key)
        return found
    finally:
        os.unlink(tmp)


def improve(content: str):
    """Apply the safe mechanical fixes. Returns (new_content, [(rule, count, note)])."""
    out = content
    applied = []
    for rid, rx, repl, note in SAFE_FIXES:
        out, n = rx.subn(repl, out)
        if n:
            applied.append((rid, n, note))
    return out, applied


def header(ext, repo, path, url, lic, applied, remaining):
    c = COMMENT.get(ext, "#")
    lines = [
        f"{c} ─ harvested & improved by AttestorVonLuneberg ─",
        f"{c} source : {repo}/{path}",
        f"{c} url    : {url}",
        f"{c} license: {lic or 'UNKNOWN — check before you reuse this'}",
    ]
    if applied:
        lines.append(f"{c} auto-fixed: " + "; ".join(f"{note} (x{n})" for _, n, note in applied))
    if remaining:
        lines.append(f"{c} still needs a human ({len(remaining)}):")
        for f in remaining:
            lines.append(f"{c}   line {f.line} [{f.rule}] {f.fix}")
    lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="a GitHub file URL (blob or raw) OR a code-search query")
    ap.add_argument("--lang", help="restrict a search to a language (python, c, cpp, ...)")
    ap.add_argument("--pick", type=int, default=0, help="which search result to take (0-based)")
    ap.add_argument("--out", help="where to write the improved file (default ./attestor_harvest/<name>)")
    ap.add_argument("--print", dest="do_print", action="store_true",
                    help="also print the improved file to stdout")
    args = ap.parse_args(argv)

    ext = LANG_EXT.get((args.lang or "").lower(), ".txt")
    parsed = parse_github_url(args.target)

    if parsed:                                  # ---- direct link mode ----
        repo, ref, path = parsed
        try:
            content, repo, path, url, lic = fetch_url(repo, ref, path)
        except urllib.error.HTTPError as e:
            print(f"GitHub fetch failed: HTTP {e.code} (not found, private, or rate-limited?)",
                  file=sys.stderr)
            return 2
        except Exception as e:                  # noqa: BLE001
            print(f"GitHub unreachable: {type(e).__name__} {e}", file=sys.stderr)
            return 2
        banner = f"Fetched {repo}/{path} directly from the link:"
    else:                                       # ---- search mode ----
        try:
            items, total = search(args.target, args.lang)
        except urllib.error.HTTPError as e:
            print(f"GitHub search failed: HTTP {e.code} (rate limit or auth?)", file=sys.stderr)
            return 2
        except Exception as e:                  # noqa: BLE001
            print(f"GitHub search unreachable: {type(e).__name__} {e}", file=sys.stderr)
            return 2
        if not items:
            print("No results. Try a broader query, a different --lang, or paste a file URL.")
            return 1
        if args.pick >= len(items):
            args.pick = 0
        content, repo, path, url, lic = fetch(items[args.pick])
        banner = f"~{total:,} matches for “{args.target}”. Reading result #{args.pick}:"

    file_ext = os.path.splitext(path)[1] or ext

    before = scan_content(content, file_ext)
    improved, applied = improve(content)
    remaining = scan_content(improved, file_ext)

    print(banner)
    print(f"  source : {repo}/{path}")
    print(f"  license: {lic or 'UNKNOWN — respect it before reuse'}")
    print(f"  Attestor found {len(before)} issue(s); auto-fixed {len(before) - len(remaining)}, "
          f"{len(remaining)} left for a human.")
    if applied:
        print("  auto-fixes: " + "; ".join(f"{note} x{n}" for _, n, note in applied))
    for f in remaining:
        print(f"    line {f.line} [{f.severity}] {f.rule}: {f.fix}")

    out_path = args.out or os.path.join("attestor_harvest", os.path.basename(path))
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(header(file_ext, repo, path, url, lic, applied, remaining))
        fh.write(improved)
    print(f"  wrote improved file -> {out_path}")

    if args.do_print:
        print("\n" + "=" * 60)
        print(header(file_ext, repo, path, url, lic, applied, remaining) + improved)
    return 0


if __name__ == "__main__":
    sys.exit(main())
