#!/usr/bin/env python3
"""
ruleforge.py -- Attestor mines code for new detector-rule candidates, then proves them.

Rule Forge is the cautious self-improvement loop for Attestor's detector. It can read
a local file, a GitHub file URL, or a GitHub code-search query; look for bug
shapes that are not yet first-class rules; generate a candidate @rule snippet;
generate positive and negative tests; and only mark the candidate PROVEN when its
matcher catches the bad example and stays quiet on the clean one.

It does not silently patch detect.py. It writes reviewable rule/test snippets to
an output folder. Promotion still means applying that generated patch and running
Attestor's full suite. Ambition with a seatbelt.

    python3 ruleforge.py app.py --out-dir attestor_ruleforge
    python3 ruleforge.py "parseInt(" --lang javascript --limit 3 --out-dir attestor_ruleforge
    python3 superattestor.py --ruleforge "verify=False" --lang python --out attestor_ruleforge
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import sys
import urllib.error

import detect
import harvest


SUFFIX_BY_LANG = {"python": ".py", "js": ".js", "c": ".c", "cpp": ".cpp", "haskell": ".hs"}


@dataclasses.dataclass(frozen=True)
class Template:
    rid: str
    lang: str
    severity: str
    title: str
    fix: str
    pattern: str
    message: str
    positive: str
    negative: str
    deep: bool = False

    @property
    def suffix(self) -> str:
        return SUFFIX_BY_LANG[self.lang]


@dataclasses.dataclass
class Candidate:
    template: Template
    source: dict
    line: int
    snippet: str
    proven: bool = False
    positive_ok: bool = False
    negative_ok: bool = False
    occurrences: int = 1

    @property
    def rid(self) -> str:
        return self.template.rid


CATALOG = [
    Template(
        "py-timeout-none", "python", "MEDIUM",
        "timeout=None disables the network bound and can hang forever",
        "pass a finite timeout such as timeout=10, never timeout=None.",
        r"\brequests\.(?:get|post|put|delete|head|patch|options|request)\s*\([^)]*\btimeout\s*=\s*None\b",
        "timeout=None is the same practical risk as no timeout: a stuck peer can wedge the caller.",
        "import requests\ndef fetch(url):\n    return requests.get(url, timeout=None)\n",
        "import requests\ndef fetch(url):\n    return requests.get(url, timeout=10)\n"),
    Template(
        "py-suppress-broad-exception", "python", "MEDIUM",
        "contextlib.suppress(Exception) hides broad failures without logging",
        "suppress only the narrow exception you truly expect, and log unexpected failures.",
        r"\bcontextlib\.suppress\s*\(\s*(?:Exception|BaseException)\s*\)",
        "broad suppression makes real production failures disappear as if they succeeded.",
        "import contextlib\nwith contextlib.suppress(Exception):\n    risky()\n",
        "import contextlib\nwith contextlib.suppress(FileNotFoundError):\n    cache.unlink()\n"),
    Template(
        "py-naive-utcnow", "python", "LOW",
        "datetime.utcnow() creates a naive datetime that looks UTC but has no timezone",
        "use datetime.now(datetime.UTC) or timezone-aware values end to end.",
        r"\bdatetime\.utcnow\s*\(\s*\)",
        "naive UTC datetimes get mixed with local/aware datetimes and create time bugs that survive tests.",
        "from datetime import datetime\ncreated_at = datetime.utcnow()\n",
        "from datetime import datetime, UTC\ncreated_at = datetime.now(UTC)\n",
        deep=True),
    Template(
        "js-parseint-no-radix", "js", "LOW",
        "parseInt without a radix leaves numeric parsing policy implicit",
        "use parseInt(value, 10) or Number.parseInt(value, 10).",
        r"(?<![\w.])(?:Number\.)?parseInt\s*\(\s*[^,\n)]+\)",
        "implicit radix has a long history of surprising behavior and is still a review smell.",
        "const n = parseInt(input);\n",
        "const n = parseInt(input, 10);\n",
        deep=True),
    Template(
        "js-async-promise-executor", "js", "MEDIUM",
        "async Promise executors turn thrown errors into unhandled promise confusion",
        "do not use async inside new Promise; return an async function or chain promises explicitly.",
        r"\bnew\s+Promise\s*\(\s*async\b",
        "an async executor returns a promise that the Promise constructor ignores; thrown errors escape the intended reject path.",
        "const p = new Promise(async (resolve) => { resolve(await load()); });\n",
        "const p = load().then(value => value);\n"),
    Template(
        "cpp-lock-guard-temporary", "cpp", "HIGH",
        "temporary std::lock_guard unlocks at the end of the statement",
        "bind the guard to a named variable for the full critical section.",
        r"\bstd::lock_guard\s*<[^;]+>\s*\(\s*[A-Za-z_]\w*\s*\)\s*;",
        "this creates and destroys the guard immediately, so the following critical section is not locked.",
        "#include <mutex>\nvoid f(std::mutex& m) { std::lock_guard<std::mutex>(m); shared++; }\n",
        "#include <mutex>\nvoid f(std::mutex& m) { std::lock_guard<std::mutex> guard(m); shared++; }\n"),
    Template(
        "cpp-string-view-temporary", "cpp", "HIGH",
        "std::string_view bound to a temporary std::string dangles immediately",
        "store the std::string owner, or take the view from a longer-lived object.",
        r"\bstd::string_view\s+[A-Za-z_]\w*\s*=\s*std::string\s*\(",
        "the view does not own the characters; the temporary string dies at the semicolon.",
        "#include <string>\n#include <string_view>\nstd::string_view v = std::string(\"abc\");\n",
        "#include <string>\n#include <string_view>\nstd::string s = \"abc\";\nstd::string_view v = s;\n"),
    Template(
        "hs-unsafe-perform-io", "haskell", "HIGH",
        "unsafePerformIO smuggles effects into pure code and breaks reasoning",
        "keep IO in IO, pass values explicitly, or isolate the unsafe boundary with extreme care.",
        r"\bunsafePerformIO\b",
        "unsafePerformIO can duplicate, reorder, or hide effects in code callers believe is pure.",
        "import System.IO.Unsafe (unsafePerformIO)\nsecret = unsafePerformIO readLine\n",
        "main = do\n  secret <- getLine\n  putStrLn secret\n"),
]


def _known_rule_ids() -> set[str]:
    return {fn.rid for fn in detect.RULES}


def _lang_for(path: str, lang: str | None = None) -> str | None:
    if lang:
        low = lang.lower()
        if low in ("javascript", "typescript"):
            return "js"
        if low in ("c++", "cpp"):
            return "cpp"
        return low
    ext = os.path.splitext(path)[1].lower()
    return detect.LANG_BY_EXT.get(ext)


def _lines_for(content: str, lang: str) -> list[str]:
    if lang == "text":
        return content.split("\n")
    return detect.blank(content, lang)


def _matches(template: Template, content: str) -> bool:
    code = "\n".join(_lines_for(content, template.lang))
    rx = re.compile(template.pattern, re.MULTILINE)
    return rx.search(code) is not None


def prove(template: Template) -> tuple[bool, bool, bool]:
    positive_ok = _matches(template, template.positive)
    negative_ok = not _matches(template, template.negative)
    return positive_ok and negative_ok, positive_ok, negative_ok


def discover_in_source(source: dict, forced_lang: str | None = None) -> list[Candidate]:
    lang = _lang_for(source["path"], forced_lang)
    if lang is None:
        return []
    known = _known_rule_ids()
    raw_lines = source["content"].split("\n")
    code = "\n".join(_lines_for(source["content"], lang))
    out = []
    seen = set()
    for template in CATALOG:
        if template.lang != lang or template.rid in known:
            continue
        rx = re.compile(template.pattern, re.MULTILINE)
        for match in rx.finditer(code):
            idx = code.count("\n", 0, match.start())
            line = raw_lines[idx] if idx < len(raw_lines) else match.group(0)
            key = (template.rid, raw_lines[idx].strip() if idx < len(raw_lines) else line.strip())
            if key in seen:
                continue
            seen.add(key)
            proven, pos, neg = prove(template)
            out.append(Candidate(
                template=template,
                source=source,
                line=idx + 1,
                snippet=raw_lines[idx].strip() if idx < len(raw_lines) else line.strip(),
                proven=proven,
                positive_ok=pos,
                negative_ok=neg))
    return out


def _source_record(content: str, repo: str, path: str, url: str = "", lic: str | None = None) -> dict:
    return {"content": content, "repo": repo, "path": path, "url": url, "license": lic}


def load_sources(target: str, lang: str | None = None, pick: int = 0, limit: int = 1) -> tuple[list[dict], int | None]:
    if os.path.exists(target):
        with open(target, encoding="utf-8", errors="replace") as fh:
            return [_source_record(fh.read(), "local", target)], None

    parsed = harvest.parse_github_url(target)
    if parsed:
        repo, ref, path = parsed
        content, repo, path, url, lic = harvest.fetch_url(repo, ref, path)
        return [_source_record(content, repo, path, url, lic)], None

    per_page = max(1, pick + limit)
    items, total = harvest.search(target, lang, per_page=per_page)
    out = []
    for item in items[pick:pick + limit]:
        content, repo, path, url, lic = harvest.fetch(item)
        out.append(_source_record(content, repo, path, url, lic))
    return out, total


def forge(target: str, lang: str | None = None, pick: int = 0, limit: int = 1) -> dict:
    sources, total = load_sources(target, lang=lang, pick=pick, limit=limit)
    candidates = []
    by_rule = {}
    for source in sources:
        for cand in discover_in_source(source, forced_lang=lang):
            if cand.rid in by_rule:
                by_rule[cand.rid].occurrences += 1
            else:
                by_rule[cand.rid] = cand
                candidates.append(cand)
    return {"target": target, "total": total, "sources": sources, "candidates": candidates}


def _fn_name(rid: str) -> str:
    return "r_" + re.sub(r"[^a-zA-Z0-9_]", "_", rid)


def rule_snippet(template: Template) -> str:
    fn = _fn_name(template.rid)
    deep_arg = ",\n      deep=True" if template.deep else ""
    return (
        "@rule(%r, (%r,), %r,\n"
        "      %r,\n"
        "      %r%s)\n"
        "def %s(ctx):\n"
        "    rx = re.compile(%r, re.MULTILINE)\n"
        "    joined = '\\n'.join(ctx.code)\n"
        "    for match in rx.finditer(joined):\n"
        "        idx = joined.count('\\n', 0, match.start())\n"
        "        yield _f(ctx, idx, %r, %r,\n"
        "                 %r,\n"
        "                 %s.fix)\n" % (
            template.rid, template.lang, template.severity, template.title,
            template.fix, deep_arg, fn, template.pattern, template.rid,
            template.severity, template.message, fn))


def test_snippet(template: Template) -> str:
    name = "test_candidate_" + re.sub(r"[^a-zA-Z0-9_]", "_", template.rid)
    return (
        "    def %s(self):\n"
        "        positive = %r\n"
        "        negative = %r\n"
        "        self.assertTrue(ruleforge._matches(ruleforge.template_by_id(%r), positive))\n"
        "        self.assertFalse(ruleforge._matches(ruleforge.template_by_id(%r), negative))\n" % (
            name, template.positive, template.negative, template.rid, template.rid))


def template_by_id(rid: str) -> Template:
    for template in CATALOG:
        if template.rid == rid:
            return template
    raise KeyError(rid)


def render(run: dict) -> str:
    out = ["Rule Forge for: %s" % run["target"], "=" * (16 + len(run["target"]))]
    if run["total"] is not None:
        out.append("GitHub search saw about %s matching file(s)." % f"{run['total']:,}")
    out.append("sources read: %d" % len(run["sources"]))
    candidates = run["candidates"]
    if not candidates:
        out += ["", "No new candidate rules found from the current catalog.",
                "Try a broader query, a different --lang, or feed Attestor code with suspicious patterns."]
        return "\n".join(out)

    proven = sum(1 for c in candidates if c.proven)
    out.append("candidate rules: %d (%d proven)" % (len(candidates), proven))
    for cand in candidates:
        src = cand.source
        status = "PROVEN" if cand.proven else "needs work"
        out += ["", "%s [%s] %s" % (cand.rid, cand.template.severity, status),
                "  source: %s/%s:%d" % (src.get("repo") or "unknown", src.get("path") or "unknown", cand.line),
                "  seen: %d occurrence(s)" % cand.occurrences,
                "  > " + cand.snippet,
                "  why: " + cand.template.message,
                "  proof: positive=%s negative=%s" % ("ok" if cand.positive_ok else "FAIL", "ok" if cand.negative_ok else "FAIL")]
    out += ["", "Use --out-dir to write reviewable rule/test snippets. Promotion still requires the full suite."]
    return "\n".join(out)


def write_results(run: dict, out_dir: str) -> list[str]:
    os.makedirs(out_dir, exist_ok=True)
    proven = [c for c in run["candidates"] if c.proven]
    manifest = [{
        "rule": c.rid,
        "severity": c.template.severity,
        "source": "%s/%s:%d" % (c.source.get("repo") or "unknown", c.source.get("path") or "unknown", c.line),
        "snippet": c.snippet,
        "occurrences": c.occurrences,
    } for c in proven]

    rules_path = os.path.join(out_dir, "candidate_rules.py")
    tests_path = os.path.join(out_dir, "test_candidate_rules.py")
    manifest_path = os.path.join(out_dir, "manifest.json")

    with open(rules_path, "w", encoding="utf-8") as fh:
        fh.write("# Generated by Attestor Rule Forge. Review before promoting into detect.py.\n")
        fh.write("# Requires: import re, and detect.py's @rule/_f helpers.\n\n")
        for cand in proven:
            fh.write(rule_snippet(cand.template) + "\n")

    with open(tests_path, "w", encoding="utf-8") as fh:
        fh.write("#!/usr/bin/env python3\n")
        fh.write("# Generated by Attestor Rule Forge. Review before promoting.\n")
        fh.write("import unittest\nimport ruleforge\n\n\n")
        fh.write("class CandidateRuleTests(unittest.TestCase):\n")
        if proven:
            for cand in proven:
                fh.write(test_snippet(cand.template) + "\n")
        else:
            fh.write("    def test_no_candidates(self):\n        self.assertTrue(True)\n")
        fh.write("\n\nif __name__ == '__main__':\n    unittest.main(verbosity=2)\n")

    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2)
    return [rules_path, tests_path, manifest_path]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="a local file, GitHub file URL, or GitHub code-search query")
    ap.add_argument("--lang", help="force/restrict language for target/search")
    ap.add_argument("--pick", type=int, default=0, help="first GitHub search result index")
    ap.add_argument("--limit", type=int, default=1, help="number of GitHub search results to mine")
    ap.add_argument("--out-dir", help="write generated candidate rule/test snippets here")
    args = ap.parse_args(argv)

    try:
        run = forge(args.target, lang=args.lang, pick=args.pick, limit=args.limit)
    except urllib.error.HTTPError as exc:
        print("GitHub said HTTP %d (private, missing auth, or rate-limited?)" % exc.code,
              file=sys.stderr)
        return 2
    except Exception as exc:                    # noqa: BLE001
        print("Rule Forge failed: %s %s" % (type(exc).__name__, exc), file=sys.stderr)
        return 2

    print(render(run))
    if args.out_dir:
        written = write_results(run, args.out_dir)
        print("\nwrote candidate artifact(s):")
        for path in written:
            print("  " + path)
    return 0 if run["candidates"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
