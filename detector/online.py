"""
Attestor's connection to the outside world.

Two layers:
  1. CURATED references (offline) -- every rule maps to authoritative reading
     (CWE ids, language docs). Always available; this is Attestor's "memory".
  2. LIVE checks (optional, --online) -- best-effort HTTPS via the session's
     egress proxy. Some hosts are allowed (e.g. api.github.com), others are
     blocked by policy and return 403; Attestor handles both gracefully and never
     retries a policy denial. In --deep mode he also asks GitHub *how many*
     issues mention a problem, so he can honestly say he "checked many results".

Everything here is wrapped in timeouts and try/except: the network failing must
never crash a scan or hang it.
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request

_CA = (os.environ.get("SSL_CERT_FILE")
       or ("/root/.ccr/ca-bundle.crt" if os.path.exists("/root/.ccr/ca-bundle.crt") else None))
_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
_GOOGLE_KEY = os.environ.get("GOOGLE_API_KEY")
_GOOGLE_CX = os.environ.get("GOOGLE_CX") or os.environ.get("GOOGLE_CSE_ID")
_TIMEOUT = 8
_MAX_LIVE_FETCHES = 12         # hard cap per run so --deep can't run away

_fetch_budget = _MAX_LIVE_FETCHES
_issue_cache: dict = {}
_google_cache: dict = {}


def _ctx():
    try:
        return ssl.create_default_context(cafile=_CA) if _CA else ssl.create_default_context()
    except Exception:
        return ssl.create_default_context()


def _get(url: str, accept: str = "text/html", timeout: int = _TIMEOUT, max_bytes: int = 20000):
    """GET a URL via the env proxy. Returns (status, body_text). Raises on failure.

    max_bytes caps the read (keeps snippet fetches cheap); pass 0 for the full body
    (needed for JSON APIs where a truncated response won't parse).
    """
    headers = {"User-Agent": "AttestorVonLuneberg/2.0", "Accept": accept}
    if "api.github.com" in url and _TOKEN:
        headers["Authorization"] = f"Bearer {_TOKEN}"
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout, context=_ctx()) as r:
        raw = r.read() if not max_bytes else r.read(max_bytes)
        return r.status, raw.decode("utf-8", "replace")


def connectivity():
    """Prove Attestor can really reach the internet. Returns (ok, message)."""
    try:
        status, body = _get("https://api.github.com/zen",
                            accept="application/vnd.github+json", timeout=6)
        zen = body.strip().splitlines()[0] if body.strip() else "(silence)"
        return True, f"online (GitHub zen: “{zen}”)"
    except urllib.error.URLError as e:
        reason = str(getattr(e, "reason", e))
        if "403" in reason or "Forbidden" in reason:
            return False, "the egress policy blocked me (403). fine. i have a good memory."
        return False, f"couldn't reach the net ({reason[:60]}). working from memory."
    except Exception as e:                    # noqa: BLE001 - never let online break a scan
        return False, f"network hiccup ({type(e).__name__}). working from memory."


# --------------------------------------------------------------------------- #
# Curated references: rule id -> list of (label, url). CWE/CVE-style anchors and
# canonical docs. These print whether or not the live net is reachable.
# --------------------------------------------------------------------------- #
CURATED = {
    "unsigned-underflow": [("CWE-191: Integer Underflow", "https://cwe.mitre.org/data/definitions/191.html")],
    "strict-aliasing":    [("CWE-704 / type punning", "https://cwe.mitre.org/data/definitions/704.html")],
    "signed-overflow-check": [("CWE-190: Integer Overflow", "https://cwe.mitre.org/data/definitions/190.html")],
    "sizeof-pointer-arg": [("CWE-467: sizeof on pointer", "https://cwe.mitre.org/data/definitions/467.html")],
    "unsafe-libc":        [("CWE-120: Buffer Copy without Size Check", "https://cwe.mitre.org/data/definitions/120.html")],
    "scanf-unbounded":    [("CWE-120 / unbounded scanf", "https://cwe.mitre.org/data/definitions/120.html")],
    "command-exec":       [("CWE-78: OS Command Injection", "https://cwe.mitre.org/data/definitions/78.html")],
    "empty-catch":        [("CWE-390: Detection of Error Condition w/o Action", "https://cwe.mitre.org/data/definitions/390.html")],
    "float-equality":     [("Floating point comparison", "https://floating-point-gui.de/errors/comparison/")],
    "weak-rng":           [("CWE-338: Weak PRNG", "https://cwe.mitre.org/data/definitions/338.html")],
    "assign-in-condition":[("CWE-481: Assigning instead of Comparing", "https://cwe.mitre.org/data/definitions/481.html")],
    "c-realloc-leak":    [("CWE-401: Missing Release of Memory", "https://cwe.mitre.org/data/definitions/401.html")],
    "c-memcmp-padding": [("CWE-457: Use of Uninitialized Variable", "https://cwe.mitre.org/data/definitions/457.html")],
    "cpp-use-after-move": [("EXP63-CPP: Do not rely on moved-from value", "https://wiki.sei.cmu.edu/confluence/display/cplusplus/EXP63-CPP.+Do+not+rely+on+the+value+of+a+moved-from+object")],
    "py-dict-fromkeys-mutable": [("Python dict.fromkeys docs", "https://docs.python.org/3/library/stdtypes.html#dict.fromkeys")],
    "js-async-foreach": [("MDN: Array.prototype.forEach", "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/forEach")],
    "js-nan-compare": [("MDN: Number.isNaN", "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Number/isNaN")],
    "c-free-stack-address": [("CWE-590: Free of Memory not on Heap", "https://cwe.mitre.org/data/definitions/590.html")],
    "c-malloc-strlen-no-nul": [("CWE-131: Incorrect Buffer Size", "https://cwe.mitre.org/data/definitions/131.html")],
    "cpp-return-cstr-local": [("CTR51-CPP: Use valid references/pointers", "https://wiki.sei.cmu.edu/confluence/display/cplusplus/CTR51-CPP.+Use+valid+references%2C+pointers%2C+and+iterators+to+reference+elements+of+a+container")],
    "cpp-delete-array-mismatch": [("CWE-762: Mismatched Memory Management Routines", "https://cwe.mitre.org/data/definitions/762.html")],
    "py-random-security": [("Python secrets module", "https://docs.python.org/3/library/secrets.html")],
    "js-date-getyear": [("MDN: Date.getYear", "https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Date/getYear")],
    "js-prototype-pollution": [("OWASP: Prototype Pollution", "https://owasp.org/www-community/attacks/Prototype_Pollution")],
    "hs-partial-function": [("Haskell partial functions", "https://wiki.haskell.org/Avoiding_partial_functions")],
    "map-operator-insert":[("std::map::operator[]", "https://en.cppreference.com/w/cpp/container/map/operator_at")],
    "object-slicing":     [("Object slicing", "https://en.cppreference.com/w/cpp/language/object")],
    "rangefor-copy":      [("Range-based for", "https://en.cppreference.com/w/cpp/language/range-for")],
    "vector-bool-proxy":  [("std::vector<bool>", "https://en.cppreference.com/w/cpp/container/vector_bool")],
    "hardcoded-secret":   [("CWE-798: Hard-coded Credentials", "https://cwe.mitre.org/data/definitions/798.html")],
    "py-empty-secret-default": [("CWE-321: Hard-coded Cryptographic Key", "https://cwe.mitre.org/data/definitions/321.html")],
    "py-mutable-default": [("Common Gotchas: mutable defaults", "https://docs.python-guide.org/writing/gotchas/")],
    "py-bare-except":     [("CWE-396 / bare except", "https://cwe.mitre.org/data/definitions/396.html")],
    "py-except-pass":     [("CWE-390: swallowed error", "https://cwe.mitre.org/data/definitions/390.html")],
    "py-is-literal":      [("PEP 8 / identity vs equality", "https://peps.python.org/pep-0008/")],
    "py-eq-none":         [("PEP 8: comparisons to None", "https://peps.python.org/pep-0008/")],
    "py-eq-bool":         [("PEP 8: comparisons to True/False", "https://peps.python.org/pep-0008/")],
    "py-sql-injection":   [("CWE-89: SQL Injection", "https://cwe.mitre.org/data/definitions/89.html")],
    "py-assert-validation": [("CWE-617 / assert in prod", "https://cwe.mitre.org/data/definitions/617.html")],
    "py-subprocess-no-timeout": [("CWE-400: Uncontrolled Resource Consumption", "https://cwe.mitre.org/data/definitions/400.html")],
    "js-client-secret-storage": [("OWASP: HTML5 Security Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html")],
    "hs-int-overflow":    [("CWE-190: Integer Overflow", "https://cwe.mitre.org/data/definitions/190.html")],
    "hs-lazy-foldl":      [("Foldr Foldl Foldl'", "https://wiki.haskell.org/Foldr_Foldl_Foldl%27")],
    "hs-lazy-io":         [("Lazy evaluation / IO", "https://wiki.haskell.org/Lazy_evaluation")],
    "hs-lazy-error-field":[("Performance/Strictness", "https://wiki.haskell.org/Performance/Strictness")],
}

# search phrase used in --deep mode to count how many results exist on GitHub
_DEEP_QUERY = {
    "py-sql-injection": "SQL injection",
    "hardcoded-secret": "hardcoded credentials",
    "command-exec": "command injection",
    "unsafe-libc": "strcpy buffer overflow",
    "scanf-unbounded": "scanf buffer overflow",
    "py-mutable-default": "mutable default argument",
    "signed-overflow-check": "signed integer overflow",
    "strict-aliasing": "strict aliasing",
}


def google_search(query: str):
    """Real Google search via the official Custom Search JSON API.

    Returns {"available": bool, ...}. Needs GOOGLE_API_KEY + GOOGLE_CX (a Custom
    Search Engine id) in the environment -- the ToS-compliant way to query Google
    programmatically. The googleapis.com host is reachable through the egress
    proxy, so this genuinely works once those are set; without them (or if the
    host is blocked) Attestor says so plainly instead of pretending.
    """
    global _fetch_budget
    if query in _google_cache:
        return _google_cache[query]
    if not _GOOGLE_KEY or not _GOOGLE_CX:
        res = {"available": False, "note": "set GOOGLE_API_KEY + GOOGLE_CX to enable Google search"}
        _google_cache[query] = res
        return res
    if _fetch_budget <= 0:
        return {"available": False, "note": "fetch budget exhausted"}
    _fetch_budget -= 1
    try:
        from urllib.parse import urlencode
        params = urlencode({"key": _GOOGLE_KEY, "cx": _GOOGLE_CX, "q": query, "num": 1})
        status, body = _get(f"https://www.googleapis.com/customsearch/v1?{params}",
                            accept="application/json", timeout=8)
        data = json.loads(body)
        total = data.get("searchInformation", {}).get("totalResults")
        items = data.get("items") or []
        top = items[0].get("link") if items else None
        res = {"available": True, "total": total, "top": top}
    except urllib.error.HTTPError as e:
        res = {"available": False, "note": f"Google API said {e.code} (key/cx/quota?)"}
    except urllib.error.URLError as e:
        reason = str(getattr(e, "reason", e))
        res = {"available": False,
               "note": "blocked by egress policy" if "403" in reason else f"unreachable ({reason[:40]})"}
    except Exception as e:                    # noqa: BLE001
        res = {"available": False, "note": f"google error ({type(e).__name__})"}
    _google_cache[query] = res
    return res


def github_json(path: str, timeout: int = 15):
    """GET an api.github.com path and parse JSON (auth + proxy + CA handled by _get)."""
    status, body = _get("https://api.github.com" + path,
                        accept="application/vnd.github+json", timeout=timeout, max_bytes=0)
    return json.loads(body)


def google_status() -> str:
    """One-line summary of whether Google search is usable right now."""
    if not _GOOGLE_KEY or not _GOOGLE_CX:
        return "Google search: not configured (set GOOGLE_API_KEY + GOOGLE_CX to switch it on)"
    g = google_search("attestor connectivity probe")
    if g.get("available"):
        return "Google search: live via the official Custom Search API"
    return f"Google search: {g.get('note', 'unavailable')}"


def github_issue_count(query: str):
    """How many GitHub issues mention `query`? Returns int or None. Cached."""
    global _fetch_budget
    if query in _issue_cache:
        return _issue_cache[query]
    if _fetch_budget <= 0:
        return None
    _fetch_budget -= 1
    try:
        from urllib.parse import quote
        url = f"https://api.github.com/search/issues?q={quote(query)}&per_page=1"
        status, body = _get(url, accept="application/vnd.github+json", timeout=8)
        count = json.loads(body).get("total_count")
        _issue_cache[query] = count
        return count
    except Exception:
        _issue_cache[query] = None
        return None


def enrich(rule_id: str, deep: bool, live: bool):
    """Return a list of (label, url, live_status) reference tuples for a rule.

    Offline: live_status is "". With live=True, Attestor tries to actually reach each
    reference (bounded), tagging it 'reachable', 'blocked (policy)', or 'offline'.
    In deep mode he also appends a GitHub result count for well-known classes.
    """
    global _fetch_budget
    out = []
    refs = CURATED.get(rule_id, [])
    max_live = (3 if deep else 1) if live else 0
    for i, (label, url) in enumerate(refs):
        status = ""
        if live and i < max_live and _fetch_budget > 0:
            _fetch_budget -= 1
            try:
                code, _ = _get(url, timeout=6)
                status = f"reachable {code}"
            except urllib.error.URLError as e:
                reason = str(getattr(e, "reason", e))
                status = "blocked (policy)" if ("403" in reason or "Forbidden" in reason) else "offline"
            except Exception:
                status = "offline"
        out.append((label, url, status))

    if deep and live:
        q = _DEEP_QUERY.get(rule_id)
        if q:
            n = github_issue_count(q)
            if n is not None:
                out.append((f"GitHub: ~{n:,} issues mention “{q}”",
                            f"https://github.com/search?q={q.replace(' ', '+')}&type=issues",
                            "checked"))
            g = google_search(f"{q} bug fix")
            if g.get("available"):
                tot = g.get("total")
                tot_s = f"~{int(tot):,}" if tot and str(tot).isdigit() else (tot or "some")
                out.append((f"Google: {tot_s} results for “{q} bug fix”",
                            g.get("top") or "https://www.google.com/search?q=" + q.replace(" ", "+"),
                            "checked"))
            elif g.get("note"):
                out.append((f"Google search: {g['note']}",
                            "https://developers.google.com/custom-search/v1/overview",
                            "unavailable"))
    return out


def reset_budget():
    global _fetch_budget
    _fetch_budget = _MAX_LIVE_FETCHES
    _issue_cache.clear()
    _google_cache.clear()
