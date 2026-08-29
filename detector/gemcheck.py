#!/usr/bin/env python3
"""
gemcheck.py -- diagnose a Google AI Studio (Gemini) key in one shot.

"It keeps giving errors" is too vague to fix -- 400 / 403 / 404 / 429 each mean
something different. This reads GEMINI_API_KEY (or GOOGLE_API_KEY) from the
environment and:

  1. lists the models your key can actually see   (GET /v1beta/models)
  2. picks a flash model and tries a tiny generateContent call

...then maps every outcome to a plain-English cause and the exact fix. No SDK --
raw HTTPS via urllib. Nothing is printed except diagnostics; your key is never
echoed.

    export GEMINI_API_KEY=...
    python3 gemcheck.py
"""
from __future__ import annotations

import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request

_CA = (os.environ.get("SSL_CERT_FILE")
       or ("/root/.ccr/ca-bundle.crt" if os.path.exists("/root/.ccr/ca-bundle.crt") else None))
_BASE = "https://generativelanguage.googleapis.com/v1beta"


def advise(status: int, message: str) -> str:
    """Map an HTTP status (+ Google's error message) to a concrete fix."""
    msg = (message or "").lower()
    if status == 200:
        return "OK."
    if status == 400 and "api key not valid" in msg:
        return ("Your key is wrong or malformed. Generate a fresh one at "
                "aistudio.google.com/app/apikey and re-export GEMINI_API_KEY "
                "(watch for stray spaces/quotes).")
    if status == 400:
        return ("Bad request: %s. Usually a malformed body or a bad model name."
                % (message or "?"))
    if status == 401:
        return "Unauthorized -- the key is missing or rejected. Re-check GEMINI_API_KEY."
    if status == 403:
        return ("The key reached Google but was refused. Either the 'Generative "
                "Language API' is not enabled on the key's project, or the key has "
                "HTTP-referrer / IP restrictions. Enable the API (or loosen the key "
                "restrictions) in the Google Cloud / AI Studio console.")
    if status == 404:
        return ("Model not found for your key. Use an EXACT name from the model list "
                "above, and keep the /v1beta/ path -- old names like 'gemini-pro' 404.")
    if status == 429:
        return ("Rate / quota limit. The free tier caps requests-per-minute and "
                "per-day: use a *flash* model (not pro), respect the retryDelay in the "
                "error, and remember the daily quota resets around midnight Pacific.")
    if status >= 500:
        return "Google-side error (%d). Transient -- retry with backoff." % status
    return "Unexpected status %d: %s" % (status, message or "?")


def _request(url: str, payload=None):
    """Return (status, parsed_body). status 0 means the host was unreachable."""
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data,
                                 method="POST" if payload is not None else "GET")
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    context = ssl.create_default_context(cafile=_CA) if _CA else None
    try:
        with urllib.request.urlopen(req, timeout=20, context=context) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, {"error": {"message": body[:200]}}
    except Exception as exc:                     # noqa: BLE001 -- network/TLS failure
        return 0, {"error": {"message": "%s: %s" % (type(exc).__name__, exc)}}


def _error_message(body: dict) -> str:
    err = body.get("error") if isinstance(body, dict) else None
    if isinstance(err, dict):
        return err.get("message", "")
    return ""


def _details(body: dict) -> list:
    err = body.get("error") if isinstance(body, dict) else None
    return err.get("details", []) if isinstance(err, dict) else []


def _retry_delay(body: dict):
    """Seconds to wait, from a 429 error's RetryInfo; None if absent."""
    for detail in _details(body):
        if isinstance(detail, dict) and detail.get("@type", "").endswith("RetryInfo"):
            m = re.match(r"(\d+(?:\.\d+)?)s", detail.get("retryDelay", ""))
            if m:
                return float(m.group(1))
    return None


def _quota_metric(body: dict) -> str:
    """The name of the exhausted quota (tells per-minute vs per-day)."""
    for detail in _details(body):
        if isinstance(detail, dict) and detail.get("@type", "").endswith("QuotaFailure"):
            violations = detail.get("violations", [])
            if violations:
                v = violations[0]
                return v.get("quotaMetric", "") or v.get("quotaId", "")
    return ""


def list_models(key: str):
    return _request(_BASE + "/models?key=" + key)


def try_generate(key: str, model: str):
    url = _BASE + "/models/" + model + ":generateContent?key=" + key
    return _request(url, {"contents": [{"parts": [{"text": "reply with the word ok"}]}]})


def _generatable(models_body: dict):
    """Names of models that support generateContent, flash first."""
    out = []
    for m in models_body.get("models", []):
        methods = m.get("supportedGenerationMethods", [])
        if "generateContent" in methods:
            out.append(m.get("name", "").replace("models/", ""))
    out.sort(key=lambda n: (0 if "flash" in n else 1, n))
    return out


def _handle_429(key: str, model: str, body: dict) -> int:
    detail = _error_message(body)
    metric = _quota_metric(body)
    delay = _retry_delay(body)
    print("    quota limit hit." + (("  metric: " + metric) if metric else ""))
    if detail:
        print("    google: " + detail[:150])
    per_day = "perday" in metric.lower() or "per day" in (detail or "").lower()
    if per_day:
        print("    -> PER-DAY cap: your free daily quota is spent. It resets around")
        print("       midnight Pacific. Wait it out, or add billing (a free tier still applies).")
        return 4
    if delay is not None and delay <= 65:
        print("    -> Google says retry in %.0fs. Waiting, then trying once more..." % delay)
        time.sleep(delay + 1)
        status, again = try_generate(key, model)
        print("    retry -> HTTP %d" % status)
        if status == 200:
            print("\nVERDICT: your key WORKS -- that was just a per-minute throttle. Use '%s'." % model)
            return 0
        print("    still limited: " + advise(status, _error_message(again)))
        return 4
    print("    -> likely a per-minute throttle. Wait ~60s and re-run; if it never")
    print("       clears, your daily free quota is spent (resets ~midnight Pacific).")
    return 4


def run() -> int:
    import envfile
    envfile.load()
    key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    print("Gemini key doctor")
    print("=" * 60)
    if not key:
        print("no key in the environment.")
        print("fix (PowerShell): $env:GEMINI_API_KEY=\"...\"")
        print("fix (bash):       export GEMINI_API_KEY=...")
        print("(get a key at aistudio.google.com/app/apikey)")
        return 1
    print("key found (%d chars, not printed). talking to Google..." % len(key))

    status, body = list_models(key)
    if status == 0:
        print("could not reach generativelanguage.googleapis.com.")
        print("fix: %s" % _error_message(body))
        print("(if you're behind a proxy/firewall, that host must be allowed.)")
        return 2

    print("\n[1] list models  -> HTTP %d" % status)
    if status != 200:
        print("    cause/fix: " + advise(status, _error_message(body)))
        return 3

    models = _generatable(body)
    print("    your key can use %d generateContent model(s):" % len(models))
    for name in models[:6]:
        print("      - " + name)
    if not models:
        print("    but none support generateContent -- unusual; check the project.")
        return 3

    model = models[0]
    print("\n[2] generate on '%s'  ->" % model, end=" ")
    gstatus, gbody = try_generate(key, model)
    print("HTTP %d" % gstatus)
    if gstatus == 200:
        try:
            text = gbody["candidates"][0]["content"]["parts"][0]["text"].strip()
        except (KeyError, IndexError, TypeError):
            text = "(200, but empty response)"
        print("    reply: %r" % text[:80])
        print("\nVERDICT: your Gemini key WORKS. Use model '%s'." % model)
        print("         wire it in:  $env:GEMINI_API_KEY=...  ;  python3 nl.py \"...\" --brain")
        return 0
    if gstatus == 429:
        return _handle_429(key, model, gbody)
    print("    cause/fix: " + advise(gstatus, _error_message(gbody)))
    return 4


if __name__ == "__main__":
    raise SystemExit(run())
