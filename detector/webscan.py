#!/usr/bin/env python3
"""
webscan.py -- point Attestor at a live website; he reads the front-end it serves,
explains how the page is built, finds the bugs in its JavaScript, and (with a
brain wired up) hands back corrected code.

This reviews the PUBLIC client-side code a site sends your browser -- the exact
HTML/JS you'd see in "View Source" or devtools. It does not log in, bypass
anything, scrape private data, or send a single write request; it GETs one public
page (and, with --scripts, a bounded number of the .js files that page links) and
reviews what came back. Code review of what's already public.

    python3 webscan.py https://example.com
    python3 webscan.py https://example.com --scripts 3        # also fetch linked .js
    python3 webscan.py https://example.com --brain --out fixed.js
"""
from __future__ import annotations

import argparse
import http.client
import ipaddress
import os
import socket
import ssl
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser

import detect

_CA = (os.environ.get("SSL_CERT_FILE")
       or ("/root/.ccr/ca-bundle.crt" if os.path.exists("/root/.ccr/ca-bundle.crt") else None))
_UA = "AttestorVonLuneberg/1.0 (public code review; +https://example.invalid)"
_MAX_FETCH_BYTES = 10_000_000
_HTTP_SCHEME = "http"
_HTTPS_SCHEME = "https"
_HTTP_PREFIX = _HTTP_SCHEME + "://"
_HTTPS_PREFIX = _HTTPS_SCHEME + "://"


class UnsafeURL(ValueError):
    """A URL could reach a non-public or unsupported network target."""


class ResponseTooLarge(ValueError):
    """A remote response exceeded Attestor's configured byte limit."""


def _addresses(host: str, port: int) -> set:
    """Resolve every address for a host; an empty/failed answer is unsafe."""
    candidate = host.strip("[]")
    literal = None
    try:
        literal = ipaddress.ip_address(candidate)
    except ValueError:
        literal = None
    if literal is not None:
        return {literal}
    try:
        ascii_host = candidate.encode("idna").decode("ascii")
        results = socket.getaddrinfo(ascii_host, port, type=socket.SOCK_STREAM)
    except (UnicodeError, OSError) as exc:
        raise UnsafeURL("could not safely resolve URL host") from exc
    addresses = set()
    for _family, _kind, _proto, _canon, sockaddr in results:
        try:
            addresses.add(ipaddress.ip_address(sockaddr[0].split("%", 1)[0]))
        except ValueError:
            continue
    if not addresses:
        raise UnsafeURL("URL host resolved to no usable address")
    return addresses


def _public_address(address) -> bool:
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    # is_global excludes private, loopback, link-local, multicast, unspecified,
    # reserved and documentation ranges. Fail closed on every non-public class.
    return bool(address.is_global)


def _connect_public(host: str, port: int, timeout, source_address=None):
    """Resolve, validate, and connect to the exact validated IP (DNS pinning)."""
    addresses = _addresses(host, port)
    blocked = [address for address in addresses if not _public_address(address)]
    if blocked:
        raise UnsafeURL("connection target became non-public")
    last_error = None
    for address in sorted(addresses, key=str):
        try:
            return socket.create_connection(
                (str(address), port), timeout, source_address=source_address)
        except OSError as exc:
            last_error = exc
    if last_error:
        raise last_error
    raise UnsafeURL("URL host resolved to no usable address")


class PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection pinned to an IP that passed public-address validation."""

    def connect(self):
        self.sock = _connect_public(
            self.host, self.port, self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Pinned HTTPS connection retaining the original hostname for SNI/certs."""

    def connect(self):
        self.sock = _connect_public(
            self.host, self.port, self.timeout, self.source_address)
        server_hostname = self.host
        if self._tunnel_host:
            self._tunnel()
            server_hostname = self._tunnel_host
        self.sock = self._context.wrap_socket(self.sock, server_hostname=server_hostname)


class SafeHTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(PinnedHTTPConnection, req)


class SafeHTTPSHandler(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(PinnedHTTPSConnection, req, context=self._context)


def validate_url(url: str, *, allow_http: bool = False) -> str:
    """Validate one fetch target and all of its current DNS answers.

    Validation is repeated for each redirect by :class:`SafeRedirectHandler`.
    This meaningfully reduces SSRF and DNS-rebinding exposure, though only a
    network sandbox can remove the DNS-check/connect race entirely.
    """
    if not isinstance(url, str) or any(ch in url for ch in "\x00\r\n\\"):
        raise UnsafeURL("invalid URL")
    try:
        parsed = urllib.parse.urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise UnsafeURL("invalid URL") from exc
    scheme = parsed.scheme.lower()
    if scheme not in {_HTTP_SCHEME, _HTTPS_SCHEME}:
        raise UnsafeURL("only public HTTP(S) URLs are supported")
    if scheme == _HTTP_SCHEME and not allow_http:
        raise UnsafeURL("plaintext HTTP is disabled; use HTTPS or explicitly allow HTTP")
    if parsed.username is not None or parsed.password is not None:
        raise UnsafeURL("URLs containing credentials are not allowed")
    host = (parsed.hostname or "").rstrip(".").lower()
    if not host or "%" in host:
        raise UnsafeURL("URL must contain a valid public host")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise UnsafeURL("local/private URL hosts are not allowed")
    effective_port = port or (443 if scheme == _HTTPS_SCHEME else 80)
    addresses = _addresses(host, effective_port)
    blocked = sorted(str(address) for address in addresses if not _public_address(address))
    if blocked:
        raise UnsafeURL("URL resolves to a non-public address: " + ", ".join(blocked))
    return url


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Revalidate every redirect target and cap redirect chains."""

    max_redirections = 5

    def __init__(self, *, allow_http: bool = False):
        super().__init__()
        self.allow_http = bool(allow_http)

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urljoin(req.full_url, newurl)
        validate_url(target, allow_http=self.allow_http)
        return super().redirect_request(req, fp, code, msg, headers, target)


def fetch(url: str, timeout: int = 15, max_bytes: int = 3_000_000, *,
          allow_http: bool = False) -> str:
    """Safely GET a public HTTP(S) URL and return bounded decoded text."""
    validate_url(url, allow_http=allow_http)
    try:
        byte_limit = max(1_024, min(int(max_bytes), _MAX_FETCH_BYTES))
    except (TypeError, ValueError):
        byte_limit = 3_000_000
    req = urllib.request.Request(url, headers={"User-Agent": _UA})
    context = ssl.create_default_context(cafile=_CA) if _CA else ssl.create_default_context()
    # Do not inherit HTTP(S)_PROXY from a reviewed repository's environment.
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        SafeHTTPHandler(),
        SafeHTTPSHandler(context=context),
        SafeRedirectHandler(allow_http=allow_http),
    )
    with opener.open(req, timeout=max(1, min(int(timeout), 60))) as resp:
        final_url = resp.geturl()
        validate_url(final_url, allow_http=allow_http)
        raw = resp.read(byte_limit + 1)
        if len(raw) > byte_limit:
            raise ResponseTooLarge("response exceeded %d bytes" % byte_limit)
        charset = resp.headers.get_content_charset() or "utf-8"
    return raw.decode(charset, "replace")


class PageParser(HTMLParser):
    """Pull the structure out of a page: title, scripts (inline + linked),
    stylesheets, forms, and inline on* event handlers."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.inline_scripts = []
        self.script_srcs = []
        self.stylesheets = []
        self.forms = 0
        self.inline_handlers = []
        self._in_title = False
        self._in_script = False
        self._script_buf = []

    def handle_starttag(self, tag, attrs):
        d = {k: (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "script":
            if d.get("src"):
                self.script_srcs.append(d["src"])
            else:
                self._in_script = True
                self._script_buf = []
        elif tag == "link" and "stylesheet" in d.get("rel", "") and d.get("href"):
            self.stylesheets.append(d["href"])
        elif tag == "form":
            self.forms += 1
        for name, value in d.items():
            if name.startswith("on") and len(name) > 2:
                self.inline_handlers.append((tag, name, value))

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "script" and self._in_script:
            self._in_script = False
            code = "".join(self._script_buf).strip()
            if code:
                self.inline_scripts.append(code)

    def handle_data(self, data):
        if self._in_title:
            self.title += data.strip()
        elif self._in_script:
            self._script_buf.append(data)


def review_js(code: str, label: str):
    """Run the detector's JavaScript rules over a blob of JS."""
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False, encoding="utf-8") as fh:
        fh.write(code)
        tmp = fh.name
    try:
        found = detect.scan_file(tmp, deep=True)
        for f in found:
            f.path = label
        return found
    finally:
        os.unlink(tmp)


def html_smells(parser: PageParser):
    """Front-end issues that live in the markup, not a .js file."""
    notes = []
    if parser.inline_handlers:
        notes.append(("inline-event-handler", len(parser.inline_handlers),
                      "inline on*= handlers mix behaviour into markup and are blocked by a "
                      "strict Content-Security-Policy; move them to addEventListener"))
    insecure = [s for s in parser.script_srcs + parser.stylesheets
                if s.startswith(_HTTP_PREFIX)]
    if insecure:
        notes.append(("mixed-content", len(insecure),
                      "resource(s) loaded over " + _HTTP_PREFIX + " -- a network attacker can rewrite "
                      "them; load everything over https"))
    return notes


def analyze(html: str, base_url: str, extra_scripts=None) -> dict:
    """Parse the page and review every script it carries. extra_scripts is a
    list of (label, code) for linked .js files already fetched."""
    parser = PageParser()
    parser.feed(html)

    findings = []
    for i, code in enumerate(parser.inline_scripts):
        findings += review_js(code, f"inline-script[{i}]")
    for label, code in (extra_scripts or []):
        findings += review_js(code, label)
    findings.sort(key=detect.Finding.sort_key)
    return {"parser": parser, "base_url": base_url,
            "findings": findings, "smells": html_smells(parser)}


def explain(report: dict) -> str:
    p = report["parser"]
    hosts = sorted({urllib.parse.urlparse(urllib.parse.urljoin(report["base_url"], s)).netloc
                    for s in p.script_srcs})
    out = [f"how {report['base_url']} is built", "=" * 60,
           f"title       : {p.title or '(none)'}",
           f"inline JS   : {len(p.inline_scripts)} block(s)",
           f"linked JS   : {len(p.script_srcs)} file(s)"
           + (f" from {len(hosts)} host(s): " + ", ".join(hosts[:6]) if hosts else ""),
           f"stylesheets : {len(p.stylesheets)}",
           f"forms       : {p.forms}",
           f"inline on*= : {len(p.inline_handlers)} handler(s)"]
    return "\n".join(out)


def render(report: dict) -> str:
    out = [explain(report), ""]
    findings = report["findings"]
    if findings:
        out.append(f"JavaScript bugs Attestor found ({len(findings)}):")
        for f in findings:
            snippet = f"  > {f.snippet}" if f.snippet else ""
            out.append(f"  {f.path}:{f.line} [{f.severity}] {f.rule}: {f.fix}")
            if snippet:
                out.append(snippet)
    else:
        out.append("JavaScript bugs: none the JS rules recognize (only the JS he ran).")
    if report["smells"]:
        out.append("")
        out.append("markup smells:")
        for rule, count, why in report["smells"]:
            out.append(f"  [{rule} x{count}] {why}")
    out += ["",
            "note: this is the site's PUBLIC front-end (view-source equivalent). Attestor's",
            "deep AST read and auto-fixer are Python-only, so on JS he reports and (with",
            "--brain) rewrites, rather than mechanically patching. Server code is not",
            "visible from the outside and is not touched."]
    return "\n".join(out)


def _biggest_buggy_script(report: dict):
    """The inline script with the most findings -- the best candidate to rewrite."""
    counts = {}
    for f in report["findings"]:
        counts[f.path] = counts.get(f.path, 0) + 1
    if not counts:
        return None, None
    label = max(counts, key=counts.get)
    p = report["parser"]
    for i, code in enumerate(p.inline_scripts):
        if f"inline-script[{i}]" == label:
            return label, code
    return None, None


def correct(report: dict, bus) -> str:
    """Ask a real LLM for a corrected version of the buggiest script, then
    re-scan it to confirm the findings actually dropped."""
    import brain
    import secret_guard
    label, code = _biggest_buggy_script(report)
    if code is None:
        return "nothing to correct (no findings in an inline script)."
    issues = "; ".join(f"{f.rule} at line {f.line}"
                       for f in report["findings"] if f.path == label)
    prompt = ("This JavaScript from a public web page has these issues: " + issues +
              ". Return a corrected version, only code, no prose.\n\n" + code)
    try:
        typed = bus.generate_result(prompt) if hasattr(bus, "generate_result") else None
        answer = typed.content if typed is not None and typed.success else (
            bus.generate(prompt) if typed is None else "")
    except brain.ProviderError as exc:
        return f"(--brain failed: {exc})"
    if typed is not None and not typed.success:
        return "ABSTAINED: provider generation " + typed.status.value + "."
    fixed = answer if isinstance(answer, str) else next(iter(answer.values()), "")
    fixed = brain.strip_fences(fixed) if isinstance(fixed, str) else ""
    before = len(review_js(code, label))
    after = len(review_js(fixed, label)) if fixed.strip() else before
    credential_findings = secret_guard.scan_text(fixed, label + ".js") if fixed else []
    if not fixed.strip():
        return "ABSTAINED: the model returned no non-empty JavaScript candidate."
    if credential_findings:
        return "REFUSED: the model candidate contains credential-like material; source withheld."
    if after >= before:
        return (f"REFUSED: model candidate did not reduce the observed findings "
                f"({before} -> {after}); source withheld.")
    return (f"STATIC-IMPROVED CANDIDATE {label}: {before} issue(s) -> {after} "
            "under the enabled JavaScript checks; browser behavior remains unproven\n"
            + "-" * 60 + "\n" + fixed)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("url", help="the website to review (https://...)")
    ap.add_argument("--scripts", type=int, default=0,
                    help="also fetch up to N linked .js files and review them")
    ap.add_argument("--brain", action="store_true",
                    help="ask a real LLM for corrected code (needs a key)")
    ap.add_argument("--allow-http", action="store_true",
                    help="explicitly allow plaintext public HTTP (HTTPS is the safe default)")
    ap.add_argument("--out", help="write the corrected script here")
    args = ap.parse_args(argv)

    if not args.url.startswith((_HTTP_PREFIX, _HTTPS_PREFIX)):
        print("give a full URL, e.g. https://example.com", file=sys.stderr)
        return 2
    try:
        html = fetch(args.url, allow_http=args.allow_http)
    except urllib.error.HTTPError as exc:
        print(f"fetch failed: HTTP {exc.code}", file=sys.stderr)
        return 2
    except Exception as exc:                     # noqa: BLE001 -- report and bail
        print(f"could not reach {args.url}: {type(exc).__name__} {exc}", file=sys.stderr)
        return 2

    extra = []
    if args.scripts > 0:
        pre = PageParser()
        pre.feed(html)
        for src in pre.script_srcs[:args.scripts]:
            full = urllib.parse.urljoin(args.url, src)
            try:
                extra.append((urllib.parse.urlparse(full).path or full,
                              fetch(full, allow_http=args.allow_http)))
            except Exception as exc:             # noqa: BLE001 -- isolate one linked script
                print("linked script skipped safely: " + type(exc).__name__, file=sys.stderr)
                continue

    report = analyze(html, args.url, extra)
    print(render(report))

    if args.brain:
        import brain
        bus = brain.from_env()
        if not bus.available():
            print("\n--brain: no LLM configured (set GROQ_API_KEY, etc.)")
        else:
            result = correct(report, bus)
            print("\n" + result)
            if args.out and result.startswith("STATIC-IMPROVED CANDIDATE"):
                with open(args.out, "w", encoding="utf-8") as fh:
                    fh.write(result.split("-" * 60 + "\n", 1)[-1])
                print("wrote -> " + args.out)
    return min(len(report["findings"]), 250)


if __name__ == "__main__":
    raise SystemExit(main())
