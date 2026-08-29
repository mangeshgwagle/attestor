#!/usr/bin/env python3
"""Attestor 4.1.3 evidence-first research for non-coding questions.

Research Mode is deliberately separate from Attestor's offline code-analysis path.
Network access is denied unless the caller explicitly authorizes it.  The live
backend uses Brave's documented Web Search endpoint and an environment-provided
subscription token; secrets never enter the report.  Optional page retrieval
accepts only public HTTP(S) destinations, validates every redirect, observes a
bounded robots.txt policy, and never submits forms or crosses authentication.

The default answer is extractive: every factual passage is tied to a source ID,
URL, retrieval state, and content/snippet digest.  Possible disagreements are
shown rather than silently averaged.  Attestor does not describe weak snippets as
verified facts and does not treat a search result as proof.
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _datetime
import hashlib
from html.parser import HTMLParser
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import zlib
from typing import Any, Callable, Mapping, Protocol, Sequence
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit


SCHEMA = "attestor-research/4.1"
VERSION = "4.1.3"
BRAVE_ENDPOINT = "https://api.search.brave.com/res/v1/web/search"
USER_AGENT_TOKEN = "AttestorResearch"
USER_AGENT = "AttestorResearch/4.1.3 evidence-client"
MAX_QUESTION_BYTES = 16 * 1024
MAX_QUERY_CHARS = 400
MAX_QUERY_WORDS = 50
MAX_QUERIES = 12
MAX_RESULTS = 120
MAX_RESULTS_PER_QUERY = 20
MAX_FETCHES = 30
MAX_SEARCH_RESPONSE = 8 * 1024 * 1024
MAX_PAGE_BYTES = 2 * 1024 * 1024
MAX_ROBOTS_BYTES = 512 * 1024
MAX_REDIRECTS = 5
MAX_EXTRACTED_CHARS = 240_000
MAX_PASSAGES = 80
MAX_EXCERPT_CHARS = 240
MAX_PUBLIC_DESCRIPTION_CHARS = 240
MAX_SOURCE_QUOTE_WORDS = 25
DEFAULT_TIMEOUT = 12.0
_TRACKING = frozenset({"fbclid", "gclid", "dclid", "msclkid", "mc_cid", "mc_eid"})
_CREDENTIAL_QUERY_KEYS = frozenset({
    "apikey", "accesskey", "accesskeyid", "accesstoken", "authtoken",
    "auth", "authorization", "bearer", "clientsecret", "code",
    "credential", "idtoken", "jwt", "key", "oauth", "password",
    "passwd", "refreshtoken", "samlresponse", "secret", "sessionid",
    "sessiontoken", "sig", "signature", "token", "xamzcredential",
    "xamzsecuritytoken", "xamzsignature", "xgoogcredential",
    "xgoogsignature", "googleaccessid",
})
_WORD = re.compile(r"[A-Za-z0-9][A-Za-z0-9'_-]{1,}")
_SENTENCE = re.compile(r"(?<=[.!?])\s+|\n+")
_NUMBER = re.compile(r"(?<![A-Za-z])(?:\d{1,4}(?:[.,]\d+)*(?:%|\s*(?:million|billion|trillion))?)(?![A-Za-z])", re.I)
_NEGATION = re.compile(r"\b(?:no|not|never|without|cannot|can't|isn't|aren't|didn't|doesn't)\b", re.I)
_SPACE = re.compile(r"\s+")
_ANSI_STRING = re.compile(
    r"(?:\x1b[\]PX^_][\s\S]*?(?:\x07|\x1b\\|$)|"
    r"[\x90\x98\x9d-\x9f][\s\S]*?(?:\x07|\x9c|$))")
_ANSI_CSI = re.compile(r"(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]")
_ANSI_ESCAPE = re.compile(r"\x1b[@-_]")
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_SAFE_CODE = re.compile(r"^[A-Za-z]{2}(?:-[A-Za-z]{2})?$")
_DATE_META = frozenset({"article:published_time", "date", "datepublished", "pubdate",
                        "dc.date", "dc.date.issued", "og:updated_time"})


class ResearchError(ValueError):
    """A research input, provider response, or network boundary is invalid."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False,
                      default=str).encode("utf-8")


def _sha(value: bytes | str | Any) -> str:
    if not isinstance(value, (bytes, str)):
        value = _canonical(value)
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()


def _utc(value: _datetime.datetime | None = None) -> str:
    current = value or _datetime.datetime.now(_datetime.timezone.utc)
    if current.tzinfo is None:
        current = current.replace(tzinfo=_datetime.timezone.utc)
    return current.astimezone(_datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _text(value: Any, maximum: int) -> str:
    clean = str(value or "")
    # Remove whole ANSI control sequences first.  Removing only ESC/C1 bytes
    # would leave attacker-controlled sequence payloads in terminal output.
    clean = _ANSI_STRING.sub("", clean)
    clean = _ANSI_CSI.sub("", clean)
    clean = _ANSI_ESCAPE.sub("", clean)
    clean = _CONTROL.sub(" ", clean)
    return _SPACE.sub(" ", clean).strip()[:maximum]


def _bounded_excerpt(value: Any, *, maximum: int = MAX_EXCERPT_CHARS,
                     words: int = MAX_SOURCE_QUOTE_WORDS) -> str:
    """Return sanitized source wording under both character and word caps."""
    clean = _text(value, max(maximum * 8, maximum))
    bounded = " ".join(clean.split()[:words])
    if len(bounded) <= maximum:
        return bounded
    clipped = bounded[:maximum].rstrip()
    if " " in clipped:
        clipped = clipped.rsplit(" ", 1)[0]
    return clipped


def _credential_query_key(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]", "", value.casefold())
    if normalized in _CREDENTIAL_QUERY_KEYS:
        return True
    return normalized.endswith((
        "apikey", "accesskey", "accesskeyid", "accesstoken", "authtoken",
        "authorizationcode", "clientsecret", "credential", "idtoken",
        "jwt", "password", "passwd",
        "refreshtoken", "samlresponse", "secret", "securitytoken",
        "sessionid", "sessiontoken", "signature", "subscriptionkey", "token",
    ))


def _has_control(value: str) -> bool:
    return any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in value)


def _public_data(value: Any) -> Any:
    """Recursively remove terminal controls from caller-visible string values."""
    if isinstance(value, str):
        return _text(value, len(value))
    if isinstance(value, list):
        return [_public_data(item) for item in value]
    if isinstance(value, tuple):
        return [_public_data(item) for item in value]
    if isinstance(value, Mapping):
        clean: dict[Any, Any] = {}
        for key, item in value.items():
            public_key = _text(key, len(key)) if isinstance(key, str) else key
            if public_key == "" or public_key in clean:
                continue
            clean[public_key] = _public_data(item)
        return clean
    return value


def _tokens(value: str) -> set[str]:
    stop = {"about", "after", "before", "could", "from", "have", "into", "more",
            "most", "should", "that", "their", "there", "these", "they", "this",
            "what", "when", "where", "which", "while", "with", "would", "your"}
    return {item.casefold() for item in _WORD.findall(value)
            if len(item) >= 3 and item.casefold() not in stop}


def _bounded_query(value: str) -> str:
    value = _text(value, MAX_QUERY_CHARS)
    words = value.split()
    if not value or len(words) > MAX_QUERY_WORDS:
        value = " ".join(words[:MAX_QUERY_WORDS])
    if not value:
        raise ResearchError("research query is empty")
    return value


def classify_question(question: str) -> dict[str, Any]:
    lower = question.casefold()
    groups = {
        "medical": ("medicine", "medical", "symptom", "diagnosis", "drug", "dose", "treatment", "disease"),
        "legal": ("law", "legal", "court", "statute", "regulation", "rights", "lawsuit", "contract"),
        "financial": ("invest", "stock", "loan", "mortgage", "tax", "insurance", "financial", "crypto"),
        "news": ("latest", "today", "breaking", "news", "current", "recent", "this week"),
        "academic": ("research", "study", "paper", "evidence", "systematic review", "meta-analysis"),
        "travel": ("travel", "hotel", "flight", "restaurant", "itinerary", "tourism", "visa"),
        "product": ("buy", "price", "product", "best", "review", "compare", "versus"),
    }
    matched = sorted(name for name, words in groups.items() if any(word in lower for word in words))
    high_stakes = sorted(set(matched) & {"medical", "legal", "financial"})
    return {"categories": matched or ["general"], "high_stakes": high_stakes,
            "time_sensitive": "news" in matched or any(word in lower for word in ("latest", "current", "today", "price"))}


def plan_queries(question: str, *, maximum: int = 6) -> list[dict[str, Any]]:
    """Create deterministic research facets; a plan is not a search result."""
    if not isinstance(question, str) or not question.strip() or len(question.encode("utf-8")) > MAX_QUESTION_BYTES:
        raise ResearchError("question must be non-empty text no larger than 16 KiB")
    if not 1 <= int(maximum) <= MAX_QUERIES:
        raise ResearchError("query count is outside the bounded policy")
    base = _bounded_query(question)
    profile = classify_question(question)
    candidates: list[tuple[str, str]] = [("direct", base)]
    candidates.extend([
        ("primary", _bounded_query(base + " official primary source")),
        ("evidence", _bounded_query(base + " evidence research")),
        ("limitations", _bounded_query(base + " limitations criticism")),
    ])
    if profile["time_sensitive"]:
        candidates.append(("freshness", _bounded_query(base + " latest update date")))
    if "academic" in profile["categories"] or "medical" in profile["categories"]:
        candidates.append(("scholarly", _bounded_query(base + " systematic review research paper")))
    if "legal" in profile["categories"]:
        candidates.append(("authority", _bounded_query(base + " government court official text")))
    if "product" in profile["categories"] or "travel" in profile["categories"]:
        candidates.append(("independent", _bounded_query(base + " independent comparison drawbacks")))
    seen: set[str] = set()
    result = []
    for purpose, query in candidates:
        key = query.casefold()
        if key in seen:
            continue
        seen.add(key)
        result.append({"purpose": purpose, "query": query, "query_sha256": _sha(query)})
        if len(result) >= maximum:
            break
    return result


@dataclasses.dataclass(frozen=True)
class SearchHit:
    title: str
    url: str
    description: str
    rank: int
    query: str
    provider: str
    age: str = ""
    language: str = ""


class SearchBackend(Protocol):
    name: str
    uses_network: bool
    retention_allowed: bool

    def search(self, query: str, *, count: int, country: str,
               language: str, freshness: str) -> tuple[list[SearchHit], Mapping[str, Any]]:
        ...


def _fixed_brave_get(url: str, headers: Mapping[str, str], timeout: float,
                     maximum: int) -> bytes:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname != "api.search.brave.com" or parsed.port not in {None, 443}:
        raise ResearchError("search provider endpoint is not the fixed Brave HTTPS origin")
    port = parsed.port or 443
    addresses = _public_addresses(parsed.hostname, port)
    last_error: Exception | None = None
    for address in addresses:
        connection = _PinnedHTTPSConnection(
            parsed.hostname, address, port, timeout=timeout,
            context=ssl.create_default_context())
        try:
            path = urlunsplit(("", "", parsed.path, parsed.query, ""))
            connection.request("GET", path, headers=dict(headers))
            response = connection.getresponse()
            raw = response.read(maximum + 1)
            if len(raw) > maximum:
                raise ResearchError("search provider response exceeded the byte boundary")
            if response.status != 200:
                raise ResearchError("search provider returned HTTP %d" % response.status)
            if "application/json" not in str(response.getheader("Content-Type", "")).casefold():
                raise ResearchError("search provider did not return JSON")
            return raw
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            last_error = exc
        finally:
            connection.close()
    raise ResearchError("search provider request failed: " +
                        type(last_error).__name__) from last_error


class BraveSearchBackend:
    name = "brave-web-search"
    uses_network = True
    # Default Brave plans may restrict persistent storage. Attestor emits the report
    # to the caller but does not silently add provider results to a local cache.
    retention_allowed = False

    def __init__(self, api_key: str | None = None, *, timeout: float = DEFAULT_TIMEOUT,
                 transport: Callable[[str, Mapping[str, str], float, int], bytes] | None = None) -> None:
        key = api_key or os.environ.get("BRAVE_SEARCH_API_KEY") or os.environ.get("BRAVE_API_KEY")
        if not isinstance(key, str) or not 8 <= len(key) <= 4_096 or "\x00" in key:
            raise ResearchError("Brave Search requires BRAVE_SEARCH_API_KEY")
        if not 1.0 <= float(timeout) <= 60.0:
            raise ResearchError("provider timeout is outside the allowed range")
        self._key = key
        self._timeout = float(timeout)
        self._transport = transport or _fixed_brave_get

    def search(self, query: str, *, count: int, country: str,
               language: str, freshness: str) -> tuple[list[SearchHit], Mapping[str, Any]]:
        query = _bounded_query(query)
        count = max(1, min(int(count), MAX_RESULTS_PER_QUERY))
        params = {"q": query, "count": str(count), "country": country.upper(),
                  "search_lang": language.casefold()}
        if freshness:
            params["freshness"] = freshness
        request_url = BRAVE_ENDPOINT + "?" + urlencode(params)
        raw = self._transport(request_url, {
            "Accept": "application/json", "Accept-Encoding": "identity",
            "User-Agent": USER_AGENT,
            "X-Subscription-Token": self._key,
        }, self._timeout, MAX_SEARCH_RESPONSE)
        try:
            document = json.loads(raw.decode("utf-8", "strict"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ResearchError("search provider returned malformed JSON") from exc
        rows = document.get("web", {}).get("results", []) if isinstance(document, dict) else []
        if not isinstance(rows, list):
            raise ResearchError("search provider result shape is invalid")
        hits = []
        for index, row in enumerate(rows[:count]):
            if not isinstance(row, Mapping):
                continue
            url = _canonical_url(str(row.get("url", "")))
            if not url:
                continue
            hits.append(SearchHit(
                _text(row.get("title"), 500), url,
                _bounded_excerpt(row.get("description"),
                                 maximum=MAX_PUBLIC_DESCRIPTION_CHARS),
                index + 1, query, self.name,
                _text(row.get("age") or row.get("page_age"), 100),
                _text(row.get("language"), 20),
            ))
        return hits, {
            "provider": self.name, "query_sha256": _sha(query),
            "response_sha256": _sha(raw), "results": len(hits),
            "endpoint_origin": "https://api.search.brave.com",
            "api_key_in_report": False, "retention_allowed": self.retention_allowed,
        }


class FixtureSearchBackend:
    """Deterministic offline backend for tests and caller-supplied search evidence."""
    name = "offline-fixture"
    uses_network = False
    retention_allowed = True

    def __init__(self, hits: Sequence[Mapping[str, Any]]) -> None:
        if len(hits) > MAX_RESULTS:
            raise ResearchError("fixture result count exceeds the boundary")
        self._hits = [dict(row) for row in hits]
        self.calls: list[str] = []

    def search(self, query: str, *, count: int, country: str,
               language: str, freshness: str) -> tuple[list[SearchHit], Mapping[str, Any]]:
        del country, language, freshness
        query = _bounded_query(query)
        self.calls.append(query)
        rows = []
        for index, row in enumerate(self._hits[:count]):
            url = _canonical_url(str(row.get("url", "")))
            if url:
                rows.append(SearchHit(_text(row.get("title"), 500), url,
                                      _bounded_excerpt(
                                          row.get("description"),
                                          maximum=MAX_PUBLIC_DESCRIPTION_CHARS),
                                      index + 1, query, self.name,
                                      _text(row.get("age"), 100),
                                      _text(row.get("language"), 20)))
        return rows, {"provider": self.name, "query_sha256": _sha(query),
                      "response_sha256": _sha(self._hits), "results": len(rows),
                      "api_key_in_report": False, "retention_allowed": True}


def _canonical_url(raw: str) -> str:
    if not isinstance(raw, str) or not 1 <= len(raw) <= 4_096:
        return ""
    if _has_control(raw):
        return ""
    try:
        parsed = urlsplit(raw.strip())
        if parsed.scheme.casefold() not in {"http", "https"} or not parsed.hostname:
            return ""
        if parsed.username is not None or parsed.password is not None:
            return ""
        host = parsed.hostname.encode("idna").decode("ascii").casefold().rstrip(".")
        if not host or parsed.port not in {None, 80, 443}:
            return ""
        netloc = "[%s]" % host if ":" in host else host
        if parsed.port and parsed.port != (443 if parsed.scheme.casefold() == "https" else 80):
            netloc += ":%d" % parsed.port
        pairs = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=128)
        if any(_has_control(key) or _has_control(value) or
               _credential_query_key(key) for key, value in pairs):
            return ""
        query = [(key, value) for key, value in pairs
                 if not key.casefold().startswith("utm_") and
                 key.casefold() not in _TRACKING]
        return urlunsplit((parsed.scheme.casefold(), netloc, parsed.path or "/",
                           urlencode(sorted(query)), ""))
    except (UnicodeError, ValueError):
        return ""


def _public_addresses(host: str, port: int) -> tuple[str, ...]:
    try:
        values = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ResearchError("web source hostname could not be resolved") from exc
    addresses = []
    for value in values:
        raw = value[4][0]
        try:
            address = ipaddress.ip_address(raw.split("%", 1)[0])
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
        except ValueError as exc:
            raise ResearchError("web source resolved to an invalid address") from exc
        if not address.is_global:
            raise ResearchError("web source resolved to a non-public address")
        addresses.append(str(address))
    if not addresses:
        raise ResearchError("web source has no usable public address")
    return tuple(sorted(set(addresses)))


def _bounded_gzip(raw: bytes, maximum: int) -> bytes:
    """Expand one gzip member without allocating beyond the response budget."""
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        expanded = decoder.decompress(raw, maximum + 1)
        if len(expanded) > maximum or decoder.unconsumed_tail:
            raise ResearchError("expanded web source exceeded the byte boundary")
        remaining = maximum + 1 - len(expanded)
        expanded += decoder.flush(remaining)
    except zlib.error as exc:
        raise ResearchError("web source gzip body is invalid") from exc
    if (len(expanded) > maximum or not decoder.eof or decoder.unused_data or
            decoder.unconsumed_tail):
        raise ResearchError("expanded web source exceeded the byte boundary")
    return expanded


@dataclasses.dataclass(frozen=True)
class FetchResult:
    requested_url: str
    final_url: str
    status: int
    content_type: str
    body: bytes
    redirects: tuple[str, ...]
    robots_checks: tuple[tuple[str, str], ...]


class _RobotsRefused(ResearchError):
    """Internal signal that prevents a denied redirect hop from being sent."""

    def __init__(self, url: str, state: str, requested_url: str,
                 redirects: tuple[str, ...],
                 checks: tuple[tuple[str, str], ...]) -> None:
        super().__init__("robots policy refused web source")
        self.url = url
        self.state = state
        self.requested_url = requested_url
        self.redirects = redirects
        self.checks = checks


class SafeWebFetcher:
    """Small direct HTTP client that connects only to prevalidated public IPs."""

    def __init__(self, *, timeout: float = DEFAULT_TIMEOUT,
                 respect_robots: bool = True) -> None:
        if not 1.0 <= float(timeout) <= 60.0:
            raise ResearchError("fetch timeout is outside the allowed range")
        self.timeout = float(timeout)
        self.respect_robots = bool(respect_robots)
        self._robots: dict[str, tuple[str, str]] = {}

    def _request(self, url: str, maximum: int, redirects: int = MAX_REDIRECTS,
                 *, enforce_robots: bool = False) -> FetchResult:
        requested = _canonical_url(url)
        if not requested:
            raise ResearchError("web source URL is invalid")
        current = requested
        trail = []
        robots_checks: list[tuple[str, str]] = []
        for _index in range(redirects + 1):
            if enforce_robots:
                allowed, state = self._robots_allowed(current)
                state = _text(state, 80) or "unknown-refuse"
                robots_checks.append((current, state))
                if not allowed:
                    raise _RobotsRefused(
                        current, state, requested, tuple(trail),
                        tuple(robots_checks))
            parsed = urlsplit(current)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            addresses = _public_addresses(parsed.hostname or "", port)
            last_error: Exception | None = None
            response = None
            connection = None
            for address in addresses:
                try:
                    if parsed.scheme == "https":
                        connection = _PinnedHTTPSConnection(
                            parsed.hostname or "", address, port,
                            timeout=self.timeout, context=ssl.create_default_context())
                    else:
                        connection = _PinnedHTTPConnection(
                            parsed.hostname or "", address, port, timeout=self.timeout)
                    path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
                    connection.request("GET", path, headers={
                        "Host": parsed.netloc, "User-Agent": USER_AGENT,
                        "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8,application/json;q=0.5",
                        "Accept-Encoding": "identity", "Connection": "close",
                    })
                    response = connection.getresponse()
                    break
                except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
                    last_error = exc
                    if connection:
                        connection.close()
                    connection = None
            if response is None or connection is None:
                raise ResearchError("web source request failed: " + type(last_error).__name__) from last_error
            try:
                status = int(response.status)
                location = response.getheader("Location", "")
                content_type = _text(response.getheader("Content-Type", ""), 200).casefold()
                encoding = _text(response.getheader("Content-Encoding", ""), 40).casefold()
                raw = response.read(maximum + 1)
            finally:
                connection.close()
            if len(raw) > maximum:
                raise ResearchError("web source response exceeded the byte boundary")
            if encoding == "gzip":
                raw = _bounded_gzip(raw, maximum)
            elif encoding not in {"", "identity"}:
                raise ResearchError("web source uses an unsupported content encoding")
            if status in {301, 302, 303, 307, 308}:
                if not location or len(trail) >= redirects:
                    raise ResearchError("web source redirect boundary was exceeded")
                next_url = _canonical_url(urljoin(current, location))
                if not next_url:
                    raise ResearchError("web source redirect is unsafe")
                trail.append(next_url)
                current = next_url
                continue
            return FetchResult(
                requested, current, status, content_type, raw, tuple(trail),
                tuple(robots_checks))
        raise ResearchError("web source redirect boundary was exceeded")

    def _robots_allowed(self, url: str) -> tuple[bool, str]:
        parsed = urlsplit(url)
        origin = "%s://%s" % (parsed.scheme, parsed.netloc)
        cached = self._robots.get(origin)
        if cached is None:
            robots_url = origin + "/robots.txt"
            try:
                result = self._request(robots_url, MAX_ROBOTS_BYTES)
                if 200 <= result.status < 300:
                    text = result.body.decode("utf-8", "replace")
                    state = "parsed"
                elif 400 <= result.status < 500 and result.status not in {401, 403}:
                    text, state = "", "unavailable-allow"
                else:
                    text, state = "User-agent: *\nDisallow: /\n", "unreachable-refuse"
            except ResearchError:
                text, state = "User-agent: *\nDisallow: /\n", "unreachable-refuse"
            cached = (text, state)
            self._robots[origin] = cached
        text, state = cached
        return _robots_can_fetch(text, url, USER_AGENT_TOKEN), state

    def fetch(self, url: str) -> dict[str, Any]:
        canonical = _canonical_url(url)
        if not canonical:
            raise ResearchError("web source URL is invalid")
        try:
            result = self._request(
                canonical, MAX_PAGE_BYTES,
                enforce_robots=self.respect_robots)
        except _RobotsRefused as exc:
            return {
                "status": "robots-refused", "url": exc.url,
                "requested_url": exc.requested_url,
                "redirects": list(exc.redirects), "robots": exc.state,
                "robots_hops": [
                    {"url": checked_url, "state": state}
                    for checked_url, state in exc.checks
                ],
                "network_accessed": True,
            }
        robots_state = (result.robots_checks[-1][1]
                        if result.robots_checks else "not-requested")
        robots_hops = [
            {"url": checked_url, "state": state}
            for checked_url, state in result.robots_checks
        ]
        allowed_types = ("text/html", "application/xhtml+xml", "text/plain", "application/json")
        if not 200 <= result.status < 300:
            return {"status": "http-error", "url": result.final_url,
                    "http_status": result.status, "robots": robots_state,
                    "robots_hops": robots_hops,
                    "network_accessed": True}
        if not any(item in result.content_type for item in allowed_types):
            return {"status": "unsupported-content", "url": result.final_url,
                    "http_status": result.status, "content_type": result.content_type,
                    "robots": robots_state, "robots_hops": robots_hops,
                    "network_accessed": True}
        extracted = extract_document(result.body, result.content_type)
        return {
            "status": "fetched", "url": result.final_url,
            "requested_url": result.requested_url, "http_status": result.status,
            "content_type": result.content_type, "bytes": len(result.body),
            "content_sha256": _sha(result.body), "redirects": list(result.redirects),
            "robots": robots_state, "robots_hops": robots_hops,
            "network_accessed": True, **extracted,
        }


class _PinnedHTTPConnection(http.client.HTTPConnection):
    def __init__(self, host: str, address: str, port: int, **options: Any) -> None:
        super().__init__(host, port, **options)
        self._address = address

    def connect(self) -> None:
        self.sock = socket.create_connection((self._address, self.port), self.timeout)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, address: str, port: int, **options: Any) -> None:
        super().__init__(host, port, **options)
        self._address = address

    def connect(self) -> None:
        raw = socket.create_connection((self._address, self.port), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)


def _robots_can_fetch(text: str, url: str, agent: str) -> bool:
    """Bounded longest-match robots evaluator for User-agent/Allow/Disallow."""
    if len(text.encode("utf-8", "replace")) > MAX_ROBOTS_BYTES:
        return False
    groups: list[tuple[list[str], list[tuple[bool, str]]]] = []
    agents: list[str] = []
    rules: list[tuple[bool, str]] = []
    saw_rule = False
    for raw in text.splitlines()[:20_000]:
        line = raw.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        name, value = (item.strip() for item in line.split(":", 1))
        lower = name.casefold()
        if lower == "user-agent":
            if saw_rule and agents:
                groups.append((agents, rules)); agents, rules, saw_rule = [], [], False
            product = value.casefold()
            if product == "*" or re.fullmatch(r"[a-z_-]+", product):
                agents.append(product)
        elif lower in {"allow", "disallow"} and agents:
            saw_rule = True
            if value or lower == "allow":
                rules.append((lower == "allow", value))
    if agents:
        groups.append((agents, rules))
    token = agent.casefold()
    if not re.fullmatch(r"[a-z_-]+", token):
        return False
    exact = [rules for names, rules in groups if token in names]
    selected = exact if exact else [rules for names, rules in groups if "*" in names]
    combined = [rule for group in selected for rule in group]
    parsed_url = urlsplit(url)
    path = _robots_octet_spelling((parsed_url.path or "/") + (
        "?" + parsed_url.query if parsed_url.query else "")
    )
    if path == "/robots.txt":
        return True
    matches: list[tuple[int, bool]] = []
    for allow, pattern in combined:
        if not pattern:
            continue
        anchored = pattern.endswith("$")
        value = _robots_octet_spelling(pattern[:-1] if anchored else pattern)
        expression = "^" + re.escape(value).replace(r"\*", ".*") + ("$" if anchored else "")
        try:
            if re.search(expression, path):
                matches.append((_robots_specificity(value), allow))
        except re.error:
            continue
    if not matches:
        return True
    longest = max(length for length, _allow in matches)
    # Equivalent Allow and Disallow matches resolve to Allow.
    return any(allow for length, allow in matches if length == longest)


_ROBOTS_UNRESERVED = frozenset(
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


def _robots_octet_spelling(value: str) -> str:
    """Normalize percent encodings to the comparison spelling from RFC 9309."""
    output: list[str] = []
    index = 0
    while index < len(value):
        character = value[index]
        if character == "%" and index + 2 < len(value) and re.fullmatch(
                r"[0-9A-Fa-f]{2}", value[index + 1:index + 3]):
            octet = int(value[index + 1:index + 3], 16)
            output.append(chr(octet) if octet in _ROBOTS_UNRESERVED else "%%%02X" % octet)
            index += 3
            continue
        raw = character.encode("utf-8")
        output.append(character if len(raw) == 1 else "".join("%%%02X" % byte for byte in raw))
        index += 1
    return "".join(output)


def _robots_specificity(pattern: str) -> int:
    """Count path octets, excluding wildcard syntax, for longest-match ties."""
    count = index = 0
    while index < len(pattern):
        if pattern[index] == "*":
            index += 1
        elif pattern[index] == "%" and index + 2 < len(pattern) and re.fullmatch(
                r"[0-9A-F]{2}", pattern[index + 1:index + 3]):
            count += 1
            index += 3
        else:
            count += len(pattern[index].encode("utf-8"))
            index += 1
    return count


class _DocumentParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.published = ""
        self.canonical = ""
        self._title_depth = 0
        self._skip = 0
        self.parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lower = tag.casefold()
        values = {str(key).casefold(): str(value or "") for key, value in attrs}
        if lower in {"script", "style", "noscript", "svg", "canvas", "template"}:
            self._skip += 1
        if lower == "title":
            self._title_depth += 1
        if lower == "meta":
            key = (values.get("property") or values.get("name") or "").casefold()
            if key in _DATE_META and not self.published:
                self.published = _text(values.get("content"), 100)
        if lower == "link" and "canonical" in values.get("rel", "").casefold():
            self.canonical = _canonical_url(values.get("href", ""))
        if lower in {"p", "div", "article", "section", "main", "h1", "h2", "h3", "li", "br"}:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        lower = tag.casefold()
        if lower in {"script", "style", "noscript", "svg", "canvas", "template"} and self._skip:
            self._skip -= 1
        if lower == "title" and self._title_depth:
            self._title_depth -= 1

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        value = _text(data, 10_000)
        if not value:
            return
        if self._title_depth:
            self.title = _text(self.title + " " + value, 500)
        self.parts.append(value)


def extract_document(raw: bytes, content_type: str) -> dict[str, Any]:
    charset = "utf-8"
    match = re.search(r"charset\s*=\s*['\"]?([A-Za-z0-9._-]+)", content_type, re.I)
    if match:
        charset = match.group(1)
    try:
        text = raw.decode(charset, "replace")
    except LookupError:
        text = raw.decode("utf-8", "replace")
    if "html" not in content_type:
        clean = _text(text, MAX_EXTRACTED_CHARS)
        return {"title": "", "published": "", "canonical_url": "",
                "extracted_text": clean, "extracted_chars": len(clean)}
    parser = _DocumentParser()
    parse_error = ""
    try:
        parser.feed(text[:MAX_EXTRACTED_CHARS * 4])
        parser.close()
    except (ValueError, AssertionError) as exc:
        parse_error = type(exc).__name__
    clean = _text(" ".join(parser.parts), MAX_EXTRACTED_CHARS)
    return {"title": parser.title, "published": parser.published,
            "canonical_url": parser.canonical,
            "extracted_text": clean, "extracted_chars": len(clean),
            "parse_complete": not parse_error, "parse_error": parse_error}


@dataclasses.dataclass(frozen=True)
class ResearchPolicy:
    allow_network: bool = False
    max_queries: int = 6
    results_per_query: int = 10
    max_sources: int = 30
    fetch_pages: bool = False
    max_fetches: int = 12
    respect_robots: bool = True
    country: str = "US"
    language: str = "en"
    freshness: str = ""

    def validated(self) -> "ResearchPolicy":
        if not 1 <= int(self.max_queries) <= MAX_QUERIES:
            raise ResearchError("max_queries is outside the bounded policy")
        if not 1 <= int(self.results_per_query) <= MAX_RESULTS_PER_QUERY:
            raise ResearchError("results_per_query is outside the bounded policy")
        if not 1 <= int(self.max_sources) <= MAX_RESULTS:
            raise ResearchError("max_sources is outside the bounded policy")
        if not 0 <= int(self.max_fetches) <= MAX_FETCHES:
            raise ResearchError("max_fetches is outside the bounded policy")
        if not _SAFE_CODE.fullmatch(self.country) or not _SAFE_CODE.fullmatch(self.language):
            raise ResearchError("country/language code is invalid")
        if self.freshness and self.freshness not in {"pd", "pw", "pm", "py"}:
            raise ResearchError("freshness must be pd, pw, pm, py, or empty")
        return self


def _source_kind(url: str) -> str:
    host = (urlsplit(url).hostname or "").casefold()
    if host.endswith(".gov") or host.endswith(".gov.uk") or host.endswith(".gc.ca"):
        return "government"
    if host.endswith(".edu") or host.endswith(".ac.uk") or host in {"doi.org", "pubmed.ncbi.nlm.nih.gov"}:
        return "scholarly-or-academic"
    if host.endswith(".org"):
        return "organization"
    return "web"


def _rank_hits(question: str, rows: Sequence[SearchHit]) -> list[dict[str, Any]]:
    query_tokens = _tokens(question)
    by_url: dict[str, dict[str, Any]] = {}
    for hit in rows:
        url = _canonical_url(str(hit.url))
        if not url:
            continue
        title = _text(hit.title, 500)
        description = _bounded_excerpt(
            hit.description, maximum=MAX_PUBLIC_DESCRIPTION_CHARS)
        query = _text(hit.query, MAX_QUERY_CHARS)
        provider = _text(hit.provider, 100)
        row = by_url.get(url)
        overlap = len(query_tokens & _tokens(title + " " + description))
        score = max(0, 120 - hit.rank * 3) + overlap * 8 + (5 if url.startswith("https://") else 0)
        if row is None:
            by_url[url] = {
                "title": title, "url": url, "description": description,
                "provider": provider, "age": _text(hit.age, 100),
                "language": _text(hit.language, 20),
                "queries": [query], "query_sha256": [_sha(query)],
                "best_rank": hit.rank, "score": score,
                "source_kind": _source_kind(url),
            }
        else:
            if query not in row["queries"]:
                row["queries"].append(query); row["query_sha256"].append(_sha(query))
                row["score"] += 18
            row["best_rank"] = min(row["best_rank"], hit.rank)
            row["score"] = max(row["score"], score) + 4
    return sorted(by_url.values(), key=lambda row: (-row["score"], row["url"]))


def _passages(question: str, sources: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    wanted = _tokens(question)
    rows = []
    for source in sources:
        text = str(source.get("extracted_text") or source.get("description") or "")
        state = "page-excerpt" if source.get("fetch", {}).get("status") == "fetched" else "provider-snippet"
        candidates = _SENTENCE.split(text)
        scored = []
        for index, sentence in enumerate(candidates[:4_000]):
            clean = _bounded_excerpt(sentence)
            if not 35 <= len(clean) <= MAX_EXCERPT_CHARS:
                continue
            overlap = len(wanted & _tokens(clean))
            if overlap <= 0:
                continue
            scored.append((overlap * 10 - index // 20, clean))
        # One excerpt per source ensures all evidence attributed to that source
        # stays within the 25-word total, rather than two independent 25-word
        # excerpts quietly doubling the quotation budget.
        for score, clean in sorted(scored, key=lambda row: (-row[0], row[1]))[:1]:
            body = {"source_id": source["source_id"], "url": source["url"],
                    "support": state, "excerpt": clean,
                    "excerpt_sha256": _sha(clean), "relevance": score}
            body["evidence_id"] = "R41-E-" + _sha(body)[:20]
            rows.append(body)
    rows.sort(key=lambda row: (-row["relevance"], row["source_id"], row["excerpt_sha256"]))
    return rows[:MAX_PASSAGES]


def _possible_disagreements(passages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for left_index, left in enumerate(passages[:40]):
        left_tokens = _tokens(str(left.get("excerpt", "")))
        left_numbers = set(_NUMBER.findall(str(left.get("excerpt", ""))))
        for right in passages[left_index + 1:40]:
            if left.get("source_id") == right.get("source_id"):
                continue
            right_text = str(right.get("excerpt", ""))
            shared = left_tokens & _tokens(right_text)
            if len(shared) < 4:
                continue
            right_numbers = set(_NUMBER.findall(right_text))
            number_conflict = bool(left_numbers and right_numbers and left_numbers != right_numbers)
            negation_conflict = bool(_NEGATION.search(str(left.get("excerpt", "")))) != bool(_NEGATION.search(right_text))
            if not number_conflict and not negation_conflict:
                continue
            body = {"state": "possible-disagreement-not-adjudicated",
                    "kind": "numeric" if number_conflict else "negation",
                    "left_evidence_id": left["evidence_id"],
                    "right_evidence_id": right["evidence_id"],
                    "shared_terms": sorted(shared)[:12]}
            body["id"] = "R41-D-" + _sha(body)[:20]
            rows.append(body)
            if len(rows) >= 20:
                return rows
    return rows


def _answer(question: str, sources: Sequence[Mapping[str, Any]],
            passages: Sequence[Mapping[str, Any]], disagreements: Sequence[Mapping[str, Any]],
            profile: Mapping[str, Any]) -> dict[str, Any]:
    selected = list(passages[:8])
    claims = [{"text": row["excerpt"], "citations": [row["source_id"]],
               "evidence_ids": [row["evidence_id"]], "support": row["support"],
               "state": "extractive-evidence-not-independent-proof"}
              for row in selected]
    gaps = []
    if not sources:
        gaps.append("no sources were returned")
    if not passages:
        gaps.append("no relevant bounded passages could be extracted")
    if len({urlsplit(str(row.get("url", ""))).hostname for row in sources}) < 2:
        gaps.append("fewer than two source domains were available")
    if profile.get("high_stakes"):
        gaps.append("high-stakes topic: this research is informational evidence, not professional advice")
    return {
        "mode": "deterministic-extractive",
        "question_sha256": _sha(question), "claims": claims,
        "citation_format": "source_id resolves through the sources array",
        "possible_disagreements": len(disagreements), "gaps": gaps,
        "abstained": not bool(claims),
        "limitations": [
            "Search ranking and snippets can be incomplete, stale, or misleading.",
            "Extracted passages retain source wording and are not Attestor-authored factual proof.",
            "Possible disagreement detection is lexical and requires human adjudication.",
            "Credentialed, paywalled, private-network, dark-web, and form-submission access is absent.",
        ],
    }


def research(question: str, *, policy: ResearchPolicy | None = None,
             backend: SearchBackend | None = None,
             fetcher: SafeWebFetcher | None = None,
             now: _datetime.datetime | None = None) -> dict[str, Any]:
    """Run bounded research or return an authorization-required report."""
    if not isinstance(question, str) or not question.strip() or len(question.encode("utf-8")) > MAX_QUESTION_BYTES:
        raise ResearchError("question must be non-empty text no larger than 16 KiB")
    question = _text(question, MAX_QUESTION_BYTES)
    if not question:
        raise ResearchError("question is empty after removing terminal controls")
    policy = (policy or ResearchPolicy()).validated()
    profile = classify_question(question)
    plan = plan_queries(question, maximum=policy.max_queries)
    if backend is None and not policy.allow_network:
        body = {
            "schema": SCHEMA, "version": VERSION,
            "status": "network-authorization-required", "question": question,
            "question_sha256": _sha(question), "profile": profile, "query_plan": plan,
            "summary": {"queries": 0, "results": 0, "sources": 0,
                        "pages_fetched": 0, "claims": 0},
            "sources": [], "evidence": [], "disagreements": [],
            "answer": {"mode": "abstention", "claims": [], "abstained": True,
                       "gaps": ["online research was not explicitly authorized"]},
            "coverage": {"gaps": ["search provider was not called"], "complete": False},
            "execution": {"network_accessed": False, "private_network_accessed": False,
                          "credentials_bypassed": False, "forms_submitted": False,
                          "dark_web_accessed": False, "provider_key_reported": False},
            "retention": {"provider_results_persisted_by_attestor": False},
        }
        body = _public_data(body)
        body["report_sha256"] = _sha(body)
        return body
    if policy.fetch_pages and not policy.allow_network:
        raise ResearchError("page retrieval requires explicit network authorization")
    if backend is None:
        backend = BraveSearchBackend()
    if backend.uses_network and not policy.allow_network:
        raise ResearchError("network backend requires explicit allow_network authorization")
    rows: list[SearchHit] = []
    query_evidence = []
    errors = []
    for planned in plan:
        try:
            hits, evidence = backend.search(
                planned["query"], count=policy.results_per_query,
                country=policy.country, language=policy.language,
                freshness=policy.freshness)
            rows.extend(hits)
            query_evidence.append(dict(evidence))
        except (OSError, ValueError, ResearchError) as exc:
            errors.append({"purpose": planned["purpose"], "error": type(exc).__name__})
    ranked = _rank_hits(question, rows)[:policy.max_sources]
    fetcher = fetcher or SafeWebFetcher(respect_robots=policy.respect_robots)
    sources = []
    page_fetches = 0
    for index, row in enumerate(ranked):
        source = dict(row)
        source["source_id"] = "S%d" % (index + 1)
        source["snippet_sha256"] = _sha(source.get("description", ""))
        source["fetch"] = {"status": "not-requested", "network_accessed": False}
        if policy.fetch_pages and page_fetches < policy.max_fetches:
            try:
                fetched = fetcher.fetch(source["url"])
            except (OSError, ValueError, ResearchError) as exc:
                fetched = {"status": "failed", "error": type(exc).__name__,
                           "network_accessed": True}
            page_fetches += 1
            source["fetch"] = {key: value for key, value in fetched.items()
                               if key != "extracted_text"}
            if fetched.get("status") == "fetched":
                source["extracted_text"] = _text(
                    fetched.get("extracted_text", ""), MAX_EXTRACTED_CHARS)
                if fetched.get("title"):
                    source["title"] = _text(fetched["title"], 500)
                source["published"] = _text(fetched.get("published", ""), 100)
        sources.append(source)
    passages = _passages(question, sources)
    disagreements = _possible_disagreements(passages)
    answer = _answer(question, sources, passages, disagreements, profile)
    fetched_count = sum(row.get("fetch", {}).get("status") == "fetched" for row in sources)
    gaps = list(answer["gaps"])
    if errors:
        gaps.append("one or more planned queries failed")
    if any(row.get("fetch", {}).get("status") in {"robots-refused", "failed"} for row in sources):
        gaps.append("one or more source pages could not be retrieved; provider snippets were retained as weaker evidence")
    status = "evidence-collected-with-gaps" if sources and gaps else \
        "evidence-collected" if sources else "no-evidence"
    body = {
        "schema": SCHEMA, "version": VERSION, "status": status,
        "researched_at": _utc(now), "question": question,
        "question_sha256": _sha(question), "profile": profile,
        "query_plan": plan, "query_evidence": query_evidence,
        "summary": {"queries": len(query_evidence), "query_errors": len(errors),
                    "raw_results": len(rows), "sources": len(sources),
                    "source_domains": len({urlsplit(row["url"]).hostname for row in sources}),
                    "pages_requested": page_fetches, "pages_fetched": fetched_count,
                    "evidence_passages": len(passages), "claims": len(answer["claims"]),
                    "possible_disagreements": len(disagreements)},
        "sources": [{key: value for key, value in row.items() if key != "extracted_text"}
                    for row in sources],
        "evidence": passages, "disagreements": disagreements,
        "answer": answer, "errors": errors,
        "coverage": {"complete": not gaps, "gaps": gaps,
                     "provider": backend.name,
                     "page_fetch_enabled": policy.fetch_pages,
                     "robots_respected": policy.respect_robots},
        "execution": {"network_accessed": bool(backend.uses_network or page_fetches),
                      "private_network_accessed": False,
                      "credentials_bypassed": False, "forms_submitted": False,
                      "dark_web_accessed": False, "provider_key_reported": False,
                      "target_code_executed": False, "filesystem_writes": False},
        "retention": {"provider_results_persisted_by_attestor": False,
                      "provider_declared_retention_allowed": bool(backend.retention_allowed),
                      "default_cache": "disabled"},
    }
    body = _public_data(body)
    body["sources_sha256"] = _sha(body["sources"])
    body["evidence_sha256"] = _sha(body["evidence"])
    body["report_sha256"] = _sha(body)
    return body


def verify_report(report: Mapping[str, Any]) -> tuple[bool, list[str]]:
    errors = []
    if type(report) is not dict or report.get("schema") != SCHEMA or report.get("version") != VERSION:
        return False, ["research schema or version is invalid"]
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    try:
        if report.get("report_sha256") != _sha(body):
            errors.append("research report digest mismatch")
        if "sources_sha256" in report and report.get("sources_sha256") != _sha(report.get("sources")):
            errors.append("research source catalog digest mismatch")
        if "evidence_sha256" in report and report.get("evidence_sha256") != _sha(report.get("evidence")):
            errors.append("research evidence catalog digest mismatch")
        source_ids = {row.get("source_id") for row in report.get("sources", []) if isinstance(row, Mapping)}
        evidence_ids = {row.get("evidence_id") for row in report.get("evidence", []) if isinstance(row, Mapping)}
        quoted_words: dict[Any, int] = {}
        for source in report.get("sources", []):
            if not isinstance(source, Mapping):
                continue
            description = str(source.get("description", ""))
            if (len(description) > MAX_PUBLIC_DESCRIPTION_CHARS or
                    len(description.split()) > MAX_SOURCE_QUOTE_WORDS):
                errors.append("research source description exceeds the public excerpt boundary")
        for evidence in report.get("evidence", []):
            if not isinstance(evidence, Mapping):
                continue
            excerpt = str(evidence.get("excerpt", ""))
            source_id = evidence.get("source_id")
            quoted_words[source_id] = quoted_words.get(source_id, 0) + len(excerpt.split())
            if len(excerpt) > MAX_EXCERPT_CHARS:
                errors.append("research evidence exceeds the character boundary")
        if any(count > MAX_SOURCE_QUOTE_WORDS for count in quoted_words.values()):
            errors.append("research evidence exceeds the per-source quotation boundary")
        for claim in report.get("answer", {}).get("claims", []):
            if not set(claim.get("citations", [])).issubset(source_ids):
                errors.append("research claim cites an unknown source")
            if not set(claim.get("evidence_ids", [])).issubset(evidence_ids):
                errors.append("research claim cites unknown evidence")
    except (TypeError, ValueError):
        errors.append("research report is not canonical JSON")
    return not errors, errors


def render(report: Mapping[str, Any]) -> str:
    valid, errors = verify_report(report)
    if not valid:
        return "Attestor Research result withheld: " + ", ".join(errors[:3])
    if report.get("status") == "network-authorization-required":
        return "Attestor Research is ready, but online access was not authorized. Re-run with --online."
    lines = ["Attestor 4.1.3 Research: " + str(report.get("status", "unknown")), ""]
    for claim in report.get("answer", {}).get("claims", []):
        citations = " ".join("[%s]" % item for item in claim.get("citations", []))
        lines.append("- %s %s" % (claim.get("text", ""), citations))
    if not report.get("answer", {}).get("claims"):
        lines.append("No bounded evidence passage supported an answer.")
    if report.get("disagreements"):
        lines.extend(["", "Possible disagreements", "----------------------"])
        for row in report["disagreements"][:5]:
            lines.append("- %s between %s and %s" % (
                row.get("kind"), row.get("left_evidence_id"), row.get("right_evidence_id")))
    lines.extend(["", "Sources", "-------"])
    for source in report.get("sources", [])[:30]:
        lines.append("[%s] %s — %s" % (source.get("source_id"), source.get("title"), source.get("url")))
    gaps = report.get("coverage", {}).get("gaps", [])
    if gaps:
        lines.extend(["", "Limits", "------", *("- " + str(item) for item in gaps[:20])])
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("question")
    parser.add_argument("--online", action="store_true",
                        help="explicitly authorize public-web network access")
    parser.add_argument("--fetch-pages", action="store_true",
                        help="retrieve selected public pages after search, subject to robots.txt")
    parser.add_argument("--max-queries", type=int, default=6)
    parser.add_argument("--results-per-query", type=int, default=10)
    parser.add_argument("--max-sources", type=int, default=30)
    parser.add_argument("--max-fetches", type=int, default=12)
    parser.add_argument("--country", default="US")
    parser.add_argument("--language", default="en")
    parser.add_argument("--freshness", choices=("", "pd", "pw", "pm", "py"), default="")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    if args.fetch_pages and not args.online:
        parser.error("--fetch-pages requires --online")
    policy = ResearchPolicy(
        allow_network=args.online, max_queries=args.max_queries,
        results_per_query=args.results_per_query, max_sources=args.max_sources,
        fetch_pages=args.fetch_pages, max_fetches=args.max_fetches,
        respect_robots=True, country=args.country,
        language=args.language, freshness=args.freshness)
    try:
        report = research(args.question, policy=policy)
    except ResearchError as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False)
          if args.format == "json" else render(report))
    return 0 if report.get("status") not in {"no-evidence"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
