from __future__ import annotations

import datetime
import gzip
import json
import os
import unittest
from unittest import mock

import research_engine41 as research


NOW = datetime.datetime(2026, 7, 17, 12, 0, tzinfo=datetime.timezone.utc)


class FakeFetcher:
    def __init__(self) -> None:
        self.urls = []

    def fetch(self, url: str):
        self.urls.append(url)
        return {
            "status": "fetched", "url": url, "requested_url": url,
            "http_status": 200, "content_type": "text/html",
            "bytes": 100, "content_sha256": "a" * 64, "redirects": [],
            "robots": "parsed", "network_accessed": False,
            "title": "Fixture title", "published": "2026-07-01",
            "canonical_url": url,
            "extracted_text": (
                "The official population estimate for Exampleland in 2020 was "
                "10 million residents according to the national census authority."
            ),
            "extracted_chars": 120,
        }


class ResearchEngine41Tests(unittest.TestCase):
    def fixture(self):
        return research.FixtureSearchBackend([
            {
                "title": "Exampleland official census",
                "url": "https://statistics.example.gov/report?utm_source=test",
                "description": (
                    "The official population estimate for Exampleland in 2020 "
                    "was 10 million residents according to the national census authority."
                ),
            },
            {
                "title": "Exampleland revised estimate",
                "url": "https://research.example.org/revision",
                "description": (
                    "The official population estimate for Exampleland in 2020 "
                    "was 12 million residents according to the revised research series."
                ),
            },
        ])

    def test_network_is_denied_by_default_with_an_explicit_abstention(self) -> None:
        report = research.research("What changed in global health policy?", now=NOW)
        self.assertEqual(report["status"], "network-authorization-required")
        self.assertTrue(report["answer"]["abstained"])
        self.assertFalse(report["execution"]["network_accessed"])
        self.assertFalse(report["execution"]["dark_web_accessed"])
        self.assertTrue(research.verify_report(report)[0])

    def test_query_plan_is_bounded_and_adds_high_stakes_facets(self) -> None:
        plan = research.plan_queries(
            "What does current medical research say about this treatment?", maximum=6)
        self.assertLessEqual(len(plan), 6)
        self.assertIn("scholarly", {row["purpose"] for row in plan})
        self.assertTrue(all(len(row["query"]) <= research.MAX_QUERY_CHARS for row in plan))
        profile = research.classify_question("medical treatment and stock investment")
        self.assertEqual(profile["high_stakes"], ["financial", "medical"])

    def test_offline_fixture_produces_cited_evidence_and_disagreement(self) -> None:
        policy = research.ResearchPolicy(
            allow_network=False, max_queries=4, results_per_query=2,
            max_sources=5, fetch_pages=False)
        first = research.research(
            "What was the official population estimate for Exampleland in 2020?",
            policy=policy, backend=self.fixture(), now=NOW)
        second = research.research(
            "What was the official population estimate for Exampleland in 2020?",
            policy=policy, backend=self.fixture(), now=NOW)
        self.assertEqual(first, second)
        self.assertEqual(first["summary"]["sources"], 2)
        self.assertGreater(first["summary"]["claims"], 0)
        self.assertGreater(first["summary"]["possible_disagreements"], 0)
        self.assertNotIn("utm_source", json.dumps(first))
        source_ids = {row["source_id"] for row in first["sources"]}
        for claim in first["answer"]["claims"]:
            self.assertTrue(set(claim["citations"]).issubset(source_ids))
        self.assertTrue(research.verify_report(first)[0])

    def test_page_fetch_is_explicit_and_evidence_output_is_excerpt_only(self) -> None:
        fetcher = FakeFetcher()
        report = research.research(
            "What was the population estimate for Exampleland?",
            policy=research.ResearchPolicy(
                max_queries=1, results_per_query=1, max_sources=1,
                fetch_pages=True, max_fetches=1, allow_network=True),
            backend=self.fixture(), fetcher=fetcher, now=NOW)
        self.assertEqual(len(fetcher.urls), 1)
        self.assertEqual(report["summary"]["pages_fetched"], 1)
        self.assertNotIn("extracted_text", report["sources"][0])
        self.assertTrue(all(len(row["excerpt"].split()) <= 25 for row in report["evidence"]))
        by_source = {}
        for row in report["evidence"]:
            by_source[row["source_id"]] = (
                by_source.get(row["source_id"], 0) + len(row["excerpt"].split()))
        self.assertTrue(all(words <= 25 for words in by_source.values()))

    def test_page_fetch_cannot_bypass_network_authorization_with_fixture_search(self) -> None:
        with self.assertRaisesRegex(research.ResearchError,
                                    "explicit network authorization"):
            research.research(
                "What was the population estimate for Exampleland?",
                policy=research.ResearchPolicy(
                    max_queries=1, results_per_query=1, max_sources=1,
                    fetch_pages=True, allow_network=False),
                backend=self.fixture(), fetcher=FakeFetcher(), now=NOW)

    def test_brave_transport_never_puts_key_in_url_or_evidence(self) -> None:
        captured = {}

        def transport(url, headers, timeout, maximum):
            captured.update({"url": url, "headers": dict(headers),
                             "timeout": timeout, "maximum": maximum})
            return json.dumps({"web": {"results": [{
                "title": "Official result", "url": "https://example.com/source",
                "description": "A relevant public source with bounded evidence."
            }]}}).encode("utf-8")

        key = "test-secret-subscription-token"
        backend = research.BraveSearchBackend(key, transport=transport)
        hits, evidence = backend.search(
            "public evidence", count=5, country="US", language="en", freshness="")
        self.assertEqual(len(hits), 1)
        self.assertEqual(captured["headers"]["X-Subscription-Token"], key)
        self.assertNotIn(key, captured["url"])
        self.assertNotIn(key, json.dumps(evidence))
        self.assertFalse(evidence["api_key_in_report"])

    def test_private_destinations_credentials_and_unsafe_ports_are_refused(self) -> None:
        self.assertEqual(research._canonical_url("file:///etc/passwd"), "")
        self.assertEqual(research._canonical_url("https://user:pass@example.com/"), "")
        self.assertEqual(research._canonical_url("https://example.com:8443/"), "")
        for url in (
            "https://example.com/?api_key=secret",
            "https://example.com/?access_token=secret",
            "https://example.com/?X-Amz-Credential=secret",
            "https://example.com/?sig=secret",
            "https://example.com/?oauth%5Ftoken=secret",
            "https://example.com/?client-secret=secret",
            "https://example.com/?AWSAccessKeyId=secret",
            "https://example.com/?custom_token=secret",
        ):
            with self.subTest(url=url):
                self.assertEqual(research._canonical_url(url), "")
        self.assertEqual(
            research._canonical_url("https://example.com/report?page=2"),
            "https://example.com/report?page=2")
        with self.assertRaises(research.ResearchError):
            research._public_addresses("127.0.0.1", 80)
        with self.assertRaises(research.ResearchError):
            research._public_addresses("::1", 80)

    def test_credential_query_result_is_dropped_before_ranking_or_fetch(self) -> None:
        backend = research.FixtureSearchBackend([
            {"title": "Signed private result",
             "url": "https://example.com/report?X-Amz-Signature=secret",
             "description": "Exampleland population evidence should not survive."},
            {"title": "Public result", "url": "https://example.org/public",
             "description": "Exampleland population evidence from a public report."},
        ])
        report = research.research(
            "Exampleland population evidence",
            policy=research.ResearchPolicy(max_queries=1, results_per_query=2),
            backend=backend, now=NOW)
        self.assertEqual([row["url"] for row in report["sources"]],
                         ["https://example.org/public"])
        self.assertNotIn("secret", json.dumps(report))

    def test_public_strings_remove_terminal_controls_and_ansi_sequences(self) -> None:
        backend = research.FixtureSearchBackend([{
            "title": "\x1b]0;PWN\x07Safe \x1b[31mRed\x1b[0m \u009b32mGreen\u009b0m",
            "url": "https://example.org/safe",
            "description": (
                "\x1b]8;;https://attacker.invalid\x07\x00Exampleland public population "
                "evidence remains relevant and visible after sanitization.\x1b]8;;\x07"),
        }])
        report = research.research(
            "\x1b[2JWhat is the Exampleland population evidence?",
            policy=research.ResearchPolicy(max_queries=1, results_per_query=1),
            backend=backend, now=NOW)
        source = report["sources"][0]
        self.assertEqual(source["title"], "Safe Red Green")
        self.assertNotIn("PWN", source["title"])
        public = json.dumps(report, ensure_ascii=False) + research.render(report)
        self.assertFalse(any(ord(char) < 32 and char not in "\n\r\t"
                             or 127 <= ord(char) <= 159 for char in public))
        self.assertNotIn("\x1b", public)
        self.assertNotIn("[31m", public)
        self.assertEqual(
            research._public_data({"\x1b[31mmetadata\x1b[0m": "\u009b32mvalue\u009b0m"}),
            {"metadata": "value"})

    def test_redirect_destination_robots_is_checked_before_cross_origin_request(self) -> None:
        first = "https://first.example/start"
        blocked = "https://second.example/private"

        class FakeResponse:
            status = 302

            @staticmethod
            def getheader(name, default=""):
                return {"Location": blocked,
                        "Content-Type": "text/plain"}.get(name, default)

            @staticmethod
            def read(_maximum):
                return b""

        class FakeConnection:
            def __init__(self):
                self.requested = False

            def request(self, *_args, **_kwargs):
                self.requested = True

            @staticmethod
            def getresponse():
                return FakeResponse()

            @staticmethod
            def close():
                return None

        fetcher = research.SafeWebFetcher(respect_robots=True)
        connection = mock.Mock(side_effect=lambda *_args, **_kwargs: FakeConnection())
        with mock.patch.object(
                fetcher, "_robots_allowed",
                side_effect=[(True, "parsed"), (False, "parsed")]) as robots, \
                mock.patch.object(research, "_public_addresses",
                                  return_value=("93.184.216.34",)), \
                mock.patch.object(research, "_PinnedHTTPSConnection", connection):
            result = fetcher.fetch(first)
        self.assertEqual(result["status"], "robots-refused")
        self.assertEqual(result["url"], blocked)
        self.assertEqual(connection.call_count, 1)
        self.assertEqual(robots.call_args_list, [mock.call(first), mock.call(blocked)])
        self.assertEqual([row["url"] for row in result["robots_hops"]],
                         [first, blocked])

    def test_allowed_cross_origin_redirect_records_every_robots_check(self) -> None:
        first = "https://first.example/start"
        second = "https://second.example/public"

        class FakeResponse:
            def __init__(self, status, headers, body):
                self.status = status
                self.headers = headers
                self.body = body

            def getheader(self, name, default=""):
                return self.headers.get(name, default)

            def read(self, _maximum):
                return self.body

        responses = [
            FakeResponse(302, {"Location": second,
                               "Content-Type": "text/plain"}, b""),
            FakeResponse(200, {"Content-Type": "text/plain"},
                         b"Exampleland public evidence is available here."),
        ]

        class FakeConnection:
            def __init__(self, response):
                self.response = response

            @staticmethod
            def request(*_args, **_kwargs):
                return None

            def getresponse(self):
                return self.response

            @staticmethod
            def close():
                return None

        connection = mock.Mock(
            side_effect=lambda *_args, **_kwargs: FakeConnection(responses.pop(0)))
        fetcher = research.SafeWebFetcher(respect_robots=True)
        with mock.patch.object(
                fetcher, "_robots_allowed", return_value=(True, "parsed")) as robots, \
                mock.patch.object(research, "_public_addresses",
                                  return_value=("93.184.216.34",)), \
                mock.patch.object(research, "_PinnedHTTPSConnection", connection):
            result = fetcher.fetch(first)
        self.assertEqual(result["status"], "fetched")
        self.assertEqual(result["url"], second)
        self.assertEqual(connection.call_count, 2)
        self.assertEqual(robots.call_args_list, [mock.call(first), mock.call(second)])
        self.assertEqual(result["robots_hops"], [
            {"url": first, "state": "parsed"},
            {"url": second, "state": "parsed"},
        ])

    def test_public_descriptions_and_total_evidence_are_bounded_per_source(self) -> None:
        description = " ".join(
            ["Exampleland", "population", "evidence"] +
            ["providerword%d" % index for index in range(60)]) + "."
        backend = research.FixtureSearchBackend([{
            "title": "Exampleland evidence", "url": "https://example.org/report",
            "description": description,
        }])

        class TwoPassageFetcher(FakeFetcher):
            def fetch(self, url: str):
                row = super().fetch(url)
                row["extracted_text"] = (
                    "Exampleland population evidence reports ten million residents "
                    "according to the official national statistical publication. "
                    "A separate Exampleland population evidence sentence discusses "
                    "a later revision with extensive supporting methodological context.")
                return row

        report = research.research(
            "Exampleland population evidence",
            policy=research.ResearchPolicy(
                allow_network=True, max_queries=1, results_per_query=1,
                max_sources=1, fetch_pages=True, max_fetches=1),
            backend=backend, fetcher=TwoPassageFetcher(), now=NOW)
        self.assertLessEqual(len(report["sources"][0]["description"]),
                             research.MAX_PUBLIC_DESCRIPTION_CHARS)
        self.assertLessEqual(len(report["sources"][0]["description"].split()),
                             research.MAX_SOURCE_QUOTE_WORDS)
        self.assertLessEqual(len(report["evidence"]), 1)
        self.assertLessEqual(
            sum(len(row["excerpt"].split()) for row in report["evidence"]
                if row["source_id"] == "S1"),
            research.MAX_SOURCE_QUOTE_WORDS)
        self.assertTrue(research.verify_report(report)[0])

    def test_live_provider_transport_refuses_non_public_dns_before_connecting(self) -> None:
        with mock.patch.object(
                research, "_public_addresses",
                side_effect=research.ResearchError("non-public")), \
                mock.patch.object(research, "_PinnedHTTPSConnection") as connection:
            with self.assertRaises(research.ResearchError):
                research._fixed_brave_get(
                    research.BRAVE_ENDPOINT + "?q=test", {}, 2.0, 1024)
        connection.assert_not_called()

    def test_gzip_expansion_is_bounded_before_materializing_a_large_body(self) -> None:
        self.assertEqual(research._bounded_gzip(gzip.compress(b"evidence"), 100),
                         b"evidence")
        bomb = gzip.compress(b"A" * 100_000)
        with self.assertRaisesRegex(research.ResearchError, "byte boundary"):
            research._bounded_gzip(bomb, 1_024)

    def test_robots_longest_match_and_allow_tie(self) -> None:
        rules = """
User-agent: *
Disallow: /private
Allow: /private/public
Disallow: /same
Allow: /same
Disallow: /*?private=1
"""
        self.assertFalse(research._robots_can_fetch(
            rules, "https://example.com/private/data", research.USER_AGENT_TOKEN))
        self.assertTrue(research._robots_can_fetch(
            rules, "https://example.com/private/public/page", research.USER_AGENT_TOKEN))
        self.assertTrue(research._robots_can_fetch(
            rules, "https://example.com/same", research.USER_AGENT_TOKEN))
        self.assertFalse(research._robots_can_fetch(
            rules, "https://example.com/page?private=1", research.USER_AGENT_TOKEN))

    def test_robots_requires_exact_product_token_and_normalizes_uri_octets(self) -> None:
        rules = """
User-agent: Research
Allow: /private
User-agent: *
Disallow: /
"""
        self.assertFalse(research._robots_can_fetch(
            rules, "https://example.com/private", research.USER_AGENT_TOKEN))
        encoded = """
User-agent: AttestorResearch
Disallow: /foo/bar/baz
"""
        self.assertFalse(research._robots_can_fetch(
            encoded, "https://example.com/foo/bar/%62%61%7A", research.USER_AGENT_TOKEN))
        self.assertTrue(research._robots_can_fetch(
            "User-agent: AttestorResearch\nDisallow: /robots.txt\n",
            "https://example.com/robots.txt", research.USER_AGENT_TOKEN))

    def test_html_extractor_ignores_script_content(self) -> None:
        raw = b"""<html><head><title>Evidence</title>
        <meta property='article:published_time' content='2026-07-01'></head>
        <body><script>secret_script_noise()</script><main>
        <p>Visible research evidence belongs in this bounded document.</p>
        </main></body></html>"""
        document = research.extract_document(raw, "text/html; charset=utf-8")
        self.assertEqual(document["title"], "Evidence")
        self.assertEqual(document["published"], "2026-07-01")
        self.assertIn("Visible research evidence", document["extracted_text"])
        self.assertNotIn("secret_script_noise", document["extracted_text"])
        self.assertTrue(document["parse_complete"])
        self.assertEqual(document["parse_error"], "")

    def test_tampered_report_is_rejected(self) -> None:
        report = research.research(
            "Exampleland population",
            policy=research.ResearchPolicy(max_queries=1, results_per_query=2),
            backend=self.fixture(), now=NOW)
        report["sources"][0]["title"] = "tampered"
        valid, errors = research.verify_report(report)
        self.assertFalse(valid)
        self.assertTrue(any("digest" in error for error in errors))

    @unittest.skipUnless(
        os.environ.get("ATTESTOR_LIVE_TESTS") == "1" and
        bool(os.environ.get("BRAVE_SEARCH_API_KEY") or os.environ.get("BRAVE_API_KEY")),
        "live Brave provider test requires ATTESTOR_LIVE_TESTS=1 and a key")
    def test_live_provider_opt_in(self) -> None:
        report = research.research(
            "RFC 9309 robots exclusion protocol",
            policy=research.ResearchPolicy(
                allow_network=True, max_queries=1, results_per_query=3,
                max_sources=3, fetch_pages=False), now=NOW)
        self.assertGreater(report["summary"]["sources"], 0)
        self.assertTrue(research.verify_report(report)[0])


if __name__ == "__main__":
    unittest.main()
