#!/usr/bin/env python3
"""Tests for webscan.py -- the live-website reviewer. Offline: HTML strings, no net."""
import ipaddress
import unittest
import urllib.request
from unittest import mock

import webscan

PAGE = '''<!doctype html>
<html><head><title>Acme Corp</title>
<link rel="stylesheet" href="http://cdn.acme.com/app.css">
<script src="https://cdn.acme.com/vendor.js"></script>
</head>
<body onload="init()">
<button onclick="buy()">Buy</button>
<form></form>
<script>
function login(u){
  if (u == null) return;
  document.getElementById("out").innerHTML = u.name;
  var token = eval(localStorage.getItem("t"));
  setTimeout("refresh()", 1000);
}
</script>
</body></html>'''


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.p = webscan.PageParser()
        self.p.feed(PAGE)

    def test_structure(self):
        self.assertEqual(self.p.title, "Acme Corp")
        self.assertEqual(len(self.p.inline_scripts), 1)
        self.assertEqual(self.p.script_srcs, ["https://cdn.acme.com/vendor.js"])
        self.assertEqual(self.p.stylesheets, ["http://cdn.acme.com/app.css"])
        self.assertEqual(self.p.forms, 1)

    def test_inline_handlers_captured(self):
        names = {name for _tag, name, _val in self.p.inline_handlers}
        self.assertEqual(names, {"onload", "onclick"})


class AnalyzeTests(unittest.TestCase):
    def setUp(self):
        self.report = webscan.analyze(PAGE, "https://acme.example", [])

    def test_finds_the_js_bugs(self):
        rules = {f.rule for f in self.report["findings"]}
        self.assertIn("js-innerhtml", rules)
        self.assertIn("dangerous-eval", rules)
        self.assertIn("js-settimeout-string", rules)
        self.assertIn("js-loose-equality", rules)

    def test_markup_smells(self):
        smells = {rule for rule, _n, _why in self.report["smells"]}
        self.assertIn("inline-event-handler", smells)   # onload + onclick
        self.assertIn("mixed-content", smells)          # http:// stylesheet

    def test_render_is_honest_about_scope(self):
        text = webscan.render(self.report)
        self.assertIn("PUBLIC front-end", text)
        self.assertIn("Server code is not", text)

    def test_explain_describes_the_page(self):
        text = webscan.explain(self.report)
        self.assertIn("Acme Corp", text)
        self.assertIn("cdn.acme.com", text)

    def test_clean_page_has_no_findings(self):
        clean = ("<html><head><title>ok</title></head><body>"
                 "<script>const x = 1; console.log(x);</script></body></html>")
        report = webscan.analyze(clean, "https://ok.example", [])
        self.assertEqual(report["findings"], [])


class CorrectTests(unittest.TestCase):
    def test_correct_uses_the_brain_and_reverifies(self):
        class FakeBrain:
            def available(self):
                return True

            def generate(self, _prompt):
                # a corrected script with none of the bugs
                return ("function login(u){\n  if (u === null) return;\n"
                        "  document.getElementById('out').textContent = u.name;\n}\n")

        report = webscan.analyze(PAGE, "https://acme.example", [])
        out = webscan.correct(report, FakeBrain())
        self.assertIn("-> 0 under the enabled JavaScript checks", out)
        self.assertIn("browser behavior remains unproven", out)
        self.assertIn("textContent", out)


class URLSecurityTests(unittest.TestCase):
    def test_plaintext_http_requires_explicit_opt_in(self):
        public = {ipaddress.ip_address("8.8.8.8")}
        with mock.patch("webscan._addresses", return_value=public):
            with self.assertRaises(webscan.UnsafeURL):
                webscan.validate_url("http://example.com/")
            self.assertEqual(
                webscan.validate_url("http://example.com/", allow_http=True),
                "http://example.com/")

    def test_non_http_and_credentialed_urls_are_blocked(self):
        for url in ("file:///etc/passwd", "gopher://8.8.8.8/x",
                    "https://user:pass@8.8.8.8/"):
            with self.subTest(url=url), self.assertRaises(webscan.UnsafeURL):
                webscan.validate_url(url)

    def test_loopback_private_link_local_and_ipv6_are_blocked(self):
        for url in ("http://127.0.0.1/", "http://10.2.3.4/",
                    "http://169.254.169.254/latest/meta-data/",
                    "http://[::1]/", "http://[fe80::1]/"):
            with self.subTest(url=url), self.assertRaises(webscan.UnsafeURL):
                webscan.validate_url(url)

    def test_every_dns_answer_must_be_public(self):
        answers = [
            (2, 1, 6, "", ("93.184.216.34", 443)),
            (2, 1, 6, "", ("127.0.0.1", 443)),
        ]
        with mock.patch("webscan.socket.getaddrinfo", return_value=answers):
            with self.assertRaises(webscan.UnsafeURL):
                webscan.validate_url("https://mixed.example/")

    def test_redirect_to_private_address_is_blocked(self):
        handler = webscan.SafeRedirectHandler()
        request = urllib.request.Request("https://8.8.8.8/")
        with self.assertRaises(webscan.UnsafeURL):
            handler.redirect_request(
                request, None, 302, "Found", {}, "http://127.0.0.1/admin")

    def test_connection_is_pinned_to_the_validated_public_ip(self):
        public = webscan.ipaddress.ip_address("93.184.216.34")
        fake_socket = mock.Mock()
        with mock.patch("webscan._addresses", return_value={public}), \
                mock.patch("webscan.socket.create_connection",
                           return_value=fake_socket) as connect:
            connection = webscan.PinnedHTTPConnection("public.example", 80, timeout=3)
            connection.connect()
        connect.assert_called_once_with(
            ("93.184.216.34", 80), 3, source_address=None)
        self.assertIs(connection.sock, fake_socket)

    def test_fetch_enforces_response_size(self):
        class Headers:
            @staticmethod
            def get_content_charset():
                return "utf-8"

        class Response:
            headers = Headers()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            @staticmethod
            def geturl():
                return "https://8.8.8.8/"

            @staticmethod
            def read(_amount):
                return b"x" * 2048

        opener = mock.Mock()
        opener.open.return_value = Response()
        with mock.patch("webscan.urllib.request.build_opener", return_value=opener):
            with self.assertRaises(webscan.ResponseTooLarge):
                webscan.fetch("https://8.8.8.8/", max_bytes=1024)


if __name__ == "__main__":
    unittest.main(verbosity=2)
