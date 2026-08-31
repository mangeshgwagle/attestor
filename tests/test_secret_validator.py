"""Tests for the live secret validator (no real API calls -- uses mocks)."""
import json
import time
import base64
from unittest.mock import patch
from dataclasses import dataclass

import secret_validator


@dataclass
class FakeSecretFinding:
    rule_id: str
    matched_text: str
    path: str = "test.py"
    line: int = 1
    description: str = ""
    severity: str = "HIGH"
    redacted: str = ""


def test_github_token_live():
    with patch("secret_validator._http_get") as mock:
        mock.return_value = (200, json.dumps({"login": "testuser"}))
        f = FakeSecretFinding(rule_id="SEC-GH-PAT", matched_text="ghp_abcdef1234567890abcdef1234567890abcd")
        r = secret_validator.validate_finding(f)
        assert r.status == "live"
        assert r.service == "GitHub"
        assert "testuser" in r.identity


def test_github_token_dead():
    with patch("secret_validator._http_get") as mock:
        mock.return_value = (401, "Bad credentials")
        f = FakeSecretFinding(rule_id="SEC-GH-PAT", matched_text="ghp_revoked_token_here_0000000000000000")
        r = secret_validator.validate_finding(f)
        assert r.status == "dead"


def test_slack_token_live():
    with patch("secret_validator._http_post_form") as mock:
        mock.return_value = (200, json.dumps({"ok": True, "team": "myteam", "user": "bot"}))
        f = FakeSecretFinding(rule_id="SEC-SLACK-TOKEN", matched_text="xoxb-123456789012-abcdefghij")
        r = secret_validator.validate_finding(f)
        assert r.status == "live"
        assert r.service == "Slack"


def test_slack_token_dead():
    with patch("secret_validator._http_post_form") as mock:
        mock.return_value = (200, json.dumps({"ok": False, "error": "invalid_auth"}))
        f = FakeSecretFinding(rule_id="SEC-SLACK-TOKEN", matched_text="xoxb-invalidtoken000-000000000000")
        r = secret_validator.validate_finding(f)
        assert r.status == "dead"


def test_stripe_live():
    with patch("secret_validator._http_get") as mock:
        mock.return_value = (200, json.dumps({"available": [{"amount": 0}]}))
        f = FakeSecretFinding(rule_id="SEC-STRIPE-SK", matched_text="sk_test_00000000000000000000000000")
        r = secret_validator.validate_finding(f)
        assert r.status == "live"
        assert r.service == "Stripe"


def test_jwt_expired():
    payload = {"sub": "user123", "exp": int(time.time()) - 3600}
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    token = f"{header}.{body}.fakesig1234567890"
    f = FakeSecretFinding(rule_id="SEC-JWT", matched_text=token)
    r = secret_validator.validate_finding(f)
    assert r.status == "expired"


def test_jwt_live():
    payload = {"sub": "user123", "exp": int(time.time()) + 3600}
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).decode().rstrip("=")
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    token = f"{header}.{body}.fakesig1234567890"
    f = FakeSecretFinding(rule_id="SEC-JWT", matched_text=token)
    r = secret_validator.validate_finding(f)
    assert r.status == "live"


def test_unknown_rule_skipped():
    f = FakeSecretFinding(rule_id="SEC-UNKNOWN-X", matched_text="some_secret_value_here")
    r = secret_validator.validate_finding(f)
    assert r.status == "skipped"


def test_dry_run():
    findings = [
        FakeSecretFinding(rule_id="SEC-GH-PAT", matched_text="ghp_test1234567890test1234567890test12"),
        FakeSecretFinding(rule_id="SEC-UNKNOWN-X", matched_text="unknown_secret"),
    ]
    results = secret_validator.validate_findings(findings, dry_run=True)
    assert len(results) == 2
    assert results[0].status == "would_validate"
    assert results[1].status == "no_validator"


def test_render_output():
    results = [
        secret_validator.ValidationResult(
            rule_id="SEC-GH-PAT", secret_redacted="ghp_****abcd",
            status="live", service="GitHub", detail="active token",
            identity="testuser", severity_override="CRITICAL"),
        secret_validator.ValidationResult(
            rule_id="SEC-SLACK-TOKEN", secret_redacted="xoxb****1234",
            status="dead", service="Slack", detail="revoked"),
    ]
    text = secret_validator.render(results)
    assert "LIVE" in text and "DEAD" in text
    assert "1 live" in text and "1 dead" in text


def test_to_dict():
    results = [
        secret_validator.ValidationResult(
            rule_id="SEC-GH-PAT", secret_redacted="ghp_****",
            status="live", service="GitHub", detail="active",
            identity="user", severity_override="CRITICAL"),
    ]
    dicts = secret_validator.to_dict(results)
    assert len(dicts) == 1
    assert dicts[0]["status"] == "live"
    assert dicts[0]["service"] == "GitHub"


def test_redact():
    assert secret_validator._redact("short") == "***"
    long_key = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
    redacted = secret_validator._redact(long_key)
    assert redacted.startswith("ghp_")
    assert redacted.endswith("7890")
    assert "*" in redacted


def test_dict_input():
    f = {"rule_id": "SEC-GH-PAT", "matched_text": "ghp_test1234567890test1234567890test12"}
    with patch("secret_validator._http_get") as mock:
        mock.return_value = (401, "")
        r = secret_validator.validate_finding(f)
        assert r.status == "dead"
