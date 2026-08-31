#!/usr/bin/env python3
"""Live secret validation -- safely check if detected secrets are active.

For each secret found by secret_scanner, attempt a READ-ONLY validation call
to determine if the credential is live (active and grants access) or dead
(revoked, expired, or invalid). A dead key is noise; a live key is critical.

Validation is strictly read-only:
- AWS: sts get-caller-identity (no side effects)
- GitHub: GET /user (token introspection)
- GitLab: GET /api/v4/user
- Slack: auth.test
- Stripe: GET /v1/balance (read-only)
- SendGrid: GET /v3/api_keys (list only)
- Twilio: GET /2010-04-01/Accounts
- NPM: whoami
- Google: tokeninfo endpoint
- Generic: check format validity only (no network call)

Never writes, deletes, creates, or modifies anything. Every call is the
equivalent of "who am I?" for that service.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


@dataclass
class ValidationResult:
    rule_id: str
    secret_redacted: str
    status: str          # "live", "dead", "expired", "invalid_format", "error", "skipped"
    service: str
    detail: str
    identity: str = ""   # who/what the credential belongs to (redacted)
    severity_override: str = ""


_TIMEOUT = 10


def _http_get(url: str, headers: dict | None = None) -> tuple[int, str]:
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")[:4096]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")[:1024] if e.fp else ""
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return 0, str(e)


def _http_post_form(url: str, data: dict, headers: dict | None = None) -> tuple[int, str]:
    encoded = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(url, data=encoded, method="POST",
                                headers={"Content-Type": "application/x-www-form-urlencoded",
                                         **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")[:4096]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")[:1024] if e.fp else ""
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return 0, str(e)


import urllib.parse  # noqa: E402 (needed by _http_post_form)


def _validate_aws_key(key_id: str, secret: str = "") -> ValidationResult:
    if not secret:
        return ValidationResult(
            rule_id="SEC-AWS-KEY", secret_redacted=_redact(key_id),
            status="skipped", service="AWS",
            detail="access key ID found but no secret key nearby -- cannot validate")
    try:
        import subprocess
        env = os.environ.copy()
        env["AWS_ACCESS_KEY_ID"] = key_id
        env["AWS_SECRET_ACCESS_KEY"] = secret
        env.pop("AWS_SESSION_TOKEN", None)
        env.pop("AWS_PROFILE", None)
        r = subprocess.run(
            ["aws", "sts", "get-caller-identity", "--output", "json"],
            capture_output=True, text=True, timeout=15, env=env)
        if r.returncode == 0:
            data = json.loads(r.stdout)
            arn = data.get("Arn", "")
            return ValidationResult(
                rule_id="SEC-AWS-KEY", secret_redacted=_redact(key_id),
                status="live", service="AWS",
                detail=f"active AWS credential (account {data.get('Account', '?')})",
                identity=_redact_arn(arn), severity_override="CRITICAL")
        if "ExpiredToken" in r.stderr or "expired" in r.stderr.lower():
            return ValidationResult(
                rule_id="SEC-AWS-KEY", secret_redacted=_redact(key_id),
                status="expired", service="AWS", detail="AWS token expired")
        return ValidationResult(
            rule_id="SEC-AWS-KEY", secret_redacted=_redact(key_id),
            status="dead", service="AWS", detail="invalid AWS credentials")
    except FileNotFoundError:
        return ValidationResult(
            rule_id="SEC-AWS-KEY", secret_redacted=_redact(key_id),
            status="skipped", service="AWS", detail="aws CLI not installed")
    except Exception as e:
        return ValidationResult(
            rule_id="SEC-AWS-KEY", secret_redacted=_redact(key_id),
            status="error", service="AWS", detail=str(e)[:200])


def _validate_github_token(token: str) -> ValidationResult:
    code, body = _http_get("https://api.github.com/user",
                           {"Authorization": f"token {token}",
                            "User-Agent": "attestor-secret-validator"})
    if code == 200:
        data = json.loads(body)
        login = data.get("login", "?")
        return ValidationResult(
            rule_id="SEC-GH-PAT", secret_redacted=_redact(token),
            status="live", service="GitHub",
            detail=f"active GitHub token (user: {login})",
            identity=login, severity_override="CRITICAL")
    if code == 401:
        return ValidationResult(
            rule_id="SEC-GH-PAT", secret_redacted=_redact(token),
            status="dead", service="GitHub", detail="token revoked or invalid")
    return ValidationResult(
        rule_id="SEC-GH-PAT", secret_redacted=_redact(token),
        status="error", service="GitHub", detail=f"HTTP {code}")


def _validate_gitlab_token(token: str) -> ValidationResult:
    code, body = _http_get("https://gitlab.com/api/v4/user",
                           {"PRIVATE-TOKEN": token})
    if code == 200:
        data = json.loads(body)
        return ValidationResult(
            rule_id="SEC-GL-PAT", secret_redacted=_redact(token),
            status="live", service="GitLab",
            detail=f"active GitLab token (user: {data.get('username', '?')})",
            identity=data.get("username", ""), severity_override="CRITICAL")
    if code == 401:
        return ValidationResult(
            rule_id="SEC-GL-PAT", secret_redacted=_redact(token),
            status="dead", service="GitLab", detail="token revoked or invalid")
    return ValidationResult(
        rule_id="SEC-GL-PAT", secret_redacted=_redact(token),
        status="error", service="GitLab", detail=f"HTTP {code}")


def _validate_slack_token(token: str) -> ValidationResult:
    code, body = _http_post_form("https://slack.com/api/auth.test",
                                 {"token": token})
    if code == 200:
        data = json.loads(body)
        if data.get("ok"):
            return ValidationResult(
                rule_id="SEC-SLACK-TOKEN", secret_redacted=_redact(token),
                status="live", service="Slack",
                detail=f"active Slack token (team: {data.get('team', '?')})",
                identity=data.get("user", ""), severity_override="CRITICAL")
        return ValidationResult(
            rule_id="SEC-SLACK-TOKEN", secret_redacted=_redact(token),
            status="dead", service="Slack",
            detail=f"invalid: {data.get('error', 'unknown')}")
    return ValidationResult(
        rule_id="SEC-SLACK-TOKEN", secret_redacted=_redact(token),
        status="error", service="Slack", detail=f"HTTP {code}")


def _validate_stripe_key(key: str) -> ValidationResult:
    code, body = _http_get("https://api.stripe.com/v1/balance",
                           {"Authorization": f"Bearer {key}"})
    if code == 200:
        return ValidationResult(
            rule_id="SEC-STRIPE-SK", secret_redacted=_redact(key),
            status="live", service="Stripe",
            detail="active Stripe secret key (read balance OK)",
            severity_override="CRITICAL")
    if code == 401:
        return ValidationResult(
            rule_id="SEC-STRIPE-SK", secret_redacted=_redact(key),
            status="dead", service="Stripe", detail="key revoked or invalid")
    return ValidationResult(
        rule_id="SEC-STRIPE-SK", secret_redacted=_redact(key),
        status="error", service="Stripe", detail=f"HTTP {code}")


def _validate_sendgrid_key(key: str) -> ValidationResult:
    code, body = _http_get("https://api.sendgrid.com/v3/api_keys",
                           {"Authorization": f"Bearer {key}"})
    if code == 200:
        return ValidationResult(
            rule_id="SEC-SENDGRID", secret_redacted=_redact(key),
            status="live", service="SendGrid",
            detail="active SendGrid key", severity_override="CRITICAL")
    if code in (401, 403):
        return ValidationResult(
            rule_id="SEC-SENDGRID", secret_redacted=_redact(key),
            status="dead", service="SendGrid", detail="key revoked or invalid")
    return ValidationResult(
        rule_id="SEC-SENDGRID", secret_redacted=_redact(key),
        status="error", service="SendGrid", detail=f"HTTP {code}")


def _validate_npm_token(token: str) -> ValidationResult:
    code, body = _http_get("https://registry.npmjs.org/-/whoami",
                           {"Authorization": f"Bearer {token}"})
    if code == 200:
        data = json.loads(body)
        return ValidationResult(
            rule_id="SEC-NPM", secret_redacted=_redact(token),
            status="live", service="npm",
            detail=f"active npm token (user: {data.get('username', '?')})",
            identity=data.get("username", ""), severity_override="CRITICAL")
    if code in (401, 403):
        return ValidationResult(
            rule_id="SEC-NPM", secret_redacted=_redact(token),
            status="dead", service="npm", detail="token revoked or invalid")
    return ValidationResult(
        rule_id="SEC-NPM", secret_redacted=_redact(token),
        status="error", service="npm", detail=f"HTTP {code}")


def _validate_pypi_token(token: str) -> ValidationResult:
    if not token.startswith("pypi-"):
        return ValidationResult(
            rule_id="SEC-PYPI", secret_redacted=_redact(token),
            status="invalid_format", service="PyPI", detail="not a valid PyPI token format")
    return ValidationResult(
        rule_id="SEC-PYPI", secret_redacted=_redact(token),
        status="skipped", service="PyPI",
        detail="PyPI tokens cannot be validated without upload attempt (read-only policy)")


def _validate_jwt(token: str) -> ValidationResult:
    import base64
    parts = token.split(".")
    if len(parts) != 3:
        return ValidationResult(
            rule_id="SEC-JWT", secret_redacted=_redact(token),
            status="invalid_format", service="JWT", detail="not a valid JWT structure")
    try:
        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        exp = data.get("exp")
        if exp:
            import time
            if exp < time.time():
                return ValidationResult(
                    rule_id="SEC-JWT", secret_redacted=_redact(token),
                    status="expired", service="JWT",
                    detail=f"JWT expired (exp={exp})")
            return ValidationResult(
                rule_id="SEC-JWT", secret_redacted=_redact(token),
                status="live", service="JWT",
                detail="JWT not yet expired (may still be valid)",
                identity=data.get("sub", ""), severity_override="HIGH")
        return ValidationResult(
            rule_id="SEC-JWT", secret_redacted=_redact(token),
            status="live", service="JWT",
            detail="JWT has no expiry (potentially long-lived)",
            severity_override="HIGH")
    except Exception:
        return ValidationResult(
            rule_id="SEC-JWT", secret_redacted=_redact(token),
            status="invalid_format", service="JWT", detail="failed to decode JWT payload")


_VALIDATOR_MAP = {
    "SEC-AWS-KEY": lambda t, **kw: _validate_aws_key(t, kw.get("aws_secret", "")),
    "SEC-GH-PAT": lambda t, **kw: _validate_github_token(t),
    "SEC-GH-OAUTH": lambda t, **kw: _validate_github_token(t),
    "SEC-GH-FINE": lambda t, **kw: _validate_github_token(t),
    "SEC-GL-PAT": lambda t, **kw: _validate_gitlab_token(t),
    "SEC-SLACK-TOKEN": lambda t, **kw: _validate_slack_token(t),
    "SEC-STRIPE-SK": lambda t, **kw: _validate_stripe_key(t),
    "SEC-STRIPE-RK": lambda t, **kw: _validate_stripe_key(t),
    "SEC-SENDGRID": lambda t, **kw: _validate_sendgrid_key(t),
    "SEC-NPM": lambda t, **kw: _validate_npm_token(t),
    "SEC-PYPI": lambda t, **kw: _validate_pypi_token(t),
    "SEC-JWT": lambda t, **kw: _validate_jwt(t),
}


def _redact(s: str) -> str:
    if len(s) <= 8:
        return "***"
    return s[:4] + "*" * min(len(s) - 8, 20) + s[-4:]


def _redact_arn(arn: str) -> str:
    parts = arn.split(":")
    if len(parts) >= 5:
        parts[4] = "****"
    return ":".join(parts)


def validate_finding(finding, **kwargs) -> ValidationResult:
    """Validate a single SecretFinding from secret_scanner."""
    rule_id = finding.rule_id if hasattr(finding, "rule_id") else finding.get("rule_id", "")
    matched = finding.matched_text if hasattr(finding, "matched_text") else finding.get("matched_text", "")
    validator = _VALIDATOR_MAP.get(rule_id)
    if not validator:
        return ValidationResult(
            rule_id=rule_id, secret_redacted=_redact(matched),
            status="skipped", service=_service_from_rule(rule_id),
            detail=f"no validator for {rule_id}")
    return validator(matched, **kwargs)


def validate_findings(findings, dry_run: bool = False, **kwargs) -> list[ValidationResult]:
    results = []
    for f in findings:
        if dry_run:
            rule_id = f.rule_id if hasattr(f, "rule_id") else f.get("rule_id", "")
            matched = f.matched_text if hasattr(f, "matched_text") else f.get("matched_text", "")
            has_validator = rule_id in _VALIDATOR_MAP
            results.append(ValidationResult(
                rule_id=rule_id, secret_redacted=_redact(matched),
                status="would_validate" if has_validator else "no_validator",
                service=_service_from_rule(rule_id),
                detail=f"dry run: {'validator available' if has_validator else 'no validator'}"))
        else:
            results.append(validate_finding(f, **kwargs))
    return results


def _service_from_rule(rule_id: str) -> str:
    parts = rule_id.split("-")
    return parts[1] if len(parts) >= 2 else "unknown"


def render(results: list[ValidationResult]) -> str:
    if not results:
        return "  No secrets to validate."
    lines = [
        f"\n  Secret Validation -- {len(results)} secret(s) checked",
        "  " + "=" * 62,
    ]
    live = [r for r in results if r.status == "live"]
    dead = [r for r in results if r.status == "dead"]
    expired = [r for r in results if r.status == "expired"]
    skipped = [r for r in results if r.status in ("skipped", "error", "no_validator")]

    if live:
        lines.append(f"\n  LIVE ({len(live)}):")
        for r in live:
            lines.append(f"    [{r.severity_override or 'CRITICAL'}] {r.service}: {r.detail}")
            lines.append(f"      secret: {r.secret_redacted}")
            if r.identity:
                lines.append(f"      identity: {r.identity}")

    if dead:
        lines.append(f"\n  DEAD ({len(dead)}):")
        for r in dead:
            lines.append(f"    [INFO] {r.service}: {r.detail}")
            lines.append(f"      secret: {r.secret_redacted}")

    if expired:
        lines.append(f"\n  EXPIRED ({len(expired)}):")
        for r in expired:
            lines.append(f"    [LOW] {r.service}: {r.detail}")

    if skipped:
        lines.append(f"\n  SKIPPED ({len(skipped)}):")
        for r in skipped:
            lines.append(f"    {r.service}: {r.detail}")

    lines.append(f"\n  Summary: {len(live)} live, {len(dead)} dead, "
                 f"{len(expired)} expired, {len(skipped)} skipped")
    return "\n".join(lines)


def to_dict(results: list[ValidationResult]) -> list[dict]:
    return [
        {
            "rule_id": r.rule_id,
            "secret_redacted": r.secret_redacted,
            "status": r.status,
            "service": r.service,
            "detail": r.detail,
            "identity": r.identity,
            "severity_override": r.severity_override,
        }
        for r in results
    ]
