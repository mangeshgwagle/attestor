#!/usr/bin/env python3
"""Enterprise hardening: tenant isolation, two-party approval, admin controls.

Composes around trusted_access.decide without touching its ordered gate:
  authenticate -> time -> revocation -> identity -> least privilege
Additions are wrappers that call it, never a replacement.
"""
from __future__ import annotations
import datetime as _dt
import re
from typing import Any, Iterable, Mapping, Sequence
import trusted_access as ta

VERSION = "4.2"
APPROVAL_SCHEMA = "attestor.enterprise-approval/4.2"
APPROVAL_REQUIRED_SCOPES = frozenset({"repo:write", "tenant:write", "admin:delete", "scan:publish"})
TENANT_RE = re.compile(r"tenant/([A-Za-z0-9_.-]{1,64})/.*")
ID_RE = ta.ID_PATTERN

class EnterpriseError(ValueError):
    pass

def _tenant(resource: str) -> str | None:
    m = TENANT_RE.fullmatch(resource) if resource.startswith("tenant/") else None
    if m:
        return m.group(1)
    if resource.startswith("tenant/"):
        raise EnterpriseError("tenant resource must be tenant/{id}/...")
    return None

def tenant_resource(tenant_id: str, suffix: str) -> str:
    if not ID_RE.fullmatch(tenant_id):
        raise EnterpriseError("tenant_id invalid")
    if not suffix or suffix.startswith("/"):
        raise EnterpriseError("suffix must be non-empty and not start with /")
    return f"tenant/{tenant_id}/{suffix}"

def issue_tenant_grant(*, tenant_id: str, subject_id: str, subject_key_fingerprint: str, suffix: str, scopes: Iterable[str], authority_key: bytes, authority_key_id: str, ttl_seconds: int = 3600, now: _dt.datetime | None = None, note: str = "") -> dict[str, Any]:
    resource = tenant_resource(tenant_id, suffix)
    return ta.issue_grant(subject_id=subject_id, subject_key_fingerprint=subject_key_fingerprint, resource=resource, scopes=scopes, authority_key=authority_key, authority_key_id=authority_key_id, ttl_seconds=ttl_seconds, now=now, note=note)

def _approval_body(*, grant_id: str, tenant_id: str | None, resource: str, scopes: Sequence[str], approver_id: str, approver_fingerprint: str, ttl_seconds: int, now: _dt.datetime) -> dict[str, Any]:
    if not re.fullmatch(r"[0-9a-f]{32}", grant_id):
        raise EnterpriseError("grant_id malformed")
    return {
        "schema": APPROVAL_SCHEMA,
        "version": VERSION,
        "grant_id": grant_id,
        "tenant_id": tenant_id or "",
        "resource": ta._resource(resource),
        "scopes": list(ta._scopes(list(scopes))),
        "approver": {"id": ta._id(approver_id, "approver id"), "key_fingerprint": approver_fingerprint},
        "issued_at": ta._iso(now),
        "expires_at": ta._iso(now + _dt.timedelta(seconds=ttl_seconds)),
    }

def issue_approval(*, grant: Mapping[str, Any], approver_id: str, approver_key: bytes, approver_key_id: str, approver_fingerprint: str, authority_key: bytes, authority_key_id: str, ttl_seconds: int = 3600, now: _dt.datetime | None = None) -> dict[str, Any]:
    if grant.get("schema") != ta.GRANT_SCHEMA:
        raise EnterpriseError("approval needs a trusted-access grant")
    now = now or ta._utc_now()
    grant_id = str(grant.get("grant_id"))
    resource = str(grant.get("resource"))
    scopes = list(grant.get("scopes") or [])
    tenant_id = None
    try:
        tenant_id = _tenant(resource)
    except EnterpriseError:
        tenant_id = None
    body = _approval_body(grant_id=grant_id, tenant_id=tenant_id, resource=resource, scopes=scopes, approver_id=approver_id, approver_fingerprint=approver_fingerprint, ttl_seconds=ttl_seconds, now=now)
    return ta._sign(body, authority_key, authority_key_id)

def verify_approval(approval: Mapping[str, Any], grant: Mapping[str, Any], trusted_keys: Mapping[str, bytes], now: _dt.datetime | None = None) -> bool:
    now = now or ta._utc_now()
    try:
        ta._signature_ok(approval, trusted_keys)
        if approval.get("schema") != APPROVAL_SCHEMA:
            return False
        if approval.get("grant_id") != str(grant.get("grant_id")):
            return False
        if approval.get("resource") != str(grant.get("resource")):
            return False
        if set(approval.get("scopes") or []) != set(grant.get("scopes") or []):
            return False
        exp = ta._parse_time(approval.get("expires_at"), "expires_at")
        iss = ta._parse_time(approval.get("issued_at"), "issued_at")
        if exp <= now or iss > now + ta.FUTURE_SKEW:
            return False
        if _tenant(str(grant.get("resource"))) != (approval.get("tenant_id") or _tenant(str(grant.get("resource")))):
            return False
        return True
    except Exception:
        return False

def needs_approval(scopes: Iterable[str]) -> bool:
    return bool(set(scopes) & APPROVAL_REQUIRED_SCOPES)

def decide_with_isolation_and_approval(*, grant: Any, approval: Mapping[str, Any] | None, resource: str, scope: str, challenge: Mapping[str, Any], subject_proof: str, authority_keys: Mapping[str, bytes], subject_keys: Mapping[str, bytes], revocations: Mapping[str, Any] | None = None, now: _dt.datetime | None = None) -> ta.AccessDecision:
    req_tenant = None
    grant_resource = ""
    try:
        grant_resource = str(grant.get("resource")) if isinstance(grant, Mapping) else ""
        req_tenant = _tenant(resource)
        grant_tenant = _tenant(grant_resource) if grant_resource else None
        if req_tenant is not None or grant_tenant is not None:
            if req_tenant != grant_tenant:
                return ta.AccessDecision(False, "tenant isolation: grant tenant does not match request tenant", decided_at=ta._iso(now or ta._utc_now()), resource=resource, scope=scope)
    except EnterpriseError as e:
        return ta.AccessDecision(False, f"tenant isolation: {e}", decided_at=ta._iso(now or ta._utc_now()), resource=resource, scope=scope)
    base = ta.decide(grant=grant, resource=resource, scope=scope, challenge=challenge, subject_proof=subject_proof, authority_keys=authority_keys, subject_keys=subject_keys, revocations=revocations, now=now)
    if not base.allowed:
        return base
    if needs_approval([scope]):
        if approval is None:
            return ta.AccessDecision(False, "dual approval required for sensitive scope", decided_at=ta._iso(now or ta._utc_now()), subject_id=base.subject_id, resource=resource, scope=scope, grant_id=base.grant_id, authority_key_id=base.authority_key_id)
        if not verify_approval(approval, grant, authority_keys, now):
            return ta.AccessDecision(False, "approval verification failed", decided_at=ta._iso(now or ta._utc_now()), subject_id=base.subject_id, resource=resource, scope=scope, grant_id=base.grant_id, authority_key_id=base.authority_key_id)
    return base

def enumerate_grants(grants: Sequence[Mapping[str, Any]], *, subject_id: str | None = None, tenant_id: str | None = None, scope: str | None = None) -> list[dict[str, Any]]:
    out = []
    for g in grants:
        if subject_id is not None and str(g.get("subject", {}).get("id")) != subject_id:
            continue
        if tenant_id is not None and _tenant(str(g.get("resource",""))) != tenant_id:
            continue
        if scope is not None and scope not in list(g.get("scopes", [])):
            continue
        out.append(dict(g))
    return out

def bulk_revoke(*, grant_ids: Iterable[str], authority_key: bytes, authority_key_id: str, ttl_seconds: int = 24*3600, now: _dt.datetime | None = None) -> dict[str, Any]:
    return ta.issue_revocation_list(revoked_grant_ids=grant_ids, authority_key=authority_key, authority_key_id=authority_key_id, ttl_seconds=ttl_seconds, now=now)

def expiry_report(grants: Sequence[Mapping[str, Any]], now: _dt.datetime | None = None, warning_seconds: int = 3600) -> dict[str, Any]:
    now = now or ta._utc_now()
    expiring, expired, active = [], [], []
    for g in grants:
        try:
            exp = ta._parse_time(g.get("expires_at"), "expires_at")
            gid = str(g.get("grant_id"))
            if exp <= now:
                expired.append(gid)
            elif exp <= now + _dt.timedelta(seconds=warning_seconds):
                expiring.append(gid)
            else:
                active.append(gid)
        except Exception:
            expired.append(str(g.get("grant_id","unknown")))
    return {"now": ta._iso(now), "warning_seconds": warning_seconds, "expiring_soon": sorted(expiring), "expired": sorted(expired), "active": sorted(active), "total": len(grants)}
