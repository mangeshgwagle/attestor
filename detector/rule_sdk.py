#!/usr/bin/env python3
"""Safe, test-first rule SDK for Attestor 3.0.

Rule packs are declarative JSON. They cannot import Python, execute commands, or
use unbounded regular expressions. Every rule must prove positive and negative
fixtures before a pack can be loaded. Packs can be authenticated with a
detached HMAC-SHA256 signature when an operator supplies a private key.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA = "attestor-rule-pack/3.0"
MAX_PACK_BYTES = 8 * 1024 * 1024
MAX_RULES = 20_000
MAX_FIXTURES_PER_RULE = 64
MAX_FIXTURE_CHARS = 128_000
MAX_TOKEN_CHARS = 256
MAX_LINE_CHARS = 64 * 1024
RULE_ID = re.compile(r"^attestor3-[a-z0-9][a-z0-9-]{2,95}$")
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}


class RulePackError(ValueError):
    """A pack failed a closed validation boundary."""


def _strings(value: Any, field: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (not value and not allow_empty):
        raise RulePackError("%s must be a%s non-empty list" % (
            field, " possibly" if allow_empty else ""))
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item or len(item) > MAX_TOKEN_CHARS:
            raise RulePackError("%s contains an invalid token" % field)
        if any(ord(char) < 32 and char not in "\t" for char in item):
            raise RulePackError("%s contains a control character" % field)
        out.append(item)
    return tuple(out)


def _expected_lines(value: Any) -> tuple[int, ...]:
    if not isinstance(value, list) or any(
            not isinstance(item, int) or isinstance(item, bool) or item < 1
            for item in value):
        raise RulePackError("fixture expected_lines must contain positive integers")
    return tuple(sorted(set(value)))


@dataclass(frozen=True)
class Fixture:
    path: str
    source: str
    expected_lines: tuple[int, ...]

    @classmethod
    def parse(cls, value: Any, *, negative: bool) -> "Fixture":
        if not isinstance(value, dict):
            raise RulePackError("fixtures must be JSON objects")
        path = value.get("path", "fixture.txt")
        source = value.get("source")
        if not isinstance(path, str) or not path or len(path) > 512:
            raise RulePackError("fixture path is invalid")
        if not isinstance(source, str) or len(source) > MAX_FIXTURE_CHARS:
            raise RulePackError("fixture source is invalid or too large")
        expected = _expected_lines(value.get("expected_lines", []))
        if negative and expected:
            raise RulePackError("negative fixtures may not expect findings")
        if not negative and not expected:
            raise RulePackError("positive fixtures must expect at least one line")
        return cls(path, source, expected)


@dataclass(frozen=True)
class RuleSpec:
    id: str
    version: str
    title: str
    language: str
    extensions: tuple[str, ...]
    severity: str
    confidence: float
    category: str
    cwe: str
    description: str
    remediation: str
    match_all: tuple[str, ...]
    match_any: tuple[str, ...]
    exclude_any: tuple[str, ...]
    case_sensitive: bool
    positive: tuple[Fixture, ...]
    negative: tuple[Fixture, ...]

    @classmethod
    def parse(cls, value: Any) -> "RuleSpec":
        if not isinstance(value, dict):
            raise RulePackError("each rule must be a JSON object")
        rule_id = value.get("id")
        if not isinstance(rule_id, str) or not RULE_ID.fullmatch(rule_id):
            raise RulePackError("rule id must match %s" % RULE_ID.pattern)
        required_text = {}
        for field in ("version", "title", "language", "category", "description", "remediation"):
            item = value.get(field)
            if not isinstance(item, str) or not item.strip() or len(item) > 2_000:
                raise RulePackError("%s.%s is invalid" % (rule_id, field))
            required_text[field] = item.strip()
        cwe = value.get("cwe", "")
        if cwe and (not isinstance(cwe, str) or not re.fullmatch(r"CWE-\d{1,5}", cwe)):
            raise RulePackError("%s.cwe must be empty or a CWE identifier" % rule_id)
        severity = value.get("severity")
        if severity not in SEVERITIES:
            raise RulePackError("%s.severity is invalid" % rule_id)
        confidence = value.get("confidence")
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) \
                or not 0 <= float(confidence) <= 1:
            raise RulePackError("%s.confidence must be between 0 and 1" % rule_id)
        extensions = _strings(value.get("extensions"), rule_id + ".extensions")
        if any(not (item.startswith(".") or re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]{0,63}", item))
               for item in extensions):
            raise RulePackError("%s.extensions contains an unsafe filename selector" % rule_id)
        match_all = _strings(value.get("match_all", []), rule_id + ".match_all", allow_empty=True)
        match_any = _strings(value.get("match_any", []), rule_id + ".match_any", allow_empty=True)
        exclude_any = _strings(value.get("exclude_any", []), rule_id + ".exclude_any", allow_empty=True)
        if not match_all and not match_any:
            raise RulePackError("%s needs match_all or match_any tokens" % rule_id)
        positives = value.get("positive_fixtures")
        negatives = value.get("negative_fixtures")
        if not isinstance(positives, list) or not positives or len(positives) > MAX_FIXTURES_PER_RULE:
            raise RulePackError("%s needs bounded positive fixtures" % rule_id)
        if not isinstance(negatives, list) or not negatives or len(negatives) > MAX_FIXTURES_PER_RULE:
            raise RulePackError("%s needs bounded negative fixtures" % rule_id)
        return cls(
            id=rule_id, version=required_text["version"], title=required_text["title"],
            language=required_text["language"], extensions=extensions, severity=severity,
            confidence=float(confidence), category=required_text["category"],
            cwe=cwe or "", description=required_text["description"],
            remediation=required_text["remediation"], match_all=match_all,
            match_any=match_any, exclude_any=exclude_any,
            case_sensitive=value.get("case_sensitive", True) is True,
            positive=tuple(Fixture.parse(item, negative=False) for item in positives),
            negative=tuple(Fixture.parse(item, negative=True) for item in negatives),
        )

    def semantic_fingerprint(self) -> str:
        semantic = {
            "id": self.id, "version": self.version, "language": self.language,
            "extensions": self.extensions, "severity": self.severity,
            "category": self.category, "cwe": self.cwe,
            "description": self.description, "remediation": self.remediation,
            "match_all": self.match_all, "match_any": self.match_any,
            "exclude_any": self.exclude_any, "case_sensitive": self.case_sensitive,
        }
        raw = json.dumps(semantic, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def applies_to(self, path: str) -> bool:
        name = Path(path).name
        suffix = Path(path).suffix.lower()
        return any(selector.lower() in {name.lower(), suffix} for selector in self.extensions)

    def scan(self, source: str, path: str = "fixture.txt") -> list[dict[str, Any]]:
        if not isinstance(source, str) or len(source) > MAX_FIXTURE_CHARS * 8:
            raise RulePackError("source is invalid or exceeds the scan boundary")
        if not self.applies_to(path):
            return []
        findings = []
        all_tokens = self.match_all if self.case_sensitive else tuple(item.lower() for item in self.match_all)
        any_tokens = self.match_any if self.case_sensitive else tuple(item.lower() for item in self.match_any)
        excluded = self.exclude_any if self.case_sensitive else tuple(item.lower() for item in self.exclude_any)
        for line_number, raw_line in enumerate(source.splitlines(), 1):
            line = raw_line[:MAX_LINE_CHARS]
            haystack = line if self.case_sensitive else line.lower()
            if all_tokens and not all(token in haystack for token in all_tokens):
                continue
            if any_tokens and not any(token in haystack for token in any_tokens):
                continue
            if excluded and any(token in haystack for token in excluded):
                continue
            findings.append({
                "path": path, "line": line_number, "rule": self.id,
                "severity": self.severity, "confidence": self.confidence,
                "category": self.category, "cwe": self.cwe,
                "message": self.description, "fix": self.remediation,
                "fingerprint": self.semantic_fingerprint(),
                # Never copy a matched source line into a report.  A custom
                # rule may deliberately or accidentally match credential
                # material; echoing the line would turn JSON/SARIF/log output
                # into a second secret leak.  Location + authenticated rule
                # identity are sufficient reproducible evidence.
                "evidence": [{
                    "kind": "rule-predicate-match",
                    "path": path,
                    "line": line_number,
                    "description": "declarative rule predicates matched; source text withheld",
                    "source_text_withheld": True,
                }],
            })
        return findings


def _canonical_pack(pack: dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in pack.items() if key != "signature"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign_pack(pack: dict[str, Any], key: bytes, key_id: str = "operator") -> dict[str, Any]:
    if not isinstance(key, bytes) or len(key) < 16:
        raise RulePackError("signing key must contain at least 16 bytes")
    if not isinstance(key_id, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", key_id):
        raise RulePackError("key id is invalid")
    signed = {key: value for key, value in pack.items() if key != "signature"}
    digest = hmac.new(key, _canonical_pack(signed), hashlib.sha256).hexdigest()
    signed["signature"] = {"algorithm": "hmac-sha256", "key_id": key_id, "digest": digest}
    return signed


def verify_signature(pack: dict[str, Any], key: bytes) -> bool:
    signature = pack.get("signature")
    if not isinstance(signature, dict) or signature.get("algorithm") != "hmac-sha256":
        return False
    digest = signature.get("digest")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        return False
    expected = hmac.new(key, _canonical_pack(pack), hashlib.sha256).hexdigest()
    return hmac.compare_digest(digest, expected)


def validate_pack(pack: Any, *, signature_key: bytes | None = None,
                  max_rule_ms: float = 250.0) -> dict[str, Any]:
    errors: list[str] = []
    if not isinstance(pack, dict):
        return {"ok": False, "schema": SCHEMA, "rules": 0,
                "errors": ["pack must be a JSON object"]}
    if pack.get("schema") != SCHEMA:
        errors.append("schema must be %s" % SCHEMA)
    values = pack.get("rules")
    if not isinstance(values, list) or not values or len(values) > MAX_RULES:
        errors.append("rules must be a non-empty list with at most %d entries" % MAX_RULES)
        values = []
    if signature_key is not None and not verify_signature(pack, signature_key):
        errors.append("pack signature did not verify")
    parsed: list[RuleSpec] = []
    ids: set[str] = set()
    fingerprints: set[str] = set()
    fixture_count = 0
    for index, raw in enumerate(values):
        try:
            rule = RuleSpec.parse(raw)
            if rule.id in ids:
                raise RulePackError("duplicate rule id: %s" % rule.id)
            fingerprint = rule.semantic_fingerprint()
            if fingerprint in fingerprints:
                raise RulePackError("duplicate semantic rule: %s" % rule.id)
            ids.add(rule.id); fingerprints.add(fingerprint)
            started = time.perf_counter()
            for fixture in rule.positive:
                actual = tuple(item["line"] for item in rule.scan(fixture.source, fixture.path))
                if actual != fixture.expected_lines:
                    raise RulePackError("%s positive fixture expected %s, got %s" % (
                        rule.id, fixture.expected_lines, actual))
                fixture_count += 1
            for fixture in rule.negative:
                actual = tuple(item["line"] for item in rule.scan(fixture.source, fixture.path))
                if actual:
                    raise RulePackError("%s negative fixture produced %s" % (rule.id, actual))
                fixture_count += 1
            elapsed_ms = (time.perf_counter() - started) * 1000
            if elapsed_ms > max_rule_ms:
                raise RulePackError("%s exceeded fixture budget: %.2f ms" % (rule.id, elapsed_ms))
            parsed.append(rule)
        except (RulePackError, TypeError, ValueError) as exc:
            errors.append("rule[%d]: %s" % (index, exc))
    return {
        "ok": not errors, "schema": SCHEMA, "rules": len(parsed),
        "fixtures": fixture_count, "fingerprints": len(fingerprints),
        "signed": isinstance(pack.get("signature"), dict), "errors": errors,
    }


def load_pack(path: str | Path, *, signature_key: bytes | None = None) -> tuple[list[RuleSpec], dict]:
    item = Path(path)
    if not item.is_file() or item.stat().st_size > MAX_PACK_BYTES:
        raise RulePackError("pack is missing or exceeds %d bytes" % MAX_PACK_BYTES)
    try:
        pack = json.loads(item.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RulePackError("cannot parse rule pack: %s" % type(exc).__name__) from exc
    report = validate_pack(pack, signature_key=signature_key)
    if not report["ok"]:
        raise RulePackError("; ".join(report["errors"][:8]))
    return [RuleSpec.parse(value) for value in pack["rules"]], report


def scan_pack(rules: list[RuleSpec], source: str, path: str) -> list[dict[str, Any]]:
    findings = []
    for rule in rules:
        findings.extend(rule.scan(source, path))
    return sorted(findings, key=lambda item: (item["path"], item["line"], item["rule"]))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pack")
    parser.add_argument("--verify-key", help="verify an authenticated pack with this key file")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    key = Path(args.verify_key).read_bytes() if args.verify_key else None
    try:
        _rules, report = load_pack(args.pack, signature_key=key)
    except (OSError, RulePackError) as exc:
        report = {"ok": False, "schema": SCHEMA, "rules": 0, "errors": [str(exc)]}
    print(json.dumps(report, indent=2, sort_keys=True) if args.json else (
        "Attestor rule pack: %s; %d rule(s); %s" % (
            "valid" if report["ok"] else "invalid", report.get("rules", 0),
            "; ".join(report.get("errors", [])) or "all fixtures passed")))
    return 0 if report["ok"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
