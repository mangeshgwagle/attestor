#!/usr/bin/env python3
"""Bounded, content-addressed local evidence history for Attestor 4.1.4.

The store keeps canonical reports and their finding identities in SQLite.  It
never reconstructs security exports from a browser preview: JSON and SARIF are
returned only when the verified report already contains those artifacts.
Source text and secret-bearing snippets are not copied into the index.
"""
from __future__ import annotations

import contextlib
import datetime as _datetime
import hashlib
import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Any, Mapping


SCHEMA = "attestor.evidence-store/4.1"
VERSION = "4.1.4"
MAX_REPORT_BYTES = 32 * 1024 * 1024
MAX_DATABASE_BYTES = 128 * 1024 * 1024
MAX_RUNS = 200
MAX_FINDINGS = 20_000
MAX_TEXT = 4_000
TRIAGE_STATES = frozenset({"open", "investigating", "fixed", "false-positive", "accepted-risk"})
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_VARIANT_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$", re.ASCII)
_VARIANT_ENGINE = "variant-orchestration/4.1.4"


class EvidenceStoreError(ValueError):
    """A history request violated a bounded storage or integrity contract."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def _text(value: Any, maximum: int = MAX_TEXT) -> str:
    return str(value or "").replace("\x00", "\\0")[:maximum]


def _root_identity(value: Any) -> str:
    """Return one deterministic, non-resolving identity for a report root."""
    raw = _text(value, 8_000)
    normalized = os.path.normcase(os.path.normpath(raw)) if raw else ""
    return _sha({"normalized_report_root": normalized.replace("\\", "/")})


def _report_profile_identity(
        report: Mapping[str, Any]) -> tuple[str, str | None, str | None]:
    """Extract an exact Attestor 4.1.4 profile identity without normalizing claims.

    Reports produced before the 4.1.4 variant layer have no identity and remain
    valid legacy evidence.  Once any 4.1.4 marker is present, however, both
    canonical analyzer fields must be present and internally consistent.
    """
    analyzer_value = report.get("analyzer")
    analyzer = analyzer_value if isinstance(analyzer_value, Mapping) else {}
    analysis_value = report.get("analysis_config")
    analysis = analysis_value if isinstance(analysis_value, Mapping) else {}
    engines = analyzer.get("engines")
    engine_marker = (
        isinstance(engines, (list, tuple)) and
        _VARIANT_ENGINE in engines
    )
    has_slug = "variant_slug" in analyzer
    has_digest = "variant_profile_sha256" in analyzer
    selection_present = "variant_414" in analysis
    policy_present = "variant_effective_policy" in analysis
    claims_profile = (
        has_slug or has_digest or selection_present or policy_present or
        engine_marker
    )
    if not claims_profile:
        return "legacy", None, None

    slug = analyzer.get("variant_slug")
    digest = analyzer.get("variant_profile_sha256")
    if (type(slug) is not str or _VARIANT_SLUG.fullmatch(slug) is None or
            type(digest) is not str or _HEX64.fullmatch(digest) is None):
        return "invalid", None, None

    if selection_present:
        selection_value = analysis.get("variant_414")
        if not isinstance(selection_value, Mapping):
            return "invalid", None, None
        selected_value = selection_value.get("selected_profile")
        selected = selected_value if isinstance(selected_value, Mapping) else {}
        if (selection_value.get("schema") != "attestor-variant-selection/4.1.4" or
                selected.get("slug") != slug or
                selected.get("profile_sha256") != digest or
                selection_value.get("selected_profile_sha256") != digest):
            return "invalid", None, None
    return "identified", slug, digest


def _utc(value: str | None = None) -> str:
    if value:
        try:
            parsed = _datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise EvidenceStoreError("timestamp must be ISO-8601") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_datetime.timezone.utc)
        return parsed.astimezone(_datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    return _datetime.datetime.now(_datetime.timezone.utc).isoformat().replace("+00:00", "Z")


def default_history_path() -> Path:
    if os.name == "nt" and os.environ.get("LOCALAPPDATA"):
        base = Path(os.environ["LOCALAPPDATA"])
    else:
        base = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
    return base / "Attestor" / "history-4.1.sqlite3"


def semantic_fingerprint(finding: Mapping[str, Any], *, root_identity: str = "") -> str:
    """Return a root-scoped identity tolerant of line movement and message edits."""
    evidence = finding.get("source_evidence") if isinstance(finding.get("source_evidence"), Mapping) else {}
    body = {
        "report_root_sha256": _text(root_identity, 64),
        "rule": _text(finding.get("rule") or finding.get("rule_id"), 300),
        "path": _text(finding.get("path"), 2_000).replace("\\", "/"),
        "category": _text(finding.get("category"), 200),
        "cwe": _text(finding.get("cwe"), 80),
        "symbol": _text(finding.get("symbol"), 500),
        "source": _text(finding.get("source_engine") or finding.get("analyzer"), 200),
        "snippet_sha256": _text(evidence.get("snippet_sha256"), 64),
        "rule_sha256": _text(evidence.get("rule_sha256"), 64),
    }
    return "attestor41-finding-" + _sha(body)[:32]


def report_fingerprints(report: Mapping[str, Any]) -> list[dict[str, Any]]:
    rows = report.get("findings") if isinstance(report.get("findings"), list) else []
    output = []
    occurrences: dict[str, int] = {}
    root_identity = _root_identity(report.get("root"))
    for finding in rows[:MAX_FINDINGS]:
        if not isinstance(finding, Mapping):
            continue
        base = semantic_fingerprint(finding, root_identity=root_identity)
        occurrence = occurrences.get(base, 0) + 1
        occurrences[base] = occurrence
        # A report can legitimately contain the same rule and source bytes more
        # than once (for example, two identical generated blocks).  Keep the
        # semantic base stable while making the per-run database key unique.
        fingerprint = base if occurrence == 1 else "%s:%d" % (base, occurrence)
        output.append({
            "fingerprint": fingerprint, "semantic_base": base,
            "rule": _text(finding.get("rule") or finding.get("rule_id"), 300),
            "path": _text(finding.get("path"), 2_000),
            "line": max(1, int(finding.get("line", 1))) if str(finding.get("line", 1)).isdigit() else 1,
            "severity": _text(finding.get("severity", "MEDIUM"), 20).upper(),
        })
    return output


class EvidenceStore:
    """Small local SQLite store with deterministic content verification."""

    def __init__(self, path: str | os.PathLike[str] | None = None, *,
                 max_runs: int = MAX_RUNS, max_database_bytes: int = MAX_DATABASE_BYTES):
        self.path = Path(path or default_history_path()).expanduser()
        self.max_runs = max(1, min(int(max_runs), 10_000))
        self.max_database_bytes = max(1024 * 1024, min(int(max_database_bytes), 1024 * 1024 * 1024))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists() and self.path.is_symlink():
            raise EvidenceStoreError("history database must not be a symbolic link")
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @contextlib.contextmanager
    def _database(self):
        """Commit or roll back and always release Windows SQLite handles."""
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._database() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS blobs(
                    digest TEXT PRIMARY KEY CHECK(length(digest)=64),
                    bytes INTEGER NOT NULL CHECK(bytes>=0),
                    payload BLOB NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS runs(
                    run_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    report_digest TEXT NOT NULL REFERENCES blobs(digest),
                    semantic_digest TEXT NOT NULL CHECK(length(semantic_digest)=64),
                    schema_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    findings INTEGER NOT NULL CHECK(findings>=0),
                    root_digest TEXT NOT NULL CHECK(length(root_digest)=64),
                    profile_identity_state TEXT NOT NULL DEFAULT 'legacy'
                        CHECK(profile_identity_state IN ('legacy','identified','invalid')),
                    variant_slug TEXT,
                    variant_profile_sha256 TEXT,
                    CHECK(
                        (profile_identity_state='identified' AND
                         variant_slug IS NOT NULL AND
                         variant_profile_sha256 IS NOT NULL) OR
                        (profile_identity_state!='identified' AND
                         variant_slug IS NULL AND
                         variant_profile_sha256 IS NULL)
                    )
                );
                CREATE INDEX IF NOT EXISTS runs_created ON runs(created_at DESC, run_id DESC);
                CREATE TABLE IF NOT EXISTS findings(
                    run_id TEXT NOT NULL REFERENCES runs(run_id) ON DELETE CASCADE,
                    fingerprint TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    path TEXT NOT NULL,
                    line INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    PRIMARY KEY(run_id, fingerprint)
                );
                CREATE INDEX IF NOT EXISTS finding_identity ON findings(fingerprint);
                CREATE TABLE IF NOT EXISTS triage(
                    fingerprint TEXT PRIMARY KEY,
                    state TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS suppressions(
                    fingerprint TEXT PRIMARY KEY,
                    owner TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
            """)
            columns = {
                str(row["name"]) for row in db.execute("PRAGMA table_info(runs)")
            }
            identity_columns = {
                "profile_identity_state", "variant_slug",
                "variant_profile_sha256",
            }
            migration_required = not identity_columns.issubset(columns)
            # SQLite cannot add a multi-column CHECK constraint in place.  The
            # application applies the same invariant on all writes and reads.
            if "profile_identity_state" not in columns:
                db.execute(
                    "ALTER TABLE runs ADD COLUMN "
                    "profile_identity_state TEXT NOT NULL DEFAULT 'unknown'")
            if "variant_slug" not in columns:
                db.execute("ALTER TABLE runs ADD COLUMN variant_slug TEXT")
            if "variant_profile_sha256" not in columns:
                db.execute(
                    "ALTER TABLE runs ADD COLUMN variant_profile_sha256 TEXT")
            self._backfill_profile_identities(
                db, include_classified=migration_required)

    @staticmethod
    def _backfill_profile_identities(
            db: sqlite3.Connection, *, include_classified: bool = False) -> None:
        """Classify pre-4.1.4 rows from their content-addressed report blobs."""
        if include_classified:
            rows = db.execute("""
                SELECT r.run_id,b.digest,b.payload
                FROM runs r JOIN blobs b ON b.digest=r.report_digest
            """).fetchall()
        else:
            rows = db.execute("""
                SELECT r.run_id,b.digest,b.payload
                FROM runs r JOIN blobs b ON b.digest=r.report_digest
                WHERE r.profile_identity_state
                      NOT IN ('legacy','identified','invalid')
                   OR r.profile_identity_state IS NULL
            """).fetchall()
        for row in rows:
            state, slug, digest = "invalid", None, None
            try:
                payload = bytes(row["payload"])
                if _sha(payload) != row["digest"]:
                    raise EvidenceStoreError("stored report digest mismatch")
                report = json.loads(payload.decode("utf-8"))
                if isinstance(report, Mapping):
                    state, slug, digest = _report_profile_identity(report)
            except (UnicodeDecodeError, json.JSONDecodeError, RecursionError,
                    EvidenceStoreError, TypeError, ValueError):
                pass
            db.execute("""
                UPDATE runs
                SET profile_identity_state=?,variant_slug=?,
                    variant_profile_sha256=?
                WHERE run_id=?
            """, (state, slug, digest, row["run_id"]))

    def _check_size(self, db: sqlite3.Connection | None = None) -> None:
        sizes = [item.stat().st_size for item in (self.path,
                 Path(str(self.path) + "-wal"), Path(str(self.path) + "-shm")) if item.exists()]
        physical_bytes = sum(sizes)
        logical_bytes = 0
        if db is not None:
            page_count = int(db.execute("PRAGMA page_count").fetchone()[0])
            page_size = int(db.execute("PRAGMA page_size").fetchone()[0])
            logical_bytes = page_count * page_size
        if max(physical_bytes, logical_bytes) > self.max_database_bytes:
            raise EvidenceStoreError("history database reached its configured byte boundary")

    def store_report(self, report: Mapping[str, Any], *, created_at: str | None = None) -> dict[str, Any]:
        if not isinstance(report, Mapping):
            raise EvidenceStoreError("report must be a mapping")
        profile_state, variant_slug, variant_profile_sha256 = \
            _report_profile_identity(report)
        if profile_state == "invalid":
            raise EvidenceStoreError(
                "report has an invalid or incomplete Attestor 4.1.4 profile identity")
        payload = _canonical(report)
        if len(payload) > MAX_REPORT_BYTES:
            raise EvidenceStoreError("report exceeds the 32 MiB history boundary")
        rows = report_fingerprints(report)
        if len(rows) > MAX_FINDINGS:
            raise EvidenceStoreError("report exceeds the finding history boundary")
        created = _utc(created_at)
        report_digest = _sha(payload)
        semantic_digest = _sha(sorted(item["fingerprint"] for item in rows))
        root_digest = _root_identity(report.get("root"))
        run_id = "run41-" + _sha([created, report_digest, semantic_digest])[:32]
        with self._database() as db:
            db.execute("INSERT OR IGNORE INTO blobs(digest,bytes,payload,created_at) VALUES(?,?,?,?)",
                       (report_digest, len(payload), payload, created))
            db.execute("""INSERT OR REPLACE INTO runs
                       (run_id,created_at,report_digest,semantic_digest,schema_name,
                        status,findings,root_digest,profile_identity_state,
                        variant_slug,variant_profile_sha256)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""", (
                run_id, created, report_digest, semantic_digest,
                _text(report.get("schema"), 200), _text(report.get("status", "unknown"), 80),
                len(rows), root_digest, profile_state, variant_slug,
                variant_profile_sha256))
            db.execute("DELETE FROM findings WHERE run_id=?", (run_id,))
            db.executemany("""INSERT INTO findings
                           (run_id,fingerprint,rule_id,path,line,severity) VALUES(?,?,?,?,?,?)""",
                           [(run_id, row["fingerprint"], row["rule"], row["path"],
                              row["line"], row["severity"]) for row in rows])
            self._prune(db)
            # Check the transaction's logical page allocation before the
            # connection context commits.  Raising here rolls back the run,
            # its findings, and any newly inserted report blob together.
            self._check_size(db)
        return {"schema": SCHEMA, "run_id": run_id, "created_at": created,
                "report_digest": report_digest, "semantic_digest": semantic_digest,
                "findings": len(rows),
                "profile_identity_state": profile_state,
                "variant_slug": variant_slug,
                "variant_profile_sha256": variant_profile_sha256}

    def _prune(self, db: sqlite3.Connection) -> None:
        stale = db.execute("SELECT run_id FROM runs ORDER BY created_at DESC,run_id DESC LIMIT -1 OFFSET ?",
                           (self.max_runs,)).fetchall()
        if stale:
            db.executemany("DELETE FROM runs WHERE run_id=?", [(row[0],) for row in stale])
        db.execute("DELETE FROM blobs WHERE digest NOT IN (SELECT report_digest FROM runs)")

    def list_runs(self, *, limit: int = 50) -> list[dict[str, Any]]:
        maximum = max(1, min(int(limit), self.max_runs))
        with self._database() as db:
            rows = db.execute("""SELECT run_id,created_at,report_digest,semantic_digest,
                              schema_name,status,findings,profile_identity_state,
                              variant_slug,variant_profile_sha256 FROM runs
                              ORDER BY created_at DESC,run_id DESC LIMIT ?""", (maximum,)).fetchall()
        return [dict(row) for row in rows]

    def clear(self) -> int:
        """Erase reports and their associated triage/suppression history."""
        with self._database() as db:
            count = int(db.execute("SELECT COUNT(*) FROM runs").fetchone()[0])
            db.execute("DELETE FROM suppressions")
            db.execute("DELETE FROM triage")
            db.execute("DELETE FROM runs")
            db.execute("DELETE FROM blobs")
        return count

    def get_report(self, run_id: str) -> dict[str, Any]:
        with self._database() as db:
            row = db.execute("""SELECT b.payload,b.digest FROM runs r JOIN blobs b
                              ON b.digest=r.report_digest WHERE r.run_id=?""", (_text(run_id, 100),)).fetchone()
        if row is None:
            raise EvidenceStoreError("history run was not found")
        payload = bytes(row["payload"])
        if _sha(payload) != row["digest"]:
            raise EvidenceStoreError("stored report digest mismatch")
        try:
            report = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceStoreError("stored report is not canonical JSON") from exc
        if not isinstance(report, dict):
            raise EvidenceStoreError("stored report root is invalid")
        return report

    def compare(self, baseline: str, current: str) -> dict[str, Any]:
        with self._database() as db:
            def snapshot(run_id: str) -> tuple[set[str], dict[str, Any]]:
                selected = _text(run_id, 100)
                row = db.execute("""
                    SELECT profile_identity_state,variant_slug,
                           variant_profile_sha256
                    FROM runs WHERE run_id=?
                """, (selected,)).fetchone()
                if row is None:
                    raise EvidenceStoreError("history run was not found")
                state = str(row["profile_identity_state"] or "")
                slug = row["variant_slug"]
                digest = row["variant_profile_sha256"]
                if state == "legacy" and slug is None and digest is None:
                    pass
                elif (state == "identified" and type(slug) is str and
                      _VARIANT_SLUG.fullmatch(slug) is not None and
                      type(digest) is str and
                      _HEX64.fullmatch(digest) is not None):
                    pass
                else:
                    state, slug, digest = "invalid", None, None
                findings = {item[0] for item in db.execute(
                    "SELECT fingerprint FROM findings WHERE run_id=?",
                    (selected,)).fetchall()}
                return findings, {
                    "state": state,
                    "variant_slug": slug,
                    "variant_profile_sha256": digest,
                }

            before, baseline_profile = snapshot(baseline)
            after, current_profile = snapshot(current)

        comparable = False
        reason = "invalid-profile-identity"
        if (baseline_profile["state"] == "legacy" and
                current_profile["state"] == "legacy"):
            comparable = True
            reason = "legacy-pair-without-profile-identity"
        elif (baseline_profile["state"] == "identified" and
              current_profile["state"] == "identified"):
            if baseline_profile == current_profile:
                comparable = True
                reason = "matching-profile-identity"
            elif (baseline_profile["variant_slug"] !=
                  current_profile["variant_slug"]):
                reason = "variant-slug-mismatch"
            else:
                reason = "variant-profile-sha256-mismatch"
        elif "invalid" not in {
                baseline_profile["state"], current_profile["state"]}:
            reason = "profile-identity-presence-mismatch"

        if comparable:
            new = sorted(after - before)
            resolved = sorted(before - after)
            persistent = sorted(before & after)
        else:
            # A finding lifecycle claim is meaningful only under the same
            # detector profile.  Keep all delta categories empty rather than
            # presenting incomparable evidence as newly introduced or fixed.
            new, resolved, persistent = [], [], []
        body = {
            "schema": "attestor.evidence-delta/4.1",
            "baseline": baseline,
            "current": current,
            "comparable": comparable,
            "comparison_reason": reason,
            "baseline_profile_identity": baseline_profile,
            "current_profile_identity": current_profile,
            "new": new,
            "resolved": resolved,
            "persistent": persistent,
        }
        if reason == "legacy-pair-without-profile-identity":
            # Preserve the pre-4.1.4 delta identity for two legacy reports.
            body["delta_sha256"] = _sha(
                [baseline, current, sorted(before), sorted(after)])
        else:
            body["delta_sha256"] = _sha(body)
        return body

    def annotations(self, run_id: str) -> list[dict[str, Any]]:
        """Return bounded triage and active suppression state for a stored run."""
        instant = _utc()
        with self._database() as db:
            exists = db.execute("SELECT 1 FROM runs WHERE run_id=?", (_text(run_id, 100),)).fetchone()
            if not exists:
                raise EvidenceStoreError("history run was not found")
            rows = db.execute("""SELECT f.fingerprint,f.rule_id,f.path,f.line,f.severity,
                              t.state,t.owner AS triage_owner,t.reason AS triage_reason,t.updated_at,
                              s.owner AS suppression_owner,s.reason AS suppression_reason,s.expires_at
                              FROM findings f
                              LEFT JOIN triage t ON t.fingerprint=f.fingerprint
                              LEFT JOIN suppressions s ON s.fingerprint=f.fingerprint AND s.expires_at>?
                              WHERE f.run_id=? ORDER BY f.path,f.line,f.rule_id LIMIT ?""",
                              (instant, _text(run_id, 100), MAX_FINDINGS)).fetchall()
        return [dict(row) for row in rows]

    def set_triage(self, fingerprint: str, state: str, *, owner: str, reason: str) -> dict[str, str]:
        if state not in TRIAGE_STATES:
            raise EvidenceStoreError("unsupported triage state")
        values = [_text(fingerprint, 200), _text(owner, 200).strip(), _text(reason, 2_000).strip()]
        if not values[0] or not values[1] or not values[2]:
            raise EvidenceStoreError("triage requires fingerprint, owner, and reason")
        updated = _utc()
        with self._database() as db:
            if not db.execute("SELECT 1 FROM findings WHERE fingerprint=? LIMIT 1", (values[0],)).fetchone():
                raise EvidenceStoreError("triage fingerprint is not present in stored evidence")
            db.execute("""INSERT INTO triage(fingerprint,state,owner,reason,updated_at)
                       VALUES(?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET
                       state=excluded.state,owner=excluded.owner,reason=excluded.reason,
                       updated_at=excluded.updated_at""", (*values[:1], state, *values[1:], updated))
            self._check_size(db)
        return {"fingerprint": values[0], "state": state, "owner": values[1],
                "reason": values[2], "updated_at": updated}

    def suppress(self, fingerprint: str, *, owner: str, reason: str,
                 expires_at: str) -> dict[str, str]:
        fp, owner_text, reason_text = (_text(fingerprint, 200), _text(owner, 200).strip(),
                                       _text(reason, 2_000).strip())
        expiry = _utc(expires_at)
        if not fp or not owner_text or not reason_text:
            raise EvidenceStoreError("suppression requires fingerprint, owner, reason, and expiry")
        if expiry <= _utc():
            raise EvidenceStoreError("suppression expiry must be in the future")
        created = _utc()
        with self._database() as db:
            if not db.execute("SELECT 1 FROM findings WHERE fingerprint=? LIMIT 1", (fp,)).fetchone():
                raise EvidenceStoreError("suppression fingerprint is not present in stored evidence")
            db.execute("""INSERT INTO suppressions(fingerprint,owner,reason,expires_at,created_at)
                       VALUES(?,?,?,?,?) ON CONFLICT(fingerprint) DO UPDATE SET
                       owner=excluded.owner,reason=excluded.reason,
                       expires_at=excluded.expires_at,created_at=excluded.created_at""",
                       (fp, owner_text, reason_text, expiry, created))
            self._check_size(db)
        return {"fingerprint": fp, "owner": owner_text, "reason": reason_text,
                "expires_at": expiry, "created_at": created}

    def active_suppressions(self, *, at: str | None = None) -> list[dict[str, str]]:
        instant = _utc(at)
        with self._database() as db:
            rows = db.execute("""SELECT fingerprint,owner,reason,expires_at,created_at
                              FROM suppressions WHERE expires_at>? ORDER BY expires_at,fingerprint LIMIT ?""",
                              (instant, MAX_FINDINGS)).fetchall()
        return [dict(row) for row in rows]

    def unsuppress(self, fingerprint: str) -> bool:
        fp = _text(fingerprint, 200)
        if not fp:
            raise EvidenceStoreError("suppression fingerprint is required")
        with self._database() as db:
            cursor = db.execute("DELETE FROM suppressions WHERE fingerprint=?", (fp,))
        return cursor.rowcount > 0

    @staticmethod
    def _verified_for_export(report: Mapping[str, Any]) -> None:
        """Fail closed through the verifier that owns the report schema."""
        if report.get("schema") == "attestor-research/4.1":
            try:
                import research_engine41
                valid, _errors = research_engine41.verify_report(report)
            except (ImportError, OSError, RuntimeError, TypeError, ValueError) as exc:
                raise EvidenceStoreError("research report verification could not run") from exc
            if valid is not True:
                raise EvidenceStoreError("canonical export refused: research evidence is invalid")
            return
        try:
            import truth_guard41
            result = truth_guard41.verify_guarded(report, require_fresh=True)
        except (ImportError, OSError, RuntimeError, TypeError, ValueError) as exc:
            raise EvidenceStoreError("canonical report verification could not run") from exc
        if not isinstance(result, Mapping) or result.get("ok") is not True \
                or result.get("fresh") is not True:
            raise EvidenceStoreError("canonical export refused: report evidence is not fresh and verified")

    def canonical_export(self, run_id: str, format_name: str) -> tuple[str, bytes]:
        report = self.get_report(run_id)
        self._verified_for_export(report)
        name = _text(format_name, 40).lower()
        if name == "json":
            return "application/json; charset=utf-8", _canonical(report)
        if name == "sarif":
            value = report.get("sarif")
            if not isinstance(value, Mapping):
                exports = report.get("exports") if isinstance(report.get("exports"), Mapping) else {}
                value = exports.get("sarif")
            if not isinstance(value, Mapping):
                raise EvidenceStoreError("verified report does not contain a canonical SARIF export")
            return "application/sarif+json; charset=utf-8", _canonical(value)
        raise EvidenceStoreError("only canonical JSON and report-supplied SARIF are exportable")


__all__ = ["SCHEMA", "VERSION", "EvidenceStore", "EvidenceStoreError",
           "default_history_path", "semantic_fingerprint", "report_fingerprints"]
