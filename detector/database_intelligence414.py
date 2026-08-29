#!/usr/bin/env python3
"""Bounded, read-only database understanding for Attestor 4.1.4.

This module never connects to a database server and never executes a supplied
SQL file.  It understands an explicitly scoped local SQLite snapshot or SQL
file, records its exact SHA-256 identity, and emits schema/migration evidence
without reading application rows.
"""
from __future__ import annotations

import hashlib
import os
import re
import sqlite3
import stat
import tempfile
from pathlib import Path
from typing import Any


VERSION = "4.1.4"
SCHEMA = "attestor-database-intelligence/4.1.4"
SQLITE_MAGIC = b"SQLite format 3\x00"
SHA256_RE = re.compile(r"[0-9a-f]{64}", re.ASCII)
MAX_DATABASE_BYTES = 512 * 1024 * 1024
MAX_SQL_BYTES = 4 * 1024 * 1024
MAX_SCHEMA_OBJECTS = 2_000
MAX_COLUMNS = 20_000
MAX_RELATIONSHIPS = 20_000
MAX_VM_STEPS = 2_000_000
MAX_SQL_STATEMENTS = 10_000
_SQL_SUFFIXES = frozenset({".sql", ".ddl", ".dml"})
_SQLITE_SUFFIXES = frozenset({".db", ".sqlite", ".sqlite3"})
_WRITE_KEYWORDS = frozenset({
    "ALTER", "ANALYZE", "CREATE", "DELETE", "DROP", "INSERT", "REINDEX",
    "REPLACE", "TRUNCATE", "UPDATE", "VACUUM",
})
_DESTRUCTIVE_KEYWORDS = frozenset({"DELETE", "DROP", "TRUNCATE"})
_PRIVILEGED_PATTERNS = (
    ("attach-database", re.compile(r"\bATTACH\s+(?:DATABASE\s+)?", re.I)),
    ("detach-database", re.compile(r"\bDETACH\s+(?:DATABASE\s+)?", re.I)),
    ("extension-load", re.compile(r"\bLOAD_EXTENSION\s*\(", re.I)),
    ("filesystem-function", re.compile(
        r"\b(?:LOAD_FILE|PG_READ_FILE|PG_WRITE_FILE|PG_LS_DIR)\s*\(", re.I)),
    ("os-command", re.compile(
        r"\b(?:XP_CMDSHELL|SYS_EXEC|COPY\s+[^;]*\s+(?:TO|FROM)\s+PROGRAM)\b",
        re.I)),
    ("broad-grant", re.compile(
        r"\bGRANT\s+ALL(?:\s+PRIVILEGES)?\b|\bGRANT\b[^;]*\bTO\s+PUBLIC\b",
        re.I)),
    ("credential-literal", re.compile(
        r"\b(?:CREATE|ALTER)\s+(?:USER|ROLE)\b[^;]*\bPASSWORD\s+['\"]",
        re.I)),
)


class DatabaseIntelligenceError(ValueError):
    """The local database artifact crossed a read-only evidence boundary."""


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    attributes = getattr(info, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse)


def _remote_windows_path(value: str | os.PathLike[str]) -> bool:
    """Reject UNC and mapped remote drives before opening the supplied path."""
    raw = os.fspath(value)
    if raw.startswith(("\\\\", "//")):
        return True
    if os.name != "nt":
        return False
    drive = Path(raw).drive
    if not drive:
        return False
    root = drive + "\\"
    try:
        import ctypes
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(root)
    except (AttributeError, OSError, TypeError):
        # A drive we cannot classify is not safe enough for a claim of local
        # operation.  DRIVE_UNKNOWN is also denied.
        return True
    return drive_type in {0, 4}  # DRIVE_UNKNOWN or DRIVE_REMOTE


def _regular_file(value: str | os.PathLike[str], maximum: int) -> Path:
    if not isinstance(value, (str, os.PathLike)):
        raise DatabaseIntelligenceError("database path must be local text")
    if _remote_windows_path(value):
        raise DatabaseIntelligenceError(
            "database artifact must not use a remote or UNC path")
    supplied = Path(value).expanduser()
    if _is_link_or_reparse(supplied):
        raise DatabaseIntelligenceError(
            "database artifact cannot be a link or reparse point")
    try:
        path = supplied.resolve(strict=True)
        info = path.stat()
    except OSError as exc:
        raise DatabaseIntelligenceError(
            "database artifact is unavailable") from exc
    if not path.is_file() or not stat.S_ISREG(info.st_mode):
        raise DatabaseIntelligenceError(
            "database artifact must be one regular local file")
    if not 0 < info.st_size <= maximum:
        raise DatabaseIntelligenceError(
            "database artifact exceeds the bounded size policy")
    return path


def _sha_file(path: Path, maximum: int) -> str:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum:
                    raise DatabaseIntelligenceError(
                        "database artifact changed beyond the size boundary")
                digest.update(chunk)
    except OSError as exc:
        raise DatabaseIntelligenceError(
            "database artifact could not be hashed") from exc
    return digest.hexdigest()


def _read_bound_bytes(
    path: Path,
    expected_sha256: str,
    maximum: int,
) -> tuple[bytes, str, tuple[int, int, int | None]]:
    """Read and hash one already-open handle, then prove its path stayed bound."""
    expected = _expected_hash(expected_sha256)
    try:
        with path.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode) or not 0 < opened.st_size <= maximum:
                raise DatabaseIntelligenceError(
                    "database artifact handle crossed its file boundary")
            data = handle.read(maximum + 1)
    except DatabaseIntelligenceError:
        raise
    except OSError as exc:
        raise DatabaseIntelligenceError(
            "database artifact could not be read") from exc
    if len(data) > maximum or len(data) != opened.st_size:
        raise DatabaseIntelligenceError(
            "database artifact changed beyond its byte boundary")
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected:
        raise DatabaseIntelligenceError(
            "database artifact does not match its authorized SHA-256")
    current = _snapshot(path)
    opened_snapshot = (
        int(opened.st_size),
        int(getattr(
            opened, "st_mtime_ns",
            int(opened.st_mtime * 1_000_000_000))),
        getattr(opened, "st_ino", None),
    )
    if current != opened_snapshot:
        raise DatabaseIntelligenceError(
            "database artifact changed while its authorized handle was read")
    return data, actual, opened_snapshot


def _expected_hash(value: Any) -> str:
    if type(value) is not str or SHA256_RE.fullmatch(value) is None:
        raise DatabaseIntelligenceError(
            "an exact lowercase SHA-256 scope is required")
    return value


def _snapshot(path: Path) -> tuple[int, int, int | None]:
    try:
        info = path.stat()
    except OSError as exc:
        raise DatabaseIntelligenceError(
            "database artifact snapshot is unavailable") from exc
    return (
        int(info.st_size),
        int(getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))),
        getattr(info, "st_ino", None),
    )


def _bound_identity(path: Path, expected_sha256: str, maximum: int) -> tuple[str, tuple[int, int, int | None]]:
    expected = _expected_hash(expected_sha256)
    before = _snapshot(path)
    actual = _sha_file(path, maximum)
    after = _snapshot(path)
    if before != after:
        raise DatabaseIntelligenceError(
            "database artifact changed while its identity was measured")
    if actual != expected:
        raise DatabaseIntelligenceError(
            "database artifact does not match its authorized SHA-256")
    return actual, after


def _sqlite_uri(path: Path) -> str:
    # Path.as_uri performs the required escaping without interpolating the path
    # into a SQL statement.  SQLite URI parameters select a read-only handle.
    return path.as_uri() + "?mode=ro&immutable=1"


def _object_risk(kind: str, sql: str) -> list[str]:
    risks: list[str] = []
    upper = sql.upper()
    if kind == "trigger":
        risks.append("triggered-side-effects")
    if "WITHOUT ROWID" in upper:
        risks.append("without-rowid")
    if "GENERATED ALWAYS" in upper:
        risks.append("generated-columns")
    if "VIRTUAL TABLE" in upper:
        risks.append("virtual-table")
    return risks


def _safe_identifier(value: Any) -> str:
    if type(value) is not str or len(value.encode("utf-8")) > 1_024:
        raise DatabaseIntelligenceError("SQLite schema identifier is invalid")
    return value


def _progress_limiter():
    remaining = MAX_VM_STEPS

    def progress() -> int:
        nonlocal remaining
        remaining -= 1_000
        return 1 if remaining <= 0 else 0

    return progress


def inspect_sqlite(
    value: str | os.PathLike[str],
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    """Understand one exact local SQLite snapshot without reading table rows."""
    path = _regular_file(value, MAX_DATABASE_BYTES)
    sidecars = [
        Path(str(path) + suffix) for suffix in ("-wal", "-shm", "-journal")
    ]
    if any(item.exists() or item.is_symlink() or _is_link_or_reparse(item)
           for item in sidecars):
        raise DatabaseIntelligenceError(
            "SQLite inspection requires a checkpointed single-file snapshot "
            "without WAL, SHM, or journal sidecars")
    data, digest, stable_snapshot = _read_bound_bytes(
        path, expected_sha256, MAX_DATABASE_BYTES)
    if data[:len(SQLITE_MAGIC)] != SQLITE_MAGIC:
        raise DatabaseIntelligenceError(
            "artifact is not a supported SQLite database")
    if any(item.exists() or item.is_symlink() or _is_link_or_reparse(item)
           for item in sidecars):
        raise DatabaseIntelligenceError(
            "SQLite sidecar appeared while the snapshot was captured")

    objects: list[dict[str, Any]] = []
    columns: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    indexes: list[dict[str, Any]] = []
    journal_mode = "unknown"
    try:
        with tempfile.TemporaryDirectory(
                prefix="attestor414-sqlite-snapshot-") as folder:
            snapshot = Path(folder) / "authorized.sqlite3"
            try:
                with snapshot.open("xb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                snapshot.chmod(0o400)
            except OSError as exc:
                raise DatabaseIntelligenceError(
                    "private SQLite snapshot could not be created") from exc
            connection = sqlite3.connect(
                _sqlite_uri(snapshot), uri=True, timeout=1.0,
                check_same_thread=False)
            try:
                connection.set_progress_handler(_progress_limiter(), 1_000)
                connection.execute("PRAGMA query_only = ON")
                connection.execute("PRAGMA trusted_schema = OFF")
                trusted = connection.execute(
                    "PRAGMA trusted_schema").fetchone()
                if not trusted or int(trusted[0]) != 0:
                    raise DatabaseIntelligenceError(
                        "SQLite trusted-schema hardening is unavailable")
                attached = connection.execute(
                    "PRAGMA database_list").fetchall()
                if len(attached) != 1 or str(attached[0][1]) != "main":
                    raise DatabaseIntelligenceError(
                        "SQLite snapshot exposed an unexpected attached database")
                journal_row = connection.execute("PRAGMA journal_mode").fetchone()
                if journal_row:
                    journal_mode = str(journal_row[0]).lower()[:32]
                rows = connection.execute(
                    "SELECT type, name, tbl_name, COALESCE(sql, '') "
                    "FROM sqlite_schema WHERE name NOT GLOB 'sqlite_*' "
                    "ORDER BY type, name LIMIT ?",
                    (MAX_SCHEMA_OBJECTS + 1,),
                ).fetchall()
                if len(rows) > MAX_SCHEMA_OBJECTS:
                    raise DatabaseIntelligenceError(
                        "SQLite schema exceeds the object boundary")
                table_names: list[str] = []
                for raw_kind, raw_name, raw_table, raw_sql in rows:
                    kind = _safe_identifier(raw_kind)
                    name = _safe_identifier(raw_name)
                    table = _safe_identifier(raw_table)
                    sql = str(raw_sql)
                    if len(sql.encode("utf-8")) > MAX_SQL_BYTES:
                        raise DatabaseIntelligenceError(
                            "one SQLite schema object exceeds the SQL boundary")
                    objects.append({
                        "type": kind,
                        "name": name,
                        "table": table,
                        "definition_sha256": hashlib.sha256(
                            sql.encode("utf-8")).hexdigest(),
                        "risk_markers": _object_risk(kind, sql),
                    })
                    if kind == "table":
                        table_names.append(name)
                    elif kind == "index":
                        indexes.append({"name": name, "table": table})

                for table in table_names:
                    column_rows = connection.execute(
                        "SELECT cid, name, type, \"notnull\", pk, hidden "
                        "FROM pragma_table_xinfo(?) ORDER BY cid",
                        (table,),
                    ).fetchall()
                    for cid, name, declared_type, not_null, primary_key, hidden in column_rows:
                        if len(columns) >= MAX_COLUMNS:
                            raise DatabaseIntelligenceError(
                                "SQLite schema exceeds the column boundary")
                        columns.append({
                            "table": table,
                            "ordinal": int(cid),
                            "name": _safe_identifier(name),
                            "declared_type": str(declared_type)[:256],
                            "nullable": not bool(not_null),
                            "primary_key_position": int(primary_key),
                            "hidden": bool(hidden),
                        })
                    foreign_rows = connection.execute(
                        "SELECT id, seq, \"table\", \"from\", \"to\", "
                        "on_update, on_delete "
                        "FROM pragma_foreign_key_list(?) ORDER BY id, seq",
                        (table,),
                    ).fetchall()
                    for identifier, sequence, target, source_column, target_column, on_update, on_delete in foreign_rows:
                        if len(relationships) >= MAX_RELATIONSHIPS:
                            raise DatabaseIntelligenceError(
                                "SQLite schema exceeds the relationship boundary")
                        relationships.append({
                            "from_table": table,
                            "from_column": _safe_identifier(source_column),
                            "to_table": _safe_identifier(target),
                            "to_column": (
                                _safe_identifier(target_column)
                                if target_column is not None else None),
                            "implicit_target_primary_key": target_column is None,
                            "on_update": str(on_update)[:32],
                            "on_delete": str(on_delete)[:32],
                            "constraint_position": "%d:%d" % (
                                int(identifier), int(sequence)),
                        })
            finally:
                connection.close()
    except DatabaseIntelligenceError:
        raise
    except sqlite3.DatabaseError as exc:
        raise DatabaseIntelligenceError(
            "SQLite read-only inspection failed safely") from exc

    after = _snapshot(path)
    if (after != stable_snapshot or
            _sha_file(path, MAX_DATABASE_BYTES) != digest or
            any(item.exists() or item.is_symlink() or _is_link_or_reparse(item)
                for item in sidecars)):
        raise DatabaseIntelligenceError(
            "SQLite snapshot changed during read-only inspection")
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "kind": "sqlite",
        "status": "understood",
        "artifact": {
            "path": str(path),
            "sha256": digest,
            "bytes": stable_snapshot[0],
        },
        "database": {
            "application_row_values_queried": False,
            "application_pages_scanned_for_integrity": False,
            "connection_mode": "local-read-only",
            "database_server_connected": False,
            "integrity_check": "not-run-schema-only-mode",
            "journal_mode": journal_mode,
            "objects": objects,
            "columns": columns,
            "relationships": relationships,
            "indexes": indexes,
            "summary": {
                "tables": sum(row["type"] == "table" for row in objects),
                "views": sum(row["type"] == "view" for row in objects),
                "indexes": sum(row["type"] == "index" for row in objects),
                "triggers": sum(row["type"] == "trigger" for row in objects),
                "columns": len(columns),
                "relationships": len(relationships),
            },
        },
        "boundaries": {
            "database_writes": False,
            "row_values_in_report": False,
            "schema_identifiers_in_report": True,
            "supplied_sql_executed": False,
            "target_database_opened_by_sqlite": False,
            "private_snapshot_inspected": True,
        },
    }


def _strip_literals_and_comments(text: str) -> str:
    """Preserve statement punctuation while removing comments/string bodies."""
    out: list[str] = []
    index = 0
    quote = ""
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if quote:
            if char == quote:
                if next_char == quote:
                    out.extend((" ", " "))
                    index += 2
                    continue
                quote = ""
            out.append("\n" if char == "\n" else " ")
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            out.append(" ")
            index += 1
            continue
        if char == "-" and next_char == "-":
            while index < len(text) and text[index] not in "\r\n":
                out.append(" ")
                index += 1
            continue
        if char == "/" and next_char == "*":
            out.extend((" ", " "))
            index += 2
            while index < len(text):
                if text[index:index + 2] == "*/":
                    out.extend((" ", " "))
                    index += 2
                    break
                out.append("\n" if text[index] == "\n" else " ")
                index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _strip_comments_preserve_literals(text: str) -> str:
    """Remove comments while retaining strings for credential-risk matching."""
    out: list[str] = []
    index = 0
    quote = ""
    while index < len(text):
        char = text[index]
        next_char = text[index + 1] if index + 1 < len(text) else ""
        if quote:
            out.append(char)
            if char == quote:
                if next_char == quote:
                    out.append(next_char)
                    index += 2
                    continue
                quote = ""
            index += 1
            continue
        if char in {"'", '"', "`"}:
            quote = char
            out.append(char)
            index += 1
            continue
        if char == "-" and next_char == "-":
            while index < len(text) and text[index] not in "\r\n":
                out.append(" ")
                index += 1
            continue
        if char == "/" and next_char == "*":
            out.extend((" ", " "))
            index += 2
            while index < len(text):
                if text[index:index + 2] == "*/":
                    out.extend((" ", " "))
                    index += 2
                    break
                out.append("\n" if text[index] == "\n" else " ")
                index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _statement_rows(text: str, scrubbed: str) -> list[dict[str, Any]]:
    statements: list[dict[str, Any]] = []
    offset = 0
    while offset <= len(scrubbed):
        boundary = scrubbed.find(";", offset)
        if boundary < 0:
            boundary = len(scrubbed)
        part = scrubbed[offset:boundary]
        raw = part.strip()
        if raw:
            if len(statements) >= MAX_SQL_STATEMENTS:
                raise DatabaseIntelligenceError(
                    "SQL artifact exceeds the statement-count boundary")
            tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_$]*", raw)
            keyword = tokens[0].upper() if tokens else "UNKNOWN"
            effective = keyword
            nested_write_keywords: set[str] = set()
            nested_destructive_keywords: set[str] = set()
            if keyword == "WITH":
                depth = 0
                for token_match in re.finditer(
                        r"[A-Za-z_][A-Za-z0-9_$]*|[()]",
                        raw):
                    token = token_match.group(0)
                    if token == "(":
                        depth += 1
                        continue
                    if token == ")":
                        depth = max(0, depth - 1)
                        continue
                    candidate = token.upper()
                    if depth > 0 and candidate in (
                            _WRITE_KEYWORDS | {"MERGE"}):
                        nested_write_keywords.add(candidate)
                    if depth > 0 and candidate in _DESTRUCTIVE_KEYWORDS:
                        nested_destructive_keywords.add(candidate)
                    if (depth == 0 and candidate != "WITH" and
                            candidate in _WRITE_KEYWORDS | {
                                "MERGE", "SELECT", "VALUES"}):
                        effective = candidate
                        break
            statements.append({
                "ordinal": len(statements) + 1,
                "keyword": keyword,
                "effective_keyword": effective,
                "writes_data_or_schema": (
                    effective in _WRITE_KEYWORDS | {"MERGE"}
                    or bool(nested_write_keywords)),
                "destructive": (
                    effective in _DESTRUCTIVE_KEYWORDS
                    or bool(nested_destructive_keywords)),
                "nested_write_keywords": sorted(
                    nested_write_keywords),
                "nested_destructive_keywords": sorted(
                    nested_destructive_keywords),
                "statement_sha256": hashlib.sha256(
                    text[offset:boundary].encode("utf-8")).hexdigest(),
            })
        if boundary == len(scrubbed):
            break
        offset = boundary + 1
    return statements


def inspect_sql_file(
    value: str | os.PathLike[str],
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    """Statically understand a SQL schema/migration; never execute it."""
    path = _regular_file(value, MAX_SQL_BYTES)
    data, digest, stable_snapshot = _read_bound_bytes(
        path, expected_sha256, MAX_SQL_BYTES)
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeError as exc:
        raise DatabaseIntelligenceError(
            "SQL artifact must be bounded UTF-8 text") from exc
    scrubbed = _strip_literals_and_comments(text)
    statements = _statement_rows(text, scrubbed)
    comment_free = _strip_comments_preserve_literals(text)
    privileged = [
        marker for marker, pattern in _PRIVILEGED_PATTERNS
        if pattern.search(
            comment_free if marker == "credential-literal" else scrubbed)
    ]
    depth = 0
    ordered = True
    saw_transaction = False
    for row in statements:
        keyword = row["effective_keyword"]
        if keyword in {"BEGIN", "START"}:
            depth += 1
            saw_transaction = True
        elif keyword in {"COMMIT", "ROLLBACK"}:
            if depth <= 0:
                ordered = False
            else:
                depth -= 1
    transaction_balanced = saw_transaction and ordered and depth == 0
    if _snapshot(path) != stable_snapshot or _sha_file(path, MAX_SQL_BYTES) != digest:
        raise DatabaseIntelligenceError(
            "SQL artifact changed during static inspection")
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "kind": "sql-file",
        "status": "lexically-classified",
        "artifact": {
            "path": str(path),
            "sha256": digest,
            "bytes": stable_snapshot[0],
        },
        "migration": {
            "statements": statements,
            "summary": {
                "statement_count": len(statements),
                "write_statement_count": sum(
                    row["writes_data_or_schema"] for row in statements),
                "destructive_statement_count": sum(
                    row["destructive"] for row in statements),
                "transaction_ordered_and_balanced": transaction_balanced,
            },
            "privileged_risk_markers": privileged,
            "analysis_contract": {
                "kind": "bounded-generic-lexical-classification",
                "dialect_parser_used": False,
                "known_limitations": [
                    "dialect-specific batch separators are not parsed",
                    "procedural or trigger bodies containing semicolons may split",
                    "nested CTE write tokens are conservative lexical risk signals",
                    "classification is not database validation",
                ],
            },
        },
        "boundaries": {
            "database_writes": False,
            "database_server_connected": False,
            "row_values_in_report": False,
            "source_sql_in_report": False,
            "supplied_sql_executed": False,
        },
    }


def understand(
    value: str | os.PathLike[str],
    *,
    expected_sha256: str,
) -> dict[str, Any]:
    """Dispatch one exact local artifact to a read-only understanding adapter."""
    path = _regular_file(value, MAX_DATABASE_BYTES)
    try:
        with path.open("rb") as handle:
            magic = handle.read(len(SQLITE_MAGIC))
    except OSError as exc:
        raise DatabaseIntelligenceError(
            "database artifact could not be classified") from exc
    if magic == SQLITE_MAGIC or path.suffix.casefold() in _SQLITE_SUFFIXES:
        return inspect_sqlite(path, expected_sha256=expected_sha256)
    if path.suffix.casefold() in _SQL_SUFFIXES:
        return inspect_sql_file(path, expected_sha256=expected_sha256)
    raise DatabaseIntelligenceError(
        "supported database artifacts are SQLite snapshots and SQL text files")


__all__ = [
    "DatabaseIntelligenceError",
    "MAX_DATABASE_BYTES",
    "MAX_SCHEMA_OBJECTS",
    "MAX_SQL_BYTES",
    "SCHEMA",
    "VERSION",
    "inspect_sql_file",
    "inspect_sqlite",
    "understand",
]
