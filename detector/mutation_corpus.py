#!/usr/bin/env python3
"""Persist the mutation gauntlet's verdicts as a labelled corpus.

``mutation_gauntlet.py`` already does the expensive part: it injects a known
defect, asks the deterministic engines whether they noticed, and knows exactly
which rule should have fired.  Today that judgement is used once, to print a
rule target, and is then discarded.  This module keeps it.

Three kinds of row are recorded, and the useful one is the third:

``baseline``
    The unmutated file.  Recorded as ``unmutated`` -- **not** as "clean".  Attestor
    reporting no finding is not proof that a file has no defect, and this corpus
    does not launder a scan result into a safety label.
``caught``
    A mutant the engines detected.  Confirms the rule works on that shape.
``survivor``
    A mutant with a *known* injected defect that the engines did not detect.
    These are the rows worth having.  Every one is a case the deterministic
    spine provably cannot express, labelled by construction rather than by
    opinion.

The store is content-addressed and deduplicating: recording the same example
twice is a no-op, so an evolve/harvest loop can run repeatedly without inflating
its own dataset.  Example identity excludes the timestamp, so identity is
reproducible across runs.

This module inspects no target, executes nothing, and contacts no network.  It
only writes the SQLite file it is given.

Provenance and licensing
------------------------
``harvest.py`` fetches real third-party source.  Recording that source stores a
copy, which is a redistribution question this module cannot answer for you.
Every row therefore carries a required non-empty ``provenance`` string, and
exports surface a notice.  Recording is opt-in everywhere; nothing writes a
corpus unless a caller supplies a path.
"""
from __future__ import annotations

import argparse
import datetime as _datetime
import hashlib
import json
import os
import sqlite3
import sys
from pathlib import Path
from typing import Any, Iterator, Mapping

import mutation_gauntlet

SCHEMA = "attestor.mutation-corpus/1.0"
VERSION = "4.1.4"

MAX_EXAMPLE_BYTES = 1024 * 1024
MAX_EXAMPLES = 200_000
MAX_DB_BYTES = 2 * 1024 * 1024 * 1024
MAX_TEXT = 320

BASELINE = "baseline"
CAUGHT = "caught"
SURVIVOR = "survivor"
DIFFICULTIES = frozenset({BASELINE, CAUGHT, SURVIVOR})

DEFECT_INJECTED = "defect-injected"
UNMUTATED = "unmutated"
LABELS = frozenset({DEFECT_INJECTED, UNMUTATED})

PROVENANCE_NOTICE = (
    "Rows may contain third-party source recorded from their stated provenance. "
    "Redistribution and training use are the operator's responsibility; this "
    "corpus asserts no license over recorded content.")


class MutationCorpusError(ValueError):
    """The corpus input, path, or stored state is unusable."""


def _sha_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha_value(value: Any) -> str:
    return hashlib.sha256(json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
        allow_nan=False).encode("utf-8")).hexdigest()


def _text(value: Any, maximum: int = MAX_TEXT) -> str:
    return value[:maximum] if type(value) is str else ""


def _now() -> str:
    return _datetime.datetime.now(
        _datetime.timezone.utc).replace(microsecond=0).isoformat()


def _language(path: str) -> str:
    return os.path.splitext(path)[1].lower() or ".py"


class MutationCorpus:
    """An append-only, content-addressed store of labelled mutation outcomes."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path).expanduser()
        if self.path.is_symlink():
            raise MutationCorpusError("corpus path is a link")
        if self.path.exists() and not self.path.is_file():
            raise MutationCorpusError("corpus path is not a regular file")
        self._connection: sqlite3.Connection | None = None
        self._open()

    # -- lifecycle ------------------------------------------------------- #
    def _open(self) -> None:
        connection = sqlite3.connect(str(self.path), timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        self._connection = connection
        with connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS blobs(
                    digest TEXT PRIMARY KEY,
                    bytes INTEGER NOT NULL,
                    payload BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS examples(
                    example_id TEXT PRIMARY KEY,
                    content_digest TEXT NOT NULL REFERENCES blobs(digest),
                    parent_digest TEXT NOT NULL,
                    language TEXT NOT NULL,
                    label TEXT NOT NULL,
                    difficulty TEXT NOT NULL,
                    mutator_id TEXT NOT NULL,
                    expected_rule TEXT NOT NULL,
                    detected INTEGER NOT NULL,
                    detected_rules TEXT NOT NULL,
                    introduced_rules TEXT NOT NULL,
                    provenance TEXT NOT NULL,
                    recorded_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS example_difficulty
                    ON examples(difficulty);
                CREATE INDEX IF NOT EXISTS example_rule
                    ON examples(expected_rule);
            """)

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    def __enter__(self) -> "MutationCorpus":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    @property
    def _db(self) -> sqlite3.Connection:
        if self._connection is None:
            raise MutationCorpusError("corpus is closed")
        return self._connection

    # -- writing --------------------------------------------------------- #
    def _check_capacity(self) -> None:
        if self.path.exists() and self.path.stat().st_size > MAX_DB_BYTES:
            raise MutationCorpusError("corpus exceeds its size boundary")
        count = int(self._db.execute(
            "SELECT COUNT(*) FROM examples").fetchone()[0])
        if count >= MAX_EXAMPLES:
            raise MutationCorpusError("corpus exceeds its example boundary")

    def _store_blob(self, source: str) -> str:
        payload = source.encode("utf-8")
        if len(payload) > MAX_EXAMPLE_BYTES:
            raise MutationCorpusError("example exceeds the per-example boundary")
        digest = _sha_bytes(payload)
        self._db.execute(
            "INSERT OR IGNORE INTO blobs(digest,bytes,payload) VALUES(?,?,?)",
            (digest, len(payload), payload))
        return digest

    def _insert(self, *, content: str, parent_digest: str, language: str,
                label: str, difficulty: str, mutator_id: str,
                expected_rule: str, detected: bool, detected_rules: list[str],
                introduced_rules: list[str], provenance: str,
                recorded_at: str) -> bool:
        if label not in LABELS:
            raise MutationCorpusError("unknown example label")
        if difficulty not in DIFFICULTIES:
            raise MutationCorpusError("unknown example difficulty")
        content_digest = self._store_blob(content)
        identity = {
            "content_digest": content_digest,
            "parent_digest": parent_digest,
            "label": label,
            "difficulty": difficulty,
            "mutator_id": mutator_id,
            "expected_rule": expected_rule,
        }
        example_id = _sha_value(identity)
        cursor = self._db.execute("""
            INSERT OR IGNORE INTO examples(
                example_id,content_digest,parent_digest,language,label,
                difficulty,mutator_id,expected_rule,detected,detected_rules,
                introduced_rules,provenance,recorded_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (example_id, content_digest, parent_digest, language, label,
              difficulty, mutator_id, expected_rule, 1 if detected else 0,
              json.dumps(sorted(detected_rules), separators=(",", ":")),
              json.dumps(sorted(introduced_rules), separators=(",", ":")),
              provenance, recorded_at))
        return cursor.rowcount > 0

    def record_gauntlet(self, result: Mapping[str, Any], source: str, *,
                        provenance: str, path: str = "",
                        recorded_at: str | None = None) -> dict[str, int]:
        """Record one ``mutation_gauntlet.run`` result plus its input source.

        The mutant bodies are re-derived deterministically from ``source`` so
        that the gauntlet's public result shape does not have to change.
        """
        if not isinstance(result, Mapping):
            raise MutationCorpusError("gauntlet result must be a mapping")
        if type(source) is not str:
            raise MutationCorpusError("source must be text")
        provenance = _text(provenance)
        if not provenance:
            raise MutationCorpusError(
                "a non-empty provenance is required for every recorded example")
        mutants = result.get("mutants")
        if type(mutants) is not list:
            raise MutationCorpusError("gauntlet result has no mutant list")

        self._check_capacity()
        stamp = _text(recorded_at, 64) or _now()
        target = _text(path or str(result.get("path", "")), MAX_TEXT)
        language = _language(target)
        bodies = {record["id"]: record["code"]
                  for record in mutation_gauntlet.mutate(source, language)}

        counts = {BASELINE: 0, CAUGHT: 0, SURVIVOR: 0, "duplicate": 0,
                  "unresolved": 0}
        with self._db:
            parent_digest = self._store_blob(source)
            added = self._insert(
                content=source, parent_digest="", language=language,
                label=UNMUTATED, difficulty=BASELINE, mutator_id="",
                expected_rule="", detected=False, detected_rules=[],
                introduced_rules=[], provenance=provenance, recorded_at=stamp)
            counts[BASELINE if added else "duplicate"] += 1

            for record in mutants:
                if not isinstance(record, Mapping):
                    raise MutationCorpusError("every mutant must be a mapping")
                mutator_id = _text(record.get("id"), 128)
                body = bodies.get(mutator_id)
                if body is None:
                    # A mutator the current build cannot reproduce; recording a
                    # label without its content would poison the corpus.
                    counts["unresolved"] += 1
                    continue
                detected = bool(record.get("caught"))
                difficulty = CAUGHT if detected else SURVIVOR
                added = self._insert(
                    content=body, parent_digest=parent_digest,
                    language=language, label=DEFECT_INJECTED,
                    difficulty=difficulty, mutator_id=mutator_id,
                    expected_rule=_text(record.get("expected_rule"), 128),
                    detected=detected,
                    detected_rules=[_text(item, 128) for item
                                    in (record.get("rules") or [])
                                    if type(item) is str],
                    introduced_rules=[_text(item, 128) for item
                                      in (record.get("introduced_rules") or [])
                                      if type(item) is str],
                    provenance=provenance, recorded_at=stamp)
                counts[difficulty if added else "duplicate"] += 1
        return counts

    # -- reading --------------------------------------------------------- #
    def stats(self) -> dict[str, Any]:
        rows = self._db.execute(
            "SELECT difficulty,COUNT(*) AS total FROM examples "
            "GROUP BY difficulty").fetchall()
        by_difficulty = {str(row["difficulty"]): int(row["total"])
                         for row in rows}
        survivors = self._db.execute(
            "SELECT expected_rule,COUNT(*) AS total FROM examples "
            "WHERE difficulty=? GROUP BY expected_rule ORDER BY total DESC,"
            "expected_rule", (SURVIVOR,)).fetchall()
        total = sum(by_difficulty.values())
        mutants = by_difficulty.get(CAUGHT, 0) + by_difficulty.get(SURVIVOR, 0)
        return {
            "schema": SCHEMA,
            "version": VERSION,
            "examples": total,
            "by_difficulty": by_difficulty,
            "detection_rate_percent": (
                round(100.0 * by_difficulty.get(CAUGHT, 0) / mutants, 1)
                if mutants else None),
            "survivors_by_rule": [
                {"expected_rule": str(row["expected_rule"]),
                 "examples": int(row["total"])} for row in survivors],
            "corpus_sha256": self.corpus_sha256(),
            "provenance_notice": PROVENANCE_NOTICE,
            "limitations": [
                "an 'unmutated' row is not labelled clean; no scan proves absence",
                "injected defects are synthetic and follow the mutator catalog",
                "a model trained only on this corpus learns the mutators",
            ],
        }

    def corpus_sha256(self) -> str:
        """Identity over example rows, independent of insertion order."""
        digests = [str(row["example_id"]) for row in self._db.execute(
            "SELECT example_id FROM examples ORDER BY example_id")]
        return _sha_value({"schema": SCHEMA, "examples": digests})

    def export(self, *, difficulty: str = "",
               include_content: bool = True) -> Iterator[dict[str, Any]]:
        """Yield rows as training-ready records, hardest class first."""
        if difficulty and difficulty not in DIFFICULTIES:
            raise MutationCorpusError("unknown difficulty filter")
        query = ("SELECT e.*,b.payload FROM examples e "
                 "JOIN blobs b ON b.digest=e.content_digest")
        parameters: tuple[Any, ...] = ()
        if difficulty:
            query += " WHERE e.difficulty=?"
            parameters = (difficulty,)
        # survivor < caught < baseline puts the informative rows first.
        query += (" ORDER BY CASE e.difficulty WHEN 'survivor' THEN 0"
                  " WHEN 'caught' THEN 1 ELSE 2 END, e.example_id")
        for row in self._db.execute(query, parameters):
            record = {
                "example_id": str(row["example_id"]),
                "content_sha256": str(row["content_digest"]),
                "parent_sha256": str(row["parent_digest"]),
                "language": str(row["language"]),
                "label": str(row["label"]),
                "difficulty": str(row["difficulty"]),
                "mutator_id": str(row["mutator_id"]),
                "expected_rule": str(row["expected_rule"]),
                "detected_by_rules": bool(row["detected"]),
                "detected_rules": json.loads(str(row["detected_rules"])),
                "introduced_rules": json.loads(str(row["introduced_rules"])),
                "provenance": str(row["provenance"]),
            }
            if include_content:
                record["content"] = bytes(row["payload"]).decode(
                    "utf-8", "replace")
            yield record


def _cli_stats(corpus: MutationCorpus) -> int:
    print(json.dumps(corpus.stats(), indent=2, sort_keys=True))
    return 0


def _cli_export(corpus: MutationCorpus, args: argparse.Namespace) -> int:
    written = 0
    stream = (open(args.out, "w", encoding="utf-8", newline="\n")
              if args.out else sys.stdout)
    try:
        for record in corpus.export(difficulty=args.difficulty,
                                    include_content=not args.no_content):
            stream.write(json.dumps(record, sort_keys=True,
                                    ensure_ascii=True) + "\n")
            written += 1
    finally:
        if args.out:
            stream.close()
    if args.out:
        print("wrote %d example(s) -> %s" % (written, args.out))
        print(PROVENANCE_NOTICE)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("corpus", help="path to the corpus SQLite file")
    parser.add_argument("--stats", action="store_true",
                        help="print corpus statistics as JSON")
    parser.add_argument("--export", action="store_true",
                        help="write JSONL training records")
    parser.add_argument("--difficulty", default="",
                        choices=("", BASELINE, CAUGHT, SURVIVOR),
                        help="restrict the export to one class")
    parser.add_argument("--no-content", action="store_true",
                        help="export labels and digests without source text")
    parser.add_argument("--out", default="",
                        help="export destination (default: stdout)")
    args = parser.parse_args(argv)
    if not args.stats and not args.export:
        args.stats = True
    with MutationCorpus(args.corpus) as corpus:
        if args.stats:
            return _cli_stats(corpus)
        return _cli_export(corpus, args)


__all__ = [
    "SCHEMA", "VERSION", "BASELINE", "CAUGHT", "SURVIVOR", "DIFFICULTIES",
    "DEFECT_INJECTED", "UNMUTATED", "LABELS", "PROVENANCE_NOTICE",
    "MAX_EXAMPLE_BYTES", "MAX_EXAMPLES", "MutationCorpusError",
    "MutationCorpus",
]


if __name__ == "__main__":
    raise SystemExit(main())
