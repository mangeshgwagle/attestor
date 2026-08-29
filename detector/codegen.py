#!/usr/bin/env python3
"""
codegen.py -- AttestorVonLuneberg's code generator.

Not an LLM: a deterministic *scaffolding* generator (the Rails-scaffold / OpenAPI
-codegen family). Give it a spec of resources and it writes a complete, runnable,
zero-dependency Python service -- model + repository (parameterized SQLite, with
counting/existence/per-field finders, bulk create, transactions, and safe dynamic
filtering/sorting) + service (validation + pagination + cache-aside) + HTTP API +
a routing app.py (per-client rate limiting, request ids, health + metrics +
OpenAPI endpoints, request logging) + real security (PBKDF2 password hashing +
HS256 tokens) + accounts & a configurable auth guard (on by default) + a TTL cache + request metrics +
retry + validators + typed errors + a client + a management CLI + a seed script +
unit AND integration tests + CI workflow + Dockerfile + config -- **~4,000 lines**
across ~80 files in the default project.

It also ships a curated internal "batteries" library -- distinct, real engineering
(not per-resource repetition): a safe fluent query builder, a versioned migration
runner, a path router, a DI container, an event bus, a thread-pool job queue, a
circuit breaker, structured JSON logging, a Result type, and core data structures
(LRU cache, ring buffer, trie, priority queue) -- each with its own tests.

The default 4-resource demo is ~4,080 lines across ~83 files; `--resources N`
dials it (fixed library + ~425 lines per resource), so **N=20 emits ~10,840 lines
across ~163 files with a 289-test suite** -- all of it still passing both engines.

Everything it emits is written to pass BOTH of Attestor's engines -- the regex
detector AND the deepscan AST analyzer -- at zero findings: secrets come from the
environment, SQL is parameterized (dynamic filters use a column whitelist + bound
values), HTTP calls carry timeouts, hashing is PBKDF2-SHA256 (never md5/sha1), no
eval, no bare excepts, no mutable defaults, no dead code, no undefined names. He
writes it; he also signs off on it, twice.

    python3 codegen.py                     # generate the default demo service
    python3 codegen.py --out ./svc         # choose the output directory
    python3 codegen.py --spec spec.json    # your own resources
    python3 codegen.py --check             # generate, then run Attestor over the result
    python3 codegen.py --stdout-only       # just report the line count, write nothing

Spec JSON:  {"resources": [{"name": "User",
                            "fields": {"name": "str", "email": "str", "age": "int"}}]}
"""
from __future__ import annotations

import argparse
import json
import keyword
import os
import shutil
import subprocess
import sys
import unicodedata
from string import Template

TYPE_PY = {"str": "str", "int": "int", "float": "float", "bool": "bool"}
TYPE_SQL = {"str": "TEXT", "int": "INTEGER", "float": "REAL", "bool": "INTEGER"}
TYPE_DEFAULT = {"str": '""', "int": "0", "float": "0.0", "bool": "False"}
TYPE_SAMPLE = {"str": '"example"', "int": "1", "float": "1.5", "bool": "True"}
GENERATED_VERSION = "3.1.0"
GENERATED_MIN_PYTHON = "3.8"
_GENERATION_MARKER = ".attestor-generated.json"
_GENERATION_SCHEMA = "attestor-codegen-inventory/1.0"
_MAX_GENERATED_PATHS = 10_000

DEFAULT_SPEC = {
    "resources": [
        {"name": "User", "fields": {"name": "str", "email": "str",
                                    "age": "int", "active": "bool"}},
        {"name": "Post", "fields": {"title": "str", "body": "str",
                                    "author_id": "int", "views": "int"}},
        {"name": "Comment", "fields": {"post_id": "int", "author": "str",
                                       "text": "str"}},
        {"name": "Tag", "fields": {"label": "str", "slug": "str"}},
    ]
}

_FIELD_SETS = [
    {"name": "str", "email": "str", "age": "int", "active": "bool"},
    {"title": "str", "body": "str", "author_id": "int", "views": "int"},
    {"sku": "str", "price": "float", "qty": "int", "in_stock": "bool"},
    {"label": "str", "slug": "str", "weight": "float"},
]

# Vocabulary for `varied_spec`. `big_spec` cycles four field sets, so every
# fourth resource is field-identical and the generated project repeats itself:
# measured at 400 resources, only 15.1% of the emitted lines were distinct.
# Field names are what the templates interpolate most often, so widening the
# pool of names is what widens the output.
_NOUN_POOL = (
    "Invoice", "Shipment", "Customer", "Ledger", "Warehouse", "Contract",
    "Payment", "Supplier", "Manifest", "Booking", "Tenant", "Policy",
    "Claim", "Route", "Vehicle", "Driver", "Depot", "Pallet", "Batch",
    "Inspection", "Permit", "Tariff", "Rebate", "Consignment", "Berth",
    "Voyage", "Charter", "Broker", "Premium", "Endorsement", "Adjuster",
    "Appraisal", "Escrow", "Lien", "Covenant", "Easement", "Parcel",
    "Zoning", "Survey", "Deed",
)

_FIELD_POOL = (
    ("reference", "str"), ("quantity", "int"), ("unit_price", "float"),
    ("issued_on", "str"), ("settled", "bool"), ("carrier", "str"),
    ("tonnage", "float"), ("origin", "str"), ("destination", "str"),
    ("eta_days", "int"), ("hazardous", "bool"), ("account_code", "str"),
    ("balance", "float"), ("currency", "str"), ("posted", "bool"),
    ("capacity", "int"), ("occupied", "int"), ("temperature", "float"),
    ("clause", "str"), ("term_months", "int"), ("renewable", "bool"),
    ("method", "str"), ("amount", "float"), ("cleared_on", "str"),
    ("contact", "str"), ("rating", "int"), ("preferred", "bool"),
    ("line_count", "int"), ("gross_weight", "float"), ("sealed", "bool"),
    ("starts_on", "str"), ("guests", "int"), ("cancelled", "bool"),
    ("plan", "str"), ("seats", "int"), ("trial", "bool"),
    ("excess", "float"), ("insured_sum", "float"), ("lapsed", "bool"),
    ("distance_km", "float"), ("stops", "int"), ("refrigerated", "bool"),
    ("plate", "str"), ("axles", "int"), ("licence", "str"),
    ("hours_driven", "float"), ("resting", "bool"), ("scenic", "bool"),
)

_RESERVED_RESOURCE_NAMES = {"account", "accounts"}
_RESERVED_FIELD_NAMES = {
    "id": "the generated primary key",
    "self": "generated method parameters",
    "validate": "the generated model API",
    "to_dict": "the generated model API",
}


def _normalized_identifier(value: str) -> str:
    """Return the filesystem/SQLite collision form used for spec validation."""
    return unicodedata.normalize("NFKC", value).casefold()


def validate_spec(spec: dict) -> None:
    """Fail fast, in plain English, instead of tracebacking mid-generation."""
    resources = spec.get("resources") if isinstance(spec, dict) else None
    if not isinstance(resources, list) or not resources:
        raise ValueError('spec needs a non-empty "resources" list, e.g. '
                         '{"resources": [{"name": "User", "fields": {"name": "str"}}]}')
    seen_resources = {}
    for res in resources:
        name = res.get("name") if isinstance(res, dict) else None
        if not isinstance(name, str) or not name.isidentifier() or not name[0].isalpha():
            raise ValueError(f"resource name {name!r} must be a valid identifier "
                             "starting with a letter (it becomes class/module names)")
        if keyword.iskeyword(name) or keyword.iskeyword(name.lower()):
            raise ValueError(f"resource name {name!r} is a Python keyword")
        normalized_name = _normalized_identifier(name)
        if normalized_name in _RESERVED_RESOURCE_NAMES:
            raise ValueError(
                f"resource name {name!r} is reserved by the built-in accounts subsystem")
        previous = seen_resources.get(normalized_name)
        if previous is not None:
            raise ValueError(
                f"resource names {previous!r} and {name!r} normalize to the same name")
        seen_resources[normalized_name] = name
        fields = res.get("fields")
        if not isinstance(fields, dict) or not fields:
            raise ValueError(f"resource {name!r} needs a non-empty 'fields' dict")
        seen_fields = {}
        for fn, ft in fields.items():
            if not isinstance(fn, str) or not fn.isidentifier():
                raise ValueError(f"{name}.{fn!r} is not a valid field name")
            if keyword.iskeyword(fn):
                raise ValueError(f"{name}.{fn!r} is a Python keyword")
            normalized_field = _normalized_identifier(fn)
            reserved_for = _RESERVED_FIELD_NAMES.get(normalized_field)
            if reserved_for is not None:
                raise ValueError(
                    f"{name}.{fn!r} is reserved for {reserved_for}")
            previous_field = seen_fields.get(normalized_field)
            if previous_field is not None:
                raise ValueError(
                    f"fields {name}.{previous_field!r} and {name}.{fn!r} "
                    "normalize to the same name")
            seen_fields[normalized_field] = fn
            if not isinstance(ft, str) or ft not in TYPE_PY:
                raise ValueError(f"{name}.{fn}: unknown type {ft!r} "
                                 f"(supported: {', '.join(sorted(TYPE_PY))})")


def big_spec(n: int) -> dict:
    """Build a spec of N standard resources -- a simple way to dial the line
    count. The fixed infrastructure is written once; each resource adds ~425
    lines, so N=20 lands around 10k."""
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("resource count must be a positive integer")
    resources = [{"name": "Entity%d" % i,
                  "fields": dict(_FIELD_SETS[i % len(_FIELD_SETS)])}
                 for i in range(1, n + 1)]
    return {"resources": resources}


def varied_spec(n: int, seed: int = 0) -> dict:
    """A spec of N resources that genuinely differ from one another.

    `big_spec` exists to dial the *line count* and does that well, but it
    cycles four field sets, so the project it describes says the same thing
    over and over: at 400 resources only 15.1% of generated lines were
    distinct, and `self.service.create(self._sample())` appeared 2,000 times.

    Here each resource draws a different number of fields (three to eight)
    from a much wider pool, at a stride that changes per resource, so two
    resources rarely share a field list even when they share a field. Names
    come from a domain vocabulary rather than Entity1..EntityN, because the
    templates interpolate the name into classes, tables, routes and tests --
    it is the single most-repeated token in the output.

    Deterministic on purpose: same `n` and `seed`, same spec, every time. A
    generator that produced different code per run could not be diffed, and
    a scaffold you cannot diff is one you cannot review.
    """
    if isinstance(n, bool) or not isinstance(n, int) or n < 1:
        raise ValueError("resource count must be a positive integer")

    resources = []
    for index in range(n):
        stem = _NOUN_POOL[index % len(_NOUN_POOL)]
        cycle = index // len(_NOUN_POOL)
        name = stem if cycle == 0 else "%s%d" % (stem, cycle + 1)

        # Three to eight fields, starting somewhere different each time and
        # stepping by a stride coprime-ish to the pool, so consecutive
        # resources overlap in fields without repeating a whole field list.
        count = 3 + (index * 5 + seed) % 6
        start = (index * 7 + seed) % len(_FIELD_POOL)
        stride = 1 + (index * 3 + seed) % 5

        fields: dict[str, str] = {}
        step = 0
        while len(fields) < count and step < len(_FIELD_POOL):
            field_name, field_type = _FIELD_POOL[
                (start + step * stride) % len(_FIELD_POOL)]
            if field_name not in _RESERVED_FIELD_NAMES:
                fields[field_name] = field_type
            step += 1
        resources.append({"name": name, "fields": fields})

    return {"resources": resources}


class Resource:
    def __init__(self, name: str, fields: dict):
        self.Name = name                      # "User"
        self.module = name.lower()            # "user"
        self.table = name.lower() + "s"       # "users"
        self.fields = list(fields.items())    # [("name","str"), ...]

    def sub(self, **extra) -> dict:
        d = {"Name": self.Name, "name": self.module,
             "module": self.module, "table": self.table}
        d.update(extra)
        return d


# --------------------------------------------------------------------------- #
# Templates ($-substitution, so literal { } in the generated code pass through)
# --------------------------------------------------------------------------- #
MODEL = Template('''"""$Name model -- generated by AttestorVonLuneberg codegen."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Optional
$validator_import


@dataclass
class $Name:
    id: Optional[int] = None
$field_decls

    def validate(self) -> list:
        errors = []
$validations
        return errors

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "$Name":
        return cls(
$from_dict_args
        )

    @classmethod
    def from_row(cls, row) -> "$Name":
        return cls(
            id=row[0],
$from_row_args
        )
''')

REPO = Template('''"""$Name repository -- SQLite persistence with parameterized queries."""
from __future__ import annotations

from typing import List, Optional

from models.$module import $Name


class ${Name}Repository:
    _COLUMNS = ($columns_tuple)
    _SELECT = "$select_cols"

    def __init__(self, db):
        self._db = db

    def create(self, item: $Name) -> $Name:
        cur = self._db.execute(
            "INSERT INTO $table ($col_names) VALUES ($placeholders)",
            ($insert_values),
        )
        item.id = cur.lastrowid
        self._db.commit()
        return item

    def get(self, item_id: int) -> Optional[$Name]:
        row = self._db.execute(
            "SELECT $select_cols FROM $table WHERE id = ?", (item_id,)
        ).fetchone()
        return $Name.from_row(row) if row else None

    def list(self, limit: int = 100, offset: int = 0) -> List[$Name]:
        rows = self._db.execute(
            "SELECT $select_cols FROM $table ORDER BY id LIMIT ? OFFSET ?",
            (limit, offset),
        ).fetchall()
        return [$Name.from_row(r) for r in rows]

    def update(self, item: $Name) -> Optional[$Name]:
        self._db.execute(
            "UPDATE $table SET $update_set WHERE id = ?",
            ($update_values),
        )
        self._db.commit()
        return self.get(item.id)

    def delete(self, item_id: int) -> bool:
        cur = self._db.execute("DELETE FROM $table WHERE id = ?", (item_id,))
        self._db.commit()
        return cur.rowcount > 0

    def count(self) -> int:
        row = self._db.execute("SELECT COUNT(*) FROM $table").fetchone()
        return int(row[0]) if row else 0

    def exists(self, item_id: int) -> bool:
        row = self._db.execute(
            "SELECT 1 FROM $table WHERE id = ? LIMIT 1", (item_id,)
        ).fetchone()
        return row is not None

    def create_many(self, items: List[$Name]) -> List[$Name]:
        return [self.create(item) for item in items]

    def query(self, filters=None, sort=None, order="asc",
              limit: int = 100, offset: int = 0) -> List[$Name]:
        """Filter/sort safely: column names are validated against the known
        column whitelist (never interpolated blindly) and every value is bound
        through a ? placeholder, so there is no injection surface."""
        filters = filters or {}
        conditions = []
        params = []
        for column in filters:
            if column in self._COLUMNS:
                conditions.append(column + " = ?")
                params.append(filters[column])
        where = ""
        if conditions:
            where = " WHERE " + " AND ".join(conditions)
        sort_column = sort if sort in self._COLUMNS else "id"
        direction = "DESC" if str(order).lower() == "desc" else "ASC"
        tail = " ORDER BY " + sort_column + " " + direction + " LIMIT ? OFFSET ?"
        sql = "SELECT " + self._SELECT + " FROM $table" + where + tail
        params.append(limit)
        params.append(offset)
        rows = self._db.execute(sql, tuple(params)).fetchall()
        return [$Name.from_row(r) for r in rows]
$finders''')

SERVICE = Template('''"""$Name service -- validation and business rules."""
from __future__ import annotations

from typing import List, Optional

from models.$module import $Name
from pagination import Page, clamp_limit
from repositories.${module}_repository import ${Name}Repository


class ValidationError(Exception):
    def __init__(self, errors):
        super().__init__("; ".join(errors))
        self.errors = errors


class ${Name}Service:
    def __init__(self, repository: ${Name}Repository, cache=None):
        self._repo = repository
        self._cache = cache

    def create(self, data: dict) -> $Name:
        item = $Name.from_dict(data)
        errors = item.validate()
        if errors:
            raise ValidationError(errors)
        return self._repo.create(item)

    def get(self, item_id: int) -> Optional[$Name]:
        if self._cache is not None:
            cached = self._cache.get(item_id)
            if cached is not None:
                return cached
        item = self._repo.get(item_id)
        if item is not None and self._cache is not None:
            self._cache.set(item_id, item)
        return item

    def list(self, limit: int = 100, offset: int = 0) -> List[$Name]:
        return self._repo.list(clamp_limit(limit), max(offset, 0))

    def paginate(self, page: int = 1, per_page: int = 20) -> Page:
        per_page = clamp_limit(per_page)
        page = max(page, 1)
        offset = (page - 1) * per_page
        items = self._repo.list(per_page, offset)
        return Page([i.to_dict() for i in items], page, per_page, self._repo.count())

    def search(self, filters=None, sort=None, order="asc",
               page: int = 1, per_page: int = 20) -> Page:
        per_page = clamp_limit(per_page)
        page = max(page, 1)
        offset = (page - 1) * per_page
        items = self._repo.query(filters, sort, order, per_page, offset)
        return Page([i.to_dict() for i in items], page, per_page, self._repo.count())

    def count(self) -> int:
        return self._repo.count()

    def exists(self, item_id: int) -> bool:
        return self._repo.exists(item_id)

    def update(self, item_id: int, data: dict) -> Optional[$Name]:
        existing = self._repo.get(item_id)
        if existing is None:
            return None
        merged = existing.to_dict()
        merged.update(data)
        updated = $Name.from_dict(merged)
        updated.id = item_id
        errors = updated.validate()
        if errors:
            raise ValidationError(errors)
        result = self._repo.update(updated)
        if self._cache is not None:
            self._cache.invalidate(item_id)
        return result

    def delete(self, item_id: int) -> bool:
        removed = self._repo.delete(item_id)
        if removed and self._cache is not None:
            self._cache.invalidate(item_id)
        return removed
''')

API = Template('''"""$Name HTTP handlers -- framework-free (status, body) pairs."""
from __future__ import annotations

from services.${module}_service import ${Name}Service, ValidationError


def _as_int(value, fallback: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return fallback


class ${Name}Handler:
    def __init__(self, service: ${Name}Service):
        self._service = service

    def create(self, payload: dict):
        try:
            item = self._service.create(payload)
        except ValidationError as exc:
            return 400, {"errors": exc.errors}
        return 201, item.to_dict()

    def get(self, item_id: int):
        item = self._service.get(item_id)
        if item is None:
            return 404, {"error": "$name not found"}
        return 200, item.to_dict()

    _RESERVED = ("page", "per_page", "sort", "order")

    def list(self, query=None):
        query = query or {}
        filters = {k: v for k, v in query.items() if k not in self._RESERVED}
        if filters or "sort" in query:
            page = _as_int(query.get("page"), 1)
            per_page = _as_int(query.get("per_page"), 20)
            result = self._service.search(
                filters, query.get("sort"), query.get("order", "asc"), page, per_page)
            return 200, result.to_dict()
        if "page" in query or "per_page" in query:
            page = _as_int(query.get("page"), 1)
            per_page = _as_int(query.get("per_page"), 20)
            return 200, self._service.paginate(page, per_page).to_dict()
        items = [i.to_dict() for i in self._service.list()]
        return 200, {"items": items, "total": self._service.count()}

    def update(self, item_id: int, payload: dict):
        try:
            item = self._service.update(item_id, payload)
        except ValidationError as exc:
            return 400, {"errors": exc.errors}
        if item is None:
            return 404, {"error": "$name not found"}
        return 200, item.to_dict()

    def delete(self, item_id: int):
        if not self._service.delete(item_id):
            return 404, {"error": "$name not found"}
        return 204, {}
''')

TEST = Template('''"""Tests for the $Name stack -- generated."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import Database                                    # noqa: E402
from services.${module}_service import ${Name}Service       # noqa: E402
from repositories.${module}_repository import ${Name}Repository          # noqa: E402


class ${Name}ServiceTest(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.db.migrate()
        self.service = ${Name}Service(${Name}Repository(self.db))

    def _sample(self):
        return $sample_dict

    def test_create_and_get(self):
        created = self.service.create(self._sample())
        self.assertIsNotNone(created.id)
        fetched = self.service.get(created.id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.id, created.id)

    def test_list_returns_all(self):
        self.service.create(self._sample())
        self.service.create(self._sample())
        self.assertEqual(len(self.service.list()), 2)

    def test_update_changes_row(self):
        created = self.service.create(self._sample())
        updated = self.service.update(created.id, self._sample())
        self.assertIsNotNone(updated)
        self.assertEqual(updated.id, created.id)

    def test_update_missing_returns_none(self):
        self.assertIsNone(self.service.update(999, self._sample()))

    def test_delete_removes_row(self):
        created = self.service.create(self._sample())
        self.assertTrue(self.service.delete(created.id))
        self.assertIsNone(self.service.get(created.id))

    def test_delete_missing_returns_false(self):
        self.assertFalse(self.service.delete(999))

    def test_count_tracks_inserts(self):
        self.assertEqual(self.service.count(), 0)
        self.service.create(self._sample())
        self.service.create(self._sample())
        self.assertEqual(self.service.count(), 2)

    def test_exists(self):
        created = self.service.create(self._sample())
        self.assertTrue(self.service.exists(created.id))
        self.assertFalse(self.service.exists(999))

    def test_paginate_respects_per_page(self):
        for _ in range(3):
            self.service.create(self._sample())
        page = self.service.paginate(page=1, per_page=2)
        self.assertEqual(len(page.items), 2)
        self.assertEqual(page.total, 3)
        self.assertEqual(page.pages, 2)
        self.assertTrue(page.has_next)
        self.assertFalse(page.has_prev)

    def test_search_sort_desc(self):
        first = self.service.create(self._sample())
        second = self.service.create(self._sample())
        page = self.service.search(sort="id", order="desc")
        self.assertEqual(page.items[0]["id"], second.id)
        self.assertEqual(page.items[1]["id"], first.id)

    def test_search_rejects_unknown_sort_column(self):
        self.service.create(self._sample())
        # an unknown/injected sort column falls back to id -- never crashes
        page = self.service.search(sort="1; DROP TABLE x")
        self.assertEqual(len(page.items), 1)


if __name__ == "__main__":
    unittest.main()
''')

DB = Template('''"""SQLite database helper -- parameterized access only, thread-safe.

check_same_thread=False plus a lock serializes connection operations used by the
bounded threaded HTTP server; every application statement is parameterized.
"""
from __future__ import annotations

import contextlib
import sqlite3
import threading

SCHEMA = [
$schema_statements
]


class Database:
    def __init__(self, path: str = "app.db"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.RLock()

    def execute(self, sql: str, params=()):
        with self._lock:
            return self._conn.execute(sql, params)

    def commit(self) -> None:
        with self._lock:
            self._conn.commit()

    def rollback(self) -> None:
        with self._lock:
            self._conn.rollback()

    @contextlib.contextmanager
    def transaction(self):
        """Commit on clean exit, roll back on any exception."""
        with self._lock:
            try:
                yield self
            except Exception:
                self._conn.rollback()
                raise
            else:
                self._conn.commit()

    def migrate(self) -> None:
        with self._lock:
            for statement in SCHEMA:
                self._conn.execute(statement)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()
''')

CONFIG = Template('''"""Configuration -- values come from the environment, never source."""
import os
import secrets


def _positive_int(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise RuntimeError(name + " must be an integer") from exc
    if value <= 0:
        raise RuntimeError(name + " must be greater than zero")
    return value


DATABASE_PATH = os.environ.get("DATABASE_PATH", "app.db")
_SECRET_KEY_ENV = os.environ.get("SECRET_KEY")
SECRET_KEY = _SECRET_KEY_ENV or secrets.token_urlsafe(32)
SECRET_KEY_CONFIGURED = bool(_SECRET_KEY_ENV)
HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "8080"))
REQUEST_TIMEOUT = _positive_int("REQUEST_TIMEOUT", 30)
MAX_BODY_BYTES = _positive_int("MAX_BODY_BYTES", 1048576)
MAX_CONCURRENT_REQUESTS = _positive_int("MAX_CONCURRENT_REQUESTS", 32)
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "120"))
RATE_REFILL = float(os.environ.get("RATE_REFILL", "2.0"))
CACHE_TTL = float(os.environ.get("CACHE_TTL", "30"))
TOKEN_TTL = int(os.environ.get("TOKEN_TTL", "3600"))
REQUIRE_AUTH = os.environ.get("REQUIRE_AUTH", "true").lower() == "true"
LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
DEBUG = os.environ.get("DEBUG", "false").lower() == "true"
''')

APP = Template('''"""HTTP application -- stdlib http.server wiring every resource. Generated.

Routing, JSON I/O, per-client rate limiting, health + OpenAPI endpoints, and
request logging via middleware. build_server() is factored out so tests can boot
the whole stack on an ephemeral port.
"""
from __future__ import annotations

import json
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import config
import middleware
from accounts import AccountError, AccountRepository, AuthService
from cache import TTLCache
from db import Database
from errors import BadRequest, PayloadTooLarge, RequestTimeout
from health import HealthHandler
from metrics import Metrics
from openapi import build_spec
from ratelimit import RateLimiter
$imports_block


def build_handlers(db) -> dict:
    handlers = {}
$handler_wiring
    return handlers


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """A threaded server with a hard cap on live request-handler threads."""
    allow_reuse_address = True
    # Request threads must finish before server_close() returns.  In particular,
    # this keeps a test or embedding application from closing the shared database
    # while the last response is still being written.
    daemon_threads = False
    block_on_close = True

    def __init__(self, server_address, handler_class, request_timeout, max_workers):
        if request_timeout <= 0 or max_workers <= 0:
            raise ValueError("request_timeout and max_workers must be greater than zero")
        self.request_timeout = request_timeout
        self.max_workers = max_workers
        self.request_queue_size = max_workers
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        super().__init__(server_address, handler_class)

    def get_request(self):
        request, client_address = super().get_request()
        request.settimeout(self.request_timeout)
        return request, client_address

    def process_request(self, request, client_address):
        self._worker_slots.acquire()
        try:
            super().process_request(request, client_address)
        except Exception:
            self._worker_slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._worker_slots.release()


class RequestHandler(BaseHTTPRequestHandler):
    def _parse(self):
        parsed = urlparse(self.path)
        parts = [p for p in parsed.path.split("/") if p]
        query = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        return parts, query

    def _client_key(self) -> str:
        return self.client_address[0] if self.client_address else "unknown"

    def _body(self) -> dict:
        value = self.headers.get("Content-Length", "0")
        try:
            length = int(value)
        except ValueError as exc:
            raise BadRequest("invalid Content-Length header") from exc
        if length < 0:
            raise BadRequest("Content-Length cannot be negative")
        if length == 0:
            return {}
        if length > self.server.max_body_bytes:
            raise PayloadTooLarge(
                "request body exceeds %d bytes" % self.server.max_body_bytes)
        try:
            raw = self.rfile.read(length)
        except TimeoutError as exc:
            raise RequestTimeout("request body timed out") from exc
        if len(raw) != length:
            raise BadRequest("incomplete request body")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BadRequest("request body must be valid UTF-8 JSON") from exc
        if not isinstance(payload, dict):
            raise BadRequest("request body must be a JSON object")
        return payload

    def _discard_body(self) -> None:
        """Consume a bounded rejected body before this HTTP/1.0 socket closes.

        Closing a Windows TCP socket with unread receive data sends a reset.  A
        client can then lose an already-written 401 and see WinError 10053
        instead.  Only a single, valid Content-Length within the configured body
        limit is drained; malformed or oversized requests remain bounded.
        """
        values = self.headers.get_all("Content-Length") or []
        if len(values) != 1:
            return
        try:
            remaining = int(values[0])
        except ValueError:
            return
        if remaining <= 0 or remaining > self.server.max_body_bytes:
            return
        try:
            while remaining:
                chunk = self.rfile.read(min(remaining, 65536))
                if not chunk:
                    return
                remaining -= len(chunk)
        except (ConnectionError, TimeoutError):
            return

    def _send(self, status: int, payload: dict, request_id: str = "") -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if request_id:
            self.send_header("X-Request-ID", request_id)
        self.end_headers()
        if body:
            self.wfile.write(body)
            self.wfile.flush()

    def send_error(self, code, message=None, explain=None):
        """Keep errors from BaseHTTPRequestHandler JSON-shaped as well."""
        del explain
        default = self.responses.get(code, ("request failed",))[0]
        self._send(code, {"error": message or default})

    def _dispatch(self, method: str) -> None:
        request_id = uuid.uuid4().hex[:12]
        if not self.server.limiter.allow(self._client_key()):
            return self._send(429, {"error": "rate limit exceeded"}, request_id)
        parts, query = self._parse()
        status, payload = middleware.handle(
            method, self.path, lambda: self._route(method, parts, query),
            metrics=self.server.metrics, request_id=request_id)
        self._send(status, payload, request_id)

    def _authorized(self) -> bool:
        header = self.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return False
        try:
            self.server.auth.verify(header[7:])
        except ValueError:
            return False
        return True

    def _auth(self, parts, method):
        if method != "POST" or len(parts) < 2:
            return 404, {"error": "not found"}
        body = self._body()
        username = body.get("username", "")
        password = body.get("password", "")
        if parts[1] == "register":
            try:
                return 201, self.server.auth.register(username, password)
            except AccountError as exc:
                return 400, {"error": str(exc)}
        if parts[1] == "login":
            token = self.server.auth.authenticate(username, password)
            if token is None:
                return 401, {"error": "invalid credentials"}
            return 200, {"token": token}
        return 404, {"error": "not found"}

    def _route(self, method: str, parts, query):
        if not parts:
            return 200, {"service": "ok"}
        head = parts[0]
        if head == "health":
            if len(parts) > 1 and parts[1] == "ready":
                return self.server.health.ready()
            return self.server.health.live()
        if head == "openapi.json":
            return 200, self.server.spec
        if head == "metrics":
            return 200, self.server.metrics.snapshot()
        if head == "auth":
            return self._auth(parts, method)
        if head not in self.server.handlers:
            return 404, {"error": "unknown resource"}
        if self.server.require_auth and method in ("POST", "PUT", "DELETE") \
                and not self._authorized():
            self._discard_body()
            return 401, {"error": "authentication required"}
        handler = self.server.handlers[head]
        item_id = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None
        if method == "GET":
            return handler.list(query) if item_id is None else handler.get(item_id)
        if method == "POST":
            return handler.create(self._body())
        if item_id is None:
            return 404, {"error": "not found"}
        if method == "PUT":
            return handler.update(item_id, self._body())
        if method == "DELETE":
            return handler.delete(item_id)
        return 405, {"error": "method not allowed"}

    def do_GET(self):
        self._dispatch("GET")

    def do_POST(self):
        self._dispatch("POST")

    def do_PUT(self):
        self._dispatch("PUT")

    def do_DELETE(self):
        self._dispatch("DELETE")

    def log_message(self, *args):
        return


def _auth_settings(require_auth, secret_key):
    effective_require_auth = config.REQUIRE_AUTH if require_auth is None else require_auth
    effective_secret = secret_key if secret_key is not None else config.SECRET_KEY
    if effective_require_auth and secret_key is None and not config.SECRET_KEY_CONFIGURED:
        raise RuntimeError("SECRET_KEY must be set when REQUIRE_AUTH=true")
    if effective_require_auth and (not isinstance(effective_secret, str)
                                   or len(effective_secret.encode("utf-8")) < 32):
        raise RuntimeError("SECRET_KEY must contain at least 32 bytes")
    return effective_require_auth, effective_secret


def _server_limits(overrides):
    unknown = sorted(set(overrides) - {
        "request_timeout", "max_body_bytes", "max_workers"})
    if unknown:
        raise TypeError("unknown server option(s): " + ", ".join(unknown))
    request_timeout = overrides.get("request_timeout")
    max_body_bytes = overrides.get("max_body_bytes")
    max_workers = overrides.get("max_workers")
    effective_timeout = (config.REQUEST_TIMEOUT if request_timeout is None
                         else request_timeout)
    effective_body_limit = (config.MAX_BODY_BYTES if max_body_bytes is None
                            else max_body_bytes)
    effective_workers = (config.MAX_CONCURRENT_REQUESTS if max_workers is None
                         else max_workers)
    if effective_body_limit <= 0:
        raise ValueError("max_body_bytes must be greater than zero")
    return effective_timeout, effective_body_limit, effective_workers


def build_server(db=None, host=None, port=None, require_auth=None, secret_key=None,
                 **limits) -> BoundedThreadingHTTPServer:
    bind_host = host if host is not None else config.HOST
    bind_port = port if port is not None else config.PORT
    effective_require_auth, effective_secret = _auth_settings(require_auth, secret_key)
    effective_timeout, effective_body_limit, effective_workers = _server_limits(limits)
    if db is None:
        db = Database(config.DATABASE_PATH)
    db.migrate()
    server = BoundedThreadingHTTPServer(
        (bind_host, bind_port), RequestHandler, effective_timeout, effective_workers)
    server.max_body_bytes = effective_body_limit
    server.handlers = build_handlers(db)
    server.health = HealthHandler(db)
    server.spec = build_spec(bind_host, bind_port)
    server.limiter = RateLimiter(config.RATE_LIMIT, config.RATE_REFILL)
    server.metrics = Metrics()
    server.auth = AuthService(AccountRepository(db), effective_secret, config.TOKEN_TTL)
    server.require_auth = effective_require_auth
    server.db = db
    return server


def main():
    server = build_server()
    print("serving on %s:%d" % (config.HOST, config.PORT))
    try:
        server.serve_forever()
    finally:
        server.server_close()
        server.db.close()


if __name__ == "__main__":
    main()
''')

CLIENT_BASE = Template('''"""Generated HTTP clients -- stdlib urllib, always with a timeout."""
from __future__ import annotations

import json
import urllib.request


class _BaseClient:
    def __init__(self, base_url="http://127.0.0.1:8080", timeout=30):
        self._base = base_url.rstrip("/")
        self._timeout = timeout

    def _request(self, method, path, payload=None):
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        req = urllib.request.Request(self._base + path, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=self._timeout) as resp:
            body = resp.read().decode("utf-8")
        return json.loads(body) if body else {}

$client_classes''')

CLIENT_CLASS = Template('''class ${Name}Client(_BaseClient):
    def create(self, payload):
        return self._request("POST", "/$table", payload)

    def get(self, item_id):
        return self._request("GET", "/$table/%d" % item_id)

    def list(self):
        return self._request("GET", "/$table")

    def update(self, item_id, payload):
        return self._request("PUT", "/$table/%d" % item_id, payload)

    def delete(self, item_id):
        return self._request("DELETE", "/$table/%d" % item_id)
''')


# --------------------------------------------------------------------------- #
# Cross-cutting infrastructure (generated once per service, not per resource)
# --------------------------------------------------------------------------- #
PAGINATION = Template('''"""Pagination helpers -- a Page value object and a safe limit clamp."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

MAX_PER_PAGE = 200


def clamp_limit(limit) -> int:
    """Keep page sizes sane: at least 1, never above MAX_PER_PAGE."""
    try:
        value = int(limit)
    except (TypeError, ValueError):
        return 20
    return max(1, min(value, MAX_PER_PAGE))


@dataclass
class Page:
    items: List[dict] = field(default_factory=list)
    page: int = 1
    per_page: int = 20
    total: int = 0

    @property
    def pages(self) -> int:
        if self.per_page <= 0:
            return 0
        return (self.total + self.per_page - 1) // self.per_page

    @property
    def has_next(self) -> bool:
        return self.page < self.pages

    @property
    def has_prev(self) -> bool:
        return self.page > 1

    def to_dict(self) -> dict:
        return {
            "items": self.items,
            "page": self.page,
            "per_page": self.per_page,
            "total": self.total,
            "pages": self.pages,
            "has_next": self.has_next,
            "has_prev": self.has_prev,
        }
''')

ERRORS = Template('''"""Typed API errors, each mapped to an HTTP status code."""
from __future__ import annotations


class ApiError(Exception):
    status = 500

    def __init__(self, message, status=None):
        super().__init__(message)
        self.message = message
        if status is not None:
            self.status = status

    def to_dict(self) -> dict:
        return {"error": self.message}


class BadRequest(ApiError):
    status = 400


class Unauthorized(ApiError):
    status = 401


class RequestTimeout(ApiError):
    status = 408


class PayloadTooLarge(ApiError):
    status = 413


class NotFound(ApiError):
    status = 404


class RateLimited(ApiError):
    status = 429
''')

SECURITY = Template('''"""Password hashing (PBKDF2-HMAC-SHA256) and stateless HS256 tokens.

Standard library only -- no third-party crypto. Secrets are supplied by the
caller (ultimately from the environment); nothing sensitive is hard-coded.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

_ITERATIONS = 120_000
_SALT_BYTES = 16


def hash_password(password: str, salt: bytes = b"") -> str:
    """Return 'salt$$hash', both base64. A fresh random salt is used unless one
    is supplied (supplying one is only for verification)."""
    if not salt:
        salt = os.urandom(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return base64.b64encode(salt).decode() + "$$" + base64.b64encode(derived).decode()


def verify_password(password: str, stored: str) -> bool:
    parts = stored.split("$$", 1)
    if len(parts) != 2:
        return False
    salt = base64.b64decode(parts[0])
    expected = base64.b64decode(parts[1])
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, _ITERATIONS)
    return hmac.compare_digest(derived, expected)


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def issue_token(secret: str, subject: str, ttl_seconds: int = 3600) -> str:
    """Mint a signed HS256 token: base64url(header).base64url(claims).base64url(sig)."""
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode("utf-8"))
    now = int(time.time())
    claims = {"sub": subject, "iat": now, "exp": now + ttl_seconds}
    payload = _b64url(json.dumps(claims).encode("utf-8"))
    signing_input = (header + "." + payload).encode("ascii")
    signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return header + "." + payload + "." + _b64url(signature)


def verify_token(secret: str, token: str) -> dict:
    """Return the claims if the signature is valid and the token has not expired,
    otherwise raise ValueError."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("malformed token")
    header, payload, signature = parts
    signing_input = (header + "." + payload).encode("ascii")
    expected = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    if not hmac.compare_digest(_b64url_decode(signature), expected):
        raise ValueError("bad signature")
    claims = json.loads(_b64url_decode(payload))
    if int(claims.get("exp", 0)) < int(time.time()):
        raise ValueError("token expired")
    return claims
''')

RATELIMIT = Template('''"""In-memory token-bucket rate limiter, keyed per client."""
from __future__ import annotations

import threading
import time


class TokenBucket:
    def __init__(self, capacity: int = 60, refill_per_second: float = 1.0):
        self._capacity = float(capacity)
        self._refill = refill_per_second
        self._tokens = float(capacity)
        self._updated = time.monotonic()
        self._lock = threading.Lock()

    def allow(self, cost: float = 1.0) -> bool:
        with self._lock:
            now = time.monotonic()
            self._tokens = min(
                self._capacity, self._tokens + (now - self._updated) * self._refill)
            self._updated = now
            if self._tokens >= cost:
                self._tokens -= cost
                return True
            return False


class RateLimiter:
    def __init__(self, capacity: int = 60, refill_per_second: float = 1.0):
        self._capacity = capacity
        self._refill = refill_per_second
        self._buckets = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = TokenBucket(self._capacity, self._refill)
                self._buckets[key] = bucket
        return bucket.allow()
''')

LOGGING_CONFIG = Template('''"""Standard logging configuration (idempotent)."""
from __future__ import annotations

import logging

_CONFIGURED = False


def configure_logging(level: str = "INFO") -> logging.Logger:
    global _CONFIGURED
    logger = logging.getLogger("service")
    if not _CONFIGURED:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        _CONFIGURED = True
    return logger
''')

MIDDLEWARE = Template('''"""Cross-cutting request handling: timing, logging, error mapping."""
from __future__ import annotations

import time

from errors import ApiError
from logging_config import configure_logging

_log = configure_logging()


def handle(method: str, path: str, action, metrics=None, request_id: str = "-"):
    """Run a zero-arg handler `action` returning (status, body); time it, record
    metrics, log it (with a correlation id), and turn known exceptions into clean
    (status, body) pairs."""
    start = time.monotonic()
    try:
        status, body = action()
    except ApiError as exc:
        status, body = exc.status, exc.to_dict()
    except (KeyError, ValueError) as exc:
        status, body = 400, {"error": str(exc)}
    except Exception:
        _log.exception("[%s] unhandled request failure", request_id)
        status, body = 500, {"error": "internal server error"}
    elapsed_ms = (time.monotonic() - start) * 1000.0
    if metrics is not None:
        metrics.observe(method, status, elapsed_ms)
    _log.info("[%s] %s %s -> %d (%.1fms)", request_id, method, path, status, elapsed_ms)
    return status, body
''')

HEALTH = Template('''"""Liveness and readiness endpoints."""
from __future__ import annotations

import time

_STARTED = time.monotonic()


class HealthHandler:
    def __init__(self, db):
        self._db = db

    def live(self):
        return 200, {"status": "ok",
                     "uptime_seconds": round(time.monotonic() - _STARTED, 3)}

    def ready(self):
        try:
            self._db.execute("SELECT 1").fetchone()
        except Exception as exc:
            return 503, {"status": "unready", "error": str(exc)}
        return 200, {"status": "ready"}
''')

OPENAPI = Template('''"""Build an OpenAPI 3.0 description of this service (stdlib only)."""
from __future__ import annotations

RESOURCES = $resources_meta


def _schema(fields: dict) -> dict:
    props = {"id": {"type": "integer"}}
    for name, kind in fields.items():
        props[name] = {"type": kind}
    return {"type": "object", "properties": props}


def build_spec(host: str = "127.0.0.1", port: int = 8080) -> dict:
    paths = {}
    schemas = {}
    for res in RESOURCES:
        name = res["name"]
        table = res["table"]
        schemas[name] = _schema(res["fields"])
        paths["/" + table] = {
            "get": {"summary": "List " + table,
                    "responses": {"200": {"description": "ok"}}},
            "post": {"summary": "Create " + name,
                     "responses": {"201": {"description": "created"}}},
        }
        paths["/" + table + "/{id}"] = {
            "get": {"summary": "Get " + name,
                    "responses": {"200": {"description": "ok"},
                                  "404": {"description": "missing"}}},
            "put": {"summary": "Update " + name,
                    "responses": {"200": {"description": "ok"}}},
            "delete": {"summary": "Delete " + name,
                       "responses": {"204": {"description": "gone"}}},
        }
    paths["/auth/register"] = {
        "post": {"summary": "Register an account",
                 "responses": {"201": {"description": "created"},
                               "400": {"description": "invalid"}}}}
    paths["/auth/login"] = {
        "post": {"summary": "Log in and receive a token",
                 "responses": {"200": {"description": "ok"},
                               "401": {"description": "denied"}}}}
    paths["/metrics"] = {
        "get": {"summary": "Service metrics",
                "responses": {"200": {"description": "ok"}}}}
    return {
        "openapi": "3.0.3",
        "info": {"title": "AttestorVonLuneberg generated service", "version": "1.0.0"},
        "servers": [{"url": "http://" + host + ":" + str(port)}],
        "paths": paths,
        "components": {"schemas": schemas},
    }
''')

SEED = Template('''"""Insert a handful of sample rows for local development."""
from __future__ import annotations

from db import Database
$seed_imports


def seed_all(db) -> int:
    inserted = 0
$seed_body
    return inserted


def main():
    db = Database()
    db.migrate()
    print("seeded %d rows" % seed_all(db))


if __name__ == "__main__":
    main()
''')

MANAGE = Template('''"""Management CLI: migrate, seed, routes, serve."""
from __future__ import annotations

import argparse

import config
from db import Database
from openapi import build_spec


def cmd_migrate(_args) -> int:
    Database(config.DATABASE_PATH).migrate()
    print("migrated " + config.DATABASE_PATH)
    return 0


def cmd_seed(_args) -> int:
    from seed import seed_all
    db = Database(config.DATABASE_PATH)
    db.migrate()
    print("seeded %d rows" % seed_all(db))
    return 0


def cmd_routes(_args) -> int:
    spec = build_spec()
    for path in sorted(spec["paths"]):
        methods = ",".join(sorted(m.upper() for m in spec["paths"][path]))
        print("%-24s %s" % (path, methods))
    return 0


def cmd_openapi(_args) -> int:
    import json
    print(json.dumps(build_spec(config.HOST, config.PORT), indent=2))
    return 0


def cmd_serve(_args) -> int:
    import app
    app.main()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="service management CLI")
    sub = parser.add_subparsers(dest="command")
    sub.required = True
    sub.add_parser("migrate").set_defaults(func=cmd_migrate)
    sub.add_parser("seed").set_defaults(func=cmd_seed)
    sub.add_parser("routes").set_defaults(func=cmd_routes)
    sub.add_parser("openapi").set_defaults(func=cmd_openapi)
    sub.add_parser("serve").set_defaults(func=cmd_serve)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
''')

SECURITY_TEST = Template('''"""Tests for the security module (hashing + tokens)."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import security                                              # noqa: E402


class SecurityTest(unittest.TestCase):
    def test_password_round_trip(self):
        stored = security.hash_password("correct horse")
        self.assertTrue(security.verify_password("correct horse", stored))
        self.assertFalse(security.verify_password("wrong", stored))

    def test_password_hash_is_salted(self):
        self.assertNotEqual(
            security.hash_password("same"), security.hash_password("same"))

    def test_token_round_trip(self):
        token = security.issue_token("secret", "user-1", ttl_seconds=60)
        self.assertEqual(security.verify_token("secret", token)["sub"], "user-1")

    def test_token_rejects_tampering(self):
        token = security.issue_token("secret", "user-1")
        with self.assertRaises(ValueError):
            security.verify_token("secret", token + "x")

    def test_token_rejects_wrong_secret(self):
        token = security.issue_token("secret", "user-1")
        with self.assertRaises(ValueError):
            security.verify_token("other", token)

    def test_expired_token(self):
        token = security.issue_token("secret", "user-1", ttl_seconds=-5)
        with self.assertRaises(ValueError):
            security.verify_token("secret", token)


if __name__ == "__main__":
    unittest.main()
''')

PAGINATION_TEST = Template('''"""Tests for pagination helpers."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from pagination import Page, clamp_limit, MAX_PER_PAGE       # noqa: E402


class PaginationTest(unittest.TestCase):
    def test_clamp_limit_bounds(self):
        self.assertEqual(clamp_limit(0), 1)
        self.assertEqual(clamp_limit(10), 10)
        self.assertEqual(clamp_limit(10 ** 9), MAX_PER_PAGE)
        self.assertEqual(clamp_limit("nonsense"), 20)

    def test_page_math(self):
        page = Page(items=[1, 2], page=2, per_page=2, total=5)
        self.assertEqual(page.pages, 3)
        self.assertTrue(page.has_next)
        self.assertTrue(page.has_prev)

    def test_page_to_dict(self):
        payload = Page(items=[], page=1, per_page=20, total=0).to_dict()
        self.assertEqual(payload["pages"], 0)
        self.assertFalse(payload["has_next"])


if __name__ == "__main__":
    unittest.main()
''')

RATELIMIT_TEST = Template('''"""Tests for the token-bucket rate limiter."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ratelimit import RateLimiter, TokenBucket               # noqa: E402


class RateLimitTest(unittest.TestCase):
    def test_bucket_allows_up_to_capacity(self):
        bucket = TokenBucket(capacity=3, refill_per_second=0.0)
        self.assertTrue(bucket.allow())
        self.assertTrue(bucket.allow())
        self.assertTrue(bucket.allow())
        self.assertFalse(bucket.allow())

    def test_limiter_is_per_key(self):
        limiter = RateLimiter(capacity=1, refill_per_second=0.0)
        self.assertTrue(limiter.allow("a"))
        self.assertFalse(limiter.allow("a"))
        self.assertTrue(limiter.allow("b"))


if __name__ == "__main__":
    unittest.main()
''')

CACHE = Template('''"""Thread-safe in-memory cache with per-entry TTL and bounded size."""
from __future__ import annotations

import threading
import time


class TTLCache:
    def __init__(self, ttl_seconds: float = 30.0, max_size: int = 1024):
        self._ttl = ttl_seconds
        self._max = max_size
        self._store = {}
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expires, value = entry
            if expires <= time.monotonic():
                self._store.pop(key, None)
                return None
            return value

    def set(self, key, value) -> None:
        with self._lock:
            if len(self._store) >= self._max and key not in self._store:
                self._evict_locked()
            self._store[key] = (time.monotonic() + self._ttl, value)

    def invalidate(self, key) -> None:
        with self._lock:
            self._store.pop(key, None)

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def _evict_locked(self) -> None:
        oldest = min(self._store, key=lambda k: self._store[k][0])
        self._store.pop(oldest, None)
''')

METRICS = Template('''"""Lightweight request metrics with Prometheus text exposition."""
from __future__ import annotations

import threading


class Metrics:
    def __init__(self):
        self._by_method = {}
        self._by_status = {}
        self._latency_sum = 0.0
        self._latency_count = 0
        self._lock = threading.Lock()

    def observe(self, method: str, status: int, elapsed_ms: float) -> None:
        with self._lock:
            self._by_method[method] = self._by_method.get(method, 0) + 1
            self._by_status[status] = self._by_status.get(status, 0) + 1
            self._latency_sum += elapsed_ms
            self._latency_count += 1

    def snapshot(self) -> dict:
        with self._lock:
            count = self._latency_count
            avg = self._latency_sum / count if count else 0.0
            return {
                "requests_total": count,
                "by_method": dict(self._by_method),
                "by_status": dict(self._by_status),
                "latency_ms_avg": round(avg, 3),
            }

    def prometheus(self) -> str:
        snap = self.snapshot()
        lines = ["# TYPE requests_total counter",
                 "requests_total %d" % snap["requests_total"]]
        for method, count in snap["by_method"].items():
            lines.append('requests_by_method{method="%s"} %d' % (method, count))
        for status, count in snap["by_status"].items():
            lines.append('requests_by_status{status="%d"} %d' % (status, count))
        lines.append("latency_ms_avg %f" % snap["latency_ms_avg"])
        return "\\n".join(lines) + "\\n"
''')

RETRY = Template('''"""A small retry decorator with exponential backoff (stdlib only)."""
from __future__ import annotations

import functools
import time


def retry(attempts: int = 3, base_delay: float = 0.0, exceptions=(Exception,)):
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            last = None
            for attempt in range(attempts):
                try:
                    return func(*args, **kwargs)
                except exceptions as exc:
                    last = exc
                    if attempt + 1 < attempts and base_delay > 0:
                        time.sleep(base_delay * (2 ** attempt))
            raise last if last is not None else RuntimeError("no attempts made")
        return wrapper
    return decorator
''')

VALIDATORS = Template('''"""Reusable field validators."""
from __future__ import annotations

import re

_EMAIL = re.compile(r"^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$$")


def is_email(value) -> bool:
    return isinstance(value, str) and _EMAIL.match(value) is not None


def non_empty(value) -> bool:
    return isinstance(value, str) and bool(value.strip())


def in_range(value, low, high) -> bool:
    try:
        return low <= value <= high
    except TypeError:
        return False
''')

CACHE_TEST = Template('''"""Tests for the TTL cache."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cache import TTLCache                                    # noqa: E402


class CacheTest(unittest.TestCase):
    def test_set_get(self):
        cache = TTLCache(ttl_seconds=10)
        cache.set("k", 42)
        self.assertEqual(cache.get("k"), 42)

    def test_miss_returns_none(self):
        self.assertIsNone(TTLCache().get("absent"))

    def test_expiry(self):
        cache = TTLCache(ttl_seconds=0.0)
        cache.set("k", 1)
        self.assertIsNone(cache.get("k"))

    def test_invalidate(self):
        cache = TTLCache()
        cache.set("k", 1)
        cache.invalidate("k")
        self.assertIsNone(cache.get("k"))

    def test_bounded_size(self):
        cache = TTLCache(ttl_seconds=100, max_size=2)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)
        self.assertLessEqual(len(cache._store), 2)


if __name__ == "__main__":
    unittest.main()
''')

METRICS_TEST = Template('''"""Tests for request metrics."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from metrics import Metrics                                   # noqa: E402


class MetricsTest(unittest.TestCase):
    def test_counts_and_average(self):
        m = Metrics()
        m.observe("GET", 200, 10.0)
        m.observe("GET", 404, 20.0)
        snap = m.snapshot()
        self.assertEqual(snap["requests_total"], 2)
        self.assertEqual(snap["by_method"]["GET"], 2)
        self.assertEqual(snap["by_status"][200], 1)
        self.assertEqual(snap["latency_ms_avg"], 15.0)

    def test_prometheus_exposition(self):
        m = Metrics()
        m.observe("POST", 201, 5.0)
        text = m.prometheus()
        self.assertIn("requests_total 1", text)
        self.assertIn("POST", text)


if __name__ == "__main__":
    unittest.main()
''')

RETRY_TEST = Template('''"""Tests for the retry decorator."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from retry import retry                                       # noqa: E402


class RetryTest(unittest.TestCase):
    def test_succeeds_after_failures(self):
        state = {"n": 0}

        @retry(attempts=3)
        def flaky():
            state["n"] += 1
            if state["n"] < 3:
                raise ValueError("not yet")
            return "ok"

        self.assertEqual(flaky(), "ok")
        self.assertEqual(state["n"], 3)

    def test_reraises_after_exhaustion(self):
        @retry(attempts=2)
        def always_fails():
            raise KeyError("nope")

        with self.assertRaises(KeyError):
            always_fails()


if __name__ == "__main__":
    unittest.main()
''')

VALIDATORS_TEST = Template('''"""Tests for field validators."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validators import in_range, is_email, non_empty          # noqa: E402


class ValidatorsTest(unittest.TestCase):
    def test_is_email(self):
        self.assertTrue(is_email("user@example.com"))
        self.assertFalse(is_email("nope"))
        self.assertFalse(is_email(123))

    def test_non_empty(self):
        self.assertTrue(non_empty("x"))
        self.assertFalse(non_empty("   "))

    def test_in_range(self):
        self.assertTrue(in_range(5, 1, 10))
        self.assertFalse(in_range(50, 1, 10))
        self.assertFalse(in_range("bad", 1, 10))


if __name__ == "__main__":
    unittest.main()
''')

ACCOUNTS = Template('''"""Account persistence + authentication (hashing and tokens via security.py)."""
from __future__ import annotations

from typing import Optional

import config
import security


class AccountError(Exception):
    pass


class AccountRepository:
    def __init__(self, db):
        self._db = db

    def create(self, username: str, password_hash: str) -> int:
        cur = self._db.execute(
            "INSERT INTO accounts (username, password_hash) VALUES (?, ?)",
            (username, password_hash),
        )
        self._db.commit()
        return cur.lastrowid

    def find_by_username(self, username: str):
        return self._db.execute(
            "SELECT id, username, password_hash FROM accounts WHERE username = ?",
            (username,),
        ).fetchone()


class AuthService:
    def __init__(self, repository: AccountRepository, secret: str = "",
                 token_ttl: int = 3600):
        self._repo = repository
        self._secret = secret or config.SECRET_KEY
        self._ttl = token_ttl

    def register(self, username: str, password: str) -> dict:
        if not username or not password:
            raise AccountError("username and password are required")
        if self._repo.find_by_username(username) is not None:
            raise AccountError("username already taken")
        account_id = self._repo.create(username, security.hash_password(password))
        return {"id": account_id, "username": username}

    def authenticate(self, username: str, password: str) -> Optional[str]:
        row = self._repo.find_by_username(username)
        if row is None or not security.verify_password(password, row[2]):
            return None
        return security.issue_token(self._secret, username, self._ttl)

    def verify(self, token: str) -> dict:
        return security.verify_token(self._secret, token)
''')

ACCOUNTS_TEST = Template('''"""Tests for account registration and authentication."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from accounts import AccountError, AccountRepository, AuthService  # noqa: E402
from db import Database                                             # noqa: E402


class AuthTest(unittest.TestCase):
    def setUp(self):
        db = Database(":memory:")
        db.migrate()
        self.auth = AuthService(AccountRepository(db), "unit-test-signing-key", 3600)

    def test_register_and_login(self):
        account = self.auth.register("alice", "s3cret-pass")
        self.assertEqual(account["username"], "alice")
        token = self.auth.authenticate("alice", "s3cret-pass")
        self.assertIsNotNone(token)
        self.assertEqual(self.auth.verify(token)["sub"], "alice")

    def test_wrong_password(self):
        self.auth.register("bob", "hunter2-ok")
        self.assertIsNone(self.auth.authenticate("bob", "wrong"))

    def test_unknown_user(self):
        self.assertIsNone(self.auth.authenticate("nobody", "whatever1"))

    def test_duplicate_username(self):
        self.auth.register("carol", "password-x")
        with self.assertRaises(AccountError):
            self.auth.register("carol", "another-1")

    def test_missing_fields(self):
        with self.assertRaises(AccountError):
            self.auth.register("", "")


if __name__ == "__main__":
    unittest.main()
''')

INTEGRATION_TEST = Template('''"""End-to-end: boot the real server on an ephemeral port, drive it via the client."""
import http.client
import json
import os
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app                                                   # noqa: E402
from client import ${First}Client                            # noqa: E402
from db import Database                                       # noqa: E402


class IntegrationTest(unittest.TestCase):
    @classmethod
    def _start_server(cls, server):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base = "http://127.0.0.1:%d" % server.server_address[1]
        deadline = time.monotonic() + 5.0
        last_error = None
        while time.monotonic() < deadline:
            if not thread.is_alive():
                raise AssertionError("integration server stopped during startup")
            try:
                with urllib.request.urlopen(
                        base + "/health/ready", timeout=0.5) as response:
                    raw = response.read()
                    if response.status != 200:
                        raise AssertionError(
                            "integration readiness returned HTTP %d" % response.status)
                try:
                    readiness = json.loads(raw.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise AssertionError(
                        "integration readiness returned invalid JSON") from exc
                if readiness != {"status": "ready"}:
                    raise AssertionError(
                        "integration readiness returned an invalid payload: %r" %
                        (readiness,))
                return thread
            except urllib.error.HTTPError as exc:
                details = exc.read().decode("utf-8", errors="replace")
                raise AssertionError(
                    "integration readiness returned HTTP %d: %s" %
                    (exc.code, details)) from exc
            except (OSError, urllib.error.URLError) as exc:
                last_error = exc
            time.sleep(0.02)
        raise AssertionError(
            "integration server did not become ready; last error: %r" %
            (last_error,)) from last_error

    @classmethod
    def setUpClass(cls):
        cls.server = app.build_server(
            Database(":memory:"), "127.0.0.1", 0, require_auth=False,
            request_timeout=5, max_body_bytes=1024, max_workers=4)
        cls.port = cls.server.server_address[1]
        cls.thread = cls._start_server(cls.server)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.server.shutdown()
        finally:
            cls.server.server_close()
            cls.thread.join(timeout=5)
            cls.server.db.close()
        if cls.thread.is_alive():
            raise AssertionError("integration server thread did not stop")

    def _base(self):
        return "http://127.0.0.1:%d" % self.port

    def test_crud_round_trip(self):
        client = ${First}Client(self._base(), timeout=5)
        created = client.create($first_sample)
        self.assertIn("id", created)
        self.assertEqual(client.get(created["id"])["id"], created["id"])
        self.assertGreaterEqual(client.list()["total"], 1)
        client.delete(created["id"])

    def test_health_and_openapi(self):
        with urllib.request.urlopen(self._base() + "/health", timeout=5) as resp:
            health = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(health["status"], "ok")
        with urllib.request.urlopen(self._base() + "/openapi.json", timeout=5) as resp:
            spec = json.loads(resp.read().decode("utf-8"))
        self.assertEqual(spec["openapi"], "3.0.3")

    def _post(self, path, payload):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(self._base() + path, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def test_auth_register_and_login(self):
        account = self._post("/auth/register",
                             {"username": "eve", "password": "p@ssword-1"})
        self.assertEqual(account["username"], "eve")
        body = self._post("/auth/login",
                          {"username": "eve", "password": "p@ssword-1"})
        self.assertIn("token", body)

    def test_metrics_endpoint(self):
        with urllib.request.urlopen(self._base() + "/metrics", timeout=5) as resp:
            metrics = json.loads(resp.read().decode("utf-8"))
        self.assertIn("requests_total", metrics)

    def test_server_limits_are_active(self):
        self.assertEqual(self.server.request_timeout, 5)
        self.assertEqual(self.server.max_body_bytes, 1024)
        self.assertEqual(self.server.max_workers, 4)

    def test_authenticated_server_rejects_a_weak_secret(self):
        db = Database(":memory:")
        try:
            with self.assertRaisesRegex(RuntimeError, "at least 32 bytes"):
                app.build_server(db, "127.0.0.1", 0,
                                 require_auth=True, secret_key="too-short")
        finally:
            db.close()

    def test_oversized_body_is_a_json_413(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            connection.putrequest("POST", "/$first_table")
            connection.putheader("Content-Type", "application/json")
            connection.putheader("Content-Length", "1025")
            connection.endheaders()
            response = connection.getresponse()
            payload = json.loads(response.read().decode("utf-8"))
        finally:
            connection.close()
        self.assertEqual(response.status, 413)
        self.assertIn("error", payload)

    def test_malformed_json_is_a_json_400(self):
        request = urllib.request.Request(
            self._base() + "/$first_table", data=b"{", method="POST")
        request.add_header("Content-Type", "application/json")
        try:
            urllib.request.urlopen(request, timeout=5)
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)
            self.assertIn("error", json.loads(exc.read().decode("utf-8")))
        else:
            self.fail("malformed JSON was accepted")

    def test_auth_guard_blocks_then_allows(self):
        server = app.build_server(Database(":memory:"), "127.0.0.1", 0,
                                  require_auth=True,
                                  secret_key="integration-test-secret-at-least-32-bytes")
        port = server.server_address[1]
        thread = self._start_server(server)
        base = "http://127.0.0.1:%d" % port
        payload = json.dumps($first_sample).encode("utf-8")
        blocked_body = dict($first_sample)
        blocked_body["_padding"] = "x" * 768
        blocked_payload = json.dumps(blocked_body).encode("utf-8")
        try:
            # A write with no token is rejected.  Repeat with a substantial body:
            # on Windows an unread body used to reset the closing socket before
            # urllib could receive the 401 status line.
            for _attempt in range(12):
                blocked = urllib.request.Request(
                    base + "/$first_table", data=blocked_payload, method="POST")
                blocked.add_header("Content-Type", "application/json")
                status = None
                try:
                    urllib.request.urlopen(blocked, timeout=5)
                except urllib.error.HTTPError as exc:
                    status = exc.code
                    exc.read()
                self.assertEqual(status, 401)
            # register + login, then retry the write with a Bearer token
            for path in ("/auth/register", "/auth/login"):
                creds = json.dumps(
                    {"username": "gate", "password": "opensesame-1"}).encode("utf-8")
                req = urllib.request.Request(base + path, data=creds, method="POST")
                req.add_header("Content-Type", "application/json")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    last = json.loads(resp.read().decode("utf-8"))
            authed = urllib.request.Request(
                base + "/$first_table", data=payload, method="POST")
            authed.add_header("Content-Type", "application/json")
            authed.add_header("Authorization", "Bearer " + last["token"])
            with urllib.request.urlopen(authed, timeout=5) as resp:
                created = json.loads(resp.read().decode("utf-8"))
            self.assertIn("id", created)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            server.db.close()
            self.assertFalse(thread.is_alive(), "authenticated server thread did not stop")


if __name__ == "__main__":
    unittest.main()
''')


# --------------------------------------------------------------------------- #
# Standard-library modules -- a curated internal "batteries" library the service
# ships with. Each is distinct, real engineering (not per-resource repetition),
# and each is clean under both of Attestor's engines with its own passing tests.
# --------------------------------------------------------------------------- #
QUERYBUILDER = Template('''"""A small, safe, fluent SQL SELECT builder.

Values are ALWAYS bound through ? placeholders; only whitelisted column names are
ever interpolated. Build once, then execute the (sql, params) pair.
"""
from __future__ import annotations

from typing import Any, List, Tuple


class QueryBuilder:
    def __init__(self, table: str, columns=None):
        self._table = table
        self._columns = tuple(columns) if columns else ("*",)
        self._allowed = set(columns) if columns else set()
        self._wheres: List[str] = []
        self._params: List[Any] = []
        self._order = ""
        self._limit = None
        self._offset = None

    def _check(self, column: str) -> None:
        if self._allowed and column not in self._allowed:
            raise ValueError("unknown column: " + column)

    def where(self, column: str, value) -> "QueryBuilder":
        self._check(column)
        self._wheres.append(column + " = ?")
        self._params.append(value)
        return self

    def where_in(self, column: str, values) -> "QueryBuilder":
        self._check(column)
        marks = ", ".join("?" for _ in values)
        self._wheres.append(column + " IN (" + marks + ")")
        self._params.extend(values)
        return self

    def order_by(self, column: str, descending: bool = False) -> "QueryBuilder":
        self._check(column)
        self._order = " ORDER BY " + column + (" DESC" if descending else " ASC")
        return self

    def limit(self, count: int) -> "QueryBuilder":
        self._limit = int(count)
        return self

    def offset(self, count: int) -> "QueryBuilder":
        self._offset = int(count)
        return self

    def build(self) -> Tuple[str, tuple]:
        sql = "SELECT " + ", ".join(self._columns) + " FROM " + self._table
        params = list(self._params)
        if self._wheres:
            sql += " WHERE " + " AND ".join(self._wheres)
        sql += self._order
        if self._limit is not None:
            sql += " LIMIT ?"
            params.append(self._limit)
        if self._offset is not None:
            sql += " OFFSET ?"
            params.append(self._offset)
        return sql, tuple(params)
''')

QUERYBUILDER_TEST = Template('''"""Tests for the query builder."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from querybuilder import QueryBuilder                          # noqa: E402


class QueryBuilderTest(unittest.TestCase):
    def test_simple_where_and_limit(self):
        sql, params = (QueryBuilder("users", ("id", "name"))
                       .where("name", "ada").limit(10).build())
        self.assertEqual(sql, "SELECT id, name FROM users WHERE name = ? LIMIT ?")
        self.assertEqual(params, ("ada", 10))

    def test_where_in(self):
        sql, params = QueryBuilder("t", ("a",)).where_in("a", [1, 2, 3]).build()
        self.assertIn("a IN (?, ?, ?)", sql)
        self.assertEqual(params, (1, 2, 3))

    def test_order_and_offset(self):
        sql, _ = QueryBuilder("t", ("a",)).order_by("a", True).offset(5).build()
        self.assertIn("ORDER BY a DESC", sql)
        self.assertIn("OFFSET ?", sql)

    def test_unknown_column_rejected(self):
        with self.assertRaises(ValueError):
            QueryBuilder("t", ("a",)).where("evil", 1)


if __name__ == "__main__":
    unittest.main()
''')

MIGRATIONS = Template('''"""A tiny versioned-migration runner.

Each migration has an id and up()/down(). Applied ids are tracked in a
schema_migrations table so migrate() is idempotent and rollback() is safe.
"""
from __future__ import annotations

from typing import List


class Migration:
    version = "0000_base"

    def up(self, db) -> None:
        raise NotImplementedError

    def down(self, db) -> None:
        raise NotImplementedError


class MigrationRunner:
    def __init__(self, db):
        self._db = db
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY)")
        self._db.commit()

    def applied(self) -> set:
        rows = self._db.execute("SELECT version FROM schema_migrations").fetchall()
        return {row[0] for row in rows}

    def migrate(self, migrations: List[Migration]) -> List[str]:
        done = self.applied()
        ran = []
        for migration in migrations:
            if migration.version in done:
                continue
            migration.up(self._db)
            self._db.execute(
                "INSERT INTO schema_migrations (version) VALUES (?)", (migration.version,))
            self._db.commit()
            ran.append(migration.version)
        return ran

    def rollback(self, migrations: List[Migration]) -> List[str]:
        done = self.applied()
        undone = []
        for migration in reversed(migrations):
            if migration.version not in done:
                continue
            migration.down(self._db)
            self._db.execute(
                "DELETE FROM schema_migrations WHERE version = ?", (migration.version,))
            self._db.commit()
            undone.append(migration.version)
        return undone
''')

MIGRATIONS_TEST = Template('''"""Tests for the migration runner."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import Database                                        # noqa: E402
from migrations import Migration, MigrationRunner              # noqa: E402


class _CreateThings(Migration):
    version = "0001_things"

    def up(self, db):
        db.execute("CREATE TABLE things (id INTEGER PRIMARY KEY)")
        db.commit()

    def down(self, db):
        db.execute("DROP TABLE things")
        db.commit()


class MigrationsTest(unittest.TestCase):
    def setUp(self):
        self.db = Database(":memory:")
        self.runner = MigrationRunner(self.db)

    def test_migrate_is_idempotent(self):
        self.assertEqual(self.runner.migrate([_CreateThings()]), ["0001_things"])
        self.assertEqual(self.runner.migrate([_CreateThings()]), [])

    def test_rollback(self):
        self.runner.migrate([_CreateThings()])
        self.assertEqual(self.runner.rollback([_CreateThings()]), ["0001_things"])
        self.assertNotIn("0001_things", self.runner.applied())


if __name__ == "__main__":
    unittest.main()
''')

ROUTER = Template('''"""A minimal path router: map (method, pattern) to a handler and match request
paths, extracting {name} path parameters. Framework-free."""
from __future__ import annotations

import re
from typing import Callable


def _compile(pattern: str):
    parts = []
    for segment in pattern.strip("/").split("/"):
        if segment.startswith("{") and segment.endswith("}"):
            parts.append("(?P<" + segment[1:-1] + ">[^/]+)")
        else:
            parts.append(re.escape(segment))
    return re.compile("^/" + "/".join(parts) + "/?$$")


class Route:
    def __init__(self, method: str, pattern: str, handler: Callable):
        self.method = method.upper()
        self.pattern = pattern
        self.handler = handler
        self.regex = _compile(pattern)


class Router:
    def __init__(self):
        self._routes = []

    def add(self, method: str, pattern: str, handler: Callable) -> None:
        self._routes.append(Route(method, pattern, handler))

    def match(self, method: str, path: str):
        """Return (handler, params). handler is None on no match; params carries
        {"__method_not_allowed__": True} when the path matched but the method
        did not."""
        method = method.upper()
        path_matched = False
        for route in self._routes:
            m = route.regex.match(path)
            if not m:
                continue
            path_matched = True
            if route.method == method:
                return route.handler, m.groupdict()
        return None, ({"__method_not_allowed__": True} if path_matched else {})
''')

ROUTER_TEST = Template('''"""Tests for the router."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from router import Router                                      # noqa: E402


def _handler():
    return "ok"


class RouterTest(unittest.TestCase):
    def setUp(self):
        self.router = Router()
        self.router.add("GET", "/users/{id}", _handler)
        self.router.add("GET", "/health", _handler)

    def test_path_param(self):
        handler, params = self.router.match("GET", "/users/42")
        self.assertIs(handler, _handler)
        self.assertEqual(params, {"id": "42"})

    def test_static_route(self):
        handler, _ = self.router.match("GET", "/health")
        self.assertIs(handler, _handler)

    def test_no_match(self):
        handler, _ = self.router.match("GET", "/nope")
        self.assertIsNone(handler)

    def test_method_not_allowed(self):
        handler, info = self.router.match("POST", "/health")
        self.assertIsNone(handler)
        self.assertTrue(info.get("__method_not_allowed__"))


if __name__ == "__main__":
    unittest.main()
''')

DI = Template('''"""A tiny dependency-injection container: register factories or singletons and
resolve them by name, with simple circular-dependency detection."""
from __future__ import annotations


class DIError(Exception):
    pass


class Container:
    def __init__(self):
        self._factories = {}
        self._singletons = {}
        self._instances = {}
        self._building = set()

    def register(self, name: str, factory, singleton: bool = True) -> None:
        self._factories[name] = factory
        self._singletons[name] = singleton

    def register_value(self, name: str, value) -> None:
        self._instances[name] = value

    def resolve(self, name: str):
        if name in self._instances:
            return self._instances[name]
        if name not in self._factories:
            raise DIError("nothing registered for: " + name)
        if name in self._building:
            raise DIError("circular dependency at: " + name)
        self._building.add(name)
        try:
            instance = self._factories[name](self)
        finally:
            self._building.discard(name)
        if self._singletons.get(name):
            self._instances[name] = instance
        return instance
''')

DI_TEST = Template('''"""Tests for the DI container."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from di import Container, DIError                              # noqa: E402


class DITest(unittest.TestCase):
    def test_value_and_factory(self):
        c = Container()
        c.register_value("cfg", {"x": 1})
        c.register("svc", lambda box: box.resolve("cfg")["x"] + 1)
        self.assertEqual(c.resolve("svc"), 2)

    def test_singleton_is_cached(self):
        c = Container()
        calls = {"n": 0}

        def make(_box):
            calls["n"] += 1
            return object()

        c.register("s", make, singleton=True)
        self.assertIs(c.resolve("s"), c.resolve("s"))
        self.assertEqual(calls["n"], 1)

    def test_missing_raises(self):
        with self.assertRaises(DIError):
            Container().resolve("nope")

    def test_circular_detected(self):
        c = Container()
        c.register("a", lambda box: box.resolve("b"))
        c.register("b", lambda box: box.resolve("a"))
        with self.assertRaises(DIError):
            c.resolve("a")


if __name__ == "__main__":
    unittest.main()
''')

EVENTS = Template('''"""A synchronous in-process event bus. Subscribe handlers to named events and
publish payloads; a failing subscriber is isolated so it can't stop the others."""
from __future__ import annotations


class EventBus:
    def __init__(self):
        self._subscribers = {}
        self._log = []

    def subscribe(self, event: str, handler) -> None:
        self._subscribers.setdefault(event, []).append(handler)

    def publish(self, event: str, payload=None) -> int:
        self._log.append((event, payload))
        delivered = 0
        for handler in self._subscribers.get(event, []):
            try:
                handler(payload)
                delivered += 1
            except Exception:                   # noqa: BLE001 -- isolate subscribers
                continue
        return delivered

    def history(self):
        return list(self._log)
''')

EVENTS_TEST = Template('''"""Tests for the event bus."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from events import EventBus                                    # noqa: E402


class EventBusTest(unittest.TestCase):
    def test_publish_reaches_subscribers(self):
        bus = EventBus()
        seen = []
        bus.subscribe("created", lambda p: seen.append(p))
        self.assertEqual(bus.publish("created", 7), 1)
        self.assertEqual(seen, [7])

    def test_failing_subscriber_is_isolated(self):
        bus = EventBus()
        ok = []

        def boom(_payload):
            raise ValueError("bad subscriber")

        bus.subscribe("e", boom)
        bus.subscribe("e", lambda p: ok.append(p))
        self.assertEqual(bus.publish("e", 1), 1)
        self.assertEqual(ok, [1])

    def test_history(self):
        bus = EventBus()
        bus.publish("a", 1)
        self.assertEqual(bus.history(), [("a", 1)])


if __name__ == "__main__":
    unittest.main()
''')

JOBS = Template('''"""A small background job queue backed by a thread pool, with bounded retries.
Submit callables by id and poll their status/result. Stdlib threading only."""
from __future__ import annotations

import queue
import threading


class JobQueue:
    def __init__(self, workers: int = 2, max_retries: int = 2):
        self._queue = queue.Queue()
        self._results = {}
        self._lock = threading.Lock()
        self._max_retries = max_retries
        self._stop = threading.Event()
        self._threads = []
        for _ in range(max(1, workers)):
            thread = threading.Thread(target=self._worker, daemon=True)
            thread.start()
            self._threads.append(thread)

    def submit(self, job_id, func, *args) -> None:
        self._set(job_id, "queued", None)
        self._queue.put((job_id, func, args, 0))

    def _worker(self) -> None:
        while not self._stop.is_set():
            try:
                job_id, func, args, attempt = self._queue.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                self._set(job_id, "done", func(*args))
            except Exception as exc:            # noqa: BLE001 -- capture + maybe retry
                if attempt < self._max_retries:
                    self._queue.put((job_id, func, args, attempt + 1))
                else:
                    self._set(job_id, "failed", str(exc))
            finally:
                self._queue.task_done()

    def _set(self, job_id, status, value) -> None:
        with self._lock:
            self._results[job_id] = (status, value)

    def status(self, job_id):
        with self._lock:
            return self._results.get(job_id, ("unknown", None))

    def wait(self) -> None:
        self._queue.join()

    def shutdown(self) -> None:
        self._stop.set()
''')

JOBS_TEST = Template('''"""Tests for the background job queue."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jobs import JobQueue                                      # noqa: E402


class JobQueueTest(unittest.TestCase):
    def test_runs_a_job(self):
        q = JobQueue(workers=2)
        q.submit("j1", lambda a, b: a + b, 2, 3)
        q.wait()
        self.assertEqual(q.status("j1"), ("done", 5))
        q.shutdown()

    def test_retries_then_fails(self):
        q = JobQueue(workers=1, max_retries=1)

        def boom():
            raise ValueError("nope")

        q.submit("j2", boom)
        q.wait()
        status, _ = q.status("j2")
        self.assertEqual(status, "failed")
        q.shutdown()


if __name__ == "__main__":
    unittest.main()
''')

CIRCUITBREAKER = Template('''"""A circuit breaker. After N consecutive failures it opens for a cooldown and
rejects calls fast; once the cooldown passes it half-opens to test recovery."""
from __future__ import annotations

import time


class CircuitOpen(Exception):
    pass


class CircuitBreaker:
    def __init__(self, threshold: int = 5, cooldown: float = 30.0):
        self._threshold = threshold
        self._cooldown = cooldown
        self._failures = 0
        self._opened_at = 0.0
        self._state = "closed"

    @property
    def state(self) -> str:
        if self._state == "open" and time.monotonic() - self._opened_at >= self._cooldown:
            self._state = "half-open"
        return self._state

    def call(self, func, *args):
        if self.state == "open":
            raise CircuitOpen("circuit is open")
        try:
            result = func(*args)
        except Exception:                       # noqa: BLE001 -- count then re-raise
            self._on_failure()
            raise
        self._on_success()
        return result

    def _on_success(self) -> None:
        self._failures = 0
        self._state = "closed"

    def _on_failure(self) -> None:
        self._failures += 1
        if self._failures >= self._threshold:
            self._state = "open"
            self._opened_at = time.monotonic()
''')

CIRCUITBREAKER_TEST = Template('''"""Tests for the circuit breaker."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from circuitbreaker import CircuitBreaker, CircuitOpen         # noqa: E402


def _boom():
    raise ValueError("fail")


class CircuitBreakerTest(unittest.TestCase):
    def test_opens_after_threshold(self):
        cb = CircuitBreaker(threshold=2, cooldown=60)
        for _ in range(2):
            with self.assertRaises(ValueError):
                cb.call(_boom)
        self.assertEqual(cb.state, "open")
        with self.assertRaises(CircuitOpen):
            cb.call(lambda: 1)

    def test_success_keeps_it_closed(self):
        cb = CircuitBreaker(threshold=2)
        self.assertEqual(cb.call(lambda: 5), 5)
        self.assertEqual(cb.state, "closed")

    def test_half_opens_after_cooldown(self):
        cb = CircuitBreaker(threshold=1, cooldown=0.0)
        with self.assertRaises(ValueError):
            cb.call(_boom)
        self.assertEqual(cb.state, "half-open")


if __name__ == "__main__":
    unittest.main()
''')

STRUCTLOG = Template('''"""Structured JSON logging with bound context (e.g. a request id) that rides on
every line. Stdlib json + any writable stream."""
from __future__ import annotations

import json
import sys
import time


class StructLogger:
    def __init__(self, stream=None, **context):
        self._stream = stream if stream is not None else sys.stdout
        self._context = dict(context)

    def bind(self, **context) -> "StructLogger":
        merged = dict(self._context)
        merged.update(context)
        return StructLogger(self._stream, **merged)

    def log(self, level: str, message: str, **fields) -> dict:
        record = {"ts": round(time.time(), 3), "level": level, "msg": message}
        record.update(self._context)
        record.update(fields)
        self._stream.write(json.dumps(record) + "\\n")
        return record

    def info(self, message: str, **fields) -> dict:
        return self.log("info", message, **fields)

    def error(self, message: str, **fields) -> dict:
        return self.log("error", message, **fields)
''')

STRUCTLOG_TEST = Template('''"""Tests for structured logging."""
import io
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from structlog import StructLogger                            # noqa: E402


class StructLogTest(unittest.TestCase):
    def test_context_rides_along(self):
        buf = io.StringIO()
        log = StructLogger(buf, request_id="abc").bind(user="u1")
        record = log.info("hello", n=3)
        self.assertEqual(record["request_id"], "abc")
        self.assertEqual(record["user"], "u1")
        self.assertEqual(record["n"], 3)
        line = json.loads(buf.getvalue().strip())
        self.assertEqual(line["level"], "info")
        self.assertEqual(line["msg"], "hello")

    def test_bind_does_not_mutate_parent(self):
        log = StructLogger(io.StringIO())
        child = log.bind(a=1)
        self.assertIsNot(log, child)


if __name__ == "__main__":
    unittest.main()
''')

RESULT = Template('''"""A tiny Result type for explicit success/failure without exceptions."""
from __future__ import annotations


class Result:
    def __init__(self, ok: bool, value=None, error=None):
        self.ok = ok
        self.value = value
        self.error = error

    @classmethod
    def of(cls, value) -> "Result":
        return cls(True, value=value)

    @classmethod
    def fail(cls, error) -> "Result":
        return cls(False, error=error)

    def map(self, func) -> "Result":
        if not self.ok:
            return self
        return Result.of(func(self.value))

    def unwrap(self):
        if not self.ok:
            raise ValueError("unwrap on an error result: " + str(self.error))
        return self.value

    def unwrap_or(self, default):
        return self.value if self.ok else default
''')

RESULT_TEST = Template('''"""Tests for the Result type."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from result import Result                                      # noqa: E402


class ResultTest(unittest.TestCase):
    def test_ok(self):
        r = Result.of(5)
        self.assertTrue(r.ok)
        self.assertEqual(r.unwrap(), 5)

    def test_map_chains_on_ok(self):
        self.assertEqual(Result.of(2).map(lambda x: x * 10).unwrap(), 20)

    def test_fail_short_circuits_map(self):
        r = Result.fail("boom").map(lambda x: x + 1)
        self.assertFalse(r.ok)
        self.assertEqual(r.unwrap_or(-1), -1)

    def test_unwrap_error_raises(self):
        with self.assertRaises(ValueError):
            Result.fail("x").unwrap()


if __name__ == "__main__":
    unittest.main()
''')

DATASTRUCTURES = Template('''"""Reusable data structures: an LRU cache, a ring buffer, a trie, and a
binary-heap priority queue. Stdlib only."""
from __future__ import annotations

import heapq
from collections import OrderedDict

_END = "__end__"


class LRUCache:
    def __init__(self, capacity: int = 128):
        self._capacity = max(1, capacity)
        self._data = OrderedDict()

    def get(self, key, default=None):
        if key not in self._data:
            return default
        self._data.move_to_end(key)
        return self._data[key]

    def put(self, key, value) -> None:
        self._data[key] = value
        self._data.move_to_end(key)
        while len(self._data) > self._capacity:
            self._data.popitem(last=False)

    def __len__(self) -> int:
        return len(self._data)


class RingBuffer:
    def __init__(self, size: int = 8):
        self._size = max(1, size)
        self._buf = []

    def push(self, item) -> None:
        self._buf.append(item)
        if len(self._buf) > self._size:
            self._buf.pop(0)

    def items(self):
        return list(self._buf)


class Trie:
    def __init__(self):
        self._root = {}

    def insert(self, word: str) -> None:
        node = self._root
        for ch in word:
            node = node.setdefault(ch, {})
        node[_END] = True

    def contains(self, word: str) -> bool:
        node = self._root
        for ch in word:
            if ch not in node:
                return False
            node = node[ch]
        return _END in node

    def starts_with(self, prefix: str) -> bool:
        node = self._root
        for ch in prefix:
            if ch not in node:
                return False
            node = node[ch]
        return True


class PriorityQueue:
    def __init__(self):
        self._heap = []
        self._count = 0

    def push(self, item, priority: int) -> None:
        heapq.heappush(self._heap, (priority, self._count, item))
        self._count += 1

    def pop(self):
        return heapq.heappop(self._heap)[2]

    def __len__(self) -> int:
        return len(self._heap)
''')

DATASTRUCTURES_TEST = Template('''"""Tests for the reusable data structures."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from datastructures import LRUCache, PriorityQueue, RingBuffer, Trie  # noqa: E402


class DataStructuresTest(unittest.TestCase):
    def test_lru_evicts_least_recently_used(self):
        cache = LRUCache(2)
        cache.put("a", 1)
        cache.put("b", 2)
        cache.get("a")            # touch a, so b is now oldest
        cache.put("c", 3)
        self.assertIsNone(cache.get("b"))
        self.assertEqual(cache.get("a"), 1)

    def test_ring_buffer_keeps_last_n(self):
        ring = RingBuffer(2)
        ring.push(1)
        ring.push(2)
        ring.push(3)
        self.assertEqual(ring.items(), [2, 3])

    def test_trie(self):
        trie = Trie()
        trie.insert("cat")
        self.assertTrue(trie.contains("cat"))
        self.assertFalse(trie.contains("ca"))
        self.assertTrue(trie.starts_with("ca"))
        self.assertFalse(trie.starts_with("dog"))

    def test_priority_queue_pops_lowest_first(self):
        pq = PriorityQueue()
        pq.push("low", 5)
        pq.push("high", 1)
        self.assertEqual(pq.pop(), "high")
        self.assertEqual(len(pq), 1)


if __name__ == "__main__":
    unittest.main()
''')


# --------------------------------------------------------------------------- #
# Per-field block builders
# --------------------------------------------------------------------------- #
def _is_email_field(fn: str) -> bool:
    return fn == "email" or fn.endswith("_email")


def _model_blocks(res: Resource) -> dict:
    decls, valids, fd, fr = [], [], [], []
    has_email = False
    for i, (fn, ft) in enumerate(res.fields, start=1):
        decls.append(f"    {fn}: {TYPE_PY[ft]} = {TYPE_DEFAULT[ft]}")
        # bool is a subclass of int, so check it before the int/float branch
        if ft == "bool":
            valids.append(f"        if not isinstance(self.{fn}, bool):")
            valids.append(f'            errors.append("{fn} must be bool")')
        elif ft == "str":
            valids.append(f"        if not isinstance(self.{fn}, str):")
            valids.append(f'            errors.append("{fn} must be str")')
            valids.append(f"        elif not self.{fn}.strip():")
            valids.append(f'            errors.append("{fn} must not be empty")')
            if _is_email_field(fn):
                has_email = True
                valids.append(f"        elif not is_email(self.{fn}):")
                valids.append(f'            errors.append("{fn} must be a valid email")')
        else:
            valids.append(
                f"        if isinstance(self.{fn}, bool) or "
                f"not isinstance(self.{fn}, {TYPE_PY[ft]}):")
            valids.append(f'            errors.append("{fn} must be {ft}")')
        fd.append(f'            {fn}=data.get("{fn}", {TYPE_DEFAULT[ft]}),')
        fr.append(f"            {fn}=row[{i}],")
    return {"field_decls": "\n".join(decls), "validations": "\n".join(valids),
            "from_dict_args": "\n".join(fd), "from_row_args": "\n".join(fr),
            "validator_import": "from validators import is_email\n" if has_email else ""}


def _finders(res: Resource) -> str:
    """One static, fully-parameterized finder per field. The column name is a
    generator-known literal baked into the query string -- never concatenated
    from input -- so there is no injection surface."""
    select = "id, " + ", ".join(fn for fn, _ in res.fields)
    blocks = []
    for fn, _ft in res.fields:
        blocks.append(
            f"\n    def find_by_{fn}(self, value) -> List[{res.Name}]:\n"
            f'        rows = self._db.execute(\n'
            f'            "SELECT {select} FROM {res.table} WHERE {fn} = ? ORDER BY id",\n'
            f"            (value,),\n"
            f"        ).fetchall()\n"
            f"        return [{res.Name}.from_row(r) for r in rows]\n")
    return "".join(blocks)


def _repo_blocks(res: Resource) -> dict:
    names = [fn for fn, _ in res.fields]
    return {
        "col_names": ", ".join(names),
        "placeholders": ", ".join("?" for _ in names),
        "insert_values": ", ".join(f"item.{n}" for n in names) + ",",
        "select_cols": "id, " + ", ".join(names),
        "update_set": ", ".join(f"{n} = ?" for n in names),
        "update_values": ", ".join(f"item.{n}" for n in names) + ", item.id,",
        "finders": _finders(res),
        "columns_tuple": "".join(f'"{n}", ' for n in names),
    }


def _sample_value(fn: str, ft: str) -> str:
    if ft == "str" and _is_email_field(fn):
        return '"user@example.com"'
    return TYPE_SAMPLE[ft]


def _sample_dict(res: Resource) -> str:
    return "{" + ", ".join(f'"{fn}": {_sample_value(fn, ft)}'
                           for fn, ft in res.fields) + "}"


def _schema_stmt(res: Resource) -> str:
    cols = ", ".join(f"{fn} {TYPE_SQL[ft]}" for fn, ft in res.fields)
    return (f'    "CREATE TABLE IF NOT EXISTS {res.table} '
            f'(id INTEGER PRIMARY KEY AUTOINCREMENT, {cols})",')


# --------------------------------------------------------------------------- #
# Generation
# --------------------------------------------------------------------------- #
def generate(spec: dict) -> dict:
    """Return {relative_path: file_contents} for the whole service."""
    validate_spec(spec)
    resources = [Resource(r["name"], r["fields"]) for r in spec["resources"]]
    files = {}

    for res in resources:
        files[f"models/{res.module}.py"] = MODEL.substitute(res.sub(**_model_blocks(res)))
        files[f"repositories/{res.module}_repository.py"] = REPO.substitute(res.sub(**_repo_blocks(res)))
        files[f"services/{res.module}_service.py"] = SERVICE.substitute(res.sub())
        files[f"api/{res.module}_handler.py"] = API.substitute(res.sub())
        files[f"tests/test_{res.module}.py"] = TEST.substitute(res.sub(sample_dict=_sample_dict(res)))

    for pkg in ("models", "repositories", "services", "api", "tests"):
        files[f"{pkg}/__init__.py"] = '"""Generated package."""\n'

    schema_lines = [_schema_stmt(r) for r in resources]
    schema_lines.append(
        '    "CREATE TABLE IF NOT EXISTS accounts '
        '(id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, '
        'password_hash TEXT NOT NULL)",')
    files["db.py"] = DB.substitute(schema_statements="\n".join(schema_lines))
    files["config.py"] = CONFIG.substitute()
    files["app.py"] = APP.substitute(
        imports_block="\n".join(
            f"from repositories.{r.module}_repository import {r.Name}Repository\n"
            f"from services.{r.module}_service import {r.Name}Service\n"
            f"from api.{r.module}_handler import {r.Name}Handler" for r in resources),
        handler_wiring="\n".join(
            f'    handlers["{r.table}"] = {r.Name}Handler('
            f'{r.Name}Service({r.Name}Repository(db), TTLCache(config.CACHE_TTL)))'
            for r in resources))
    files["client.py"] = CLIENT_BASE.substitute(
        client_classes="\n".join(CLIENT_CLASS.substitute(r.sub()) for r in resources))

    # ----- cross-cutting infrastructure (once per service) -----
    files["pagination.py"] = PAGINATION.substitute()
    files["errors.py"] = ERRORS.substitute()
    files["security.py"] = SECURITY.substitute()
    files["ratelimit.py"] = RATELIMIT.substitute()
    files["logging_config.py"] = LOGGING_CONFIG.substitute()
    files["middleware.py"] = MIDDLEWARE.substitute()
    files["health.py"] = HEALTH.substitute()
    files["cache.py"] = CACHE.substitute()
    files["metrics.py"] = METRICS.substitute()
    files["retry.py"] = RETRY.substitute()
    files["validators.py"] = VALIDATORS.substitute()
    files["accounts.py"] = ACCOUNTS.substitute()
    files["querybuilder.py"] = QUERYBUILDER.substitute()
    files["migrations.py"] = MIGRATIONS.substitute()
    files["router.py"] = ROUTER.substitute()
    files["di.py"] = DI.substitute()
    files["events.py"] = EVENTS.substitute()
    files["jobs.py"] = JOBS.substitute()
    files["circuitbreaker.py"] = CIRCUITBREAKER.substitute()
    files["structlog.py"] = STRUCTLOG.substitute()
    files["result.py"] = RESULT.substitute()
    files["datastructures.py"] = DATASTRUCTURES.substitute()

    resources_meta = repr([{"name": r.Name, "table": r.table, "fields": dict(r.fields)}
                           for r in resources])
    files["openapi.py"] = OPENAPI.substitute(resources_meta=resources_meta)

    files["seed.py"] = SEED.substitute(
        seed_imports="\n".join(
            f"from repositories.{r.module}_repository import {r.Name}Repository\n"
            f"from services.{r.module}_service import {r.Name}Service"
            for r in resources),
        seed_body="\n".join(
            f"    {r.Name}Service({r.Name}Repository(db)).create({_sample_dict(r)})\n"
            f"    inserted += 1"
            for r in resources))
    files["manage.py"] = MANAGE.substitute()

    # ----- generated tests for the infrastructure -----
    files["tests/test_security.py"] = SECURITY_TEST.substitute()
    files["tests/test_pagination.py"] = PAGINATION_TEST.substitute()
    files["tests/test_ratelimit.py"] = RATELIMIT_TEST.substitute()
    files["tests/test_cache.py"] = CACHE_TEST.substitute()
    files["tests/test_metrics.py"] = METRICS_TEST.substitute()
    files["tests/test_retry.py"] = RETRY_TEST.substitute()
    files["tests/test_validators.py"] = VALIDATORS_TEST.substitute()
    files["tests/test_auth.py"] = ACCOUNTS_TEST.substitute()
    files["tests/test_querybuilder.py"] = QUERYBUILDER_TEST.substitute()
    files["tests/test_migrations.py"] = MIGRATIONS_TEST.substitute()
    files["tests/test_router.py"] = ROUTER_TEST.substitute()
    files["tests/test_di.py"] = DI_TEST.substitute()
    files["tests/test_events.py"] = EVENTS_TEST.substitute()
    files["tests/test_jobs.py"] = JOBS_TEST.substitute()
    files["tests/test_circuitbreaker.py"] = CIRCUITBREAKER_TEST.substitute()
    files["tests/test_structlog.py"] = STRUCTLOG_TEST.substitute()
    files["tests/test_result.py"] = RESULT_TEST.substitute()
    files["tests/test_datastructures.py"] = DATASTRUCTURES_TEST.substitute()
    first = resources[0]
    files["tests/test_integration.py"] = INTEGRATION_TEST.substitute(
        First=first.Name, first_sample=_sample_dict(first), first_table=first.table)

    # ----- project scaffolding -----
    files["requirements.txt"] = (
        f"# Requires Python >= {GENERATED_MIN_PYTHON}.\n"
        "# No third-party dependencies: the generated service uses the standard library.\n")
    files["Makefile"] = (
        ".PHONY: test run migrate seed routes\n"
        "test:\n\tpython3 -m unittest discover -s tests -v\n"
        "run:\n\tpython3 manage.py serve\n"
        "migrate:\n\tpython3 manage.py migrate\n"
        "seed:\n\tpython3 manage.py seed\n"
        "routes:\n\tpython3 manage.py routes\n")
    files["Dockerfile"] = (
        "FROM python:3.12-slim\n"
        "WORKDIR /app\n"
        "RUN useradd --create-home --uid 10001 appuser \\\n"
        "    && mkdir /data \\\n"
        "    && chown appuser:appuser /data\n"
        "COPY --chown=appuser:appuser . /app\n"
        "ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \\\n"
        "    HOST=0.0.0.0 PORT=8080 DATABASE_PATH=/data/app.db REQUIRE_AUTH=true\n"
        "USER appuser\n"
        "VOLUME [\"/data\"]\n"
        "EXPOSE 8080\n"
        "# Supply SECRET_KEY at runtime with -e/--env-file; never bake it into the image.\n"
        "HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD "
        "[\"python\", \"-c\", \"import urllib.request; "
        "urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).read()\"]\n"
        'CMD ["python", "manage.py", "serve"]\n')
    files[".gitignore"] = "__pycache__/\n*.pyc\n*.db\n.env\n"
    files[".dockerignore"] = (
        ".git\n.github\n.env\n__pycache__\n*.py[cod]\n*.db\n")
    files[".env.example"] = (
        "# Reference for shell exports or `docker run --env-file`; never commit secrets.\n"
        "# The Python service deliberately does NOT auto-load .env files.\n"
        "# Leave DATABASE_PATH unset for app.db on the host or /data/app.db in Docker.\n"
        "# DATABASE_PATH=app.db\n"
        "# Fill SECRET_KEY with at least 32 random bytes before starting the service.\n"
        "SECRET_KEY=\n"
        "REQUIRE_AUTH=true\n"
        "HOST=127.0.0.1\n"
        "PORT=8080\n"
        "REQUEST_TIMEOUT=30\n"
        "MAX_BODY_BYTES=1048576\n"
        "MAX_CONCURRENT_REQUESTS=32\n"
        "RATE_LIMIT=120\n"
        "RATE_REFILL=2.0\n"
        "CACHE_TTL=30\n"
        "TOKEN_TTL=3600\n"
        "LOG_LEVEL=INFO\n")
    files["pyproject.toml"] = (
        "[project]\n"
        'name = "generated-service"\n'
        f'version = "{GENERATED_VERSION}"\n'
        'description = "Scaffolded by AttestorVonLuneberg codegen. Standard library only."\n'
        f'requires-python = ">={GENERATED_MIN_PYTHON}"\n'
        "dependencies = []\n")
    files[".github/workflows/ci.yml"] = (
        "name: ci\n"
        "on: [push, pull_request]\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: actions/setup-python@v5\n"
        "        with:\n"
        f'          python-version: "{GENERATED_MIN_PYTHON}"\n'
        "      - run: python -m unittest discover -s tests -v\n")
    files["CHANGELOG.md"] = (
        "# Changelog\n\n"
        f"## {GENERATED_VERSION}\n\n"
        "- Authenticated writes by default; bounded threaded HTTP serving\n"
        "- Enforced request timeouts and body-size limits with JSON errors\n"
        "- Accounts + auth (PBKDF2 hashing, HS256 tokens, default-on write guard)\n"
        "- TTL cache (cache-aside reads), request metrics + `/metrics`, request ids\n"
        "- Safe dynamic filtering/sorting, bulk create, transactions\n"
        "- Retry decorator, field validators, management CLI, integration tests\n")
    files["README.md"] = _readme(resources)
    files[_GENERATION_MARKER] = json.dumps({
        "schema": _GENERATION_SCHEMA,
        "generator_version": GENERATED_VERSION,
        "paths": sorted(files),
    }, sort_keys=True, separators=(",", ":")) + "\n"
    return files


def _readme(resources) -> str:
    lines = ["# Generated service", "",
             "Scaffolded by AttestorVonLuneberg's codegen. **Standard library only** — no",
             "third-party dependencies. Clean by construction: parameterized SQL,",
             "secrets from the environment, real crypto, timeouts on every HTTP call.", "",
             "## Architecture", "",
             "```",
             "model  ->  repository (parameterized SQLite)  ->  service (validation,",
             "pagination)  ->  HTTP handler  ->  app.py (routing, rate limiting,",
             "health, OpenAPI, request logging)",
             "```", "",
             "## Resources", ""]
    for r in resources:
        cols = ", ".join(f"`{fn}` ({ft})" for fn, ft in r.fields)
        lines.append(f"- **{r.Name}** (`/{r.table}`): {cols}")
    lines += ["", "Each resource gets full CRUD plus `count`, `exists`, per-field",
              "finders, bulk create, pagination (`?page=&per_page=`) and safe",
              "filtering/sorting (`?<field>=&sort=&order=`, column whitelist +",
              "parameterized values).", "",
              "## Endpoints", "",
              "- `GET/POST /<resource>`, `GET/PUT/DELETE /<resource>/{id}`",
              "- `POST /auth/register`, `POST /auth/login` — accounts + tokens",
              "- `GET /health`, `GET /health/ready` — liveness / readiness",
              "- `GET /metrics` — request counters + latency",
              "- `GET /openapi.json` — generated OpenAPI 3.0 spec", "",
              "Writes require a Bearer token by default (`REQUIRE_AUTH=true`). Set a",
              "strong `SECRET_KEY` before starting; the service fails closed if it is",
              "missing. Disable the guard only for an intentional local test.", "",
              "## Infrastructure modules", "",
              "- `security.py` — PBKDF2-HMAC-SHA256 password hashing + HS256 tokens",
              "- `accounts.py` — account store + auth service",
              "- `ratelimit.py` — per-client token-bucket limiter",
              "- `cache.py` — thread-safe TTL cache (cache-aside reads)",
              "- `metrics.py` — request metrics + Prometheus exposition",
              "- `pagination.py` — page math + safe limit clamping",
              "- `validators.py` — email/range/non-empty validators",
              "- `retry.py` — retry decorator with backoff",
              "- `middleware.py` — request timing, logging, metrics, error mapping",
              "- `errors.py` — typed API errors  ·  `openapi.py` · `health.py`", "",
              "## Run", "", "```sh",
              "make migrate   # create the schema",
              "make seed      # insert sample rows",
              "make routes    # list every endpoint",
              "make run       # start the HTTP API (python3 manage.py serve)",
              "make test      # run the full generated test suite", "```", "",
              "`python3 manage.py openapi` dumps the spec. Configuration comes from",
              "the process environment. `.env.example` is a reference for shell exports",
              "or Docker's `--env-file`; this zero-dependency app does not auto-load it.",
              "Supported variables: `DATABASE_PATH`, `SECRET_KEY`, `HOST`, `PORT`,",
              "`REQUEST_TIMEOUT`, `MAX_BODY_BYTES`, `MAX_CONCURRENT_REQUESTS`,",
              "`RATE_LIMIT`, `RATE_REFILL`, `CACHE_TTL`, `TOKEN_TTL`, `REQUIRE_AUTH`,",
              "`LOG_LEVEL`, and `DEBUG`.", "",
              "The Docker image runs as an unprivileged user, stores SQLite data under",
              "`/data`, binds inside the container on `0.0.0.0`, and still requires",
              "`SECRET_KEY` to be injected at runtime.", ""]
    return "\n".join(lines)


def _is_link_or_junction(path: str) -> bool:
    is_junction = getattr(os.path, "isjunction", None)
    return os.path.islink(path) or bool(is_junction and is_junction(path))


# Artifacts the generated service creates for itself once it has been run.
# These are the only unplanned entries --force may destroy, because this
# generator is what put the code there that produced them.
_DERIVED_DIRS = frozenset({"__pycache__", ".pytest_cache", ".mypy_cache"})
_DERIVED_SUFFIXES = (".pyc", ".pyo")


def _generated_inventory(target: str) -> frozenset[str]:
    """Return the exact prior generated-file inventory, or an empty set.

    Common filenames are not provenance: ordinary Python services routinely
    contain ``app.py``, ``config.py`` and a Makefile.  The marker lets --force
    remove obsolete files Attestor actually generated while protecting databases,
    logs and user additions even inside a generated project.
    """
    marker = os.path.join(target, _GENERATION_MARKER)
    if _is_link_or_junction(marker) or not os.path.isfile(marker):
        return frozenset()
    try:
        if os.path.getsize(marker) > 512 * 1024:
            return frozenset()
        with open(marker, encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, ValueError, TypeError):
        return frozenset()
    if (not isinstance(value, dict)
            or value.get("schema") != _GENERATION_SCHEMA
            or value.get("generator_version") != GENERATED_VERSION
            or not isinstance(value.get("paths"), list)
            or len(value["paths"]) > _MAX_GENERATED_PATHS):
        return frozenset()
    paths = set()
    for relative in value["paths"]:
        if not isinstance(relative, str) or not relative:
            return frozenset()
        normalized = os.path.normpath(relative)
        if (os.path.isabs(relative) or normalized in {"", ".", ".."}
                or normalized.startswith(".." + os.sep)):
            return frozenset()
        paths.add(normalized.replace(os.sep, "/"))
    paths.add(_GENERATION_MARKER)
    return frozenset(paths)


def _unplanned_entries(target: str, planned,
                       prior_generated=frozenset()) -> list:
    """Files in the output directory that this run would not rewrite.

    Only consulted when the directory is *not* recognisably a previous
    generation.  Anything this returns is content the caller would lose
    silently, so it is worth naming before the delete rather than after it.
    """
    expected = {os.path.normcase(path) for path in planned}
    unexpected = []
    for root, dirs, names in os.walk(target):
        dirs[:] = [name for name in dirs if name not in _DERIVED_DIRS]
        for name in names:
            full = os.path.join(root, name)
            if os.path.normcase(full) in expected:
                continue
            relative = os.path.relpath(full, target).replace(os.sep, "/")
            if relative in prior_generated:
                continue
            if name.endswith(_DERIVED_SUFFIXES):
                continue
            unexpected.append(relative)
            if len(unexpected) > 64:
                return sorted(unexpected)
    return sorted(unexpected)


def _clean_output_dir(out_dir: str) -> None:
    """Remove an output directory's contents without following a target symlink."""
    target = os.path.abspath(out_dir)
    resolved = os.path.realpath(target)
    root = os.path.abspath(os.path.join(target, os.pardir))
    while os.path.abspath(os.path.join(root, os.pardir)) != root:
        root = os.path.abspath(os.path.join(root, os.pardir))
    cwd = os.path.realpath(os.getcwd())
    home = os.path.realpath(os.path.expanduser("~"))
    try:
        contains_cwd = os.path.commonpath((resolved, cwd)) == resolved
    except ValueError:
        contains_cwd = False
    if resolved in {root, home} or contains_cwd:
        raise SystemExit(f"refusing to clean unsafe output directory: {out_dir}")
    if _is_link_or_junction(target):
        raise SystemExit(f"refusing to clean linked output directory: {out_dir}")
    for entry in os.scandir(target):
        if entry.is_dir(follow_symlinks=False):
            shutil.rmtree(entry.path)
        else:
            os.unlink(entry.path)


def write_files(files: dict, out_dir: str, force: bool) -> None:
    target = os.path.abspath(out_dir)
    planned = []
    for rel, content in files.items():
        if not isinstance(rel, str) or not rel or not isinstance(content, str):
            raise ValueError("generated file paths and contents must be strings")
        path = os.path.abspath(os.path.join(target, rel))
        try:
            inside_target = os.path.commonpath((target, path)) == target
        except ValueError:
            inside_target = False
        if os.path.isabs(rel) or path == target or not inside_target:
            raise ValueError(f"generated path escapes output directory: {rel!r}")
        planned.append((path, content))
    if _is_link_or_junction(out_dir):
        raise SystemExit(f"refusing to write through linked output directory: {out_dir}")
    if os.path.lexists(out_dir) and not os.path.isdir(out_dir):
        raise SystemExit(f"{out_dir} exists and is not a directory")
    if os.path.isdir(out_dir) and os.listdir(out_dir):
        if not force:
            raise SystemExit(f"{out_dir} is not empty (use --force to replace it)")
        unplanned = _unplanned_entries(
            target, [p for p, _ in planned], _generated_inventory(target))
        if unplanned:
            shown = ", ".join(unplanned[:5])
            more = "" if len(unplanned) <= 5 else f" (+{len(unplanned) - 5} more)"
            raise SystemExit(
                f"refusing to clean {out_dir}: it holds {len(unplanned)} file(s) "
                f"this run would not regenerate, and --force would delete them: "
                f"{shown}{more}. Point at an empty directory, or remove them "
                f"deliberately first.")
        _clean_output_dir(out_dir)
    for path, content in planned:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)


def total_lines(files: dict) -> int:
    return sum(content.count("\n") + (0 if content.endswith("\n") else 1)
               for content in files.values())


def check_generated(out_dir: str, timeout: int = 180) -> bool:
    """Compile, test, and scan a generated project; return whether every gate passed."""
    ok = True
    python_files = []
    for root, dirs, names in os.walk(out_dir):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        python_files.extend(
            os.path.join(root, name) for name in sorted(names) if name.endswith(".py"))

    compile_failures = []
    sources = {}
    for path in python_files:
        try:
            with open(path, encoding="utf-8") as fh:
                source = fh.read()
            sources[path] = source
            compile(source, path, "exec")
        except (OSError, SyntaxError) as exc:
            compile_failures.append((path, exc))
    if compile_failures:
        ok = False
        print(f"[check] compile failed for {len(compile_failures)} file(s).")
        for path, exc in compile_failures:
            print(f"  {os.path.relpath(path, out_dir)}: {exc}")
    else:
        print(f"[check] compiled {len(python_files)} Python files.")

    try:
        result = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"],
            cwd=out_dir, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        ok = False
        print(f"[check] generated tests could not complete: {exc}")
    else:
        if result.returncode:
            ok = False
            output = (result.stdout + "\n" + result.stderr).strip()
            print(f"[check] generated tests failed (exit {result.returncode}).")
            if output:
                print(output[-4000:])
        else:
            print("[check] generated tests passed.")

    try:
        import deepscan
        import detect
    except ImportError as exc:
        print(f"[check] Attestor scanners are unavailable: {exc}")
        return False

    findings = []
    for path in detect.collect_paths([out_dir]):
        findings += detect.scan_file(path)
    deep_findings = []
    for path, source in sources.items():
        deep_findings += deepscan.analyze(source, path)
    if findings or deep_findings:
        ok = False
    print(f"[check] detector: {len(findings)} finding(s); "
          f"deepscan: {len(deep_findings)} finding(s).")
    for finding in findings + deep_findings:
        print(f"  {os.path.relpath(finding.path)}:{finding.line} "
              f"[{finding.severity}] {finding.rule}")
    return ok


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="generated_service", help="output directory")
    source = ap.add_mutually_exclusive_group()
    source.add_argument("--spec", help="JSON spec file (default: a 4-resource demo)")
    source.add_argument("--resources", type=int, metavar="N",
                        help="generate N standard resources (dial the line count; "
                             "~2.4k fixed lines + ~425 per resource -> 20 gives ~10k)")
    ap.add_argument("--force", action="store_true",
                    help="safely replace all contents of a non-empty --out")
    ap.add_argument("--check", action="store_true",
                    help="compile, test, and run both Attestor scanners over the output")
    ap.add_argument("--stdout-only", action="store_true",
                    help="report the line count only; write nothing")
    args = ap.parse_args(argv)

    try:
        spec = DEFAULT_SPEC
        if args.spec:
            with open(args.spec, encoding="utf-8") as fh:
                spec = json.load(fh)
        elif args.resources is not None:
            spec = big_spec(args.resources)
        files = generate(spec)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"bad spec: {exc}", file=sys.stderr)
        return 2
    n_lines = total_lines(files)
    n_files = len(files)

    if args.stdout_only:
        print(f"would generate {n_files} files, {n_lines} lines "
              f"({len(spec['resources'])} resources)")
        return 0

    write_files(files, args.out, args.force)
    print(f"AttestorVonLuneberg wrote {n_lines} lines across {n_files} files "
          f"into {args.out}/  ({len(spec['resources'])} resources)")
    if n_lines > 1000:
        print("...that's over a thousand lines. He'd like that noted.")

    if args.check:
        return 0 if check_generated(args.out) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
