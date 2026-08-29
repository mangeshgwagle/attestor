from __future__ import annotations

import hashlib
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

import database_intelligence414 as database


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class DatabaseIntelligence414Tests(unittest.TestCase):
    def test_sqlite_schema_is_understood_without_row_values(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "business.sqlite3"
            connection = sqlite3.connect(path)
            connection.executescript(
                "CREATE TABLE customer(id INTEGER PRIMARY KEY, secret TEXT);"
                "CREATE TABLE invoice(id INTEGER PRIMARY KEY, customer_id INTEGER "
                "REFERENCES customer(id));"
                "CREATE INDEX invoice_customer ON invoice(customer_id);"
                "INSERT INTO customer(secret) VALUES ('never-emit-this-row');")
            connection.commit()
            connection.close()

            report = database.understand(path, expected_sha256=_sha(path))

        self.assertEqual(report["status"], "understood")
        self.assertEqual(report["kind"], "sqlite")
        self.assertFalse(
            report["database"]["application_row_values_queried"])
        self.assertEqual(report["database"]["summary"]["tables"], 2)
        self.assertEqual(report["database"]["summary"]["relationships"], 1)
        self.assertIn("customer", {
            item["name"] for item in report["database"]["objects"]})
        self.assertNotIn("never-emit-this-row", repr(report))
        self.assertFalse(report["boundaries"]["database_writes"])

    def test_sqlite_requires_the_exact_authorized_hash(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "database.db"
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE sample(id INTEGER)")
            connection.commit()
            connection.close()
            with self.assertRaises(database.DatabaseIntelligenceError):
                database.inspect_sqlite(
                    path, expected_sha256="0" * 64)

    def test_sql_analysis_is_static_and_flags_privileged_constructs(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "migration.sql"
            path.write_text(
                "BEGIN;\n"
                "CREATE TABLE sample(id INTEGER);\n"
                "DROP TABLE old_sample;\n"
                "ATTACH DATABASE 'other.db' AS other;\n"
                "COMMIT;\n",
                encoding="utf-8")
            report = database.inspect_sql_file(
                path, expected_sha256=_sha(path))

        summary = report["migration"]["summary"]
        self.assertEqual(summary["statement_count"], 5)
        self.assertEqual(summary["destructive_statement_count"], 1)
        self.assertTrue(summary["transaction_ordered_and_balanced"])
        self.assertIn(
            "attach-database",
            report["migration"]["privileged_risk_markers"])
        self.assertFalse(report["boundaries"]["supplied_sql_executed"])
        self.assertNotIn("other.db", repr(report))

    def test_sqlite_refuses_unbound_wal_sidecar(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "database.sqlite3"
            connection = sqlite3.connect(path)
            connection.execute("CREATE TABLE baseline(id INTEGER)")
            connection.commit()
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA wal_autocheckpoint=0")
            connection.execute("CREATE TABLE sidecar_only(id INTEGER)")
            connection.commit()
            digest = _sha(path)
            self.assertTrue(Path(str(path) + "-wal").exists())
            with self.assertRaises(database.DatabaseIntelligenceError):
                database.inspect_sqlite(path, expected_sha256=digest)
            connection.close()

    def test_sqlite_implicit_foreign_key_and_sqlite_x_name_are_supported(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "database.sqlite3"
            connection = sqlite3.connect(path)
            connection.executescript(
                "CREATE TABLE parent(id INTEGER PRIMARY KEY);"
                "CREATE TABLE child(parent_id INTEGER REFERENCES parent);"
                "CREATE TABLE sqliteX(id INTEGER);")
            connection.commit()
            connection.close()
            report = database.inspect_sqlite(
                path, expected_sha256=_sha(path))
        names = {
            row["name"] for row in report["database"]["objects"]}
        self.assertIn("sqliteX", names)
        relation = report["database"]["relationships"][0]
        self.assertIsNone(relation["to_column"])
        self.assertTrue(relation["implicit_target_primary_key"])

    def test_sql_flags_credential_literal_and_cte_delete(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "migration.sql"
            path.write_text(
                "CREATE USER analyst PASSWORD 'not-for-output';"
                "WITH doomed AS (SELECT id FROM old) "
                "DELETE FROM old WHERE id IN (SELECT id FROM doomed);",
                encoding="utf-8")
            report = database.inspect_sql_file(
                path, expected_sha256=_sha(path))
        self.assertIn(
            "credential-literal",
            report["migration"]["privileged_risk_markers"])
        self.assertTrue(report["migration"]["statements"][1]["destructive"])
        self.assertNotIn("not-for-output", repr(report))

    def test_nested_data_modifying_cte_is_a_lexical_write_risk(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "migration.sql"
            path.write_text(
                "WITH moved AS ("
                "DELETE FROM products WHERE id < 10 RETURNING *"
                ") SELECT * FROM moved;",
                encoding="utf-8")
            report = database.inspect_sql_file(
                path, expected_sha256=_sha(path))
        statement = report["migration"]["statements"][0]
        self.assertEqual(statement["effective_keyword"], "SELECT")
        self.assertTrue(statement["writes_data_or_schema"])
        self.assertTrue(statement["destructive"])
        self.assertIn("DELETE", statement["nested_write_keywords"])
        self.assertEqual(
            report["migration"]["summary"]["write_statement_count"], 1)
        self.assertEqual(
            report["migration"]["summary"][
                "destructive_statement_count"], 1)

    def test_reversed_transaction_is_not_reported_balanced(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "migration.sql"
            path.write_text("COMMIT; BEGIN;", encoding="utf-8")
            report = database.inspect_sql_file(
                path, expected_sha256=_sha(path))
        self.assertFalse(
            report["migration"]["summary"][
                "transaction_ordered_and_balanced"])

    def test_sql_statement_separator_bomb_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "migration.sql"
            path.write_text(
                "X;" * (database.MAX_SQL_STATEMENTS + 1),
                encoding="utf-8")
            with self.assertRaises(database.DatabaseIntelligenceError):
                database.inspect_sql_file(
                    path, expected_sha256=_sha(path))

    def test_string_true_cannot_be_used_as_a_hash(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "schema.sql"
            path.write_text("SELECT 1;", encoding="utf-8")
            with self.assertRaises(database.DatabaseIntelligenceError):
                database.inspect_sql_file(
                    path, expected_sha256="true")

    @unittest.skipUnless(
        hasattr(os, "symlink"), "symbolic links are unavailable")
    def test_link_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root / "schema.sql"
            link = root / "linked.sql"
            source.write_text("SELECT 1;", encoding="utf-8")
            try:
                link.symlink_to(source)
            except OSError:
                self.skipTest("symbolic-link creation is not permitted")
            with self.assertRaises(database.DatabaseIntelligenceError):
                database.inspect_sql_file(
                    link, expected_sha256=_sha(source))


if __name__ == "__main__":
    unittest.main()
