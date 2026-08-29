"""Bundled synthetic cases for the Attestor enterprise-security lab.

The labels live in this manifest and are never passed to the detector. Source
paths and source text deliberately contain no ``good``, ``bad``, ``expected``
or vulnerability-label markers that could leak the answer to an analyzer.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FixtureSource:
    path: str
    content: str


@dataclass(frozen=True)
class BenchmarkFixture:
    case_id: str
    group_id: str
    cwe: str
    rule_id: str
    vulnerable: bool
    sources: tuple[FixtureSource, ...]


COMMAND_SINK = """\
public class Runner {
    public void launch(String value) throws Throwable {
        Runtime.getRuntime().exec("git show " + value);
    }
}
"""

SQL_SINK = """\
import java.sql.Statement;
public class Store {
    public void save(String value) throws Throwable {
        Statement statement = dbConnection.createStatement();
        statement.addBatch("update users set active=1 where name='" + value + "'");
    }
}
"""


BENCHMARK_FIXTURES: tuple[BenchmarkFixture, ...] = (
    BenchmarkFixture(
        case_id="case-001",
        group_id="pair-001",
        cwe="CWE-78",
        rule_id="java-command-injection",
        vulnerable=True,
        sources=(
            FixtureSource("src/Entry.java", """\
public class Entry {
    public void handle() throws Throwable {
        String value = System.getenv("REVISION");
        (new Runner()).launch(value);
    }
}
"""),
            FixtureSource("src/Runner.java", COMMAND_SINK),
        ),
    ),
    BenchmarkFixture(
        case_id="case-002",
        group_id="pair-001",
        cwe="CWE-78",
        rule_id="java-command-injection",
        vulnerable=False,
        sources=(
            FixtureSource("src/Entry.java", """\
public class Entry {
    public void handle() throws Throwable {
        String value = "release";
        (new Runner()).launch(value);
    }
}
"""),
            FixtureSource("src/Runner.java", COMMAND_SINK),
        ),
    ),
    BenchmarkFixture(
        case_id="case-003",
        group_id="pair-002",
        cwe="CWE-89",
        rule_id="java-sql-injection",
        vulnerable=True,
        sources=(
            FixtureSource("src/Entry.java", """\
public class Entry {
    public void handle() throws Throwable {
        String value = System.getenv("ACCOUNT_NAME");
        (new Store()).save(value);
    }
}
"""),
            FixtureSource("src/Store.java", SQL_SINK),
        ),
    ),
    BenchmarkFixture(
        case_id="case-004",
        group_id="pair-002",
        cwe="CWE-89",
        rule_id="java-sql-injection",
        vulnerable=False,
        sources=(
            FixtureSource("src/Entry.java", """\
public class Entry {
    public void handle() throws Throwable {
        String value = "service-account";
        (new Store()).save(value);
    }
}
"""),
            FixtureSource("src/Store.java", SQL_SINK),
        ),
    ),
    BenchmarkFixture(
        case_id="case-005",
        group_id="pair-003",
        cwe="CWE-94",
        rule_id="dangerous-eval",
        vulnerable=True,
        sources=(
            FixtureSource("src/handler.py", """\
def decode(payload):
    return eval(payload)
"""),
        ),
    ),
    BenchmarkFixture(
        case_id="case-006",
        group_id="pair-003",
        cwe="CWE-94",
        rule_id="dangerous-eval",
        vulnerable=False,
        sources=(
            FixtureSource("src/handler.py", """\
import json

def decode(payload):
    return json.loads(payload)
"""),
        ),
    ),
)


TENANT_FIXTURES: dict[str, tuple[FixtureSource, ...]] = {
    "tenant-alpha": (
        FixtureSource("src/handler.py", """\
TENANT_MARKER = "ORANGE-ALPHA-ONLY"

def decode(payload):
    return eval(payload)
"""),
    ),
    "tenant-beta": (
        FixtureSource("src/handler.py", """\
import hashlib

TENANT_MARKER = "BLUE-BETA-ONLY"

def checksum(payload):
    return hashlib.md5(payload).hexdigest()
"""),
    ),
}


TENANT_CANARIES = {
    "tenant-alpha": "ORANGE-ALPHA-ONLY",
    "tenant-beta": "BLUE-BETA-ONLY",
}
