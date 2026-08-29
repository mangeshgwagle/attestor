"""Deterministic, source-free evidence for the synthetic enterprise lab.

This module accepts in-memory source units only. It never opens a target
repository, starts a process, imports target code, uses the network, installs a
package, or writes a report. The top-level Attestor launcher provides process
isolation; that is not an operating-system sandbox.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any, Iterable, Sequence
import unicodedata

try:  # Package import for library users; script import for the isolated CLI.
    from .fixtures import (
        BENCHMARK_FIXTURES,
        TENANT_CANARIES,
        TENANT_FIXTURES,
        BenchmarkFixture,
    )
except ImportError:
    from fixtures import (
        BENCHMARK_FIXTURES,
        TENANT_CANARIES,
        TENANT_FIXTURES,
        BenchmarkFixture,
    )


VERSION = "4.2"
REPORT_SCHEMA = "attestor.enterprise-security-lab/1.0"
TENANT_SCHEMA = "attestor.enterprise-tenant-analysis/1.0"
MANIFEST_SCHEMA = "attestor.enterprise-input-manifest/1.0"
FIXTURES_ROOT = "bundled-synthetic-enterprise-security42"
DATASET_DESIGN = (
    "Labels are withheld from the detector. Paired synthetic cases measure "
    "regression behavior; this is not an independent or real-world accuracy "
    "benchmark."
)
ISOLATION_CLAIM_BOUNDARY = (
    "This proves deterministic logical separation in one local process. It "
    "does not prove operating-system sandboxing, enterprise identity, storage "
    "isolation or authorization."
)

EXIT_PASS = 0
EXIT_QUALITY = 1
EXIT_INVALID = 2
EXIT_INCOMPLETE = 3
EXIT_OPERATIONAL = 4

MAX_SOURCES = 64
MAX_SOURCE_BYTES = 512 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_FINDINGS = 2_000
TENANT_RE = re.compile(r"[a-z][a-z0-9-]{0,47}\Z")
CWE_RE = re.compile(r"CWE-[1-9][0-9]*\Z")
WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"}
    | {"com%d" % number for number in range(1, 10)}
    | {"lpt%d" % number for number in range(1, 10)}
)
SUPPORTED_SUFFIXES = frozenset({
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp",
    ".hs", ".lhs", ".java", ".js", ".jsx", ".mjs", ".cjs",
    ".py", ".pyw", ".ts", ".tsx",
})
_TRUSTED_DETECTOR: Any | None = None


class LabInputError(ValueError):
    """The synthetic input violates the bounded lab contract."""


class LabOperationalError(RuntimeError):
    """The local detector could not complete the requested measurement."""


@dataclass(frozen=True)
class SourceUnit:
    """One logical source file; content is never serialized into a report."""

    path: str
    content: str
    complete: bool = True


def canonical_json(value: Any) -> str:
    """Canonical UTF-8 JSON text used for every digest in this lab."""

    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _cost_profile() -> dict[str, Any]:
    return {
        "external_tools": False,
        "incremental_cost_usd": 0,
        "network": False,
        "provider_cost_usd": 0,
        "subprocess": False,
        "target_execution": False,
    }


def _seal(payload: dict[str, Any]) -> dict[str, Any]:
    if "report_sha256" in payload:
        raise LabOperationalError("a report was sealed twice")
    payload["report_sha256"] = digest_json(payload)
    return payload


def _logical_path(raw: str) -> str:
    if not isinstance(raw, str) or not raw or len(raw) > 240:
        raise LabInputError("source path must be a bounded non-empty string")
    if "\x00" in raw or "\\" in raw or raw.startswith("/"):
        raise LabInputError("source paths must be canonical relative POSIX paths")
    if any(unicodedata.category(character) in {"Cc", "Cf"} for character in raw):
        raise LabInputError("source paths cannot contain control or format characters")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise LabInputError("source paths cannot be absolute or traverse")
    canonical = path.as_posix()
    if canonical != raw or ":" in path.parts[0]:
        raise LabInputError("source paths must already be canonical")
    for part in path.parts:
        if part.endswith((" ", ".")):
            raise LabInputError("source paths cannot use cross-platform aliases")
        stem = part.split(".", 1)[0].casefold()
        if stem in WINDOWS_RESERVED:
            raise LabInputError("source path uses a reserved device name")
    return canonical


def _validated_sources(sources: Iterable[SourceUnit]) -> tuple[SourceUnit, ...]:
    try:
        rows = tuple(sources)
    except TypeError as exc:
        raise LabInputError("sources must be an iterable of SourceUnit values") from exc
    if not rows or len(rows) > MAX_SOURCES:
        raise LabInputError("a tenant needs between 1 and %d sources" % MAX_SOURCES)

    seen: set[str] = set()
    total = 0
    validated: list[SourceUnit] = []
    for row in rows:
        if not isinstance(row, SourceUnit):
            raise LabInputError("every source must be a SourceUnit")
        path = _logical_path(row.path)
        folded = path.casefold()
        if folded in seen:
            raise LabInputError("duplicate or case-colliding source path")
        seen.add(folded)
        if not isinstance(row.content, str):
            raise LabInputError("source content must be Unicode text")
        encoded = row.content.encode("utf-8")
        total += len(encoded)
        if total > MAX_TOTAL_BYTES:
            raise LabInputError("source bytes exceed the lab boundary")
        if type(row.complete) is not bool:
            raise LabInputError("source completeness must be Boolean")
        validated.append(SourceUnit(path, row.content, row.complete))
    return tuple(sorted(validated, key=lambda item: item.path.casefold()))


def _tenant_id(value: str) -> str:
    if not isinstance(value, str) or TENANT_RE.fullmatch(value) is None:
        raise LabInputError(
            "tenant id must be lowercase letters, digits and hyphens")
    return value


def build_manifest(
    tenant_id: str,
    sources: Iterable[SourceUnit],
) -> dict[str, Any]:
    """Build a content-bound manifest without returning source text."""

    tenant = _tenant_id(tenant_id)
    rows = _validated_sources(sources)
    files = []
    for row in rows:
        encoded = row.content.encode("utf-8")
        eligible = (
            row.complete
            and len(encoded) <= MAX_SOURCE_BYTES
            and PurePosixPath(row.path).suffix.lower() in SUPPORTED_SUFFIXES
        )
        files.append({
            "bytes": len(encoded),
            "complete": bool(row.complete),
            "eligible": eligible,
            "line_count": max(1, len(row.content.splitlines())),
            "path": row.path,
            "sha256": _sha256(encoded),
        })
    manifest: dict[str, Any] = {
        "schema": MANIFEST_SCHEMA,
        "fixture_root": FIXTURES_ROOT,
        "tenant_id": tenant,
        "files": files,
    }
    manifest["manifest_sha256"] = digest_json(manifest)
    return manifest


def _release_root() -> Path:
    here = Path(__file__).resolve(strict=True)
    root = here.parents[2].resolve(strict=True)
    here.relative_to(root)
    return root


def _load_detector() -> Any:
    global _TRUSTED_DETECTOR

    root = _release_root()
    directory = (root / "detector").resolve(strict=True)
    directory.relative_to(root)
    text = os.fspath(directory)
    if text not in sys.path:
        sys.path.insert(0, text)
    detector_path = directory / "detect.py"
    if detector_path.is_symlink():
        raise LabOperationalError("the reviewed detector file cannot be a link")
    expected = detector_path.resolve(strict=True)
    try:
        expected.relative_to(root)
    except ValueError as exc:
        raise LabOperationalError(
            "the reviewed detector resolved outside the release") from exc
    existing = sys.modules.get("detect")
    if _TRUSTED_DETECTOR is not None:
        if existing is not _TRUSTED_DETECTOR:
            raise LabOperationalError("the reviewed detector module was replaced")
        return _TRUSTED_DETECTOR
    if existing is not None:
        # __file__ and __spec__.origin are mutable strings, so they cannot turn
        # a module imported by somebody else into a trusted dependency.
        raise LabOperationalError("a detector module was preloaded before trust was established")
    module = __import__("detect")
    try:
        actual = Path(module.__file__).resolve(strict=True)
        spec_origin = Path(module.__spec__.origin).resolve(strict=True)
    except (AttributeError, OSError, TypeError) as exc:
        raise LabOperationalError("the detector origin could not be verified") from exc
    if actual != expected or spec_origin != expected:
        raise LabOperationalError("the detector origin did not match the reviewed file")
    _TRUSTED_DETECTOR = module
    return _TRUSTED_DETECTOR


def _detector_identity() -> tuple[str, str]:
    root = _release_root()
    path = root / "detector" / "detect.py"
    if path.is_symlink():
        raise LabOperationalError("the reviewed detector file cannot be a link")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        data = resolved.read_bytes()
    except (OSError, ValueError) as exc:
        raise LabOperationalError("the reviewed detector is unavailable") from exc
    digest = _sha256(data)
    return digest, "attestor-detect/%s+%s" % (VERSION, digest[:16])


def _bundled_fixture_manifests() -> dict[str, dict[str, Any]]:
    """Rebuild the reviewed corpus manifests from the bundled source bytes."""

    return {
        case.case_id: build_manifest(
            "benchmark-%s" % case.case_id,
            tuple(SourceUnit(item.path, item.content) for item in case.sources),
        )
        for case in BENCHMARK_FIXTURES
    }


def _bundled_fixture_rows() -> list[dict[str, Any]]:
    manifests = _bundled_fixture_manifests()
    return [
        {
            "case_id": case.case_id,
            "group_id": case.group_id,
            "cwe": case.cwe,
            "rule_id": case.rule_id,
            "vulnerable": case.vulnerable,
            "input_manifest_sha256": manifests[case.case_id]["manifest_sha256"],
        }
        for case in BENCHMARK_FIXTURES
    ]


def _bundled_fixture_corpus_sha256() -> str:
    """Pin case metadata and every bundled source byte through its manifest."""

    return digest_json(_bundled_fixture_rows())


def _tenant_fixture_manifests() -> dict[str, dict[str, Any]]:
    """Rebuild the two isolation manifests from their bundled source bytes."""

    return {
        tenant: build_manifest(
            tenant,
            tuple(SourceUnit(item.path, item.content) for item in sources),
        )
        for tenant, sources in TENANT_FIXTURES.items()
    }


def _coverage_gap(row: SourceUnit) -> str | None:
    encoded = row.content.encode("utf-8")
    if not row.complete:
        return "fixture-declared-incomplete"
    if len(encoded) > MAX_SOURCE_BYTES:
        return "source-exceeds-byte-boundary"
    if PurePosixPath(row.path).suffix.lower() not in SUPPORTED_SUFFIXES:
        return "unsupported-source-type"
    return None


def analyze_tenant(
    tenant_id: str,
    sources: Iterable[SourceUnit],
    *,
    detector_module: Any | None = None,
) -> dict[str, Any]:
    """Analyze one in-memory tenant without returning source or snippets.

    ``detector_module`` exists only for boundary testing. Reports made with an
    injected detector are explicitly untrusted and incomplete, and findings are
    restricted to the reviewed detector's rule taxonomy.
    """

    tenant = _tenant_id(tenant_id)
    rows = _validated_sources(sources)
    manifest = build_manifest(tenant, rows)
    source_by_path = {row.path: row for row in rows}
    eligible: dict[str, str] = {}
    gaps: list[dict[str, str]] = []
    for row in rows:
        reason = _coverage_gap(row)
        if reason is None:
            eligible[row.path] = row.content
        else:
            gaps.append({"path": row.path, "reason": reason})

    reviewed_detector = _load_detector()
    reviewed_rules = getattr(reviewed_detector, "RULE_CWE", None)
    if not isinstance(reviewed_rules, dict):
        raise LabOperationalError("the reviewed detector taxonomy is unavailable")
    if detector_module is None:
        detector = reviewed_detector
        detector_mode = "reviewed-local"
        detector_sha256, rule_version = _detector_identity()
    else:
        detector = detector_module
        detector_mode = "injected-test-double"
        detector_sha256 = None
        rule_version = "injected-test-double/untrusted"
        gaps.append({"path": "<analysis>", "reason": "test-double-detector"})
    raw_findings: Sequence[Any] = ()
    if eligible:
        try:
            raw_findings = detector.scan_project(eligible, deep=True)
        except Exception as exc:  # noqa: BLE001 - sanitized at the CLI boundary
            raise LabOperationalError("the local detector failed") from exc
    if len(raw_findings) > MAX_FINDINGS:
        gaps.append({"path": "<analysis>", "reason": "finding-boundary-exceeded"})
        raw_findings = raw_findings[:MAX_FINDINGS]

    file_hashes = {
        item["path"]: item["sha256"] for item in manifest["files"]
    }
    evidence: list[dict[str, Any]] = []
    for finding in raw_findings:
        path = getattr(finding, "path", "")
        if path not in eligible or path not in source_by_path:
            gaps.append({"path": "<analysis>", "reason": "unknown-finding-path"})
            continue
        line = getattr(finding, "line", 0)
        rule = getattr(finding, "rule", "")
        if type(line) is not int or line < 1 or not isinstance(rule, str) or not rule:
            gaps.append({"path": path, "reason": "invalid-finding-shape"})
            continue
        manifest_item = next(
            item for item in manifest["files"] if item["path"] == path)
        if line > manifest_item["line_count"]:
            gaps.append({"path": path, "reason": "out-of-range-finding-line"})
            continue
        cwe = str(reviewed_rules.get(rule, ""))
        if CWE_RE.fullmatch(cwe) is None:
            gaps.append({"path": path, "reason": "unreviewed-finding-rule"})
            continue
        core: dict[str, Any] = {
            "cwe": cwe,
            "input_sha256": file_hashes[path],
            "line": line,
            "manifest_sha256": manifest["manifest_sha256"],
            "path": path,
            "rule_id": rule,
            "rule_version": rule_version,
        }
        core["evidence_sha256"] = digest_json(core)
        binding = {
            "evidence_sha256": core["evidence_sha256"],
            "manifest_sha256": manifest["manifest_sha256"],
            "tenant_id": tenant,
        }
        core["finding_sha256"] = digest_json(binding)
        evidence.append(core)

    evidence.sort(key=lambda item: (
        item["path"], item["line"], item["rule_id"], item["finding_sha256"]))
    duplicate_tokens = len({item["finding_sha256"] for item in evidence}) != len(evidence)
    if duplicate_tokens:
        gaps.append({"path": "<analysis>", "reason": "duplicate-finding-token"})

    complete = not gaps and bool(eligible)
    status = "incomplete" if not complete else ("findings" if evidence else "clean")
    report = {
        "schema": TENANT_SCHEMA,
        "command": "tenant-analysis",
        "status": status,
        "complete": complete,
        "tenant_id": tenant,
        "detector_mode": detector_mode,
        "detector_sha256": detector_sha256,
        "analysis_policy": {
            "cache": False,
            "deep": True,
            "external_tools": False,
            "network": False,
            "target_execution": False,
        },
        "cost_profile": _cost_profile(),
        "manifest": manifest,
        "coverage_gaps": sorted(
            gaps, key=lambda item: (item["path"], item["reason"])),
        "findings": evidence,
    }
    return _seal(report)


def _score(counts: dict[str, int]) -> dict[str, Any]:
    tp, tn, fp, fn = (counts[key] for key in ("tp", "tn", "fp", "fn"))

    def ratio(numerator: int, denominator: int) -> float | None:
        return None if denominator == 0 else round(numerator / denominator, 6)

    precision = ratio(tp, tp + fp)
    recall = ratio(tp, tp + fn)
    f1 = ratio(2 * tp, 2 * tp + fp + fn)
    accuracy = ratio(tp + tn, tp + tn + fp + fn)
    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
    }


def _empty_counts() -> dict[str, int]:
    return {"tp": 0, "tn": 0, "fp": 0, "fn": 0}


def _validate_fixture_structure(cases: Sequence[BenchmarkFixture]) -> None:
    groups: dict[str, list[BenchmarkFixture]] = {}
    for case in cases:
        groups.setdefault(case.group_id, []).append(case)
    if not groups:
        raise LabInputError("the benchmark needs paired cases")
    for rows in groups.values():
        if (len(rows) != 2
                or len({row.cwe for row in rows}) != 1
                or len({row.rule_id for row in rows}) != 1
                or {row.vulnerable for row in rows} != {False, True}):
            raise LabInputError(
                "each benchmark group needs one positive and one clean control")


def run_benchmark(
    cases: Sequence[BenchmarkFixture] | None = None,
    *,
    detector_module: Any | None = None,
) -> dict[str, Any]:
    """Run the bundled paired synthetic smoke benchmark."""

    bundled = cases is None
    selected = tuple(BENCHMARK_FIXTURES if bundled else cases)
    if not selected:
        raise LabInputError("the benchmark needs at least one case")
    if bundled:
        _validate_fixture_structure(selected)
    seen: set[str] = set()
    observations: list[dict[str, Any]] = []
    counts_by_cwe: dict[str, dict[str, int]] = {}
    dataset_rows: list[dict[str, Any]] = []
    complete = True
    quality_ok = True

    for case in selected:
        if not isinstance(case, BenchmarkFixture):
            raise LabInputError("benchmark cases must use the bundled schema")
        if case.case_id in seen:
            raise LabInputError("benchmark case ids must be unique")
        seen.add(case.case_id)
        if type(case.vulnerable) is not bool:
            raise LabInputError("benchmark labels must be Boolean")
        if not case.cwe.startswith("CWE-") or not case.rule_id:
            raise LabInputError("benchmark labels need a CWE and rule id")

        sources = tuple(SourceUnit(item.path, item.content) for item in case.sources)
        analysis = analyze_tenant(
            "benchmark-%s" % case.case_id,
            sources,
            detector_module=detector_module,
        )
        complete = complete and bool(analysis["complete"])
        rule_ids = [item["rule_id"] for item in analysis["findings"]]
        detected = case.rule_id in rule_ids
        unexpected = sorted({rule for rule in rule_ids if rule != case.rule_id})
        if case.vulnerable and detected:
            outcome = "tp"
        elif case.vulnerable:
            outcome = "fn"
        elif detected:
            outcome = "fp"
        else:
            outcome = "tn"
        counts = counts_by_cwe.setdefault(case.cwe, _empty_counts())
        counts[outcome] += 1
        case_ok = outcome in {"tp", "tn"} and not unexpected and analysis["complete"]
        quality_ok = quality_ok and case_ok
        observations.append({
            "case_id": case.case_id,
            "group_id": case.group_id,
            "cwe": case.cwe,
            "expected_rule_id": case.rule_id,
            "expected_vulnerable": case.vulnerable,
            "detected": detected,
            "outcome": outcome,
            "unexpected_rule_ids": unexpected,
            "analysis": analysis,
        })
        dataset_rows.append({
            "case_id": case.case_id,
            "group_id": case.group_id,
            "cwe": case.cwe,
            "rule_id": case.rule_id,
            "vulnerable": case.vulnerable,
            "input_manifest_sha256": analysis["manifest"]["manifest_sha256"],
        })

    aggregate = _empty_counts()
    per_cwe: dict[str, dict[str, Any]] = {}
    for cwe in sorted(counts_by_cwe):
        per_cwe[cwe] = _score(counts_by_cwe[cwe])
        for key in aggregate:
            aggregate[key] += counts_by_cwe[cwe][key]

    complete = complete and bundled
    status = "incomplete" if not complete else (
        "success" if quality_ok else "quality_gate_miss")
    report = {
        "schema": REPORT_SCHEMA,
        "command": "benchmark",
        "status": status,
        "complete": complete,
        "cost_profile": _cost_profile(),
        "dataset": {
            "name": (
                "Attestor bundled paired synthetic smoke corpus" if bundled
                else "Custom unverified synthetic case set"
            ),
            "fixture_set": "bundled-exact-v1" if bundled else "custom-unverified",
            "fixture_root": FIXTURES_ROOT,
            "case_count": len(observations),
            "design": (
                DATASET_DESIGN
            ),
            "cases_sha256": digest_json(dataset_rows),
            "fixture_corpus_sha256": (
                _bundled_fixture_corpus_sha256() if bundled else None
            ),
        },
        "quality_gate": {
            "complete_required": True,
            "minimum_precision": 1.0,
            "minimum_recall": 1.0,
            "unexpected_rule_ids_allowed": 0,
            "passed": bundled and status == "success",
        },
        "metrics": {
            "aggregate": _score(aggregate),
            "per_cwe": per_cwe,
        },
        "cases": observations,
    }
    return _seal(report)


def run_isolation_self_test(*, detector_module: Any | None = None) -> dict[str, Any]:
    """Check logical report separation for two in-memory synthetic tenants."""

    analyses: dict[str, dict[str, Any]] = {}
    for tenant in sorted(TENANT_FIXTURES):
        sources = tuple(
            SourceUnit(item.path, item.content)
            for item in TENANT_FIXTURES[tenant]
        )
        analyses[tenant] = analyze_tenant(
            tenant, sources, detector_module=detector_module)

    alpha = analyses["tenant-alpha"]
    beta = analyses["tenant-beta"]
    alpha_json = canonical_json(alpha)
    beta_json = canonical_json(beta)
    alpha_tokens = {item["finding_sha256"] for item in alpha["findings"]}
    beta_tokens = {item["finding_sha256"] for item in beta["findings"]}
    checks = {
        "alpha_canary_redacted": TENANT_CANARIES["tenant-alpha"] not in alpha_json,
        "beta_canary_redacted": TENANT_CANARIES["tenant-beta"] not in beta_json,
        "alpha_canary_absent_from_beta": TENANT_CANARIES["tenant-alpha"] not in beta_json,
        "beta_canary_absent_from_alpha": TENANT_CANARIES["tenant-beta"] not in alpha_json,
        "different_input_manifests": (
            alpha["manifest"]["manifest_sha256"]
            != beta["manifest"]["manifest_sha256"]
        ),
        "finding_tokens_disjoint": alpha_tokens.isdisjoint(beta_tokens),
        "tenant_ids_not_crossed": (
            "tenant-beta" not in alpha_json and "tenant-alpha" not in beta_json
        ),
        "both_tenants_have_independent_findings": bool(alpha_tokens and beta_tokens),
        "tenant_reports_verify": verify_report(alpha) and verify_report(beta),
    }
    complete = bool(alpha["complete"] and beta["complete"])
    status = "incomplete" if not complete else (
        "success" if all(checks.values()) else "quality_gate_miss")
    tenant_summaries = {}
    for tenant, analysis in sorted(analyses.items()):
        tenant_summaries[tenant] = {
            "analysis": analysis,
            "finding_tokens": [
                item["finding_sha256"] for item in analysis["findings"]
            ],
            "manifest_sha256": analysis["manifest"]["manifest_sha256"],
            "path_hashes": [
                _sha256(item["path"].encode("utf-8"))
                for item in analysis["manifest"]["files"]
            ],
        }
    report = {
        "schema": REPORT_SCHEMA,
        "command": "isolation",
        "status": status,
        "complete": complete,
        "cost_profile": _cost_profile(),
        "claim_boundary": ISOLATION_CLAIM_BOUNDARY,
        "checks": checks,
        "tenants": tenant_summaries,
    }
    return _seal(report)


def run_self_test(*, detector_module: Any | None = None) -> dict[str, Any]:
    benchmark = run_benchmark(detector_module=detector_module)
    isolation = run_isolation_self_test(detector_module=detector_module)
    complete = bool(benchmark["complete"] and isolation["complete"])
    children_verify = verify_report(benchmark) and verify_report(isolation)
    if not complete:
        status = "incomplete"
    elif (benchmark["status"] == "success"
          and isolation["status"] == "success" and children_verify):
        status = "success"
    else:
        status = "quality_gate_miss"
    return _seal({
        "schema": REPORT_SCHEMA,
        "command": "self-test",
        "status": status,
        "complete": complete,
        "cost_profile": _cost_profile(),
        "children_verify": children_verify,
        "benchmark": benchmark,
        "isolation": isolation,
    })


def _verify_manifest(manifest: Any) -> bool:
    if not isinstance(manifest, dict):
        return False
    if set(manifest) != {
            "schema", "fixture_root", "tenant_id", "files",
            "manifest_sha256"}:
        return False
    if (manifest.get("schema") != MANIFEST_SCHEMA
            or manifest.get("fixture_root") != FIXTURES_ROOT):
        return False
    try:
        _tenant_id(manifest.get("tenant_id"))
    except (LabInputError, TypeError):
        return False
    supplied = manifest.get("manifest_sha256")
    if not isinstance(supplied, str) or re.fullmatch(r"[0-9a-f]{64}", supplied) is None:
        return False
    unsigned = dict(manifest)
    unsigned.pop("manifest_sha256", None)
    if digest_json(unsigned) != supplied:
        return False
    files = manifest.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= MAX_SOURCES:
        return False
    paths: set[str] = set()
    total_bytes = 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {
                "bytes", "complete", "eligible", "line_count", "path",
                "sha256"}:
            return False
        try:
            path = _logical_path(item.get("path"))
        except (LabInputError, TypeError):
            return False
        if path.casefold() in paths:
            return False
        paths.add(path.casefold())
        byte_count = item.get("bytes")
        line_count = item.get("line_count")
        complete = item.get("complete")
        eligible = item.get("eligible")
        if (type(byte_count) is not int or byte_count < 0
                or type(line_count) is not int or line_count < 1
                or type(complete) is not bool or type(eligible) is not bool):
            return False
        total_bytes += byte_count
        expected_eligible = (
            complete
            and byte_count <= MAX_SOURCE_BYTES
            and PurePosixPath(path).suffix.lower() in SUPPORTED_SUFFIXES
        )
        if eligible is not expected_eligible:
            return False
        if not re.fullmatch(r"[0-9a-f]{64}", str(item.get("sha256", ""))):
            return False
    return total_bytes <= MAX_TOTAL_BYTES


def _verify_tenant(report: dict[str, Any]) -> bool:
    if set(report) != {
            "schema", "command", "status", "complete", "tenant_id",
            "detector_mode", "detector_sha256", "analysis_policy",
            "cost_profile", "manifest", "coverage_gaps", "findings",
            "report_sha256"}:
        return False
    if report.get("analysis_policy") != {
            "cache": False,
            "deep": True,
            "external_tools": False,
            "network": False,
            "target_execution": False}:
        return False
    if report.get("cost_profile") != _cost_profile():
        return False
    try:
        reviewed_detector = _load_detector()
        current_sha256, current_rule_version = _detector_identity()
    except (LabOperationalError, OSError, TypeError):
        return False
    reviewed_rules = getattr(reviewed_detector, "RULE_CWE", None)
    if not isinstance(reviewed_rules, dict):
        return False
    detector_mode = report.get("detector_mode")
    detector_sha256 = report.get("detector_sha256")
    if detector_mode == "reviewed-local":
        if detector_sha256 != current_sha256:
            return False
        expected_rule_version = current_rule_version
    elif detector_mode == "injected-test-double":
        if detector_sha256 is not None:
            return False
        expected_rule_version = "injected-test-double/untrusted"
    else:
        return False
    manifest = report.get("manifest")
    if not _verify_manifest(manifest):
        return False
    tenant = report.get("tenant_id")
    try:
        _tenant_id(tenant)
    except (LabInputError, TypeError):
        return False
    if manifest.get("tenant_id") != tenant:
        return False
    manifest_paths = {item["path"]: item for item in manifest["files"]}
    tokens: set[str] = set()
    findings = report.get("findings")
    if not isinstance(findings, list) or len(findings) > MAX_FINDINGS:
        return False
    for finding in findings:
        if not isinstance(finding, dict) or set(finding) != {
                "cwe", "input_sha256", "line", "manifest_sha256", "path",
                "rule_id", "rule_version", "evidence_sha256",
                "finding_sha256"}:
            return False
        core = {
            key: finding.get(key)
            for key in (
                "cwe", "input_sha256", "line", "manifest_sha256", "path",
                "rule_id", "rule_version",
            )
        }
        if finding.get("evidence_sha256") != digest_json(core):
            return False
        manifest_item = manifest_paths.get(core["path"])
        if (manifest_item is None or not manifest_item["eligible"]
                or core["input_sha256"] != manifest_item["sha256"]
                or core["manifest_sha256"] != manifest["manifest_sha256"]):
            return False
        if (type(core["line"]) is not int or core["line"] < 1
                or core["line"] > manifest_item["line_count"]
                or CWE_RE.fullmatch(str(core["cwe"] or "")) is None
                or not isinstance(core["rule_id"], str) or not core["rule_id"]
                or reviewed_rules.get(core["rule_id"]) != core["cwe"]
                or core["rule_version"] != expected_rule_version):
            return False
        binding = {
            "evidence_sha256": finding["evidence_sha256"],
            "manifest_sha256": manifest["manifest_sha256"],
            "tenant_id": tenant,
        }
        token = finding.get("finding_sha256")
        if token != digest_json(binding) or token in tokens:
            return False
        tokens.add(token)
    gaps = report.get("coverage_gaps")
    complete = report.get("complete")
    status = report.get("status")
    if not isinstance(gaps, list) or type(complete) is not bool:
        return False
    gap_tokens: set[tuple[str, str]] = set()
    for gap in gaps:
        if (not isinstance(gap, dict) or set(gap) != {"path", "reason"}
                or not isinstance(gap["reason"], str) or not gap["reason"]):
            return False
        if gap["path"] != "<analysis>" and gap["path"] not in manifest_paths:
            return False
        token = (gap["path"], gap["reason"])
        if token in gap_tokens:
            return False
        gap_tokens.add(token)
    test_double_gap = ("<analysis>", "test-double-detector")
    if ((detector_mode == "injected-test-double")
            is not (test_double_gap in gap_tokens)):
        return False
    expected_complete = not gaps and all(
        item["eligible"] for item in manifest["files"])
    expected_status = "incomplete" if not expected_complete else (
        "findings" if findings else "clean")
    return complete is expected_complete and status == expected_status


def _verify_benchmark(report: dict[str, Any]) -> bool:
    if set(report) != {
            "schema", "command", "status", "complete", "cost_profile",
            "dataset", "quality_gate", "metrics", "cases", "report_sha256"}:
        return False
    if report.get("cost_profile") != _cost_profile():
        return False
    dataset = report.get("dataset")
    cases = report.get("cases")
    if not isinstance(dataset, dict) or not isinstance(cases, list) or not cases:
        return False
    if set(dataset) != {
            "name", "fixture_set", "fixture_root", "case_count", "design",
            "cases_sha256", "fixture_corpus_sha256"}:
        return False
    fixture_set = dataset.get("fixture_set")
    bundled = fixture_set == "bundled-exact-v1"
    if fixture_set not in {"bundled-exact-v1", "custom-unverified"}:
        return False
    expected_name = (
        "Attestor bundled paired synthetic smoke corpus" if bundled
        else "Custom unverified synthetic case set"
    )
    if (dataset.get("name") != expected_name
            or dataset.get("fixture_root") != FIXTURES_ROOT
            or dataset.get("design") != DATASET_DESIGN
            or dataset.get("case_count") != len(cases)):
        return False
    expected_corpus_sha256 = (
        _bundled_fixture_corpus_sha256() if bundled else None)
    if dataset.get("fixture_corpus_sha256") != expected_corpus_sha256:
        return False

    ids: set[str] = set()
    groups: dict[str, list[tuple[str, str, bool]]] = {}
    counts: dict[str, dict[str, int]] = {}
    dataset_rows: list[dict[str, Any]] = []
    analysis_complete = True
    quality_ok = True
    metadata_rows: list[tuple[str, str, str, str, bool]] = []
    for case in cases:
        if not isinstance(case, dict) or set(case) != {
                "case_id", "group_id", "cwe", "expected_rule_id",
                "expected_vulnerable", "detected", "outcome",
                "unexpected_rule_ids", "analysis"}:
            return False
        case_id = case.get("case_id")
        group_id = case.get("group_id")
        cwe = case.get("cwe")
        rule = case.get("expected_rule_id")
        vulnerable = case.get("expected_vulnerable")
        if (not isinstance(case_id, str) or not case_id or case_id in ids
                or not isinstance(group_id, str) or not group_id
                or CWE_RE.fullmatch(str(cwe or "")) is None
                or not isinstance(rule, str) or not rule
                or type(vulnerable) is not bool):
            return False
        ids.add(case_id)
        analysis = case.get("analysis")
        if (not verify_report(analysis)
                or analysis.get("tenant_id") != "benchmark-%s" % case_id):
            return False
        analysis_complete = analysis_complete and bool(analysis.get("complete"))
        actual_rules = [item["rule_id"] for item in analysis["findings"]]
        detected = rule in actual_rules
        unexpected = sorted({item for item in actual_rules if item != rule})
        if case.get("detected") is not detected or case.get("unexpected_rule_ids") != unexpected:
            return False
        if vulnerable and detected:
            outcome = "tp"
        elif vulnerable:
            outcome = "fn"
        elif detected:
            outcome = "fp"
        else:
            outcome = "tn"
        if case.get("outcome") != outcome:
            return False
        counts.setdefault(cwe, _empty_counts())[outcome] += 1
        case_ok = outcome in {"tp", "tn"} and not unexpected and analysis["complete"]
        quality_ok = quality_ok and case_ok
        groups.setdefault(group_id, []).append((cwe, rule, vulnerable))
        metadata_rows.append((case_id, group_id, cwe, rule, vulnerable))
        dataset_rows.append({
            "case_id": case_id,
            "group_id": group_id,
            "cwe": cwe,
            "rule_id": rule,
            "vulnerable": vulnerable,
            "input_manifest_sha256": analysis["manifest"]["manifest_sha256"],
        })

    if bundled:
        expected_manifests = _bundled_fixture_manifests()
        for rows in groups.values():
            if (len(rows) != 2
                    or len({row[0] for row in rows}) != 1
                    or len({row[1] for row in rows}) != 1
                    or {row[2] for row in rows} != {False, True}):
                return False
        expected_metadata = [
            (case.case_id, case.group_id, case.cwe, case.rule_id, case.vulnerable)
            for case in BENCHMARK_FIXTURES
        ]
        if metadata_rows != expected_metadata:
            return False
        for case in cases:
            expected_manifest = expected_manifests.get(case["case_id"])
            if (expected_manifest is None
                    or case["analysis"]["manifest"] != expected_manifest):
                return False
    if dataset.get("cases_sha256") != digest_json(dataset_rows):
        return False

    expected_per_cwe = {cwe: _score(counts[cwe]) for cwe in sorted(counts)}
    aggregate = _empty_counts()
    for values in counts.values():
        for key in aggregate:
            aggregate[key] += values[key]
    if report.get("metrics") != {
            "aggregate": _score(aggregate), "per_cwe": expected_per_cwe}:
        return False

    complete = analysis_complete and bundled
    status = "incomplete" if not complete else (
        "success" if quality_ok else "quality_gate_miss")
    expected_gate = {
        "complete_required": True,
        "minimum_precision": 1.0,
        "minimum_recall": 1.0,
        "unexpected_rule_ids_allowed": 0,
        "passed": bundled and status == "success",
    }
    return (
        report.get("complete") is complete
        and report.get("status") == status
        and report.get("quality_gate") == expected_gate
    )


def verify_report(report: Any) -> bool:
    """Verify deterministic integrity and the report's internal bindings.

    These hashes detect accidental or unsophisticated modification. They are
    not digital signatures and do not authenticate who produced a report.
    """

    if not isinstance(report, dict):
        return False
    supplied = report.get("report_sha256")
    if not isinstance(supplied, str):
        return False
    unsigned = dict(report)
    unsigned.pop("report_sha256", None)
    if digest_json(unsigned) != supplied:
        return False
    command = report.get("command")
    if command == "tenant-analysis":
        return report.get("schema") == TENANT_SCHEMA and _verify_tenant(report)
    if report.get("schema") != REPORT_SCHEMA:
        return False
    if command == "benchmark":
        return _verify_benchmark(report)
    if command == "isolation":
        if set(report) != {
                "schema", "command", "status", "complete", "cost_profile",
                "claim_boundary", "checks", "tenants", "report_sha256"}:
            return False
        if (report.get("cost_profile") != _cost_profile()
                or report.get("claim_boundary") != ISOLATION_CLAIM_BOUNDARY):
            return False
        tenants = report.get("tenants")
        if not isinstance(tenants, dict) or set(tenants) != {
                "tenant-alpha", "tenant-beta"}:
            return False
        expected_manifests = _tenant_fixture_manifests()
        analyses: dict[str, dict[str, Any]] = {}
        for tenant, summary in tenants.items():
            if not isinstance(summary, dict) or set(summary) != {
                    "analysis", "finding_tokens", "manifest_sha256",
                    "path_hashes"}:
                return False
            analysis = summary.get("analysis")
            if (not verify_report(analysis)
                    or analysis.get("tenant_id") != tenant
                    or analysis.get("manifest") != expected_manifests[tenant]):
                return False
            expected_tokens = [
                item["finding_sha256"] for item in analysis["findings"]
            ]
            expected_paths = [
                _sha256(item["path"].encode("utf-8"))
                for item in analysis["manifest"]["files"]
            ]
            if (summary.get("finding_tokens") != expected_tokens
                    or summary.get("path_hashes") != expected_paths
                    or summary.get("manifest_sha256")
                    != analysis["manifest"]["manifest_sha256"]):
                return False
            analyses[tenant] = analysis
        alpha = analyses["tenant-alpha"]
        beta = analyses["tenant-beta"]
        alpha_json = canonical_json(alpha)
        beta_json = canonical_json(beta)
        alpha_tokens = {item["finding_sha256"] for item in alpha["findings"]}
        beta_tokens = {item["finding_sha256"] for item in beta["findings"]}
        expected_checks = {
            "alpha_canary_redacted": TENANT_CANARIES["tenant-alpha"] not in alpha_json,
            "beta_canary_redacted": TENANT_CANARIES["tenant-beta"] not in beta_json,
            "alpha_canary_absent_from_beta": TENANT_CANARIES["tenant-alpha"] not in beta_json,
            "beta_canary_absent_from_alpha": TENANT_CANARIES["tenant-beta"] not in alpha_json,
            "different_input_manifests": (
                alpha["manifest"]["manifest_sha256"]
                != beta["manifest"]["manifest_sha256"]
            ),
            "finding_tokens_disjoint": alpha_tokens.isdisjoint(beta_tokens),
            "tenant_ids_not_crossed": (
                "tenant-beta" not in alpha_json and "tenant-alpha" not in beta_json
            ),
            "both_tenants_have_independent_findings": bool(alpha_tokens and beta_tokens),
            "tenant_reports_verify": True,
        }
        complete = bool(alpha["complete"] and beta["complete"])
        status = "incomplete" if not complete else (
            "success" if all(expected_checks.values()) else "quality_gate_miss")
        return (
            report.get("checks") == expected_checks
            and report.get("complete") is complete
            and report.get("status") == status
        )
    if command == "self-test":
        if set(report) != {
                "schema", "command", "status", "complete", "cost_profile",
                "children_verify", "benchmark", "isolation", "report_sha256"}:
            return False
        benchmark = report.get("benchmark")
        isolation = report.get("isolation")
        children_verify = verify_report(benchmark) and verify_report(isolation)
        complete = bool(
            children_verify and benchmark.get("complete")
            and isolation.get("complete"))
        if not complete:
            status = "incomplete"
        elif (benchmark.get("status") == "success"
              and isolation.get("status") == "success"):
            status = "success"
        else:
            status = "quality_gate_miss"
        return (
            report.get("cost_profile") == _cost_profile()
            and report.get("children_verify") is children_verify
            and children_verify
            and report.get("complete") is complete
            and report.get("status") == status
        )
    return False


def exit_for_status(status: str) -> int:
    return {
        "success": EXIT_PASS,
        "pass": EXIT_PASS,
        "quality_gate_miss": EXIT_QUALITY,
        "quality-gate-failed": EXIT_QUALITY,
        "invalid_input": EXIT_INVALID,
        "invalid": EXIT_INVALID,
        "incomplete": EXIT_INCOMPLETE,
        "operational_failure": EXIT_OPERATIONAL,
        "operational-failure": EXIT_OPERATIONAL,
    }.get(status, EXIT_OPERATIONAL)
