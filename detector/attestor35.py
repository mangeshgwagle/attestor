#!/usr/bin/env python3
"""Attestor 3.5 evidence-backed maximum analysis and repair orchestrator.

Attestor 3.5 retains the proven 3.0 pipeline and adds bounded path/field-sensitive
symbolic analysis, a common polyglot IR, content-addressed incremental semantic
metadata, read-only Git impact intelligence, exact lockfile dependency edges,
empirical confidence calibration, fail-closed execution capability reporting,
and Truth Guard 2.  Target code is not executed unless the caller supplies the
separate authorizations required by the selected verification path.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import hashlib
import json
import math
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import calibration35
import execution_fabric35
import git_intelligence35
import attestor3
import polyglot_ir35
import precision_catalog
import response35
import supply_chain35
import supply_chain_center
import symbolic_engine35
import transactional_repair35
import truth_guard35


SCHEMA = "attestor-maximum/3.5"
VERSION = "3.5.0"
CORE_COMPONENTS = tuple(attestor3.DEFAULT_COMPONENTS)
NEW_COMPONENTS = ("symbolic", "polyglot-ir", "supply-chain-graph",
                  "git-intelligence", "execution-fabric")
DEFAULT_COMPONENTS = CORE_COMPONENTS + NEW_COMPONENTS
SEVERITY_RANK = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
MAX_TOP_FINDINGS = 100
MAX_ATTACK_PATHS = 100
MAX_SYMBOLIC_OUTPUT = 16 * 1024 * 1024
PUBLIC_IR_LIMITS = {
    "files": 500, "modules": 500, "imports": 2_000, "types": 2_000,
    "functions": 2_000, "calls": 3_000, "routes": 1_000,
    "manifests": 500, "parse_gaps": 500,
}


class Attestor35Error(ValueError):
    pass


def transactional_repair(
        root: str | os.PathLike[str],
        change_set: transactional_repair35.ChangeSet,
        hooks: Sequence[transactional_repair35.VerificationHook], *,
        execution_authorization: execution_fabric35.ExecutionAuthorization | None = None,
        apply: bool = False,
        apply_authorization: transactional_repair35.ApplyAuthorization | None = None,
        fabric: execution_fabric35.ExecutionFabric | None = None,
        policy: transactional_repair35.RepairPolicy | None = None) -> dict[str, Any]:
    """Run a proof-gated multi-file repair; dry-run and fail-closed by default."""
    engine = transactional_repair35.TransactionalRepair(
        root, fabric or execution_fabric35.ExecutionFabric(), policy)
    return dataclasses.asdict(engine.repair(
        change_set, hooks, execution_authorization=execution_authorization,
        apply=apply, apply_authorization=apply_authorization))


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False, default=str).encode("utf-8")


def _sha(value: Any) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _component(name: str, function, errors: list[dict[str, str]]) -> Any:
    try:
        return function()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        errors.append({"component": name, "error": type(exc).__name__})
        return None


def _symbolic_job(requested: Path, timeout_seconds: float) -> dict[str, Any]:
    """Run the trusted analyzer out of process so wall time/output are enforceable."""
    if not isinstance(timeout_seconds, (int, float)) or isinstance(timeout_seconds, bool) \
            or not 1 <= float(timeout_seconds) <= 300:
        raise Attestor35Error("symbolic timeout must be between 1 and 300 seconds")
    here = Path(__file__).resolve().parent
    worker = here / "symbolic_worker35.py"
    bootstrap = (
        "import runpy,sys; root,worker,*rest=sys.argv[1:]; "
        "sys.path.insert(0,root); sys.argv=[worker,*rest]; "
        "runpy.run_path(worker,run_name='__main__')"
    )
    command = [sys.executable, "-I", "-B", "-X", "utf8", "-c", bootstrap,
               str(here), str(worker), str(requested),
               "--max-files", "500", "--max-states", "96",
               "--max-steps", "20000", "--max-contexts", "16"]
    environment = os.environ.copy()
    for name in ("PYTHONHOME", "PYTHONPATH", "PYTHONSTARTUP"):
        environment.pop(name, None)
    environment.update({"PYTHONIOENCODING": "utf-8", "PYTHONUTF8": "1",
                        "PYTHONDONTWRITEBYTECODE": "1"})
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        process = subprocess.Popen(
            command, cwd=str(here), stdin=subprocess.DEVNULL,
            stdout=stdout_file, stderr=stderr_file, env=environment,
            shell=False, close_fds=True)
        deadline = time.monotonic() + float(timeout_seconds)
        reason = ""
        while process.poll() is None:
            if time.monotonic() >= deadline:
                reason = "symbolic analyzer exceeded its wall-clock boundary"; break
            try:
                if os.fstat(stdout_file.fileno()).st_size > MAX_SYMBOLIC_OUTPUT or \
                        os.fstat(stderr_file.fileno()).st_size > 256 * 1024:
                    reason = "symbolic analyzer exceeded its output boundary"; break
            except OSError:
                reason = "symbolic analyzer output could not be bounded"; break
            time.sleep(0.01)
        if reason:
            process.kill(); process.wait(timeout=5)
            raise Attestor35Error(reason)
        process.wait(timeout=5)
        if process.returncode != 0:
            raise Attestor35Error("symbolic analyzer worker failed safely")
        stdout_file.seek(0)
        raw = stdout_file.read(MAX_SYMBOLIC_OUTPUT + 1)
    if len(raw) > MAX_SYMBOLIC_OUTPUT:
        raise Attestor35Error("symbolic analyzer exceeded its output boundary")
    try:
        report = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise Attestor35Error("symbolic analyzer returned malformed evidence") from exc
    if type(report) is not dict or report.get("schema") != symbolic_engine35.SCHEMA:
        raise Attestor35Error("symbolic analyzer returned an unsupported evidence schema")
    digest = report.get("report_sha256")
    body = {key: value for key, value in report.items() if key != "report_sha256"}
    if digest != hashlib.sha256(json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")).hexdigest():
        raise Attestor35Error("symbolic analyzer evidence digest mismatch")
    report.setdefault("analysis", {})["analyzer_process_isolated"] = True
    report["analysis"]["wall_clock_boundary_seconds"] = float(timeout_seconds)
    # The worker digest covered its native result.  Keep that identity explicit
    # after adding transport metadata instead of pretending the old hash covers it.
    report["worker_report_sha256"] = report.pop("report_sha256")
    report["transport_report_sha256"] = _sha(report)
    return report


def _project_root(requested: Path) -> Path:
    return requested if requested.is_dir() else requested.parent


def _single_file_supply_graph(requested: Path) -> dict[str, Any]:
    """Preserve exact file scope instead of silently scanning sibling lockfiles."""
    gap = ("single-file scope was preserved; sibling lockfiles were not read, so an "
           "exact workspace dependency graph was not produced")
    body = {
        "schema": supply_chain35.SCHEMA, "version": supply_chain35.VERSION,
        "status": "unavailable", "root": str(requested), "manifests": [],
        "nodes": [], "edges": [], "gaps": [gap],
        "scope": {"kind": "file", "requested_root": str(requested),
                  "effective_root": str(requested), "expanded": False},
        "execution": {"dependencies_installed": False, "network": False,
                      "build_scripts": False, "target_code": False},
    }
    body["graph_sha256"] = _sha({key: value for key, value in body.items()
                                  if key not in {"root", "graph_sha256"}})
    return body


def _slim_ir(report: Mapping[str, Any]) -> dict[str, Any]:
    """Bound public IR transport while retaining a digest of the complete IR."""
    output: dict[str, Any] = {
        key: value for key, value in report.items()
        if key not in PUBLIC_IR_LIMITS
    }
    totals = {}
    truncated = False
    for key, maximum in PUBLIC_IR_LIMITS.items():
        rows = report.get(key)
        safe_rows = list(rows) if type(rows) is list else []
        totals[key] = len(safe_rows)
        output[key] = safe_rows[:maximum]
        truncated = truncated or len(safe_rows) > maximum
    coverage = dict(output.get("coverage", {})) if type(output.get("coverage")) is dict else {}
    coverage.update({"public_report_truncated": truncated,
                     "full_counts": totals,
                     "full_content_sha256": polyglot_ir35.content_fingerprint(dict(report))})
    if truncated:
        limitations = list(coverage.get("limitations", []))
        limitations.append("the public IR view is bounded; use full_content_sha256 to identify the complete in-memory result")
        coverage["limitations"] = limitations
    output["coverage"] = coverage
    return output


def _normalise_symbolic(value: Mapping[str, Any], project: Path) -> dict[str, Any]:
    try:
        path = Path(str(value.get("path", "workspace")))
        if path.is_absolute():
            path_text = path.resolve().relative_to(project).as_posix()
        else:
            path_text = path.as_posix()
    except (OSError, ValueError):
        path_text = Path(str(value.get("path", "workspace"))).name or "workspace"
    try:
        line = max(1, int(value.get("line", 1)))
    except (TypeError, ValueError):
        line = 1
    severity = str(value.get("severity", "HIGH")).upper()
    if severity not in SEVERITY_RANK:
        severity = "HIGH"
    fingerprint = str(value.get("fingerprint") or _sha([
        value.get("rule"), path_text, line, value.get("message")]))
    return {
        "rule": str(value.get("rule", "symbolic-analysis"))[:300],
        "severity": severity, "cwe": str(value.get("cwe", ""))[:80],
        "owasp": "", "path": path_text, "line": line,
        "message": str(value.get("message", "Symbolic evidence requires review."))[:4_000],
        "fix": str(value.get("remediation", ""))[:8_000],
        # Symbolic witnesses are strong structured evidence, but no empirical
        # probability is invented before an independently labelled corpus exists.
        "confidence": None,
        "confidence_basis": "unscored-bounded-symbolic-witness",
        "exploitability": "evidence-dependent", "safe_to_autofix": False,
        "source": "symbolic-engine35", "fingerprint": fingerprint[:128],
        "evidence_level": value.get("evidence_level", "bounded-symbolic-witness"),
        "path_predicates": list(value.get("path_predicates", []))[:128],
        "witness": list(value.get("witness", []))[:256],
        "symbolic_source": value.get("source", {}), "symbolic_sink": value.get("sink", {}),
    }


def _symbolic_paths(report: Mapping[str, Any], project: Path) -> list[dict[str, Any]]:
    rows = []
    for finding in report.get("findings", []) if type(report.get("findings")) is list else []:
        if type(finding) is not dict:
            continue
        nodes = []
        for step in finding.get("witness", []) if type(finding.get("witness")) is list else []:
            if type(step) is not dict:
                continue
            node = {"kind": str(step.get("kind", "step"))[:64],
                    "label": str(step.get("detail", step.get("symbol", "evidence")))[:500]}
            if step.get("path"):
                try:
                    node["path"] = Path(str(step["path"])).as_posix()
                except ValueError:
                    node["path"] = "<invalid-path>"
            if step.get("line"):
                try:
                    node["line"] = max(1, int(step["line"]))
                except (TypeError, ValueError):
                    node["line"] = 1
            nodes.append(node)
        if len(nodes) >= 2:
            rows.append({
                "id": str(finding.get("fingerprint", _sha(nodes)))[:128],
                "title": str(finding.get("message", "Bounded symbolic source-to-sink path"))[:1_000],
                "severity": str(finding.get("severity", "HIGH")).upper(),
                "rule": str(finding.get("rule", "symbolic-taint"))[:300],
                "nodes": nodes, "confidence": None, "source": "symbolic-engine35",
                "evidence_level": "bounded-symbolic-witness",
            })
    return rows


def _merge_findings(core_rows: Iterable[Any], symbolic: Mapping[str, Any] | None,
                    project: Path, profile: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    combined = [dict(row) for row in core_rows if type(row) is dict]
    if symbolic:
        combined.extend(_normalise_symbolic(row, project)
                        for row in symbolic.get("findings", []) if type(row) is dict)
    unique: dict[str, dict[str, Any]] = {}
    for row in combined:
        fingerprint = str(row.get("fingerprint") or _sha([
            row.get("rule"), row.get("path"), row.get("line"), row.get("message")]))[:128]
        row["fingerprint"] = fingerprint
        previous = unique.get(fingerprint)
        if previous is None or SEVERITY_RANK.get(str(row.get("severity", "MEDIUM")), 3) > \
                SEVERITY_RANK.get(str(previous.get("severity", "MEDIUM")), 3):
            unique[fingerprint] = row
    calibrated = calibration35.apply_profile(list(unique.values()), profile)

    def confidence(row: Mapping[str, Any]) -> float:
        value = row.get("confidence")
        return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) \
            and math.isfinite(float(value)) else -1.0
    return sorted(calibrated, key=lambda row: (
        -SEVERITY_RANK.get(str(row.get("severity", "MEDIUM")).upper(), 3),
        -confidence(row), str(row.get("path", "")).casefold(),
        int(row.get("line", 1) or 1), str(row.get("rule", ""))))


def _calibration_summary(profile: Mapping[str, Any] | None,
                         findings: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    calibrated = sum(type(row.get("confidence_calibration")) is dict and
                     row["confidence_calibration"].get("state") == "calibrated"
                     for row in findings)
    if profile is None:
        return {"status": "unavailable", "calibrated_findings": 0,
                "uncalibrated_findings": len(findings),
                "statement": "detector scores are not empirical probabilities without verified labels"}
    return {"status": "active" if calibrated else "insufficient-evidence",
            "profile_sha256": profile.get("profile_sha256", ""),
            "corpus": profile.get("corpus", {}), "calibrated_findings": calibrated,
            "uncalibrated_findings": len(findings) - calibrated,
            "statement": "only bins meeting the verified-label sample policy replace detector scores"}


def _semantic_git(project: Path, ir: Mapping[str, Any] | None, git_base: str,
                  enabled: bool) -> tuple[dict[str, Any], dict[str, Any]]:
    if not enabled or ir is None:
        return ({"status": "not-run"}, {"status": "not-run"})
    database = git_intelligence35.SemanticDatabase(project)
    update = database.update(dict(ir))
    semantic = {"status": "ready", "update": update,
                "database": database.to_document(),
                "persistence": "not-written; call SemanticDatabase.save explicitly"}
    try:
        repository = git_intelligence35.GitRepository(project)
        head = repository.resolve_commit("HEAD")
        git_report: dict[str, Any] = {
            "status": "available", "head": head,
            "mode": "read-only-fixed-argv", "target_code_executed": False,
            "impact": {"status": "not-requested",
                       "reason": "supply git_base to compute change impact"},
        }
        if git_base:
            git_report["impact"] = {"status": "complete", **git_intelligence35.change_impact(
                repository, database, git_base, "HEAD")}
        return semantic, git_report
    except git_intelligence35.GitIntelligenceError:
        return semantic, {"status": "unavailable", "head": "", "mode": "read-only-fixed-argv",
                          "target_code_executed": False,
                          "reason": "workspace is not a readable Git repository or Git is unavailable"}


def _fabric_report(capabilities: execution_fabric35.FabricCapabilities | None,
                   enabled: bool) -> dict[str, Any]:
    if not enabled:
        return {"status": "not-run", "eligible_runtimes": [],
                "fallback": "none"}
    if capabilities is None:
        return {"status": "unavailable", "eligible_runtimes": [],
                "fallback": "none", "reason": "capability detection failed safely"}
    rows = [dataclasses.asdict(item) for item in capabilities.runtimes]
    eligible = [item.name for item in capabilities.eligible]
    return {"status": "available" if eligible else "unavailable",
            "eligible_runtimes": eligible, "runtimes": rows,
            "windows_isolation_available": capabilities.windows_isolation_available,
            "fallback": "none",
            "policy": "rootless hardened Linux container or refuse; never run target code on the host"}


def maximum(root: str | os.PathLike[str], *, improve: bool = True,
            max_improvement_files: int = 3, compiler_checks: bool = False,
            use_cache: bool = True, jobs: int = 4,
            test_command: Sequence[str] | None = None, authorize_tests: bool = False,
            apply_improvements: bool = False, backup_root: str = "",
            advisory_snapshot: Mapping[str, Any] | None = None,
            advisory_keys: Mapping[str, bytes] | None = None,
            rule_packs: Sequence[str] = (), rule_pack_key: bytes | None = None,
            require_signed_packs: bool = False,
            memory_baseline: Mapping[str, Any] | None = None,
            components: Sequence[str] = DEFAULT_COMPONENTS,
            calibration_profile: Mapping[str, Any] | None = None,
            calibration_observations: Iterable[Mapping[str, Any]] | None = None,
            git_base: str = "", symbolic_timeout: float = 45.0,
            truth_key: bytes | None = None,
            truth_key_id: str = "") -> dict[str, Any]:
    requested = Path(root).expanduser().resolve()
    if not requested.exists() or not (requested.is_file() or requested.is_dir()):
        raise Attestor35Error("target does not exist or is not a regular file/directory")
    project = _project_root(requested)
    component_set = set(components)
    unknown = component_set - set(DEFAULT_COMPONENTS)
    if unknown:
        raise Attestor35Error("unknown component(s): " + ", ".join(sorted(unknown)))
    if calibration_profile is not None and calibration_observations is not None:
        raise Attestor35Error("choose a calibration profile or observations, not both")
    if calibration_observations is not None:
        calibration_profile = calibration35.build_profile(calibration_observations)
    if calibration_profile is not None and not calibration35.verify_profile(calibration_profile)[0]:
        raise Attestor35Error("calibration profile failed integrity/policy verification")
    errors: list[dict[str, str]] = []
    core_components = tuple(name for name in CORE_COMPONENTS if name in component_set)

    def core_job():
        return attestor3.maximum(
            requested, improve=improve, max_improvement_files=max_improvement_files,
            compiler_checks=compiler_checks, use_cache=use_cache, jobs=jobs,
            test_command=test_command, authorize_tests=authorize_tests,
            apply_improvements=apply_improvements, backup_root=backup_root,
            advisory_snapshot=advisory_snapshot, advisory_keys=advisory_keys,
            rule_packs=rule_packs, rule_pack_key=rule_pack_key,
            require_signed_packs=require_signed_packs,
            memory_baseline=memory_baseline, components=core_components)

    jobs_map = {"core-3.0": core_job}
    if "symbolic" in component_set:
        jobs_map["symbolic"] = lambda: _symbolic_job(requested, symbolic_timeout)
    if "polyglot-ir" in component_set:
        jobs_map["polyglot-ir"] = lambda: polyglot_ir35.analyze(requested)
    if "supply-chain-graph" in component_set:
        jobs_map["supply-chain-graph"] = lambda: (
            _single_file_supply_graph(requested) if requested.is_file() else
            supply_chain35.analyze_dependency_graph(project))
    if "execution-fabric" in component_set:
        jobs_map["execution-fabric"] = execution_fabric35.detect_capabilities
    results: dict[str, Any] = {}
    workers = max(1, min(5, len(jobs_map)))
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers,
                                               thread_name_prefix="attestor35") as pool:
        pending = {name: pool.submit(_component, name, function, errors)
                   for name, function in jobs_map.items()}
        for name, future in pending.items():
            results[name] = future.result()

    core = results.get("core-3.0")
    if core is not None:
        base = attestor3.safe_public_report(core)
    else:
        base = {"root": str(requested), "status": "failed", "summary": {},
                "findings": [], "top_findings": [], "priorities": [],
                "attack_paths": [], "improvements": [], "errors": [],
                "coverage": {"gaps": ["Attestor 3.0 compatibility core failed"],
                             "absence_proven": False}}
    report = {key: value for key, value in base.items()
              if key not in {"schema", "version", "truth_guard", "truth_guard_runtime",
                             "truth_guard2", "report_sha256", "view_sha256",
                             "source_report_sha256"} and not key.startswith("_")}
    symbolic = results.get("symbolic") if type(results.get("symbolic")) is dict else None
    ir_full = results.get("polyglot-ir") if type(results.get("polyglot-ir")) is dict else None
    supply_graph = results.get("supply-chain-graph") \
        if type(results.get("supply-chain-graph")) is dict else {"status": "not-run"}
    findings = _merge_findings(report.get("findings", []), symbolic, project,
                               calibration_profile)
    existing_paths = report.get("attack_paths") if type(report.get("attack_paths")) is list else []
    attack_paths = list(existing_paths)
    if symbolic:
        attack_paths.extend(_symbolic_paths(symbolic, project))
    path_map = {str(row.get("id", _sha(row))): row for row in attack_paths if type(row) is dict}
    attack_paths = sorted(path_map.values(), key=lambda row: (
        -SEVERITY_RANK.get(str(row.get("severity", "HIGH")).upper(), 4),
        -len(row.get("nodes", [])), str(row.get("id", ""))))[:MAX_ATTACK_PATHS]
    if requested.is_file() and "git-intelligence" in component_set:
        incremental = {"status": "not-run", "reason": "single-file scope preserved"}
        git_report = {
            "status": "unavailable", "head": "", "mode": "not-run-file-scope",
            "target_code_executed": False,
            "reason": "single-file scope was preserved; repository-wide Git evidence was not read",
        }
    else:
        incremental, git_report = _semantic_git(
            project, ir_full, git_base, "git-intelligence" in component_set)
    fabric = _fabric_report(results.get("execution-fabric"),
                            "execution-fabric" in component_set)

    previous_errors = report.get("errors") if type(report.get("errors")) is list else []
    all_errors = [*previous_errors, *errors]
    coverage = dict(report.get("coverage", {})) if type(report.get("coverage")) is dict else {}
    gaps = list(coverage.get("gaps", [])) if type(coverage.get("gaps")) is list else []
    core_report_failed = bool(
        core is None or base.get("status") == "failed" or previous_errors)
    core_completed: set[str] = set()
    if not core_report_failed:
        reported_core_completed = coverage.get("completed_components", [])
        if type(reported_core_completed) is list:
            core_completed = (set(core_components) &
                              {str(name) for name in reported_core_completed})
    elif core_components:
        gaps.append(
            "Attestor 3.0 compatibility core failed or reported component errors; "
            "legacy component completion withheld")
    omitted = sorted(set(DEFAULT_COMPONENTS) - component_set)
    if omitted:
        gaps.append("components not run: " + ", ".join(omitted))
    if symbolic and symbolic.get("status") == "partial":
        gaps.append("symbolic analysis partial: " + ", ".join(symbolic.get("partial_reasons", [])))
    if ir_full and not ir_full.get("coverage", {}).get("complete"):
        gaps.append("polyglot IR has explicit parse/discovery coverage gaps")
    if supply_graph.get("status") != "complete" and "supply-chain-graph" in component_set:
        gaps.append("exact dependency graph state: " + str(supply_graph.get("status", "unavailable")))
        for item in supply_graph.get("gaps", []) if type(supply_graph.get("gaps")) is list else []:
            if item:
                gaps.append(str(item)[:1_000])
    if git_report.get("status") == "unavailable" and "git-intelligence" in component_set:
        gaps.append("Git change intelligence unavailable for this workspace")
    if fabric.get("status") == "unavailable" and "execution-fabric" in component_set:
        gaps.append("no eligible fail-closed container runtime; authorized target execution will be refused")
    gaps = list(dict.fromkeys(str(item)[:1_000] for item in gaps if item))
    completed_components = {
        name for name in component_set - set(CORE_COMPONENTS)
        if results.get(name) is not None and
        not (name == "supply-chain-graph" and supply_graph.get("status") == "unavailable")
    }
    completed_components.update(core_completed)
    if ("git-intelligence" in component_set and
            git_report.get("status") == "available"):
        completed_components.add("git-intelligence")
    coverage.update({
        "requested_components": sorted(component_set),
        "completed_components": sorted(completed_components),
        "omitted_components": omitted, "gaps": gaps, "absence_proven": False,
    })
    severity = {name: sum(str(row.get("severity", "")).upper() == name for row in findings)
                for name in SEVERITY_RANK}
    improvements = report.get("improvements") if type(report.get("improvements")) is list else []
    accepted = sum(type(row) is dict and row.get("accepted") is True for row in improvements)
    refused = sum(type(row) is dict and row.get("accepted") is not True for row in improvements)
    status = "failed" if all_errors else (
        "improved-with-review" if findings and accepted else
        "action-required" if findings else
        "no-findings-with-gaps" if gaps else "no-findings-from-enabled-checks")
    summary = dict(report.get("summary", {})) if type(report.get("summary")) is dict else {}
    summary.update({
        "findings": len(findings), "severity": severity,
        "symbolic_findings": len(symbolic.get("findings", [])) if symbolic else 0,
        "polyglot_files": len(ir_full.get("files", [])) if ir_full else 0,
        "attack_paths": len(attack_paths),
        "dependency_graph_nodes": len(supply_graph.get("nodes", [])),
        "dependency_graph_edges": len(supply_graph.get("edges", [])),
        "verified_improvements": accepted, "refused_improvements": refused,
        "component_errors": len(all_errors),
    })
    priorities = []
    seen_actions = set()
    for row in findings:
        action = row.get("fix") or row.get("message")
        if action and action not in seen_actions:
            seen_actions.add(action)
            priorities.append({"priority": row.get("severity", "MEDIUM"),
                               "fix": action, "rule": row.get("rule", ""),
                               "path": row.get("path", "")})
        if len(priorities) >= 40:
            break
    execution = dict(report.get("execution", {})) if type(report.get("execution")) is dict else {}
    execution.update({"fabric_status": fabric.get("status", "unknown"),
                      "sandbox_state": fabric.get("status", "unknown"),
                      "host_execution_fallback": False})
    report.update({
        "schema": SCHEMA, "version": VERSION, "status": status,
        "summary": summary, "findings": findings,
        "top_findings": findings[:MAX_TOP_FINDINGS], "priorities": priorities,
        "attack_paths": attack_paths, "errors": all_errors, "coverage": coverage,
        "symbolic_35": symbolic or {"status": "not-run"},
        "polyglot_ir_35": _slim_ir(ir_full) if ir_full else {"status": "not-run"},
        "incremental_semantics_35": incremental,
        "git_intelligence_35": git_report,
        "supply_chain_graph_35": supply_graph,
        "execution_fabric_35": fabric,
        "transactional_repair_35": {
            "status": "not-requested", "default": "verified-dry-run",
            "mandatory_hook_kinds": ["scanner", "build", "test"],
            "separate_execution_authorization": True,
            "separate_apply_authorization": True,
            "rollback_on_partial_apply_failure": True,
        },
        "confidence_calibration_35": _calibration_summary(calibration_profile, findings),
        "execution": execution,
        "engines": {
            "compatibility_core": "3.0", "symbolic": "bounded-path-field-symbolic/3.5",
            "polyglot_ir": polyglot_ir35.ANALYSIS_LEVEL,
            "truth_guard": "2.0", "response": "evidence-locked/3.5",
        },
        "catalog": {"precision_rules": len(precision_catalog.RULES),
                    "count_is_not_recall_claim": True},
        "assurance_35": [
            "A detector score is not presented as an empirical probability without independently verified labels.",
            "Lexical polyglot IR is not described as compiler-grade type or dispatch resolution.",
            "Git blame identifies introducing-commit candidates only; it does not prove historical causality.",
            "VEX not_affected requires a content-addressed unreachable proof, never a caller-supplied boolean.",
            "Execution requires a separately authorized eligible rootless hardened container; there is no host fallback.",
            "Truth Guard 2 binds the redacted public report to an independently rebuilt evidence chain.",
        ],
    })
    return truth_guard35.guard_document(report, key=truth_key, key_id=truth_key_id)


def safe_public_report(report: Mapping[str, Any], *, truth_key: bytes | None = None) -> dict[str, Any]:
    verification = truth_guard35.verify_guarded(report, key=truth_key)
    if verification.get("ok"):
        return json.loads(json.dumps(report, ensure_ascii=False, allow_nan=False, default=str))
    return truth_guard35.guard_document({
        "schema": SCHEMA, "version": VERSION, "status": "inconsistent",
        "summary": {"findings": 0, "component_errors": 1},
        "findings": [], "attack_paths": [], "improvements": [],
        "priorities": [], "errors": [{"component": "truth-guard2",
                                        "error": "public-report-integrity-failure"}],
        "coverage": {"gaps": ["the supplied report failed Truth Guard 2 verification"],
                     "absence_proven": False},
        "response": "Result withheld because its evidence ledger did not verify.",
    })


public_report = safe_public_report


def render(report: Mapping[str, Any], style: str = "professional", *,
           truth_key: bytes | None = None) -> str:
    safe = safe_public_report(report, truth_key=truth_key)
    return response35.render_guarded(safe, style, truth_key=truth_key)


def to_sarif(report: Mapping[str, Any], *, truth_key: bytes | None = None) -> dict[str, Any]:
    sarif = attestor3._generic_sarif(safe_public_report(report, truth_key=truth_key))
    driver = sarif["runs"][0]["tool"]["driver"]
    driver["name"] = "Attestor 3.5"
    driver["semanticVersion"] = VERSION
    return sarif


def _write_improvements(report: Mapping[str, Any], output: str | os.PathLike[str], *,
                        truth_key: bytes | None = None) -> list[str]:
    destination_root = Path(output).expanduser().resolve()
    destination_root.mkdir(parents=True, exist_ok=True)
    written = []
    for row in safe_public_report(report, truth_key=truth_key).get("improvements", []):
        if type(row) is not dict or row.get("accepted") is not True or not row.get("improved_source"):
            continue
        relative = Path(str(row.get("target", "")))
        if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
            raise Attestor35Error("improvement output path is unsafe")
        destination = (destination_root / relative).resolve()
        try:
            destination.relative_to(destination_root)
        except ValueError as exc:
            raise Attestor35Error("improvement output escapes destination") from exc
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(str(row["improved_source"]), encoding="utf-8", newline="")
        written.append(str(destination))
    return written


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--no-improve", action="store_true")
    parser.add_argument("--max-improvement-files", type=int, default=3)
    parser.add_argument("--compiler-checks", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--run-tests", action="store_true")
    parser.add_argument("--test-command-json")
    parser.add_argument("--apply-improvements", action="store_true")
    parser.add_argument("--backup-root", default="")
    parser.add_argument("--advisory-snapshot")
    parser.add_argument("--advisory-key-file")
    parser.add_argument("--advisory-key-id", default="default")
    parser.add_argument("--rule-pack", action="append", default=[])
    parser.add_argument("--rule-key-file")
    parser.add_argument("--require-signed-packs", action="store_true")
    parser.add_argument("--calibration-data")
    parser.add_argument("--calibration-profile")
    parser.add_argument("--git-base", default="")
    parser.add_argument("--symbolic-timeout", type=float, default=45.0)
    parser.add_argument("--component", action="append", choices=DEFAULT_COMPONENTS)
    parser.add_argument("--truth-key-file")
    parser.add_argument("--truth-key-id", default="")
    parser.add_argument("--improved-out")
    parser.add_argument("--response-style", choices=response35.STYLES, default="professional")
    parser.add_argument("--format", choices=("text", "json", "sarif", "cyclonedx", "spdx", "vex"),
                        default="text")
    parser.add_argument("--out")
    args = parser.parse_args(argv)
    if not 0 <= args.max_improvement_files <= 10:
        parser.error("--max-improvement-files must be between 0 and 10")
    if not 1 <= args.jobs <= 64:
        parser.error("--jobs must be between 1 and 64")
    command = None
    if args.test_command_json:
        try:
            command = json.loads(args.test_command_json)
        except json.JSONDecodeError as exc:
            parser.error("--test-command-json is invalid: %s" % exc)
        if type(command) is not list or not command or any(type(item) is not str or not item for item in command):
            parser.error("--test-command-json must be a non-empty argv list")
    if bool(command) != bool(args.run_tests):
        parser.error("selected tests require both --run-tests and --test-command-json")
    if args.apply_improvements and args.no_improve:
        parser.error("--apply-improvements conflicts with --no-improve")
    if args.calibration_data and args.calibration_profile:
        parser.error("choose --calibration-data or --calibration-profile")

    def load_json(path: str) -> Any:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    observations = load_json(args.calibration_data) if args.calibration_data else None
    profile = load_json(args.calibration_profile) if args.calibration_profile else None
    if observations is not None and type(observations) is not list:
        parser.error("--calibration-data must contain a JSON list")
    snapshot = supply_chain_center.load_advisory_snapshot(args.advisory_snapshot) \
        if args.advisory_snapshot else None
    advisory_keys = {args.advisory_key_id: Path(args.advisory_key_file).read_bytes()} \
        if args.advisory_key_file else None
    rule_key = Path(args.rule_key_file).read_bytes() if args.rule_key_file else None
    truth_key = Path(args.truth_key_file).read_bytes() if args.truth_key_file else None
    if truth_key and not args.truth_key_id:
        parser.error("--truth-key-file requires --truth-key-id")
    try:
        report = maximum(
            args.root, improve=not args.no_improve,
            max_improvement_files=args.max_improvement_files,
            compiler_checks=args.compiler_checks, use_cache=not args.no_cache,
            jobs=args.jobs, test_command=command, authorize_tests=args.run_tests,
            apply_improvements=args.apply_improvements, backup_root=args.backup_root,
            advisory_snapshot=snapshot, advisory_keys=advisory_keys,
            rule_packs=args.rule_pack, rule_pack_key=rule_key,
            require_signed_packs=args.require_signed_packs,
            components=tuple(args.component or DEFAULT_COMPONENTS),
            calibration_profile=profile, calibration_observations=observations,
            git_base=args.git_base, symbolic_timeout=args.symbolic_timeout,
            truth_key=truth_key, truth_key_id=args.truth_key_id)
        public = safe_public_report(report, truth_key=truth_key)
        if args.format == "json":
            text = truth_guard35.deterministic_json(public)
        elif args.format == "sarif":
            text = json.dumps(to_sarif(report, truth_key=truth_key), indent=2, sort_keys=True)
        elif args.format == "cyclonedx":
            text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get("cyclonedx", {}), indent=2, sort_keys=True)
        elif args.format == "spdx":
            text = json.dumps(public.get("supply_chain", {}).get("sbom", {}).get("spdx", {}), indent=2, sort_keys=True)
        elif args.format == "vex":
            text = json.dumps(public.get("supply_chain", {}).get("vex", {}), indent=2, sort_keys=True)
        else:
            text = response35.render_guarded(public, args.response_style, truth_key=truth_key)
        if args.out:
            Path(args.out).write_text(text + ("" if text.endswith("\n") else "\n"), encoding="utf-8")
        else:
            print(text)
        if args.improved_out:
            _write_improvements(report, args.improved_out, truth_key=truth_key)
        return 2 if public.get("status") in {"failed", "inconsistent", "no-evidence"} else (
            1 if public.get("summary", {}).get("findings", 0) or
            public.get("status") == "no-findings-with-gaps" else 0)
    except (OSError, Attestor35Error, PermissionError, RuntimeError, TypeError, ValueError) as exc:
        print("Attestor 3.5 failed safely: %s" % type(exc).__name__, file=os.sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
