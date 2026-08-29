#!/usr/bin/env python3
"""Permission-gated, pathless project discovery for Attestor 4.1.3.

This module deliberately separates *permission to discover* from Attestor's normal
path-scoped analysis.  Every invocation starts denied.  When a caller grants
permission for that invocation, discovery remains bounded and read-only: it
does not follow links or reparse points, inspect excluded sensitive/system
trees, execute discovered code, enable compiler/test hooks, use analysis
caches, or apply a repair.  Optional improvements are review summaries only.

The returned document is intentionally compact.  It contains project and
finding metadata, never source text, candidate source, secret values, build
logs, or an embedded full Attestor report.
"""
from __future__ import annotations

import os
from pathlib import Path, PurePath
import stat
from typing import Any, Callable, Iterable, Mapping, Sequence

import attestor41


SCHEMA = "attestor-computer-scan/4.1"
VERSION = "4.1.3"

MAX_PROJECTS = 12
DEFAULT_MAX_DIRECTORIES = 20_000
DEFAULT_MAX_FILES = 200_000
DEFAULT_MAX_DEPTH = 12
MAX_DIRECTORIES = 100_000
MAX_FILES = 1_000_000
MAX_DEPTH = 24
MAX_DISCOVERED_PROJECTS = 500
MAX_ENTRIES_PER_DIRECTORY = 20_000
MAX_MARKERS_PER_PROJECT = 24
MAX_SOURCE_SAMPLES = 200
MAX_PROJECT_FINDINGS = 50
MAX_TOTAL_FINDINGS = 300
MAX_PROJECT_IMPROVEMENTS = 20
MAX_TOTAL_IMPROVEMENTS = 100
MAX_GAPS = 200


class ComputerScanError(ValueError):
    """A computer-scan permission, scope, or resource boundary is invalid."""


_PROJECT_MARKERS = frozenset({
    ".git", ".hg", ".svn",
    "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
    "pipfile", "poetry.lock", "tox.ini",
    "package.json", "pnpm-workspace.yaml", "yarn.lock", "bun.lockb",
    "cargo.toml", "go.mod", "go.work", "pom.xml", "build.gradle",
    "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
    "composer.json", "gemfile", "mix.exs", "pubspec.yaml",
    "cmakelists.txt", "makefile", "meson.build", "deno.json",
    "deno.jsonc", "project.clj", "deps.edn",
})
_PROJECT_MARKER_SUFFIXES = (
    ".sln", ".csproj", ".fsproj", ".vbproj", ".xcodeproj",
)
_SOURCE_SUFFIXES = frozenset({
    ".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
    ".java", ".kt", ".kts", ".go", ".rs", ".c", ".h", ".cc",
    ".cpp", ".cxx", ".hpp", ".cs", ".fs", ".fsx", ".vb", ".rb",
    ".php", ".swift", ".scala", ".sc", ".sh", ".bash", ".zsh",
    ".fish", ".ps1", ".psm1", ".sql", ".r", ".dart", ".lua",
    ".ex", ".exs", ".erl", ".hrl", ".clj", ".cljs", ".vue",
    ".svelte", ".html", ".htm", ".css", ".scss", ".sass", ".less",
    ".sol", ".tf", ".hcl",
})

# Names are matched case-insensitively at every depth.  This is conservative
# by design: pathless discovery should miss an oddly named project rather than
# wander into credentials, browser profiles, dependency trees, or OS state.
_EXCLUDED_DIRECTORY_NAMES = frozenset({
    # Credentials, identity, cloud tooling, and user application state.
    ".ssh", ".gnupg", ".gpg", ".aws", ".azure", ".kube", ".docker",
    ".config", ".local", ".cache", "appdata", "application data",
    "local settings", "cookies", "keychains", "library",
    # Browser/mail profiles and similarly sensitive application stores.
    "bravesoftware", "chrome", "chromium", "edge", "firefox", "mozilla",
    "thunderbird", "mail", "outlook files",
    # VCS internals, dependencies, caches, generated/build output.
    ".git", ".hg", ".svn", ".idea", ".vscode", "node_modules", "vendor",
    ".venv", "venv", "env", "__pycache__", ".pytest_cache", ".mypy_cache",
    ".ruff_cache", ".tox", ".nox", ".gradle", ".npm", ".pnpm-store",
    ".yarn", "bower_components", "dist", "build", "target", "out",
    ".next", ".nuxt", ".svelte-kit", "coverage", ".coverage",
    # Windows, macOS, Linux, device, runtime, and recovery state.
    "windows", "program files", "program files (x86)", "programdata",
    "system volume information", "$recycle.bin", "recovery", "perflogs",
    "documents and settings", "system32", "winsxs", "proc", "sys", "dev",
    "run", "etc", "root", "lost+found", "private", "volumes", "mnt",
    "media", "net", "automount",
})


def _text(value: Any, maximum: int = 1_000) -> str:
    # Keep ordinary Unicode but visibly escape terminal controls and Unicode
    # bidi controls that could disguise a filename, finding, or coverage gap.
    result: list[str] = []
    size = 0
    bidi_controls = {
        0x061C, 0x200E, 0x200F, 0x202A, 0x202B, 0x202C, 0x202D,
        0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x206A, 0x206B,
        0x206C, 0x206D, 0x206E, 0x206F,
    }
    for character in str(value or ""):
        codepoint = ord(character)
        if codepoint < 0x20 or 0x7F <= codepoint <= 0x9F:
            clean = "\\x%02x" % codepoint
        elif codepoint in bidi_controls:
            clean = "\\u%04x" % codepoint
        else:
            clean = character
        if size + len(clean) > maximum:
            break
        result.append(clean)
        size += len(clean)
    return "".join(result)


def _integer(value: Any, default: int = 0, maximum: int = 2_000_000_000) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        return default
    return number if 0 <= number <= maximum else default


def _dedupe(values: Iterable[Any], maximum: int = MAX_GAPS) -> list[str]:
    rows: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = _text(value)
        if not item or item in seen:
            continue
        seen.add(item)
        rows.append(item)
        if len(rows) >= maximum:
            break
    return rows


def _is_link_or_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except OSError:
        return False
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _entry_is_link_or_reparse(entry: os.DirEntry[str]) -> bool:
    try:
        if entry.is_symlink():
            return True
        metadata = entry.stat(follow_symlinks=False)
    except OSError:
        # An entry that cannot be classified safely is not traversed.
        return True
    attributes = int(getattr(metadata, "st_file_attributes", 0))
    reparse_flag = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return stat.S_ISLNK(metadata.st_mode) or bool(attributes & reparse_flag)


def _safe_root(value: str | os.PathLike[str]) -> Path:
    supplied = Path(value).expanduser()
    try:
        spelling = supplied if supplied.is_absolute() else Path.cwd() / supplied
        current = Path(spelling.anchor)
        for part in spelling.parts[1:]:
            if part in {"", "."}:
                continue
            if part == "..":
                current = current.parent
                continue
            current = current / part
            if _is_link_or_reparse(current):
                raise ComputerScanError("discovery root traverses a link or reparse point")
        lexical = Path(os.path.abspath(os.fspath(spelling)))
        selected = lexical.resolve(strict=True)
    except ComputerScanError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ComputerScanError("discovery root is unavailable") from exc
    if not selected.is_dir() or _is_link_or_reparse(selected):
        raise ComputerScanError("discovery root must be a real directory")
    if not _path_is_local_fixed(selected):
        raise ComputerScanError("network and removable discovery roots are denied")
    return selected


def _path_is_local_fixed(path: Path) -> bool:
    """Reject Windows UNC, mapped-network, and removable-backed paths."""
    if os.name != "nt":
        return True
    anchor = path.anchor
    if not anchor or anchor.startswith("\\\\"):
        return False
    try:
        import ctypes
        return int(ctypes.windll.kernel32.GetDriveTypeW(anchor)) == 3
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def _fixed_drive_roots() -> tuple[list[Path], list[str]]:
    """Return local fixed drives only; never removable or network drives."""
    if os.name != "nt":
        return [Path(os.path.abspath(os.sep))], [
            "portable fixed-drive enumeration covers only the primary filesystem root"
        ]
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        mask = int(kernel32.GetLogicalDrives())
        roots: list[Path] = []
        for index in range(26):
            if not mask & (1 << index):
                continue
            root = "%s:\\" % chr(ord("A") + index)
            # DRIVE_FIXED == 3.  Network (4), removable (2), CD-ROM (5),
            # RAM disk (6), and unknown/no-root types are deliberately denied.
            if int(kernel32.GetDriveTypeW(root)) == 3:
                roots.append(Path(root))
        return roots, ([] if roots else ["no local fixed drive was available"])
    except (AttributeError, OSError, TypeError, ValueError):
        return [], ["local fixed-drive enumeration failed closed"]


def _scope_roots(
        scope: str,
        roots_override: Sequence[str | os.PathLike[str]] | None,
        ) -> tuple[list[Path], list[str]]:
    if roots_override is not None:
        values: list[str | os.PathLike[str]] = []
        try:
            for value in roots_override:
                if len(values) >= 32:
                    raise ComputerScanError("roots_override must contain 1 to 32 roots")
                values.append(value)
        except ComputerScanError:
            raise
        except TypeError as exc:
            raise ComputerScanError("roots_override must be a bounded sequence") from exc
        if not values:
            raise ComputerScanError("roots_override must contain 1 to 32 roots")
        raw_roots = [Path(value) for value in values]
        gaps: list[str] = []
    elif scope == "home":
        raw_roots = [Path.home()]
        gaps = []
    else:
        raw_roots, gaps = _fixed_drive_roots()

    roots: list[Path] = []
    seen: set[str] = set()
    for raw in raw_roots:
        try:
            selected = _safe_root(raw)
        except ComputerScanError:
            gaps.append("a discovery root was unavailable or link-backed and was skipped")
            continue
        identity = os.path.normcase(os.fspath(selected))
        if identity not in seen:
            seen.add(identity)
            roots.append(selected)
    roots.sort(key=lambda item: os.path.normcase(os.fspath(item)))
    return roots, gaps


def _is_project_marker(name: str, *, is_directory: bool) -> bool:
    lowered = name.casefold()
    del is_directory  # Marker suffixes can name either a file or a bundle directory.
    return lowered in _PROJECT_MARKERS or lowered.endswith(_PROJECT_MARKER_SUFFIXES)


def _is_source_file(name: str) -> bool:
    return Path(name).suffix.casefold() in _SOURCE_SUFFIXES


def _relative_to(value: Path, parent: Path) -> bool:
    try:
        value.relative_to(parent)
        return True
    except ValueError:
        return False


def _discover(
        roots: Sequence[Path], *, max_directories: int, max_files: int,
        max_depth: int, max_projects: int,
        ) -> dict[str, Any]:
    directories_seen = 0
    files_seen = 0
    source_files_seen = 0
    excluded_directories = 0
    linked_paths_skipped = 0
    cross_filesystem_paths_skipped = 0
    unreadable_directories = 0
    depth_omissions = 0
    entry_omissions = 0
    project_boundary_omissions = 0
    marker_omissions = 0
    limit_hits = {"directories": False, "files": False, "depth": False,
                  "entries_per_directory": False, "discovered_projects": False}
    samples: list[str] = []
    unreadable_samples: list[str] = []
    candidates: dict[str, dict[str, Any]] = {}
    stopped = False

    for root in roots:
        if stopped:
            break
        if root.name.casefold() in _EXCLUDED_DIRECTORY_NAMES:
            excluded_directories += 1
            continue
        try:
            root_device = root.stat().st_dev
        except OSError:
            unreadable_directories += 1
            continue
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            if directories_seen >= max_directories:
                limit_hits["directories"] = True
                stopped = True
                break
            directory, depth = stack.pop()
            if _is_link_or_reparse(directory):
                linked_paths_skipped += 1
                continue
            directories_seen += 1
            try:
                entries: list[os.DirEntry[str]] = []
                with os.scandir(directory) as stream:
                    for entry in stream:
                        if len(entries) >= MAX_ENTRIES_PER_DIRECTORY:
                            entry_omissions += 1
                            limit_hits["entries_per_directory"] = True
                            break
                        entries.append(entry)
                entries.sort(key=lambda item: (item.name.casefold(), item.name))
            except OSError:
                unreadable_directories += 1
                if len(unreadable_samples) < 20:
                    unreadable_samples.append(_text(directory, 2_000))
                continue

            markers: list[str] = []
            direct_sources = 0
            children: list[Path] = []
            for entry in entries:
                if files_seen >= max_files:
                    limit_hits["files"] = True
                    stopped = True
                    break
                if _entry_is_link_or_reparse(entry):
                    linked_paths_skipped += 1
                    continue
                try:
                    # On Windows, DirEntry.stat().st_dev can be zero even when
                    # os.stat() exposes the volume id; use the latter for the
                    # cross-filesystem boundary.
                    metadata = os.stat(entry.path, follow_symlinks=False)
                    if metadata.st_dev != root_device:
                        cross_filesystem_paths_skipped += 1
                        continue
                    is_directory = entry.is_dir(follow_symlinks=False)
                    is_file = entry.is_file(follow_symlinks=False)
                except OSError:
                    linked_paths_skipped += 1
                    continue
                if is_directory:
                    if _is_project_marker(entry.name, is_directory=True):
                        if len(markers) < MAX_MARKERS_PER_PROJECT:
                            markers.append(entry.name)
                        else:
                            marker_omissions += 1
                    if entry.name.casefold() in _EXCLUDED_DIRECTORY_NAMES:
                        excluded_directories += 1
                        continue
                    if depth >= max_depth:
                        depth_omissions += 1
                        limit_hits["depth"] = True
                        continue
                    children.append(Path(entry.path))
                    continue
                if not is_file:
                    continue
                files_seen += 1
                if _is_project_marker(entry.name, is_directory=False):
                    if len(markers) < MAX_MARKERS_PER_PROJECT:
                        markers.append(entry.name)
                    else:
                        marker_omissions += 1
                if _is_source_file(entry.name):
                    source_files_seen += 1
                    direct_sources += 1
                    if len(samples) < MAX_SOURCE_SAMPLES:
                        samples.append(_text(Path(entry.path), 2_000))

            if markers or direct_sources:
                identity = os.path.normcase(os.fspath(directory))
                if identity not in candidates:
                    if len(candidates) < MAX_DISCOVERED_PROJECTS:
                        candidates[identity] = {
                            "root": directory,
                            "markers": sorted(set(markers), key=str.casefold),
                            "direct_source_files": direct_sources,
                        }
                    else:
                        project_boundary_omissions += 1
                        limit_hits["discovered_projects"] = True
            if stopped:
                break
            # LIFO plus reverse order preserves lexical traversal order.
            for child in reversed(children):
                stack.append((child, depth + 1))

    ranked = sorted(
        candidates.values(),
        key=lambda row: (
            0 if row["markers"] else 1,
            -len(row["markers"]),
            -int(row["direct_source_files"]),
            len(PurePath(row["root"]).parts),
            os.path.normcase(os.fspath(row["root"])),
        ))
    selected: list[dict[str, Any]] = []
    overlap_omissions = 0
    selection_omissions = 0
    for row in ranked:
        root = row["root"]
        if any(_relative_to(root, chosen["root"]) or
               _relative_to(chosen["root"], root) for chosen in selected):
            overlap_omissions += 1
            continue
        if len(selected) >= max_projects:
            selection_omissions += 1
            continue
        selected.append(row)

    gaps: list[str] = []
    if limit_hits["directories"]:
        gaps.append("directory discovery stopped at the configured boundary")
    if limit_hits["files"]:
        gaps.append("file discovery stopped at the configured boundary")
    if depth_omissions:
        gaps.append("%d directorie(s) were not traversed at the depth boundary" % depth_omissions)
    if entry_omissions:
        gaps.append("at least %d directorie(s) exceeded the per-directory entry boundary" % entry_omissions)
    if project_boundary_omissions:
        gaps.append("%d project candidate(s) were omitted at the discovery-project boundary" %
                    project_boundary_omissions)
    if marker_omissions:
        gaps.append("%d additional project marker(s) were omitted from compact discovery metadata" %
                    marker_omissions)
    if selection_omissions:
        gaps.append("%d non-overlapping project(s) were not analyzed at the project-selection boundary" %
                    selection_omissions)
    if overlap_omissions:
        gaps.append("%d overlapping project candidate(s) were consolidated to avoid duplicate analysis" %
                    overlap_omissions)
    if excluded_directories:
        gaps.append("%d directorie(s) excluded by sensitive, system, dependency, or cache policy were not traversed" %
                    excluded_directories)
    if linked_paths_skipped:
        gaps.append("%d linked, reparse, or safely unclassifiable path(s) were not traversed" %
                    linked_paths_skipped)
    if cross_filesystem_paths_skipped:
        gaps.append("%d cross-filesystem path(s) were not traversed" %
                    cross_filesystem_paths_skipped)
    if unreadable_directories:
        gaps.append("%d directorie(s) were unreadable and skipped" % unreadable_directories)
    if not selected:
        gaps.append("no bounded project root was selected for analysis")

    public_projects = [{
        "root": _text(row["root"], 2_000),
        "markers": list(row["markers"]),
        "direct_source_files": int(row["direct_source_files"]),
    } for row in ranked[:MAX_DISCOVERED_PROJECTS]]
    selected_public = [{
        "root": _text(row["root"], 2_000),
        "markers": list(row["markers"]),
        "direct_source_files": int(row["direct_source_files"]),
    } for row in selected]
    return {
        "roots": [_text(root, 2_000) for root in roots],
        "directories_seen": directories_seen,
        "files_seen": files_seen,
        "source_files_seen": source_files_seen,
        "sample_source_files": sorted(samples, key=lambda item: (item.casefold(), item)),
        "excluded_directories": excluded_directories,
        "linked_or_reparse_paths_skipped": linked_paths_skipped,
        "cross_filesystem_paths_skipped": cross_filesystem_paths_skipped,
        "unreadable_directories": unreadable_directories,
        "unreadable_directory_samples": sorted(unreadable_samples, key=str.casefold),
        "projects_discovered": len(ranked),
        "projects": public_projects,
        "projects_selected": len(selected),
        "selected_projects": selected_public,
        "selected_internal": selected,
        "overlapping_projects_consolidated": overlap_omissions,
        "selection_omissions": selection_omissions,
        "limit_hits": limit_hits,
        "gaps": _dedupe(gaps),
    }


def _compact_finding(value: Mapping[str, Any]) -> dict[str, Any]:
    severity = _text(value.get("severity"), 20).upper()
    if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        severity = "INFO"
    row = {
        "rule": _text(value.get("rule") or value.get("id") or "unknown", 160),
        "severity": severity,
        "path": _text(value.get("path") or "workspace", 1_000),
        "line": _integer(value.get("line"), 0),
        "message": _text(value.get("message"), 1_000),
        "fix": _text(value.get("fix") or value.get("remediation"), 1_000),
        "source_engine": _text(value.get("source_engine"), 160),
    }
    return row


def _candidate_paths(value: Mapping[str, Any]) -> list[str]:
    rows: list[str] = []
    examined = 0
    for key in ("path", "paths", "changed_paths", "files"):
        item = value.get(key)
        values = item if isinstance(item, list) else [item]
        for candidate in values:
            examined += 1
            if examined > 256:
                return rows
            if isinstance(candidate, Mapping):
                candidate = candidate.get("path")
            if isinstance(candidate, str):
                clean = _text(candidate, 1_000)
                if clean and clean not in rows:
                    rows.append(clean)
            if len(rows) >= 64:
                return rows
    return rows


def _compact_improvement(value: Mapping[str, Any]) -> dict[str, Any]:
    # Deliberately allowlisted: source, patches, diffs, logs, prompts, secret
    # material, and arbitrary provider fields cannot cross this boundary.
    return {
        "id": _text(value.get("candidate_id") or value.get("id"), 160),
        "status": _text(value.get("status") or value.get("verification_status") or
                        "review-only", 80),
        "rule": _text(value.get("rule"), 160),
        "summary": _text(value.get("summary") or value.get("message") or
                         value.get("fix"), 1_000),
        "paths": _candidate_paths(value),
        "digest": _text(value.get("digest") or value.get("candidate_sha256"), 64),
    }


def _reported_effects(report: Mapping[str, Any]) -> dict[str, bool]:
    execution = report.get("execution") if isinstance(report.get("execution"), Mapping) else {}
    repair = (report.get("repair_director_41")
              if isinstance(report.get("repair_director_41"), Mapping) else {})
    return {
        "target_code_executed": bool(
            execution.get("attestor41_target_code_executed") or
            execution.get("target_code_executed") or
            execution.get("target_modules_imported") or
            execution.get("imports_executed") or
            execution.get("selected_tests_executed") or
            execution.get("host_execution_fallback")),
        "network_accessed": bool(
            execution.get("attestor41_network_accessed") or
            execution.get("network_accessed") or
            execution.get("research_network_accessed") or
            execution.get("network_probing")),
        "target_files_written": bool(
            execution.get("attestor41_target_files_written") or
            execution.get("target_files_written") or
            execution.get("workspace_written") or
            execution.get("filesystem_writes") or
            execution.get("changes_applied")),
        "improvements_applied": bool(
            execution.get("repair_apply_performed") or
            execution.get("changes_applied") or
            repair.get("status") == "applied"),
    }


def _compact_project(
        root: Path, report: Mapping[str, Any], *, finding_limit: int,
        improvement_limit: int,
        ) -> tuple[dict[str, Any], list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    raw_findings = report.get("findings") if isinstance(report.get("findings"), list) else []
    findings: list[dict[str, Any]] = []
    if finding_limit > 0:
        for raw_finding in raw_findings:
            if isinstance(raw_finding, Mapping):
                findings.append(_compact_finding(raw_finding))
            if len(findings) >= finding_limit:
                break

    improvement_lists: list[list[Any]] = []
    for key in ("improvements", "verified_improvements"):
        if isinstance(report.get(key), list):
            improvement_lists.append(report[key])
    repair = (report.get("repair_director_41")
              if isinstance(report.get("repair_director_41"), Mapping) else {})
    for key in ("candidates", "ranked_candidates", "improvements"):
        if isinstance(repair.get(key), list):
            improvement_lists.append(repair[key])
    raw_improvement_total = sum(len(values) for values in improvement_lists)
    improvements: list[dict[str, Any]] = []
    if improvement_limit > 0:
        for values in improvement_lists:
            for raw_improvement in values:
                if isinstance(raw_improvement, Mapping):
                    improvements.append(_compact_improvement(raw_improvement))
                if len(improvements) >= improvement_limit:
                    break
            if len(improvements) >= improvement_limit:
                break

    project_status = _text(report.get("status") or "unknown", 80)
    failed_status = (project_status.casefold() in {"failed", "error", "stale"} or
                     project_status.casefold().endswith("-failed"))
    coverage = report.get("coverage") if isinstance(report.get("coverage"), Mapping) else {}
    gaps = _dedupe(coverage.get("gaps", []) if isinstance(coverage.get("gaps"), list) else [], 40)
    if failed_status:
        gaps.append("analyzer returned a non-success project status: " + project_status)
    effects = _reported_effects(report)
    if effects["target_code_executed"]:
        gaps.append("analyzer reported target-code execution despite the static-only request")
    if effects["network_accessed"]:
        gaps.append("analyzer reported network access despite the offline request")
    if effects["target_files_written"]:
        gaps.append("analyzer reported target-file writes despite the read-only request")
    if effects["improvements_applied"]:
        gaps.append("analyzer reported an applied improvement despite apply denial")
    config = report.get("analysis_config") if isinstance(report.get("analysis_config"), Mapping) else {}
    request_invariant_violated = config.get("apply_improvements_authorized") is True
    if request_invariant_violated:
        gaps.append("analyzer evidence unexpectedly reports apply authorization")
    if _text(report.get("status"), 80) == "inconsistent":
        request_invariant_violated = True
        gaps.append("analyzer evidence was internally inconsistent")
    gaps = _dedupe(gaps, 50)

    reported_total = _integer(
        (report.get("summary") or {}).get("findings")
        if isinstance(report.get("summary"), Mapping) else len(raw_findings),
        len(raw_findings))
    finding_omitted = max(0, max(reported_total, len(raw_findings)) - len(findings))
    improvement_omitted = max(0, raw_improvement_total - len(improvements))
    row = {
        "root": _text(root, 2_000),
        "schema": _text(report.get("schema"), 160),
        "version": _text(report.get("version"), 40),
        "status": project_status,
        "analysis_completed": not failed_status,
        "summary": {
            "findings_reported": max(reported_total, len(raw_findings)),
            "findings_returned": len(findings),
            "findings_omitted": finding_omitted,
            "improvements_returned": len(improvements),
            "improvements_omitted": improvement_omitted,
        },
        "findings": findings,
        "improvements": improvements,
        "coverage": {"complete": bool(coverage.get("complete")) and not gaps,
                     "gaps": gaps},
        "execution": {**effects,
                      "request_invariant_violated": request_invariant_violated},
        "report_sha256": _text(report.get("report_sha256"), 64),
    }
    return row, findings, improvements, gaps


def _empty_report(scope: str, *, authorized: bool, max_projects: int,
                  max_directories: int, max_files: int, max_depth: int) -> dict[str, Any]:
    reason = "computer discovery and analysis were not authorized for this run"
    return {
        "schema": SCHEMA,
        "version": VERSION,
        "status": "authorization-required",
        "authorization": {
            "authorized": authorized,
            "per_run_required": True,
            "permission_retained": False,
            "scope": scope,
            "permission_kind": "application-level-read-consent",
            "os_privilege_elevation_requested": False,
            "access_control_bypass_requested": False,
        },
        "summary": {
            "roots_considered": 0,
            "projects_discovered": 0,
            "projects_analyzed": 0,
            "findings_returned": 0,
            "improvements_returned": 0,
            "analysis_errors": 0,
        },
        "discovery": {
            "scope": scope, "roots": [], "directories_seen": 0,
            "files_seen": 0, "source_files_seen": 0,
            "sample_source_files": [], "excluded_directories": 0,
            "linked_or_reparse_paths_skipped": 0, "unreadable_directories": 0,
            "cross_filesystem_paths_skipped": 0,
            "unreadable_directory_samples": [], "projects_discovered": 0,
            "projects": [], "projects_selected": 0, "selected_projects": [],
            "overlapping_projects_consolidated": 0, "selection_omissions": 0,
            "limit_hits": {"directories": False, "files": False,
                           "depth": False, "entries_per_directory": False,
                           "discovered_projects": False},
            "bounds": {"max_projects": max_projects,
                       "max_directories": max_directories,
                       "max_files": max_files, "max_depth": max_depth,
                       "max_entries_per_directory": MAX_ENTRIES_PER_DIRECTORY},
            "gaps": [reason],
        },
        "projects": [], "findings": [], "improvements": [], "errors": [],
        "coverage": {"complete": False, "absence_proven": False,
                     "gaps": [reason]},
        "execution": {
            "discovery_started": False, "analysis_started": False,
            "target_code_executed": False, "network_accessed": False,
            "target_files_written": False, "discovered_files_written": False,
            "improvements_applied": False,
            "os_privilege_elevation_requested": False,
            "access_control_bypass_requested": False,
        },
    }


def scan_computer(
        *, authorized: bool = False, scope: str = "home",
        max_projects: int = 3, review_improvements: bool = False,
        roots_override: Sequence[str | os.PathLike[str]] | None = None,
        analyzer: Callable[..., Mapping[str, Any]] | None = None,
        max_directories: int = DEFAULT_MAX_DIRECTORIES,
        max_files: int = DEFAULT_MAX_FILES,
        max_depth: int = DEFAULT_MAX_DEPTH,
        ) -> dict[str, Any]:
    """Discover and statically analyze projects without a caller-supplied path.

    ``authorized`` is never persisted.  A false value returns before root/home
    or drive enumeration.  ``roots_override`` and ``analyzer`` exist for
    deterministic tests and trusted embedding; the normal path uses the home
    or fixed-drive scope and :func:`attestor41.maximum`.
    """
    if type(authorized) is not bool or type(review_improvements) is not bool:
        raise ComputerScanError("authorization and improvement flags must be booleans")
    if scope not in {"home", "fixed-drives"}:
        raise ComputerScanError("scope must be 'home' or 'fixed-drives'")
    if type(max_projects) is not int or not 1 <= max_projects <= MAX_PROJECTS:
        raise ComputerScanError("max_projects must be between 1 and %d" % MAX_PROJECTS)
    if type(max_directories) is not int or not 1 <= max_directories <= MAX_DIRECTORIES:
        raise ComputerScanError("max_directories must be between 1 and %d" % MAX_DIRECTORIES)
    if type(max_files) is not int or not 1 <= max_files <= MAX_FILES:
        raise ComputerScanError("max_files must be between 1 and %d" % MAX_FILES)
    if type(max_depth) is not int or not 0 <= max_depth <= MAX_DEPTH:
        raise ComputerScanError("max_depth must be between 0 and %d" % MAX_DEPTH)
    if analyzer is not None and not callable(analyzer):
        raise ComputerScanError("analyzer must be callable")

    # Critical ordering invariant: do not call Path.home(), enumerate drives,
    # inspect overrides, or touch the filesystem before explicit permission.
    if not authorized:
        return _empty_report(scope, authorized=False, max_projects=max_projects,
                             max_directories=max_directories, max_files=max_files,
                             max_depth=max_depth)

    roots, root_gaps = _scope_roots(scope, roots_override)
    discovery = _discover(
        roots, max_directories=max_directories, max_files=max_files,
        max_depth=max_depth, max_projects=max_projects)
    selected = discovery.pop("selected_internal")
    discovery["scope"] = scope
    discovery["bounds"] = {
        "max_projects": max_projects, "max_directories": max_directories,
        "max_files": max_files, "max_depth": max_depth,
        "max_entries_per_directory": MAX_ENTRIES_PER_DIRECTORY,
        "max_project_findings": MAX_PROJECT_FINDINGS,
        "max_total_findings": MAX_TOTAL_FINDINGS,
        "max_project_improvements": MAX_PROJECT_IMPROVEMENTS,
        "max_total_improvements": MAX_TOTAL_IMPROVEMENTS,
    }
    discovery["gaps"] = _dedupe([*root_gaps, *discovery["gaps"]])

    production_analyzer = analyzer is None
    analyze = attestor41.maximum if production_analyzer else analyzer
    project_rows: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    all_improvements: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    analysis_gaps: list[str] = []
    effects = {"target_code_executed": False, "network_accessed": False,
               "target_files_written": False, "improvements_applied": False}
    request_invariant_violated = False
    completed_projects = 0
    failed_report_projects = 0

    for candidate in selected:
        project = candidate["root"]
        try:
            raw = analyze(
                project,
                improve=review_improvements,
                max_improvement_files=3,
                compiler_checks=False,
                use_cache=False,
                jobs=4,
                test_command=None,
                authorize_tests=False,
                apply_improvements=False,
                include_candidate_source=False,
            )
            if not isinstance(raw, Mapping):
                raise ComputerScanError("analyzer returned a non-object report")
            report = (attestor41.safe_public_report(raw, root=project)
                      if production_analyzer else raw)
            finding_room = min(MAX_PROJECT_FINDINGS,
                               MAX_TOTAL_FINDINGS - len(all_findings))
            improvement_room = min(MAX_PROJECT_IMPROVEMENTS,
                                   MAX_TOTAL_IMPROVEMENTS - len(all_improvements))
            row, findings, improvements, gaps = _compact_project(
                project, report, finding_limit=finding_room,
                improvement_limit=improvement_room)
            for finding in findings:
                all_findings.append({"project_root": _text(project, 2_000), **finding})
            for improvement in improvements:
                all_improvements.append({"project_root": _text(project, 2_000),
                                         **improvement})
            for name in effects:
                effects[name] = effects[name] or bool(row["execution"].get(name))
            request_invariant_violated = (
                request_invariant_violated or
                bool(row["execution"].get("request_invariant_violated")))
            if row["analysis_completed"]:
                completed_projects += 1
            else:
                failed_report_projects += 1
                analysis_gaps.append(
                    "analyzer returned a non-success project status: %s (%s)" %
                    (_text(row.get("status"), 80), _text(project, 1_000)))
            if gaps:
                analysis_gaps.append("project analysis reported coverage gaps: " +
                                     _text(project, 1_000))
            project_rows.append(row)
        except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
            errors.append({
                "project_root": _text(project, 2_000),
                "component": "attestor-4.1-static-analysis",
                "error": type(exc).__name__,
            })

    if len(all_findings) >= MAX_TOTAL_FINDINGS:
        analysis_gaps.append("additional findings may be omitted at the computer-report boundary")
    if len(all_improvements) >= MAX_TOTAL_IMPROVEMENTS:
        analysis_gaps.append("additional improvement summaries may be omitted at the computer-report boundary")
    if errors:
        analysis_gaps.append("%d selected project analysis run(s) failed closed" % len(errors))
    if failed_report_projects:
        analysis_gaps.append("%d analyzer project report(s) returned failed, error, or stale status" %
                             failed_report_projects)
    gaps = _dedupe([*discovery["gaps"], *analysis_gaps])
    failed_projects = len(errors) + failed_report_projects
    invariant_violation = any(effects.values()) or request_invariant_violated
    if invariant_violation:
        status = "inconsistent"
    elif selected and not completed_projects:
        status = "failed"
    elif failed_projects:
        status = "partial"
    elif all_findings:
        status = "action-required"
    elif gaps:
        status = "partial"
    else:
        status = "complete"

    return {
        "schema": SCHEMA,
        "version": VERSION,
        "status": status,
        "authorization": {
            "authorized": True,
            "per_run_required": True,
            "permission_retained": False,
            "scope": scope,
            "permission_kind": "application-level-read-consent",
            "os_privilege_elevation_requested": False,
            "access_control_bypass_requested": False,
        },
        "summary": {
            "roots_considered": len(roots),
            "projects_discovered": discovery["projects_discovered"],
            "projects_selected": discovery["projects_selected"],
            "projects_analyzed": completed_projects,
            "findings_returned": len(all_findings),
            "improvements_returned": len(all_improvements),
            "analysis_errors": failed_projects,
        },
        "discovery": discovery,
        "projects": project_rows,
        "findings": all_findings,
        "improvements": all_improvements,
        "errors": errors,
        "coverage": {"complete": not gaps and not errors,
                     "absence_proven": False, "gaps": gaps},
        "execution": {
            "discovery_started": True,
            "analysis_started": bool(selected),
            "target_code_executed": effects["target_code_executed"],
            "network_accessed": effects["network_accessed"],
            "target_files_written": effects["target_files_written"],
            "discovered_files_written": effects["target_files_written"],
            "improvements_applied": effects["improvements_applied"],
            "tests_authorized": False,
            "compiler_checks_enabled": False,
            "analysis_cache_enabled": False,
            "review_improvements_requested": review_improvements,
            "os_privilege_elevation_requested": False,
            "access_control_bypass_requested": False,
        },
        "assurance": [
            "Permission applies to this invocation only and is not retained.",
            "Permission is application-level read consent; Attestor does not request UAC/admin elevation or bypass operating-system access controls.",
            "Unreadable areas remain unread and are recorded as coverage gaps.",
            "Discovery reads directory metadata and never follows links or reparse points.",
            "Discovered code is statically analyzed without import, execution, tests, compiler hooks, or network access.",
            "Candidate source and secret values are excluded from this compact report.",
            "Improvement generation is review-only; apply authorization is always false.",
            "Bounded and excluded areas mean absence of findings is not proof that the computer is defect-free.",
        ],
    }


def render_text(report: Mapping[str, Any]) -> str:
    """Render a compact, terminal-safe summary of a computer-scan report."""
    summary = report.get("summary") if isinstance(report.get("summary"), Mapping) else {}
    authorization = (report.get("authorization")
                     if isinstance(report.get("authorization"), Mapping) else {})
    lines = [
        "Attestor 4.1.3 computer scan: " + _text(report.get("status"), 80),
        "Permission: " + ("granted for this run" if authorization.get("authorized")
                          else "required (no discovery performed)"),
        "Scope: " + _text(authorization.get("scope") or "home", 40),
        "Projects: %d discovered, %d analyzed" % (
            _integer(summary.get("projects_discovered")),
            _integer(summary.get("projects_analyzed"))),
        "Findings: %d; review improvements: %d; analysis errors: %d" % (
            _integer(summary.get("findings_returned")),
            _integer(summary.get("improvements_returned")),
            _integer(summary.get("analysis_errors"))),
    ]
    projects = report.get("projects") if isinstance(report.get("projects"), list) else []
    for row in projects[:MAX_PROJECTS]:
        if not isinstance(row, Mapping):
            continue
        project_summary = row.get("summary") if isinstance(row.get("summary"), Mapping) else {}
        lines.append("- %s: %s, %d finding(s) returned" % (
            _text(row.get("root"), 1_000), _text(row.get("status"), 80),
            _integer(project_summary.get("findings_returned"))))
    coverage = report.get("coverage") if isinstance(report.get("coverage"), Mapping) else {}
    gaps = coverage.get("gaps") if isinstance(coverage.get("gaps"), list) else []
    if gaps:
        lines.append("Coverage gaps:")
        for gap in gaps[:20]:
            lines.append("- " + _text(gap, 1_000))
    return "\n".join(lines)
