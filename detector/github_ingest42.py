#!/usr/bin/env python3
"""GitHub ingestion pipeline for Owen.

Feed Owen GitHub repository URLs and he reads, scans, and learns from
the code. Supports individual repos, organization-wide sweeps, search
queries, and bulk URL lists.

Architecture:

    URLs / org / search query
           │
    ┌──────▼──────┐
    │  RepoQueue   │  dedup, rate-limit, prioritize
    └──────┬──────┘
           │
    ┌──────▼──────┐
    │  Fetcher     │  clone --depth 1 / archive download / API tree
    └──────┬──────┘
           │
    ┌──────▼──────┐
    │  FileWalker  │  language detect, skip binaries, respect .gitignore
    └──────┬──────┘
           │
    ┌──────▼──────┐
    │  Scanner     │  run detect.py rules on every source file
    └──────┬──────┘
           │
    ┌──────▼──────┐
    │  Ingester    │  push findings into OwenOS knowledge store
    └──────┬──────┘
           │
    ┌──────▼──────┐
    │  Reporter    │  per-repo and aggregate summaries
    └──────┘

Usage:

    ingest = GitHubIngest()
    ingest.add_repo("https://github.com/user/repo")
    ingest.add_repos_from_file("repos.txt")       # one URL per line
    ingest.add_org("myorg")                         # all public repos
    ingest.add_search("language:python stars:>100") # GitHub code search
    results = ingest.run()                          # fetch, scan, ingest
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse


VERSION = "4.2"

GITHUB_API = "https://api.github.com"

SCANNABLE_EXTENSIONS = {
    ".py", ".java", ".js", ".ts", ".jsx", ".tsx", ".c", ".h", ".cpp",
    ".hpp", ".cc", ".cxx", ".cs", ".go", ".rs", ".rb", ".php", ".swift",
    ".kt", ".kts", ".scala", ".m", ".mm", ".pl", ".pm", ".sh", ".bash",
    ".zsh", ".ps1", ".psm1", ".sql", ".hrl", ".erl", ".ex", ".exs",
    ".hs", ".lhs", ".lua", ".r", ".R", ".jl", ".groovy", ".gradle",
    ".xml", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".env", ".dockerfile", ".tf", ".hcl",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".tox", ".venv", "venv",
    "vendor", "third_party", "dist", "build", ".eggs", ".mypy_cache",
    ".pytest_cache", "target", "bin", "obj", ".gradle", ".idea",
    ".vs", ".vscode",
}

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB per file
MAX_REPO_FILES = 50_000


# =========================================================================== #
#  DATA TYPES                                                                  #
# =========================================================================== #

class RepoStatus(Enum):
    QUEUED = auto()
    FETCHING = auto()
    SCANNING = auto()
    DONE = auto()
    FAILED = auto()
    SKIPPED = auto()


class FetchMethod(Enum):
    GIT_CLONE = "git_clone"
    API_TARBALL = "api_tarball"
    API_TREE = "api_tree"


@dataclass
class RepoEntry:
    """A repository in the ingestion queue."""
    url: str
    owner: str = ""
    name: str = ""
    status: RepoStatus = RepoStatus.QUEUED
    fetch_method: FetchMethod = FetchMethod.GIT_CLONE
    local_path: str = ""
    files_scanned: int = 0
    findings_count: int = 0
    languages: set[str] = field(default_factory=set)
    error: str = ""
    elapsed: float = 0.0
    sha: str = ""
    stars: int = 0
    size_kb: int = 0
    default_branch: str = "main"

    def __post_init__(self):
        if not self.owner or not self.name:
            self.owner, self.name = parse_github_url(self.url)

    @property
    def full_name(self) -> str:
        return "%s/%s" % (self.owner, self.name)

    @property
    def repo_id(self) -> str:
        return hashlib.sha256(self.full_name.lower().encode()).hexdigest()[:12]


@dataclass
class ScanResult:
    """Results from scanning a single repository."""
    repo: RepoEntry
    findings: list[dict[str, Any]]
    files_scanned: int
    languages_found: set[str]
    scan_time: float
    errors: list[str] = field(default_factory=list)


@dataclass
class IngestReport:
    """Aggregate report across all ingested repositories."""
    total_repos: int = 0
    repos_scanned: int = 0
    repos_failed: int = 0
    repos_skipped: int = 0
    total_files: int = 0
    total_findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    findings_by_cwe: dict[str, int] = field(default_factory=dict)
    languages_seen: set[str] = field(default_factory=set)
    elapsed: float = 0.0
    repo_results: list[ScanResult] = field(default_factory=list)

    def summary(self) -> str:
        lines = [
            "=== Owen GitHub Ingest Report ===",
            "Repos: %d scanned, %d failed, %d skipped (of %d total)" %
            (self.repos_scanned, self.repos_failed, self.repos_skipped,
             self.total_repos),
            "Files scanned: %d" % self.total_files,
            "Findings: %d" % self.total_findings,
        ]
        if self.findings_by_severity:
            sev_line = ", ".join(
                "%s: %d" % (k, v)
                for k, v in sorted(self.findings_by_severity.items()))
            lines.append("  By severity: %s" % sev_line)
        if self.findings_by_cwe:
            top_cwes = sorted(self.findings_by_cwe.items(),
                              key=lambda x: -x[1])[:10]
            cwe_line = ", ".join("%s: %d" % (k, v) for k, v in top_cwes)
            lines.append("  Top CWEs: %s" % cwe_line)
        if self.languages_seen:
            lines.append("Languages: %s" % ", ".join(sorted(self.languages_seen)))
        lines.append("Time: %.1fs" % self.elapsed)
        return "\n".join(lines)


# =========================================================================== #
#  URL PARSING                                                                 #
# =========================================================================== #

def parse_github_url(url: str) -> tuple[str, str]:
    """Extract (owner, repo) from a GitHub URL.

    Handles:
        https://github.com/owner/repo
        https://github.com/owner/repo.git
        https://github.com/owner/repo/tree/main/...
        git@github.com:owner/repo.git
        owner/repo (shorthand)
    """
    url = url.strip()

    if url.startswith("git@github.com:"):
        path = url[len("git@github.com:"):]
        path = path.removesuffix(".git")
        parts = path.split("/")
        if len(parts) >= 2:
            return parts[0], parts[1]

    if "/" in url and not url.startswith("http"):
        parts = url.split("/")
        if len(parts) >= 2:
            return parts[0], parts[1].removesuffix(".git")

    parsed = urlparse(url)
    path = parsed.path.strip("/").removesuffix(".git")
    parts = path.split("/")
    if len(parts) >= 2:
        return parts[0], parts[1]

    return "", url


def normalize_github_url(url: str) -> str:
    """Normalize a GitHub URL to https://github.com/owner/repo."""
    owner, name = parse_github_url(url)
    if owner and name:
        return "https://github.com/%s/%s" % (owner, name)
    return url


def is_github_url(url: str) -> bool:
    """Check if a URL points to GitHub."""
    url = url.strip().lower()
    return ("github.com" in url or
            url.startswith("git@github.com:") or
            re.match(r"^[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+$", url) is not None)


# =========================================================================== #
#  GITHUB API CLIENT                                                           #
# =========================================================================== #

class GitHubAPI:
    """Minimal GitHub API client. Uses gh CLI or direct HTTP."""

    def __init__(self, token: str | None = None):
        self._token = token or os.environ.get("GITHUB_TOKEN", "")
        self._has_gh = shutil.which("gh") is not None
        self._rate_remaining = 5000
        self._rate_reset = 0.0

    def _headers(self) -> dict[str, str]:
        h = {"Accept": "application/vnd.github.v3+json",
             "User-Agent": "Owen-Attestor/4.2"}
        if self._token:
            h["Authorization"] = "token %s" % self._token
        return h

    def _gh_api(self, endpoint: str) -> dict | list | None:
        """Call GitHub API via gh CLI."""
        if not self._has_gh:
            return None
        try:
            result = subprocess.run(
                ["gh", "api", endpoint, "--paginate"],
                capture_output=True, text=True, timeout=30)
            if result.returncode == 0 and result.stdout.strip():
                return json.loads(result.stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            pass
        return None

    def _http_get(self, url: str) -> dict | list | None:
        """Call GitHub API via urllib (no external deps)."""
        try:
            import urllib.request
            req = urllib.request.Request(url, headers=self._headers())
            with urllib.request.urlopen(req, timeout=15) as resp:
                remaining = resp.headers.get("X-RateLimit-Remaining", "")
                if remaining:
                    self._rate_remaining = int(remaining)
                return json.loads(resp.read().decode())
        except Exception:
            return None

    def get(self, endpoint: str) -> dict | list | None:
        """GET a GitHub API endpoint. Tries gh CLI first, falls back to HTTP."""
        result = self._gh_api(endpoint)
        if result is not None:
            return result
        url = GITHUB_API + endpoint if endpoint.startswith("/") else endpoint
        return self._http_get(url)

    def repo_info(self, owner: str, name: str) -> dict | None:
        data = self.get("/repos/%s/%s" % (owner, name))
        return data if isinstance(data, dict) else None

    def org_repos(self, org: str, max_repos: int = 500) -> list[dict]:
        """List all public repos for an organization."""
        repos = []
        page = 1
        while len(repos) < max_repos:
            data = self.get(
                "/orgs/%s/repos?type=public&per_page=100&page=%d" % (org, page))
            if not data or not isinstance(data, list) or len(data) == 0:
                break
            repos.extend(data)
            if len(data) < 100:
                break
            page += 1
        return repos[:max_repos]

    def user_repos(self, user: str, max_repos: int = 500) -> list[dict]:
        """List all public repos for a user."""
        repos = []
        page = 1
        while len(repos) < max_repos:
            data = self.get(
                "/users/%s/repos?type=public&per_page=100&page=%d" % (user, page))
            if not data or not isinstance(data, list) or len(data) == 0:
                break
            repos.extend(data)
            if len(data) < 100:
                break
            page += 1
        return repos[:max_repos]

    def search_repos(self, query: str, max_results: int = 100) -> list[dict]:
        """Search GitHub repositories."""
        repos = []
        page = 1
        while len(repos) < max_results:
            data = self.get(
                "/search/repositories?q=%s&per_page=100&page=%d" %
                (query.replace(" ", "+"), page))
            if not data or not isinstance(data, dict):
                break
            items = data.get("items", [])
            if not items:
                break
            repos.extend(items)
            if len(items) < 100:
                break
            page += 1
        return repos[:max_results]

    @property
    def rate_remaining(self) -> int:
        return self._rate_remaining

    @property
    def authenticated(self) -> bool:
        return bool(self._token) or self._has_gh


# =========================================================================== #
#  REPO FETCHER                                                                #
# =========================================================================== #

class RepoFetcher:
    """Clones or downloads repository contents to a local directory."""

    def __init__(self, work_dir: str | None = None):
        self._work_dir = work_dir or tempfile.mkdtemp(prefix="owen_ingest_")
        self._has_git = shutil.which("git") is not None

    @property
    def work_dir(self) -> str:
        return self._work_dir

    def fetch(self, entry: RepoEntry) -> str:
        """Fetch repository contents. Returns local path."""
        dest = os.path.join(self._work_dir, entry.repo_id)
        if os.path.exists(dest):
            return dest

        if self._has_git and entry.fetch_method == FetchMethod.GIT_CLONE:
            return self._git_clone(entry, dest)
        return self._api_download(entry, dest)

    def _git_clone(self, entry: RepoEntry, dest: str) -> str:
        clone_url = "https://github.com/%s/%s.git" % (entry.owner, entry.name)
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", "--single-branch",
                 "--no-tags", clone_url, dest],
                capture_output=True, text=True, timeout=120,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0"})
        except subprocess.TimeoutExpired:
            raise RuntimeError("git clone timed out for %s" % entry.full_name)

        if not os.path.isdir(dest):
            raise RuntimeError("git clone failed for %s" % entry.full_name)

        git_dir = os.path.join(dest, ".git")
        if os.path.isdir(git_dir):
            shutil.rmtree(git_dir, ignore_errors=True)

        return dest

    def _api_download(self, entry: RepoEntry, dest: str) -> str:
        """Download via GitHub API tarball."""
        import urllib.request
        url = "https://api.github.com/repos/%s/%s/tarball" % (
            entry.owner, entry.name)
        headers = {"User-Agent": "Owen-Attestor/4.2"}
        token = os.environ.get("GITHUB_TOKEN", "")
        if token:
            headers["Authorization"] = "token %s" % token

        tarball = dest + ".tar.gz"
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=60) as resp:
                with open(tarball, "wb") as f:
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        f.write(chunk)
        except Exception as e:
            raise RuntimeError("API download failed for %s: %s" %
                               (entry.full_name, e))

        os.makedirs(dest, exist_ok=True)
        try:
            import tarfile
            with tarfile.open(tarball, "r:gz") as tf:
                tf.extractall(dest, filter="data")
        except Exception as e:
            raise RuntimeError("tarball extraction failed: %s" % e)
        finally:
            try:
                os.unlink(tarball)
            except OSError:
                pass

        return dest

    def cleanup(self, entry: RepoEntry) -> None:
        dest = os.path.join(self._work_dir, entry.repo_id)
        if os.path.isdir(dest):
            shutil.rmtree(dest, ignore_errors=True)

    def cleanup_all(self) -> None:
        if os.path.isdir(self._work_dir):
            shutil.rmtree(self._work_dir, ignore_errors=True)


# =========================================================================== #
#  FILE WALKER                                                                 #
# =========================================================================== #

LANG_MAP = {
    ".py": "python", ".java": "java", ".js": "javascript",
    ".ts": "typescript", ".jsx": "javascript", ".tsx": "typescript",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".hpp": "cpp",
    ".cc": "cpp", ".cxx": "cpp", ".cs": "csharp", ".go": "go",
    ".rs": "rust", ".rb": "ruby", ".php": "php", ".swift": "swift",
    ".kt": "kotlin", ".scala": "scala", ".hs": "haskell",
    ".sh": "shell", ".bash": "shell", ".ps1": "powershell",
    ".sql": "sql", ".lua": "lua", ".r": "r", ".R": "r",
    ".groovy": "groovy", ".pl": "perl", ".pm": "perl",
    ".ex": "elixir", ".exs": "elixir", ".erl": "erlang",
}


def walk_source_files(root: str,
                      max_files: int = MAX_REPO_FILES,
                      ) -> Iterator[tuple[str, str]]:
    """Walk a directory yielding (file_path, language) for scannable files."""
    count = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]

        for fname in filenames:
            if count >= max_files:
                return

            ext = os.path.splitext(fname)[1].lower()
            if ext not in SCANNABLE_EXTENSIONS:
                continue

            fpath = os.path.join(dirpath, fname)

            try:
                size = os.path.getsize(fpath)
            except OSError:
                continue
            if size > MAX_FILE_SIZE or size == 0:
                continue

            lang = LANG_MAP.get(ext, "unknown")
            count += 1
            yield fpath, lang


def detect_languages(root: str) -> set[str]:
    """Detect programming languages present in a directory."""
    langs = set()
    for _, lang in walk_source_files(root, max_files=500):
        langs.add(lang)
    return langs


# =========================================================================== #
#  SCANNER BRIDGE                                                              #
# =========================================================================== #

def scan_file(file_path: str, language: str,
              repo_root: str = "") -> list[dict[str, Any]]:
    """Scan a single file using detect.py and return findings as dicts."""
    try:
        from detect import scan as detect_scan, Finding, RULE_CWE
    except ImportError:
        try:
            import importlib
            detect = importlib.import_module("detect")
            detect_scan = detect.scan
            Finding = detect.Finding
            RULE_CWE = detect.RULE_CWE
        except ImportError:
            return _fallback_scan(file_path, language)

    try:
        findings = detect_scan(file_path)
    except Exception:
        return []

    results = []
    for f in findings:
        rel_path = f.path
        if repo_root:
            try:
                rel_path = os.path.relpath(f.path, repo_root)
            except ValueError:
                pass

        cwe = RULE_CWE.get(f.rule, "")
        results.append({
            "rule": f.rule,
            "cwe": cwe,
            "path": rel_path,
            "file_path": rel_path,
            "line": f.line,
            "severity": f.severity,
            "message": f.message,
            "fix": f.fix,
            "snippet": f.snippet,
            "language": language,
            "confidence": getattr(f, "confidence", 0.0),
        })

    return results


def _fallback_scan(file_path: str, language: str) -> list[dict[str, Any]]:
    """Minimal regex-based scanner when detect.py is not available."""
    findings = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except OSError:
        return []

    patterns = [
        (r"eval\s*\(", "CWE-94", "code-injection", "HIGH",
         "Potential code injection via eval()"),
        (r"exec\s*\(", "CWE-94", "code-injection", "HIGH",
         "Potential code injection via exec()"),
        (r"shell\s*=\s*True", "CWE-78", "command-injection", "HIGH",
         "subprocess with shell=True"),
        (r"pickle\.loads?\s*\(", "CWE-502", "insecure-deserialize", "HIGH",
         "Insecure deserialization via pickle"),
        (r"innerHTML\s*=", "CWE-79", "xss", "HIGH",
         "Potential XSS via innerHTML"),
        (r"document\.write\s*\(", "CWE-79", "xss", "MEDIUM",
         "Potential XSS via document.write"),
        (r"SELECT\s+.*\+\s*['\"]?\s*\+", "CWE-89", "sql-injection", "HIGH",
         "Potential SQL injection via string concatenation"),
        (r"password\s*=\s*['\"][^'\"]+['\"]", "CWE-798", "hardcoded-cred", "HIGH",
         "Hardcoded password"),
        (r"os\.system\s*\(", "CWE-78", "command-injection", "HIGH",
         "OS command execution"),
        (r"\.execute\s*\(\s*['\"].*%", "CWE-89", "sql-injection", "HIGH",
         "SQL injection via format string"),
    ]

    for i, line in enumerate(lines, 1):
        for regex, cwe, rule, sev, msg in patterns:
            if re.search(regex, line):
                findings.append({
                    "rule": rule,
                    "cwe": cwe,
                    "path": file_path,
                    "file_path": file_path,
                    "line": i,
                    "severity": sev,
                    "message": msg,
                    "fix": "",
                    "snippet": line.strip()[:200],
                    "language": language,
                    "confidence": 0.5,
                })

    return findings


# =========================================================================== #
#  REPO SCANNER                                                                #
# =========================================================================== #

class RepoScanner:
    """Scans all source files in a fetched repository."""

    def __init__(self, max_files: int = MAX_REPO_FILES):
        self._max_files = max_files

    def scan(self, entry: RepoEntry) -> ScanResult:
        start = time.time()
        all_findings: list[dict[str, Any]] = []
        languages: set[str] = set()
        errors: list[str] = []
        file_count = 0

        root = entry.local_path
        if not os.path.isdir(root):
            return ScanResult(
                repo=entry, findings=[], files_scanned=0,
                languages_found=set(), scan_time=0,
                errors=["local path does not exist: %s" % root])

        for fpath, lang in walk_source_files(root, self._max_files):
            file_count += 1
            languages.add(lang)
            try:
                findings = scan_file(fpath, lang, root)
                for f in findings:
                    f["repo"] = entry.full_name
                    f["repo_url"] = entry.url
                all_findings.extend(findings)
            except Exception as e:
                errors.append("error scanning %s: %s" % (fpath, e))

        return ScanResult(
            repo=entry,
            findings=all_findings,
            files_scanned=file_count,
            languages_found=languages,
            scan_time=time.time() - start,
            errors=errors,
        )


# =========================================================================== #
#  REPO QUEUE                                                                  #
# =========================================================================== #

class RepoQueue:
    """Manages the queue of repositories to ingest."""

    def __init__(self):
        self._entries: dict[str, RepoEntry] = {}
        self._order: list[str] = []

    def add(self, url: str, **kwargs) -> RepoEntry:
        url = normalize_github_url(url)
        owner, name = parse_github_url(url)
        entry = RepoEntry(url=url, owner=owner, name=name, **kwargs)
        key = entry.full_name.lower()
        if key not in self._entries:
            self._entries[key] = entry
            self._order.append(key)
        return self._entries[key]

    def add_many(self, urls: list[str]) -> int:
        count = 0
        for url in urls:
            url = url.strip()
            if url and not url.startswith("#"):
                self.add(url)
                count += 1
        return count

    def get(self, full_name: str) -> RepoEntry | None:
        return self._entries.get(full_name.lower())

    def queued(self) -> list[RepoEntry]:
        return [self._entries[k] for k in self._order
                if self._entries[k].status == RepoStatus.QUEUED]

    def all_entries(self) -> list[RepoEntry]:
        return [self._entries[k] for k in self._order]

    def __len__(self) -> int:
        return len(self._entries)

    def __contains__(self, url: str) -> bool:
        owner, name = parse_github_url(url)
        return ("%s/%s" % (owner, name)).lower() in self._entries


# =========================================================================== #
#  GITHUB INGEST PIPELINE                                                      #
# =========================================================================== #

class GitHubIngest:
    """The main ingestion pipeline.

    Usage:
        ingest = GitHubIngest()
        ingest.add_repo("https://github.com/user/repo")
        ingest.add_org("myorg")
        ingest.add_repos_from_file("repos.txt")
        report = ingest.run()
        print(report.summary())
    """

    def __init__(self, work_dir: str | None = None,
                 github_token: str | None = None,
                 max_workers: int = 4,
                 max_files_per_repo: int = MAX_REPO_FILES,
                 cleanup_after: bool = True):
        self._queue = RepoQueue()
        self._api = GitHubAPI(github_token)
        self._fetcher = RepoFetcher(work_dir)
        self._scanner = RepoScanner(max_files_per_repo)
        self._max_workers = max_workers
        self._cleanup_after = cleanup_after
        self._results: list[ScanResult] = []
        self._owen_os = None

    # -- Queue management --------------------------------------------------- #

    def add_repo(self, url: str) -> RepoEntry:
        return self._queue.add(url)

    def add_repos(self, urls: list[str]) -> int:
        return self._queue.add_many(urls)

    def add_repos_from_file(self, path: str) -> int:
        with open(path, "r", encoding="utf-8") as f:
            urls = [line.strip() for line in f
                    if line.strip() and not line.startswith("#")]
        return self._queue.add_many(urls)

    def add_org(self, org: str, max_repos: int = 500) -> int:
        repos = self._api.org_repos(org, max_repos)
        if not repos:
            repos = self._api.user_repos(org, max_repos)
        count = 0
        for r in repos:
            url = r.get("html_url", r.get("clone_url", ""))
            if url:
                entry = self._queue.add(url)
                entry.stars = r.get("stargazers_count", 0)
                entry.size_kb = r.get("size", 0)
                entry.default_branch = r.get("default_branch", "main")
                count += 1
        return count

    def add_search(self, query: str, max_results: int = 100) -> int:
        repos = self._api.search_repos(query, max_results)
        count = 0
        for r in repos:
            url = r.get("html_url", "")
            if url:
                entry = self._queue.add(url)
                entry.stars = r.get("stargazers_count", 0)
                entry.size_kb = r.get("size", 0)
                count += 1
        return count

    def queue_size(self) -> int:
        return len(self._queue)

    # -- Execution ---------------------------------------------------------- #

    def run(self, owen_os: Any | None = None) -> IngestReport:
        """Run the full ingestion pipeline.

        Args:
            owen_os: optional OwenOS instance to ingest findings into
        """
        self._owen_os = owen_os
        start = time.time()
        report = IngestReport(total_repos=len(self._queue))

        entries = self._queue.queued()
        if not entries:
            report.elapsed = time.time() - start
            return report

        if self._max_workers <= 1 or len(entries) <= 2:
            for entry in entries:
                result = self._process_repo(entry)
                self._collect_result(result, report)
        else:
            with ThreadPoolExecutor(max_workers=self._max_workers) as pool:
                futures = {pool.submit(self._process_repo, e): e
                           for e in entries}
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        self._collect_result(result, report)
                    except Exception as e:
                        entry = futures[future]
                        entry.status = RepoStatus.FAILED
                        entry.error = str(e)
                        report.repos_failed += 1

        report.elapsed = time.time() - start
        return report

    def _process_repo(self, entry: RepoEntry) -> ScanResult:
        """Fetch, scan, and optionally ingest one repository."""
        entry.status = RepoStatus.FETCHING
        start = time.time()

        try:
            local_path = self._fetcher.fetch(entry)
            entry.local_path = local_path
        except Exception as e:
            entry.status = RepoStatus.FAILED
            entry.error = "fetch failed: %s" % e
            entry.elapsed = time.time() - start
            return ScanResult(
                repo=entry, findings=[], files_scanned=0,
                languages_found=set(), scan_time=0,
                errors=[entry.error])

        entry.status = RepoStatus.SCANNING
        result = self._scanner.scan(entry)

        entry.files_scanned = result.files_scanned
        entry.findings_count = len(result.findings)
        entry.languages = result.languages_found
        entry.elapsed = time.time() - start
        entry.status = RepoStatus.DONE

        if self._owen_os and result.findings:
            try:
                self._owen_os.ingest_findings(result.findings)
            except Exception:
                pass

        if self._cleanup_after:
            self._fetcher.cleanup(entry)

        return result

    def _collect_result(self, result: ScanResult,
                        report: IngestReport) -> None:
        report.repo_results.append(result)
        report.total_files += result.files_scanned
        report.total_findings += len(result.findings)
        report.languages_seen.update(result.languages_found)

        if result.repo.status == RepoStatus.DONE:
            report.repos_scanned += 1
        elif result.repo.status == RepoStatus.FAILED:
            report.repos_failed += 1
        else:
            report.repos_skipped += 1

        for f in result.findings:
            sev = f.get("severity", "UNKNOWN")
            report.findings_by_severity[sev] = (
                report.findings_by_severity.get(sev, 0) + 1)
            cwe = f.get("cwe", "")
            if cwe:
                report.findings_by_cwe[cwe] = (
                    report.findings_by_cwe.get(cwe, 0) + 1)

    # -- Results ------------------------------------------------------------ #

    def results(self) -> list[ScanResult]:
        return self._results

    def findings(self) -> list[dict[str, Any]]:
        all_f = []
        for r in self._results:
            all_f.extend(r.findings)
        return all_f

    # -- Cleanup ------------------------------------------------------------ #

    def cleanup(self) -> None:
        self._fetcher.cleanup_all()

    # -- Persistence -------------------------------------------------------- #

    def save_queue(self, path: str) -> None:
        """Save the queue to a JSON file."""
        data = []
        for entry in self._queue.all_entries():
            data.append({
                "url": entry.url,
                "owner": entry.owner,
                "name": entry.name,
                "status": entry.status.name,
                "files_scanned": entry.files_scanned,
                "findings_count": entry.findings_count,
                "stars": entry.stars,
                "size_kb": entry.size_kb,
            })
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def load_queue(self, path: str) -> int:
        """Load a queue from a JSON file."""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        count = 0
        for item in data:
            url = item.get("url", "")
            if url:
                entry = self._queue.add(url)
                entry.stars = item.get("stars", 0)
                entry.size_kb = item.get("size_kb", 0)
                count += 1
        return count

    def save_report(self, report: IngestReport, path: str) -> None:
        """Save a report to a JSON file."""
        data = {
            "total_repos": report.total_repos,
            "repos_scanned": report.repos_scanned,
            "repos_failed": report.repos_failed,
            "total_files": report.total_files,
            "total_findings": report.total_findings,
            "findings_by_severity": report.findings_by_severity,
            "findings_by_cwe": report.findings_by_cwe,
            "languages": sorted(report.languages_seen),
            "elapsed": report.elapsed,
            "repos": [],
        }
        for r in report.repo_results:
            data["repos"].append({
                "name": r.repo.full_name,
                "url": r.repo.url,
                "files": r.files_scanned,
                "findings": len(r.findings),
                "languages": sorted(r.languages_found),
                "time": r.scan_time,
                "status": r.repo.status.name,
            })
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def __repr__(self) -> str:
        return "GitHubIngest(queue=%d, results=%d)" % (
            len(self._queue), len(self._results))
