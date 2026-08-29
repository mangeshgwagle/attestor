#!/usr/bin/env python3
"""Attestor 4.1.3 bounded Language Server Protocol presentation.

The server analyzes in-memory buffers and bounded files below declared
workspace roots.  It never writes source files and never sends
``workspace/applyEdit``.  A verified candidate is returned only as a
consent-gated preview ``WorkspaceEdit`` for the editor to display.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import sys
import threading
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Mapping
from urllib.parse import quote, unquote, urlparse

import deepscan
import detect
import rarebugs


SERVER_VERSION = "4.1.3"
DIAGNOSTIC_SOURCE = "Attestor 4.1.3"
ANALYSIS_ENGINE = "deterministic-live-core/4.1"
MAX_MESSAGE_BYTES = 4 * 1024 * 1024
MAX_DOCUMENT_CHARS = 2 * 1024 * 1024
MAX_WORKSPACE_FILES = 500
MAX_WORKSPACE_BYTES = 32 * 1024 * 1024
MAX_DIAGNOSTICS = 500
MAX_WORKSPACE_RESPONSE_BYTES = MAX_MESSAGE_BYTES
MAX_PENDING_MESSAGES = 16
LANGUAGES = {
    "python": "python", "javascript": "javascript", "javascriptreact": "javascript",
    "typescript": "typescript", "typescriptreact": "typescript", "c": "c", "cpp": "cpp",
    "haskell": "haskell", "rust": "rust", "go": "go", "java": "java",
    "csharp": "csharp", "php": "php", "ruby": "ruby", "shellscript": "shell",
}
EXTENSIONS = {
    ".py": "python", ".pyw": "python", ".js": "javascript", ".jsx": "javascript",
    ".mjs": "javascript", ".cjs": "javascript", ".ts": "typescript", ".tsx": "typescript",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".hs": "haskell", ".rs": "rust", ".go": "go", ".java": "java",
    ".cs": "csharp", ".php": "php", ".rb": "ruby", ".sh": "shell",
}
LSP_SEVERITY = {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
SKIP_DIRS = frozenset({".git", ".hg", ".svn", "node_modules", "vendor", "dist", "build",
                       "target", "__pycache__", ".venv", "venv"})


class LspProtocolError(ValueError):
    """A client message violated the bounded JSON-RPC/LSP contract."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _sha(value: Any) -> str:
    raw = value if isinstance(value, bytes) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def read_message(stream: BinaryIO) -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    total = 0
    while True:
        line = stream.readline(8193)
        if not line:
            if not headers:
                return None
            raise LspProtocolError("truncated headers")
        total += len(line)
        if total > 64 * 1024 or len(line) > 8192:
            raise LspProtocolError("header boundary exceeded")
        if line in {b"\r\n", b"\n"}:
            break
        try:
            name, value = line.decode("ascii").strip().split(":", 1)
        except (UnicodeDecodeError, ValueError) as exc:
            raise LspProtocolError("malformed header") from exc
        key = name.strip().lower()
        if key in headers:
            raise LspProtocolError("duplicate header")
        headers[key] = value.strip()
    try:
        length = int(headers["content-length"])
    except (KeyError, ValueError) as exc:
        raise LspProtocolError("valid Content-Length is required") from exc
    if not 0 <= length <= MAX_MESSAGE_BYTES:
        raise LspProtocolError("message boundary exceeded")
    raw = stream.read(length)
    if len(raw) != length:
        raise LspProtocolError("truncated JSON body")
    try:
        message = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LspProtocolError("invalid JSON body") from exc
    if not isinstance(message, dict):
        raise LspProtocolError("JSON-RPC message must be an object")
    return message


def encode_message(message: Mapping[str, Any]) -> bytes:
    raw = _canonical(dict(message))
    if len(raw) > MAX_MESSAGE_BYTES:
        raise LspProtocolError("response boundary exceeded")
    return b"Content-Length: %d\r\n\r\n" % len(raw) + raw


def _uri_path(uri: str) -> str:
    try:
        parsed = urlparse(uri)
    except ValueError:
        return "<memory>"
    if parsed.scheme != "file":
        return "<memory>"
    path = unquote(parsed.path)
    if parsed.netloc:
        path = "//" + parsed.netloc + path
    if len(path) > 2 and path[0] == "/" and path[2] == ":":
        path = path[1:]
    return path


def _path_uri(path: Path) -> str:
    try:
        return path.resolve().as_uri()
    except ValueError:
        return "file://" + quote(str(path).replace("\\", "/"))


def _language(uri: str, language_id: str = "") -> str:
    if language_id in LANGUAGES:
        return LANGUAGES[language_id]
    lowered = _uri_path(uri).lower()
    return next((language for extension, language in EXTENSIONS.items()
                 if lowered.endswith(extension)), "text")


def _row(finding: Any) -> dict[str, Any]:
    if is_dataclass(finding):
        return asdict(finding)
    if hasattr(finding, "__dict__"):
        return vars(finding)
    return finding if isinstance(finding, dict) else {}


def _utf16_units(value: str) -> int:
    return len(value.encode("utf-16-le")) // 2


def _position_offset(text: str, position: Mapping[str, Any]) -> int:
    try:
        requested_line = int(position.get("line", -1))
        requested_units = int(position.get("character", -1))
    except (TypeError, ValueError) as exc:
        raise LspProtocolError("position is invalid") from exc
    if requested_line < 0 or requested_units < 0:
        raise LspProtocolError("position is invalid")
    lines = text.splitlines(keepends=True)
    if not lines:
        lines = [""]
    if requested_line > len(lines) or (requested_line == len(lines) and requested_units != 0):
        raise LspProtocolError("position is outside the document")
    if requested_line == len(lines):
        return len(text)
    line = lines[requested_line]
    content = line.rstrip("\r\n")
    used = 0
    for index, character in enumerate(content):
        if used == requested_units:
            return sum(len(item) for item in lines[:requested_line]) + index
        used += _utf16_units(character)
        if used > requested_units:
            raise LspProtocolError("position splits a UTF-16 surrogate pair")
    if used == requested_units:
        return sum(len(item) for item in lines[:requested_line]) + len(content)
    raise LspProtocolError("position is outside the line")


def _end_position(text: str) -> dict[str, int]:
    lines = text.splitlines()
    if text.endswith(("\n", "\r")):
        return {"line": len(lines), "character": 0}
    if not lines:
        return {"line": 0, "character": 0}
    return {"line": len(lines) - 1, "character": _utf16_units(lines[-1])}


def apply_content_changes(text: str, changes: Iterable[Mapping[str, Any]]) -> str:
    """Apply LSP incremental changes in order using negotiated UTF-16 positions."""
    output = text
    rows = list(changes)
    if not rows or len(rows) > 1_000:
        raise LspProtocolError("contentChanges must be a bounded non-empty list")
    for change in rows:
        replacement = change.get("text")
        if not isinstance(replacement, str):
            raise LspProtocolError("change text is required")
        if "range" not in change:
            output = replacement
        else:
            selected = change.get("range")
            if not isinstance(selected, Mapping) or not isinstance(selected.get("start"), Mapping) \
                    or not isinstance(selected.get("end"), Mapping):
                raise LspProtocolError("change range is invalid")
            start = _position_offset(output, selected["start"])
            end = _position_offset(output, selected["end"])
            if start > end:
                raise LspProtocolError("change range is reversed")
            output = output[:start] + replacement + output[end:]
        if len(output) > MAX_DOCUMENT_CHARS:
            raise LspProtocolError("changed document exceeds the live-analysis boundary")
    return output


class AttestorLanguageServer41:
    def __init__(self):
        self.documents: dict[str, dict[str, Any]] = {}
        self.findings: dict[str, list[dict[str, Any]]] = {}
        self.diagnostics: dict[str, list[dict[str, Any]]] = {}
        self.workspace_roots: dict[str, Path] = {}
        self.active_requests: set[str] = set()
        self.cancelled: set[str] = set()
        self._request_state_lock = threading.Lock()
        self.shutdown_requested = False
        self.exit_requested = False

    @staticmethod
    def _response(request_id: Any, result: Any = None,
                  error: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id,
                "error" if error else "result": dict(error) if error else result}

    @staticmethod
    def _request_key(request_id: Any) -> str:
        return json.dumps(request_id, sort_keys=True, default=str)[:1_000]

    def _activate_request(self, request_id: Any) -> None:
        with self._request_state_lock:
            self.active_requests.add(self._request_key(request_id))

    def _cancel_request(self, request_id: Any) -> None:
        key = self._request_key(request_id)
        with self._request_state_lock:
            if key in self.active_requests:
                self.cancelled.add(key)

    def _is_cancelled(self, request_id: Any) -> bool:
        with self._request_state_lock:
            return self._request_key(request_id) in self.cancelled

    def _finish_request(self, request_id: Any) -> None:
        key = self._request_key(request_id)
        with self._request_state_lock:
            self.active_requests.discard(key)
            self.cancelled.discard(key)

    def _clear_request_state(self) -> None:
        with self._request_state_lock:
            self.active_requests.clear()
            self.cancelled.clear()

    @staticmethod
    def _progress(token: Any, kind: str, message: str, percentage: int | None = None) -> dict[str, Any]:
        value: dict[str, Any] = {"kind": kind, "message": message}
        if percentage is not None:
            value["percentage"] = max(0, min(100, percentage))
        return {"jsonrpc": "2.0", "method": "$/progress", "params": {"token": token, "value": value}}

    @staticmethod
    def _workspace_coverage(omitted: int) -> dict[str, Any]:
        partial = omitted > 0
        return {"complete": not partial, "partial": partial,
                "omittedDocuments": omitted,
                "reason": "workspace-response-byte-budget" if partial else "complete",
                "responseByteBudget": min(MAX_MESSAGE_BYTES, MAX_WORKSPACE_RESPONSE_BYTES)}

    def _workspace_response(self, request_id: Any, items: list[dict[str, Any]],
                            omitted: int) -> dict[str, Any]:
        return self._response(request_id, {
            "items": items, "attestorCoverage": self._workspace_coverage(omitted)})

    def _workspace_response_size(self, request_id: Any, item_payload_bytes: int,
                                 item_count: int, omitted: int) -> int:
        empty_size = len(_canonical(self._workspace_response(request_id, [], omitted)))
        return empty_size + item_payload_bytes + max(0, item_count - 1)

    def _set_roots(self, values: Iterable[Mapping[str, Any]]) -> None:
        for raw in values:
            uri = raw.get("uri") if isinstance(raw, Mapping) else None
            path_text = _uri_path(uri) if isinstance(uri, str) else "<memory>"
            try:
                path = Path(path_text).expanduser().resolve()
            except (OSError, RuntimeError, ValueError):
                continue
            if path_text != "<memory>" and path.is_dir() and not path.is_symlink():
                self.workspace_roots[uri] = path

    @staticmethod
    def _evidence(row: Mapping[str, Any], text: str, path: str) -> dict[str, Any]:
        line = max(1, int(row.get("line", 1)))
        raw = text.encode("utf-8")
        encoded_lines = text.splitlines(keepends=True)
        before = "".join(encoded_lines[:line - 1]).encode("utf-8")
        snippet = (encoded_lines[line - 1] if line <= len(encoded_lines) else "").encode("utf-8")
        body = {"path": path, "line": line, "byte_start": len(before),
                "byte_end": len(before) + len(snippet), "document_sha256": _sha(raw),
                "snippet_sha256": _sha(snippet),
                "rule_sha256": _sha({"rule": str(row.get("rule", "finding")),
                                      "engine": ANALYSIS_ENGINE})}
        body["evidence_id"] = "lsp41-" + _sha(body)[:32]
        return body

    def _analyze(self, uri: str, document: Mapping[str, Any]) -> list[dict[str, Any]]:
        text = str(document.get("text", ""))
        if len(text) > MAX_DOCUMENT_CHARS:
            self.findings[uri] = []
            return [{"range": {"start": {"line": 0, "character": 0},
                               "end": {"line": 0, "character": 1}},
                     "severity": 2, "source": DIAGNOSTIC_SOURCE, "code": "analysis-boundary",
                     "message": "Document exceeds Attestor's live-analysis boundary; run a workspace scan.",
                     "data": {"analysis_engine": ANALYSIS_ENGINE, "evidence_state": "unavailable"}}]
        language = _language(uri, str(document.get("languageId", "")))
        path = _uri_path(uri)
        rows = list(detect.scan_source(text, path, language, deep=True))
        if language == "python":
            rows.extend(deepscan.analyze(text, path))
            rows.extend(rarebugs.analyze(text, path))
        unique: dict[tuple[Any, ...], dict[str, Any]] = {}
        for finding in rows:
            row = _row(finding)
            key = (row.get("rule"), int(row.get("line", 1)), row.get("message"))
            unique.setdefault(key, row)
        findings = sorted(unique.values(), key=lambda row: (
            int(row.get("line", 1)), str(row.get("severity", "INFO")), str(row.get("rule", ""))))[:MAX_DIAGNOSTICS]
        self.findings[uri] = findings
        lines = text.splitlines()
        diagnostics = []
        for row in findings:
            line = max(0, int(row.get("line", 1)) - 1)
            width = _utf16_units(lines[line]) if line < len(lines) else 1
            evidence = self._evidence(row, text, path)
            diagnostics.append({
                "range": {"start": {"line": line, "character": 0},
                          "end": {"line": line, "character": max(1, min(2_000, width))}},
                "severity": LSP_SEVERITY.get(str(row.get("severity", "INFO")).upper(), 3),
                "source": DIAGNOSTIC_SOURCE, "code": str(row.get("rule", "finding"))[:300],
                "message": str(row.get("message", "Review this evidence."))[:4_000],
                "data": {"fix": str(row.get("fix", ""))[:4_000],
                         "confidence": row.get("confidence", 0),
                         "safe_to_autofix": bool(row.get("safe_to_autofix", False)),
                         "analysis_engine": ANALYSIS_ENGINE, **evidence},
            })
        self.diagnostics[uri] = diagnostics
        return diagnostics

    def _publish(self, uri: str) -> dict[str, Any]:
        document = self.documents[uri]
        return {"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics",
                "params": {"uri": uri, "version": document.get("version"),
                           "diagnostics": self._analyze(uri, document)}}

    def _workspace_documents(self) -> Iterable[tuple[str, dict[str, Any]]]:
        emitted = set()
        total = 0
        for uri, document in self.documents.items():
            emitted.add(uri)
            total += len(str(document.get("text", "")).encode("utf-8"))
            yield uri, document
        count = len(emitted)
        for root in sorted(set(self.workspace_roots.values()), key=str):
            for base, dirs, files in os.walk(root, followlinks=False):
                dirs[:] = sorted(name for name in dirs if name not in SKIP_DIRS
                                  and not (Path(base) / name).is_symlink())
                for name in sorted(files):
                    if count >= MAX_WORKSPACE_FILES or total >= MAX_WORKSPACE_BYTES:
                        return
                    path = (Path(base) / name)
                    if path.suffix.lower() not in EXTENSIONS or path.is_symlink():
                        continue
                    uri = _path_uri(path)
                    if uri in emitted:
                        continue
                    try:
                        raw = path.read_bytes()
                    except OSError:
                        continue
                    if len(raw) > MAX_DOCUMENT_CHARS or total + len(raw) > MAX_WORKSPACE_BYTES:
                        continue
                    try:
                        text = raw.decode("utf-8")
                    except UnicodeDecodeError:
                        continue
                    emitted.add(uri); count += 1; total += len(raw)
                    yield uri, {"text": text, "version": None, "languageId": _language(uri)}

    def _preview_edit(self, uri: str, selection: Mapping[str, Any] | None,
                      consent: bool) -> dict[str, Any]:
        if consent is not True:
            return {"available": False, "previewOnly": True, "consentRequired": True,
                    "reason": "explicit preview consent is required; Attestor did not write the workspace"}
        document = self.documents.get(uri)
        if not document:
            return {"available": False, "previewOnly": True, "reason": "document is not open"}
        try:
            import verified_remediation
            result = verified_remediation.improve_source(
                document["text"], _uri_path(uri), findings=self.findings.get(uri, []),
                selection=dict(selection or {}), verify=True)
            result = asdict(result) if is_dataclass(result) else result
        except (ImportError, OSError, RuntimeError, TypeError, ValueError) as exc:
            return {"available": False, "previewOnly": True,
                    "reason": "verification failed safely: %s" % type(exc).__name__}
        if not isinstance(result, Mapping) or result.get("accepted") is not True \
                or not isinstance(result.get("improved_source"), str):
            reasons = result.get("reasons", []) if isinstance(result, Mapping) else []
            return {"available": False, "previewOnly": True, "accepted": False,
                    "reason": str(reasons[0])[:1_000] if isinstance(reasons, list) and reasons
                              else "candidate did not pass every verification gate"}
        edit = {"documentChanges": [{"textDocument": {"uri": uri,
                                                        "version": document.get("version")},
                                     "edits": [{"range": {"start": {"line": 0, "character": 0},
                                                          "end": _end_position(document["text"])},
                                                "newText": result["improved_source"]}]}]}
        return {"available": True, "accepted": True, "previewOnly": True,
                "consentRecorded": True, "workspaceEdit": edit,
                "verification": {"accepted": True, "source_sha256": _sha(document["text"].encode("utf-8")),
                                 "candidate_sha256": _sha(result["improved_source"].encode("utf-8"))},
                "reason": "verified candidate returned for editor preview; no workspace write occurred"}

    def handle(self, message: Mapping[str, Any]) -> list[dict[str, Any]]:
        if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            return [self._response(message.get("id"), error={"code": -32600, "message": "Invalid Request"})] \
                if "id" in message else []
        method = message["method"]
        params = message.get("params") if isinstance(message.get("params"), Mapping) else {}
        if method == "$/cancelRequest":
            self._cancel_request(params.get("id"))
            return []
        if "id" not in message:
            return self._handle(message)
        request_id = message.get("id")
        self._activate_request(request_id)
        try:
            return self._handle(message)
        finally:
            self._finish_request(request_id)

    def _handle(self, message: Mapping[str, Any]) -> list[dict[str, Any]]:
        method = message["method"]
        params = message.get("params") if isinstance(message.get("params"), Mapping) else {}
        request_id = message.get("id")
        if "id" in message and self._is_cancelled(request_id):
            return [self._response(request_id, error={"code": -32800, "message": "Request cancelled"})]
        try:
            if method == "initialize":
                folders = params.get("workspaceFolders") if isinstance(params.get("workspaceFolders"), list) else []
                if not folders and isinstance(params.get("rootUri"), str):
                    folders = [{"uri": params["rootUri"], "name": "root"}]
                self._set_roots(folders)
                result = {"serverInfo": {"name": DIAGNOSTIC_SOURCE, "version": SERVER_VERSION},
                          "capabilities": {"positionEncoding": "utf-16",
                              "textDocumentSync": {"openClose": True, "change": 2,
                                                   "save": {"includeText": True}},
                              "hoverProvider": True,
                              "codeActionProvider": {"resolveProvider": False},
                              "executeCommandProvider": {"commands": ["attestor.previewWorkspaceEdit"]},
                              "diagnosticProvider": {"identifier": "attestor41", "interFileDependencies": True,
                                                     "workspaceDiagnostics": True},
                              "workspace": {"workspaceFolders": {"supported": True,
                                                                  "changeNotifications": True}},
                              "experimental": {"attestor": {"presentationVersion": SERVER_VERSION,
                                  "analysisEngine": ANALYSIS_ENGINE, "previewOnly": True,
                                  "workspaceWrites": False, "evidenceHover": True}}}}
                return [self._response(request_id, result)]
            if method == "shutdown":
                self.shutdown_requested = True
                return [self._response(request_id, None)]
            if method == "exit":
                self.exit_requested = True
                return []
            if method == "workspace/didChangeWorkspaceFolders":
                event = params.get("event") if isinstance(params.get("event"), Mapping) else {}
                for raw in event.get("removed", []) if isinstance(event.get("removed"), list) else []:
                    if isinstance(raw, Mapping):
                        self.workspace_roots.pop(raw.get("uri"), None)
                self._set_roots(event.get("added", []) if isinstance(event.get("added"), list) else [])
                return []
            if method == "textDocument/didOpen":
                item = params.get("textDocument") if isinstance(params.get("textDocument"), Mapping) else {}
                uri, text = item.get("uri"), item.get("text")
                if not isinstance(uri, str) or not isinstance(text, str) or len(text) > MAX_DOCUMENT_CHARS:
                    raise LspProtocolError("didOpen requires a bounded URI and text")
                self.documents[uri] = {"text": text, "version": item.get("version"),
                                       "languageId": item.get("languageId", "")}
                return [self._publish(uri)]
            if method == "textDocument/didChange":
                item = params.get("textDocument") if isinstance(params.get("textDocument"), Mapping) else {}
                uri = item.get("uri")
                changes = params.get("contentChanges")
                if uri not in self.documents or not isinstance(changes, list):
                    raise LspProtocolError("didChange requires an open document")
                prior_version, version = self.documents[uri].get("version"), item.get("version")
                if isinstance(prior_version, int) and isinstance(version, int) and version <= prior_version:
                    raise LspProtocolError("didChange version must increase")
                self.documents[uri]["text"] = apply_content_changes(self.documents[uri]["text"], changes)
                self.documents[uri]["version"] = version
                return [self._publish(uri)]
            if method == "textDocument/didSave":
                item = params.get("textDocument") if isinstance(params.get("textDocument"), Mapping) else {}
                uri = item.get("uri")
                if uri not in self.documents:
                    return []
                if isinstance(params.get("text"), str):
                    self.documents[uri]["text"] = params["text"]
                return [self._publish(uri)]
            if method == "textDocument/didClose":
                item = params.get("textDocument") if isinstance(params.get("textDocument"), Mapping) else {}
                uri = item.get("uri")
                self.documents.pop(uri, None); self.findings.pop(uri, None); self.diagnostics.pop(uri, None)
                return [{"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics",
                         "params": {"uri": uri, "diagnostics": []}}]
            if method == "textDocument/diagnostic":
                uri = params.get("textDocument", {}).get("uri") if isinstance(params.get("textDocument"), Mapping) else None
                if uri not in self.documents:
                    return [self._response(request_id, {"kind": "full", "items": [], "resultId": "closed"})]
                diagnostics = self._analyze(uri, self.documents[uri])
                result_id = _sha([uri, self.documents[uri].get("version"), diagnostics])[:32]
                return [self._response(request_id, {"kind": "full", "items": diagnostics,
                                                    "resultId": result_id})]
            if method == "workspace/diagnostic":
                token = params.get("workDoneToken")
                output = [self._progress(token, "begin", "Scanning declared workspace roots", 0)] if token is not None else []
                items: list[dict[str, Any]] = []
                item_sizes: list[int] = []
                item_payload_bytes = 0
                omitted = 0
                analyzed = 0
                response_budget = min(MAX_MESSAGE_BYTES, MAX_WORKSPACE_RESPONSE_BYTES)
                for uri, document in self._workspace_documents():
                    if self._is_cancelled(request_id):
                        if token is not None:
                            output.append(self._progress(token, "end", "Workspace diagnostics cancelled"))
                        output.append(self._response(request_id, error={"code": -32800,
                                                                       "message": "Request cancelled"}))
                        return output
                    if omitted:
                        omitted += 1
                        continue
                    diagnostics = self._analyze(uri, document)
                    analyzed += 1
                    if self._is_cancelled(request_id):
                        if token is not None:
                            output.append(self._progress(token, "end", "Workspace diagnostics cancelled"))
                        output.append(self._response(request_id, error={"code": -32800,
                                                                       "message": "Request cancelled"}))
                        return output
                    item = {"uri": uri, "version": document.get("version"), "kind": "full",
                            "items": diagnostics, "resultId": _sha([uri, diagnostics])[:32]}
                    item_size = len(_canonical(item))
                    projected = self._workspace_response_size(
                        request_id, item_payload_bytes + item_size, len(items) + 1, 1)
                    if projected > response_budget:
                        omitted = 1
                        continue
                    items.append(item)
                    item_sizes.append(item_size)
                    item_payload_bytes += item_size
                    if token is not None and analyzed % 25 == 0:
                        output.append(self._progress(token, "report", "%d files analyzed" % analyzed))
                while items and self._workspace_response_size(
                        request_id, item_payload_bytes, len(items), omitted) > response_budget:
                    item_payload_bytes -= item_sizes.pop()
                    items.pop()
                    omitted += 1
                if token is not None:
                    message = "%d files analyzed" % analyzed
                    if omitted:
                        message += "; %d omitted by response-byte budget" % omitted
                    output.append(self._progress(token, "end", message, 100))
                output.append(self._workspace_response(request_id, items, omitted))
                return output
            if method == "textDocument/hover":
                item = params.get("textDocument") if isinstance(params.get("textDocument"), Mapping) else {}
                uri = item.get("uri"); position = params.get("position")
                if uri not in self.documents or not isinstance(position, Mapping):
                    return [self._response(request_id, None)]
                line = int(position.get("line", -1))
                match = next((row for row in self.diagnostics.get(uri, [])
                              if row["range"]["start"]["line"] <= line <= row["range"]["end"]["line"]), None)
                if not match:
                    return [self._response(request_id, None)]
                data = match["data"]
                value = ("**%s** (`%s`)\n\n%s\n\nEvidence `%s`  \n"
                         "document `%s`  \nsnippet `%s`  \nrule `%s`") % (
                             DIAGNOSTIC_SOURCE, match["code"], match["message"], data["evidence_id"],
                             data["document_sha256"], data["snippet_sha256"], data["rule_sha256"])
                return [self._response(request_id, {"contents": {"kind": "markdown", "value": value},
                                                    "range": match["range"]})]
            if method == "textDocument/codeAction":
                item = params.get("textDocument") if isinstance(params.get("textDocument"), Mapping) else {}
                uri = item.get("uri")
                actions = [{"title": "Attestor: preview verified improvement for %s" % row.get("rule", "finding"),
                            "kind": "quickfix", "isPreferred": False,
                            "command": {"title": "Preview verified improvement",
                                        "command": "attestor.previewWorkspaceEdit",
                                        "arguments": [{"uri": uri, "rule": row.get("rule"),
                                                       "line": row.get("line", 1), "consent": False}]}}
                           for row in self.findings.get(str(uri), [])[:100]]
                return [self._response(request_id, actions)]
            if method in {"workspace/executeCommand", "attestor/previewWorkspaceEdit"}:
                if method == "workspace/executeCommand" and params.get("command") != "attestor.previewWorkspaceEdit":
                    return [self._response(request_id, error={"code": -32602, "message": "Unknown command"})]
                arguments = params.get("arguments") if isinstance(params.get("arguments"), list) else []
                selection = arguments[0] if arguments and isinstance(arguments[0], Mapping) else params
                uri = selection.get("uri") or (selection.get("textDocument", {}).get("uri")
                                                if isinstance(selection.get("textDocument"), Mapping) else "")
                result = self._preview_edit(str(uri), selection, selection.get("consent") is True)
                return [self._response(request_id, result)]
            if "id" in message:
                return [self._response(request_id, error={"code": -32601, "message": "Method not found"})]
            return []
        except (KeyError, LspProtocolError, OSError, TypeError, ValueError):
            if "id" in message:
                return [self._response(request_id, error={"code": -32602,
                                                          "message": "Invalid params"})]
            return []


# Compatibility-friendly class name for clients that import the module.
AttestorLanguageServer = AttestorLanguageServer41


def serve(input_stream: BinaryIO, output_stream: BinaryIO) -> int:
    server = AttestorLanguageServer41()
    pending: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=MAX_PENDING_MESSAGES)
    stopped = threading.Event()

    def enqueue(kind: str, value: Any) -> bool:
        while not stopped.is_set():
            try:
                pending.put((kind, value), timeout=0.05)
                return True
            except queue.Full:
                continue
        return False

    def read_loop() -> None:
        try:
            while not stopped.is_set():
                message = read_message(input_stream)
                if message is None:
                    enqueue("eof", None)
                    return
                valid = (message.get("jsonrpc") == "2.0" and
                         isinstance(message.get("method"), str))
                if valid and message["method"] == "$/cancelRequest":
                    params = message.get("params") if isinstance(message.get("params"), Mapping) else {}
                    server._cancel_request(params.get("id"))
                    continue
                active = valid and "id" in message
                if active:
                    server._activate_request(message.get("id"))
                if not enqueue("message", message) and active:
                    server._finish_request(message.get("id"))
                    return
        except LspProtocolError as exc:
            enqueue("error", exc)
        except OSError:
            enqueue("error", LspProtocolError("input stream failed"))

    reader = threading.Thread(target=read_loop, name="attestor-lsp41-reader", daemon=True)
    reader.start()
    try:
        while not server.exit_requested:
            kind, value = pending.get()
            if kind == "eof":
                break
            if kind == "error":
                output_stream.write(encode_message({"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": str(value)}}))
                output_stream.flush()
                break
            message = value
            valid_request = (message.get("jsonrpc") == "2.0" and
                             isinstance(message.get("method"), str) and "id" in message)
            try:
                for response in server.handle(message):
                    output_stream.write(encode_message(response))
                    output_stream.flush()
            except LspProtocolError as exc:
                output_stream.write(encode_message({"jsonrpc": "2.0", "id": None,
                    "error": {"code": -32700, "message": str(exc)}}))
                output_stream.flush()
                break
            finally:
                if valid_request:
                    server._finish_request(message.get("id"))
    finally:
        stopped.set()
        server._clear_request_state()
        reader.join(timeout=0.2)
    return 0 if server.shutdown_requested else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    return serve(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["LspProtocolError", "AttestorLanguageServer", "AttestorLanguageServer41",
           "apply_content_changes", "encode_message", "read_message", "serve"]
