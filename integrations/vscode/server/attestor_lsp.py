#!/usr/bin/env python3
"""Attestor 4.0 Language Server Protocol 3.18 presentation.

The server analyzes unsaved in-memory documents, publishes bounded diagnostics,
and exposes verified-improvement preview actions without writing the workspace.
Live buffers use the deterministic 3.0 analysis core; repository-wide Attestor 4.0
Engineering and Security Fabrics remain explicit CLI/workbench operations.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, is_dataclass
from typing import Any, BinaryIO
from urllib.parse import unquote, urlparse

import deepscan
import detect
import rarebugs


SERVER_VERSION = "4.0.0"
DIAGNOSTIC_SOURCE = "Attestor 4.0"
ANALYSIS_ENGINE = "deterministic-live-core/3.0"
COMPATIBILITY_VERSIONS = ("3.5", "3.0")
MAX_MESSAGE_BYTES = 4 * 1024 * 1024
MAX_DOCUMENT_CHARS = 2 * 1024 * 1024
MAX_DIAGNOSTICS = 500
LANGUAGES = {
    "python": "python", "javascript": "javascript", "javascriptreact": "javascript",
    "typescript": "typescript", "typescriptreact": "typescript", "c": "c", "cpp": "cpp",
    "haskell": "haskell", "rust": "rust", "go": "go", "java": "java",
    "csharp": "csharp", "php": "php", "ruby": "ruby", "shellscript": "shell",
}
EXTENSIONS = {
    ".py": "python", ".pyw": "python", ".js": "javascript", ".jsx": "javascript",
    ".mjs": "javascript", ".ts": "typescript", ".tsx": "typescript", ".c": "c",
    ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".hs": "haskell",
    ".rs": "rust", ".go": "go", ".java": "java", ".cs": "csharp", ".php": "php",
    ".rb": "ruby", ".sh": "shell",
}
LSP_SEVERITY = {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class LspProtocolError(ValueError):
    pass


def read_message(stream: BinaryIO) -> dict[str, Any] | None:
    headers: dict[str, str] = {}
    total_header = 0
    while True:
        line = stream.readline(8193)
        if not line:
            return None if not headers else (_ for _ in ()).throw(LspProtocolError("truncated headers"))
        total_header += len(line)
        if total_header > 64 * 1024 or len(line) > 8192:
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
    body = stream.read(length)
    if len(body) != length:
        raise LspProtocolError("truncated JSON body")
    try:
        message = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LspProtocolError("invalid JSON body") from exc
    if not isinstance(message, dict):
        raise LspProtocolError("JSON-RPC message must be an object")
    return message


def encode_message(message: dict[str, Any]) -> bytes:
    body = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(body) > MAX_MESSAGE_BYTES:
        raise LspProtocolError("response boundary exceeded")
    return b"Content-Length: %d\r\n\r\n" % len(body) + body


def _uri_path(uri: str) -> str:
    try:
        parsed = urlparse(uri)
        if parsed.scheme == "file":
            path = unquote(parsed.path)
            if parsed.netloc:
                path = "//" + parsed.netloc + path
            if len(path) > 2 and path[0] == "/" and path[2] == ":":
                path = path[1:]
            return path
    except ValueError:
        return "<memory>"
    return "<memory>"


def _language(uri: str, language_id: str) -> str:
    if language_id in LANGUAGES:
        return LANGUAGES[language_id]
    path = _uri_path(uri).lower()
    for extension, language in EXTENSIONS.items():
        if path.endswith(extension):
            return language
    return "text"


def _row(finding: Any) -> dict[str, Any]:
    if is_dataclass(finding):
        return asdict(finding)
    if hasattr(finding, "__dict__"):
        return vars(finding)
    return finding if isinstance(finding, dict) else {}


class AttestorLanguageServer:
    def __init__(self):
        self.documents: dict[str, dict[str, Any]] = {}
        self.findings: dict[str, list[dict[str, Any]]] = {}
        self.shutdown_requested = False
        self.exit_requested = False

    def _response(self, request_id: Any, result: Any = None,
                  error: dict[str, Any] | None = None) -> dict[str, Any]:
        message = {"jsonrpc": "2.0", "id": request_id}
        message["error" if error else "result"] = error if error else result
        return message

    def _diagnose(self, uri: str) -> list[dict[str, Any]]:
        document = self.documents[uri]
        text = document["text"]
        if len(text) > MAX_DOCUMENT_CHARS:
            self.findings[uri] = []
            return [{
                "range": {"start": {"line": 0, "character": 0},
                          "end": {"line": 0, "character": 1}},
                "severity": 2, "source": DIAGNOSTIC_SOURCE, "code": "analysis-boundary",
                "message": "Document exceeds Attestor's 2 MiB live-analysis boundary; run a workspace scan.",
                "data": {"analysis_engine": ANALYSIS_ENGINE},
            }]
        language = _language(uri, document.get("languageId", ""))
        path = _uri_path(uri)
        findings = list(detect.scan_source(text, path, language, deep=True))
        if language == "python":
            findings.extend(deepscan.analyze(text, path))
            findings.extend(rarebugs.analyze(text, path))
        unique: dict[tuple, dict[str, Any]] = {}
        for finding in findings:
            row = _row(finding)
            key = (row.get("rule"), int(row.get("line", 1)), row.get("message"))
            unique.setdefault(key, row)
        rows = sorted(unique.values(), key=lambda item: (
            int(item.get("line", 1)), item.get("severity", "INFO"), item.get("rule", "")))[:MAX_DIAGNOSTICS]
        self.findings[uri] = rows
        diagnostics = []
        lines = text.splitlines()
        for row in rows:
            line = max(0, int(row.get("line", 1)) - 1)
            width = min(2_000, len(lines[line]) if line < len(lines) else 1)
            diagnostics.append({
                "range": {"start": {"line": line, "character": 0},
                          "end": {"line": line, "character": max(1, width)}},
                "severity": LSP_SEVERITY.get(str(row.get("severity", "INFO")).upper(), 3),
                "source": DIAGNOSTIC_SOURCE, "code": row.get("rule", "finding"),
                "message": str(row.get("message", "Review this evidence."))[:4_000],
                "data": {"fix": str(row.get("fix", ""))[:4_000],
                         "confidence": row.get("confidence", 0),
                          "safe_to_autofix": bool(row.get("safe_to_autofix", False)),
                          "analysis_engine": ANALYSIS_ENGINE},
            })
        return diagnostics

    def _publish(self, uri: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics",
                "params": {"uri": uri, "diagnostics": self._diagnose(uri),
                           "version": self.documents[uri].get("version")}}

    def _improved_result(self, uri: str, selection: dict[str, Any] | None = None) -> dict[str, Any]:
        document = self.documents.get(uri)
        if not document:
            return {"available": False, "reason": "document is not open"}
        try:
            import verified_remediation
            improve = getattr(verified_remediation, "improve_source", None)
            if improve is None:
                return {"available": False, "reason": "verified remediation engine is unavailable"}
            result = improve(document["text"], _uri_path(uri), findings=self.findings.get(uri, []),
                             selection=selection, verify=True)
            result = asdict(result) if is_dataclass(result) else result
            if not isinstance(result, dict):
                return {"available": False, "accepted": False,
                        "reason": "remediation returned an invalid result"}
            if result.get("accepted") is not True:
                # A rejected candidate may carry an internal proposal for audit,
                # but editor clients must never present it as an improved result.
                reasons = result.get("reasons") if isinstance(result.get("reasons"), list) else []
                return {**result, "available": False, "improved_source": "", "diff": "",
                        "reason": str(reasons[0])[:1000] if reasons else
                                  "the candidate did not pass every verification gate"}
            return result
        except (ImportError, TypeError, ValueError, RuntimeError) as exc:
            return {"available": False, "reason": "improvement failed safely: %s" % type(exc).__name__}

    def handle(self, message: dict[str, Any]) -> list[dict[str, Any]]:
        if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
            request_id = message.get("id")
            return [self._response(request_id, error={"code": -32600, "message": "Invalid Request"})] \
                if "id" in message else []
        method = message["method"]
        params = message.get("params") if isinstance(message.get("params"), dict) else {}
        request_id = message.get("id")
        try:
            if method == "initialize":
                result = {"serverInfo": {"name": "Attestor 4.0", "version": SERVER_VERSION},
                          "capabilities": {
                              "positionEncoding": "utf-16",
                              "textDocumentSync": {"openClose": True, "change": 1, "save": {"includeText": True}},
                              "codeActionProvider": {"resolveProvider": False},
                              "executeCommandProvider": {"commands": ["attestor.previewImprovement"]},
                              "diagnosticProvider": {"interFileDependencies": True,
                                                     "workspaceDiagnostics": False},
                              "experimental": {"attestor": {
                                  "presentationVersion": "4.0",
                                  "analysisEngine": ANALYSIS_ENGINE,
                                  "compatibilityVersions": list(COMPATIBILITY_VERSIONS),
                                  "workspaceFabricViaCli": True,
                              }},
                          }}
                return [self._response(request_id, result)]
            if method == "shutdown":
                self.shutdown_requested = True
                return [self._response(request_id, None)]
            if method == "exit":
                self.exit_requested = True
                return []
            if method == "textDocument/didOpen":
                item = params.get("textDocument", {})
                uri = item.get("uri"); text = item.get("text")
                if not isinstance(uri, str) or not isinstance(text, str):
                    raise LspProtocolError("didOpen requires URI and text")
                self.documents[uri] = {"text": text, "version": item.get("version"),
                                       "languageId": item.get("languageId", "")}
                return [self._publish(uri)]
            if method == "textDocument/didChange":
                item = params.get("textDocument", {}); uri = item.get("uri")
                changes = params.get("contentChanges")
                if uri not in self.documents or not isinstance(changes, list) or len(changes) != 1 \
                        or not isinstance(changes[0].get("text"), str) or "range" in changes[0]:
                    raise LspProtocolError("Attestor accepts one full-document change")
                self.documents[uri]["text"] = changes[0]["text"]
                self.documents[uri]["version"] = item.get("version")
                return [self._publish(uri)]
            if method == "textDocument/didSave":
                item = params.get("textDocument", {}); uri = item.get("uri")
                if uri not in self.documents:
                    return []
                if isinstance(params.get("text"), str):
                    self.documents[uri]["text"] = params["text"]
                return [self._publish(uri)]
            if method == "textDocument/didClose":
                uri = params.get("textDocument", {}).get("uri")
                self.documents.pop(uri, None); self.findings.pop(uri, None)
                return [{"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics",
                         "params": {"uri": uri, "diagnostics": []}}]
            if method == "textDocument/codeAction":
                uri = params.get("textDocument", {}).get("uri")
                actions = []
                for row in self.findings.get(uri, [])[:100]:
                    actions.append({
                        "title": "Attestor: preview verified improvement for %s" % row.get("rule", "finding"),
                        "kind": "quickfix", "isPreferred": bool(row.get("safe_to_autofix", False)),
                        "command": {"title": "Preview verified improvement",
                                    "command": "attestor.previewImprovement",
                                    "arguments": [{"uri": uri, "rule": row.get("rule"),
                                                   "line": row.get("line", 1)}]},
                    })
                return [self._response(request_id, actions)]
            if method == "workspace/executeCommand":
                if params.get("command") != "attestor.previewImprovement":
                    return [self._response(request_id, error={"code": -32602, "message": "Unknown command"})]
                arguments = params.get("arguments") or []
                selection = arguments[0] if arguments and isinstance(arguments[0], dict) else {}
                return [self._response(request_id, self._improved_result(selection.get("uri", ""), selection))]
            if method == "attestor/improvedResult":
                uri = params.get("textDocument", {}).get("uri", "")
                return [self._response(request_id, self._improved_result(uri, params.get("selection")))]
            if "id" in message:
                return [self._response(request_id, error={"code": -32601, "message": "Method not found"})]
            return []
        except (KeyError, LspProtocolError, TypeError, ValueError) as exc:
            if "id" in message:
                return [self._response(request_id, error={"code": -32602,
                                                          "message": "Invalid params: %s" % type(exc).__name__})]
            return []


def serve(input_stream: BinaryIO, output_stream: BinaryIO) -> int:
    server = AttestorLanguageServer()
    while not server.exit_requested:
        try:
            message = read_message(input_stream)
            if message is None:
                break
            for response in server.handle(message):
                output_stream.write(encode_message(response)); output_stream.flush()
        except LspProtocolError as exc:
            error = {"jsonrpc": "2.0", "id": None,
                     "error": {"code": -32700, "message": str(exc)}}
            output_stream.write(encode_message(error)); output_stream.flush()
            break
    return 0 if server.shutdown_requested else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    return serve(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    raise SystemExit(main())
