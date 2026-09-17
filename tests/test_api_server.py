"""Tests for Attestor REST API server."""
import json
import os
import socket
import sys
import threading
import time
import urllib.request
import urllib.error

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
import api_server


def _free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_PORT = 0
_server = None


def _get(path):
    url = f"http://127.0.0.1:{_PORT}{path}"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8")), resp.status


def _post(path, body=None, api_key=None):
    url = f"http://127.0.0.1:{_PORT}{path}"
    data = json.dumps(body or {}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("X-Attestor-Key", api_key)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8")), resp.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode("utf-8")), e.code


def setup_module():
    global _PORT, _server
    _PORT = _free_port()
    _server = api_server.HTTPServer(("127.0.0.1", _PORT), api_server.AttestorHandler)
    t = threading.Thread(target=_server.serve_forever, daemon=True)
    t.start()
    for _ in range(20):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{_PORT}/api/health", timeout=1)
            return
        except Exception:
            time.sleep(0.1)


def teardown_module():
    if _server:
        _server.shutdown()


def test_health():
    data, status = _get("/api/health")
    assert status == 200
    assert data["status"] == "ok"
    assert data["version"] == "4.4"


def test_version():
    data, status = _get("/api/version")
    assert status == 200
    assert data["branding"] == "for AI's, by AI"
    assert "endpoints" in data
    assert len(data["endpoints"]) > 0


def test_routes():
    data, status = _get("/api/routes")
    assert status == 200
    assert "/api/check" in data["routes"]
    assert "/api/secrets" in data["routes"]
    assert "/api/compliance" in data["routes"]


def test_404_get():
    try:
        _get("/api/nonexistent")
        assert False
    except urllib.error.HTTPError as e:
        assert e.code == 404


def test_unknown_post():
    data, status = _post("/api/nonexistent")
    assert status == 404
    assert "error" in data


def test_invalid_json():
    url = f"http://127.0.0.1:{_PORT}/api/check"
    req = urllib.request.Request(url, data=b"not json", method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        urllib.request.urlopen(req, timeout=10)
        assert False
    except urllib.error.HTTPError as e:
        assert e.code == 400


def test_routes_include_all_endpoints():
    data, _ = _get("/api/routes")
    routes = data["routes"]
    expected = ["/api/check", "/api/secrets", "/api/exploits",
                "/api/compliance", "/api/sca", "/api/iac",
                "/api/taint", "/api/dataflow", "/api/surface",
                "/api/hybrid", "/api/memory/stats", "/api/memory/feedback",
                "/api/sales/ingest", "/api/sales/analyze",
                "/api/inventory/check", "/api/schedule/solve",
                "/api/sbom", "/api/threat-model",
                "/api/novel", "/api/explain"]
    for ep in expected:
        assert ep in routes, f"Missing endpoint: {ep}"


def test_handler_has_version_header():
    url = f"http://127.0.0.1:{_PORT}/api/health"
    req = urllib.request.Request(url)
    with urllib.request.urlopen(req, timeout=10) as resp:
        assert resp.headers.get("X-Attestor-Version") == "4.4"


def test_auth_required():
    old = os.environ.get("ATTESTOR_API_KEY")
    try:
        os.environ["ATTESTOR_API_KEY"] = "test-secret-key-12345"
        data, status = _post("/api/memory/stats", {"root": "."})
        assert status == 401

        data, status = _post("/api/memory/stats", {"root": "."},
                             api_key="wrong-key")
        assert status == 401
    finally:
        if old is None:
            os.environ.pop("ATTESTOR_API_KEY", None)
        else:
            os.environ["ATTESTOR_API_KEY"] = old


def test_auth_passes():
    old = os.environ.get("ATTESTOR_API_KEY")
    try:
        os.environ["ATTESTOR_API_KEY"] = "test-secret-key-12345"
        data, status = _post("/api/memory/stats", {"root": "."},
                             api_key="test-secret-key-12345")
        assert status in (200, 500)
    finally:
        if old is None:
            os.environ.pop("ATTESTOR_API_KEY", None)
        else:
            os.environ["ATTESTOR_API_KEY"] = old


def test_auth_disabled():
    old = os.environ.get("ATTESTOR_API_KEY")
    try:
        os.environ.pop("ATTESTOR_API_KEY", None)
        data, status = _post("/api/memory/stats", {"root": "."})
        assert status in (200, 500)
    finally:
        if old is not None:
            os.environ["ATTESTOR_API_KEY"] = old


def test_meta_in_response():
    old = os.environ.get("ATTESTOR_API_KEY")
    os.environ.pop("ATTESTOR_API_KEY", None)
    try:
        data, status = _post("/api/memory/stats", {"root": "."})
        if status == 200:
            assert "_meta" in data
            assert data["_meta"]["endpoint"] == "/api/memory/stats"
            assert "duration_ms" in data["_meta"]
    finally:
        if old is not None:
            os.environ["ATTESTOR_API_KEY"] = old
