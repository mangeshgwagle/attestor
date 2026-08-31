"""Tests for API security scanner."""
import json
import api_scan


def _make_spec(**overrides):
    base = {
        "openapi": "3.0.0",
        "info": {"title": "Test API", "version": "1.0"},
        "paths": {},
    }
    base.update(overrides)
    return base


def test_bola_detection():
    spec = _make_spec(paths={
        "/users/{id}": {
            "get": {"operationId": "getUser", "responses": {"200": {}}}
        }
    })
    findings = api_scan.scan_spec(spec)
    bola = [f for f in findings if f.category == "bola"]
    assert len(bola) >= 1


def test_no_bola_with_security():
    spec = _make_spec(
        paths={
            "/users/{id}": {
                "get": {
                    "operationId": "getUser",
                    "security": [{"bearerAuth": []}],
                    "responses": {"200": {}},
                }
            }
        },
        components={"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
    )
    findings = api_scan.scan_spec(spec)
    bola = [f for f in findings if f.category == "bola"]
    assert len(bola) == 0


def test_missing_auth_on_write():
    spec = _make_spec(paths={
        "/items": {
            "post": {"operationId": "createItem", "responses": {"201": {}}}
        }
    })
    findings = api_scan.scan_spec(spec)
    auth = [f for f in findings if f.category == "missing_auth"]
    assert len(auth) >= 1


def test_basic_auth_warning():
    spec = _make_spec(
        components={"securitySchemes": {
            "basic": {"type": "http", "scheme": "basic"}
        }},
        paths={},
    )
    findings = api_scan.scan_spec(spec)
    weak = [f for f in findings if f.category == "weak_auth"]
    assert len(weak) >= 1


def test_api_key_in_query():
    spec = _make_spec(
        components={"securitySchemes": {
            "apiKey": {"type": "apiKey", "in": "query", "name": "key"}
        }},
        paths={},
    )
    findings = api_scan.scan_spec(spec)
    cred = [f for f in findings if f.category == "credential_exposure"]
    assert len(cred) >= 1


def test_sensitive_response_fields():
    spec = _make_spec(paths={
        "/users/{id}": {
            "get": {
                "security": [{"auth": []}],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "name": {"type": "string"},
                                        "password": {"type": "string"},
                                        "ssn": {"type": "string"},
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    })
    findings = api_scan.scan_spec(spec)
    exposure = [f for f in findings if f.category == "data_exposure"]
    assert len(exposure) >= 1


def test_unconstrained_string_param():
    spec = _make_spec(paths={
        "/search": {
            "get": {
                "security": [{"auth": []}],
                "parameters": [
                    {"name": "q", "in": "query", "schema": {"type": "string"}}
                ],
                "responses": {"200": {}},
            }
        }
    })
    findings = api_scan.scan_spec(spec)
    inject = [f for f in findings if f.category == "injection_vector"]
    assert len(inject) >= 1


def test_constrained_param_no_finding():
    spec = _make_spec(paths={
        "/search": {
            "get": {
                "security": [{"auth": []}],
                "parameters": [
                    {"name": "q", "in": "query",
                     "schema": {"type": "string", "pattern": "^[a-z]+$"}}
                ],
                "responses": {"200": {}},
            }
        }
    })
    findings = api_scan.scan_spec(spec)
    inject = [f for f in findings if f.category == "injection_vector"]
    assert len(inject) == 0


def test_scan_file(tmp_path):
    spec = _make_spec(paths={
        "/items/{id}": {
            "delete": {"operationId": "deleteItem", "responses": {"204": {}}}
        }
    })
    f = tmp_path / "openapi.json"
    f.write_text(json.dumps(spec), encoding="utf-8")
    findings = api_scan.scan_file(str(f))
    assert len(findings) >= 1


def test_to_dict():
    spec = _make_spec(paths={
        "/users/{id}": {
            "get": {"responses": {"200": {}}}
        }
    })
    findings = api_scan.scan_spec(spec, "spec.json")
    dicts = api_scan.to_dict(findings)
    assert len(dicts) >= 1
    assert "sink_file" in dicts[0]


def test_render():
    spec = _make_spec(paths={
        "/users/{id}": {
            "get": {"responses": {"200": {}}}
        }
    })
    findings = api_scan.scan_spec(spec)
    output = api_scan.render(findings)
    assert "API Security Scan" in output
    assert "BOLA" in output.upper() or "bola" in output


def test_not_openapi():
    spec = {"name": "not an api spec"}
    findings = api_scan.scan_spec(spec)
    assert len(findings) == 0


def test_global_security_inherited():
    spec = _make_spec(
        security=[{"bearerAuth": []}],
        paths={
            "/users/{id}": {
                "get": {"responses": {"200": {}}}
            }
        }
    )
    findings = api_scan.scan_spec(spec)
    bola = [f for f in findings if f.category == "bola"]
    assert len(bola) == 0
