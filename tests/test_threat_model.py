"""Tests for threat model generator."""
import textwrap
import threat_model


def test_entry_point_detection():
    code = textwrap.dedent("""\
        from flask import Flask
        app = Flask(__name__)

        @app.route('/api/users')
        def get_users():
            return users
    """)
    comps, bounds, threats = threat_model.analyze_source(code)
    entries = [c for c in comps if c.type == "entry_point"]
    assert len(entries) >= 1
    assert "ROUTE" in entries[0].name or "/api/users" in entries[0].name


def test_data_store_detection():
    code = textwrap.dedent("""\
        def save_user(user):
            cursor.execute("INSERT INTO users VALUES (?)", (user,))
            db.commit()
    """)
    comps, bounds, threats = threat_model.analyze_source(code)
    stores = [c for c in comps if c.type == "data_store"]
    assert len(stores) >= 1


def test_external_service_detection():
    code = textwrap.dedent("""\
        def notify(url, data):
            response = requests.post(url, json=data)
            return response.json()
    """)
    comps, bounds, threats = threat_model.analyze_source(code)
    externals = [c for c in comps if c.type == "external_service"]
    assert len(externals) >= 1


def test_auth_boundary_detection():
    code = textwrap.dedent("""\
        from flask_login import login_required

        @login_required
        @app.route('/admin')
        def admin():
            return "admin"
    """)
    comps, bounds, threats = threat_model.analyze_source(code)
    auth = [b for b in bounds if b.kind == "auth_decorator"]
    assert len(auth) >= 1


def test_spoofing_threat_no_auth():
    code = textwrap.dedent("""\
        @app.get('/api/data')
        def get_data():
            return data
    """)
    comps, bounds, threats = threat_model.analyze_source(code)
    spoofing = [t for t in threats if t.stride_category == "Spoofing"]
    assert len(spoofing) >= 1


def test_no_spoofing_with_auth():
    code = textwrap.dedent("""\
        @login_required
        @app.get('/api/data')
        def get_data():
            return data
    """)
    comps, bounds, threats = threat_model.analyze_source(code)
    spoofing = [t for t in threats if t.stride_category == "Spoofing"
                and "entry_point" in t.component.type]
    assert len(spoofing) == 0


def test_stride_categories():
    code = textwrap.dedent("""\
        @app.post('/api/items')
        def create_item():
            cursor.execute("INSERT INTO items VALUES (?)", (data,))
            response = requests.post("https://webhook.example.com", json=data)
            return "ok"
    """)
    comps, bounds, threats = threat_model.analyze_source(code)
    categories = {t.stride_category for t in threats}
    assert "Spoofing" in categories
    assert "Tampering" in categories
    assert "Denial of Service" in categories


def test_ssrf_threat():
    code = textwrap.dedent("""\
        def proxy(url):
            return requests.get(url).text
    """)
    comps, bounds, threats = threat_model.analyze_source(code)
    eop = [t for t in threats if t.stride_category == "Elevation of Privilege"]
    assert any("SSRF" in t.description for t in eop)


def test_scan_paths(tmp_path):
    f = tmp_path / "app.py"
    f.write_text(textwrap.dedent("""\
        @app.route('/search')
        def search():
            cursor.execute("SELECT * FROM items WHERE q = ?", (q,))
    """), encoding="utf-8")
    comps, bounds, threats = threat_model.scan_paths([str(tmp_path)])
    assert len(comps) >= 2
    assert len(threats) >= 1


def test_to_dict():
    code = textwrap.dedent("""\
        @app.get('/api')
        def handler():
            pass
    """)
    _, _, threats = threat_model.analyze_source(code, "app.py")
    dicts = threat_model.to_dict(threats)
    assert len(dicts) >= 1
    assert "stride" in dicts[0]
    assert "mitigation" in dicts[0]
    assert "sink_file" in dicts[0]


def test_render():
    code = textwrap.dedent("""\
        @app.post('/api/items')
        def create():
            cursor.execute("INSERT ...")
    """)
    comps, bounds, threats = threat_model.analyze_source(code)
    output = threat_model.render(comps, bounds, threats)
    assert "STRIDE" in output
    assert "component" in output.lower()
    assert "threat" in output.lower()


def test_repudiation_for_data_store():
    code = textwrap.dedent("""\
        def delete_user(uid):
            cursor.execute("DELETE FROM users WHERE id = ?", (uid,))
    """)
    _, _, threats = threat_model.analyze_source(code)
    repudiation = [t for t in threats if t.stride_category == "Repudiation"]
    assert len(repudiation) >= 1
