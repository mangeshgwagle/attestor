"""Tests for SBOM generator."""
import json
import sbom_gen


def test_parse_requirements_txt():
    text = "flask==2.3.0\nrequests>=2.28.0\nnumpy\n# comment\n"
    deps = sbom_gen.parse_requirements_txt(text, "requirements.txt")
    assert len(deps) == 3
    assert deps[0].name == "flask"
    assert deps[0].version == "2.3.0"
    assert deps[2].version == "*"


def test_parse_pipfile_lock():
    data = {
        "default": {
            "flask": {"version": "==2.3.0"},
            "requests": {"version": "==2.28.0"},
        },
        "develop": {
            "pytest": {"version": "==7.4.0"},
        }
    }
    deps = sbom_gen.parse_pipfile_lock(json.dumps(data), "Pipfile.lock")
    assert len(deps) == 3
    names = {d.name for d in deps}
    assert "flask" in names
    assert "pytest" in names


def test_parse_package_json():
    data = {
        "dependencies": {"express": "^4.18.0", "axios": "~1.4.0"},
        "devDependencies": {"jest": "^29.0.0"},
    }
    deps = sbom_gen.parse_package_json(json.dumps(data), "package.json")
    assert len(deps) == 3
    express = next(d for d in deps if d.name == "express")
    assert express.version == "4.18.0"


def test_parse_package_lock():
    data = {
        "packages": {
            "": {"name": "myapp"},
            "node_modules/express": {"version": "4.18.2"},
            "node_modules/debug": {"version": "4.3.4"},
        }
    }
    deps = sbom_gen.parse_package_lock(json.dumps(data), "package-lock.json")
    assert len(deps) == 2
    names = {d.name for d in deps}
    assert "express" in names


def test_parse_go_sum():
    text = (
        "github.com/gin-gonic/gin v1.9.1 h1:abc=\n"
        "github.com/gin-gonic/gin v1.9.1/go.mod h1:def=\n"
        "golang.org/x/net v0.15.0 h1:ghi=\n"
    )
    deps = sbom_gen.parse_go_sum(text, "go.sum")
    assert len(deps) == 2
    names = {d.name for d in deps}
    assert "github.com/gin-gonic/gin" in names


def test_parse_cargo_toml():
    text = (
        "[dependencies]\n"
        'serde = "1.0"\n'
        'tokio = {version = "1.32", features = ["full"]}\n'
        "\n"
        "[dev-dependencies]\n"
        'assert_cmd = "2.0"\n'
    )
    deps = sbom_gen.parse_cargo_toml(text, "Cargo.toml")
    assert len(deps) == 3
    names = {d.name for d in deps}
    assert "serde" in names
    assert "tokio" in names


def test_purl_generation():
    d = sbom_gen.Dependency(name="flask", version="2.3.0",
                            ecosystem="pip", source_file="req.txt")
    assert d.purl == "pkg:pypi/flask@2.3.0"

    d2 = sbom_gen.Dependency(name="express", version="4.18.0",
                             ecosystem="npm", source_file="pkg.json")
    assert d2.purl == "pkg:npm/express@4.18.0"


def test_cyclonedx_output():
    deps = [
        sbom_gen.Dependency(name="flask", version="2.3.0",
                            ecosystem="pip", source_file="req.txt"),
        sbom_gen.Dependency(name="express", version="4.18.0",
                            ecosystem="npm", source_file="pkg.json"),
    ]
    cdx = sbom_gen.to_cyclonedx(deps, "test-project")
    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.5"
    assert len(cdx["components"]) == 2
    assert cdx["metadata"]["component"]["name"] == "test-project"
    assert "urn:uuid:" in cdx["serialNumber"]


def test_spdx_output():
    deps = [
        sbom_gen.Dependency(name="flask", version="2.3.0",
                            ecosystem="pip", source_file="req.txt"),
    ]
    spdx = sbom_gen.to_spdx(deps, "test-project")
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert len(spdx["packages"]) == 1
    assert spdx["packages"][0]["name"] == "flask"
    assert len(spdx["relationships"]) == 1


def test_collect_deps(tmp_path):
    (tmp_path / "requirements.txt").write_text(
        "flask==2.3.0\nrequests==2.28.0\n", encoding="utf-8")
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"express": "^4.18.0"}}), encoding="utf-8")
    deps = sbom_gen.collect_deps([str(tmp_path)])
    assert len(deps) == 3
    ecosystems = {d.ecosystem for d in deps}
    assert "pip" in ecosystems
    assert "npm" in ecosystems


def test_render():
    deps = [
        sbom_gen.Dependency(name="flask", version="2.3.0",
                            ecosystem="pip", source_file="req.txt"),
        sbom_gen.Dependency(name="express", version="4.18.0",
                            ecosystem="npm", source_file="pkg.json"),
    ]
    output = sbom_gen.render(deps)
    assert "SBOM Summary" in output
    assert "2 component" in output
    assert "PIP" in output
    assert "NPM" in output


def test_to_dict():
    deps = [
        sbom_gen.Dependency(name="flask", version="2.3.0",
                            ecosystem="pip", source_file="req.txt"),
    ]
    dicts = sbom_gen.to_dict(deps)
    assert len(dicts) == 1
    assert dicts[0]["purl"] == "pkg:pypi/flask@2.3.0"
    assert dicts[0]["category"] == "dependency"


def test_no_deps():
    assert "no dependencies found" in sbom_gen.render([])
    assert sbom_gen.to_dict([]) == []
