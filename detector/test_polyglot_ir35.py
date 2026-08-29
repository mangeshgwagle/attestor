from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path

import polyglot_ir35


class PolyglotIR35Tests(unittest.TestCase):
    def test_extracts_common_ir_across_all_supported_language_families(self):
        sources = {
            "web/app.js": (
                "import api from './api.js';\n"
                "class WebApp {}\n"
                "export function boot(value) { helper(value); }\n"
                "app.get('/health', boot);\n"
            ),
            "web/view.ts": (
                "import { boot } from './app.js';\n"
                "interface View { render(): void }\n"
                "const render = (value: string) => boot(value);\n"
                "@Get('/view')\nfunction endpoint() { render('x'); }\n"
            ),
            "java/App.java": (
                "package demo.api;\nimport java.util.List;\n"
                "record User(String name) {}\n"
                "@GetMapping(\"/java\") public void serve() { helper(); }\n"
            ),
            "dotnet/App.cs": (
                "namespace Demo.Api;\nusing System.Text;\n"
                "public record User(string Name);\n"
                "[HttpGet(\"/dotnet\")] public void Serve() { Helper(); }\n"
            ),
            "go/app.go": (
                "package api\nimport \"net/http\"\ntype Server struct {}\n"
                "func serve(w http.ResponseWriter) { helper() }\n"
                "func routes() { HandleFunc(\"/go\", serve) }\n"
            ),
            "rust/app.rs": (
                "use crate::db;\nstruct User { id: u64 }\n"
                "#[get(\"/rust\")]\nfn serve() { helper(); }\n"
            ),
            "native/app.c": (
                "#include \"app.h\"\nstruct user { int id; };\n"
                "int run(int value) { return helper(value); }\n"
            ),
            "native/app.cpp": (
                "#include <vector>\nclass App {};\n"
                "int main() { launch(); return 0; }\n"
            ),
            "php/app.php": (
                "<?php\nnamespace Demo\\Api;\nuse Demo\\Db;\nclass App {}\n"
                "function serve($x) { helper($x); }\n"
                "Route::post('/php', 'serve');\n"
            ),
        }
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            for relative, source in sources.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(source, encoding="utf-8")
            report = polyglot_ir35.analyze(root)

        self.assertEqual(set(report["coverage"]["languages"]), {
            "javascript", "typescript", "java", "csharp", "go", "rust",
            "c", "cpp", "php",
        })
        self.assertEqual(report["coverage"]["source_files_parsed"], len(sources))
        self.assertTrue(report["coverage"]["complete"], report["parse_gaps"])
        self.assertEqual({item["name"] for item in report["types"]},
                         {"WebApp", "View", "User", "Server", "user", "App"})
        function_names = {item["name"] for item in report["functions"]}
        self.assertTrue({"boot", "render", "endpoint", "serve", "Serve", "run", "main"}
                        <= function_names, function_names)
        self.assertIn("helper", {item["target"] for item in report["calls"]})
        self.assertEqual({item["route"] for item in report["routes"]},
                         {"/health", "/view", "/java", "/dotnet", "/go", "/rust", "/php"})
        self.assertIn("demo.api", {item["name"] for item in report["modules"]})

    def test_manifests_store_names_and_hashes_but_not_values_or_scripts(self):
        secret = "DO-NOT-STORE-secret-value"
        package = {
            "name": "sample", "scripts": {"postinstall": "touch " + secret},
            "dependencies": {"express": "1.2.3"},
            "config": {"token": secret},
        }
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "package.json").write_text(json.dumps(package), encoding="utf-8")
            (root / "Cargo.toml").write_text(
                "[package]\nname='x'\n[dependencies]\nserde='1'\n", encoding="utf-8")
            (root / "go.mod").write_text(
                "module example.test/app\ngo 1.22\nrequire example.test/lib v1.2.3\n",
                encoding="utf-8")
            report = polyglot_ir35.analyze(root)
        encoded = json.dumps(report)
        self.assertNotIn(secret, encoded)
        manifests = {item["kind"]: item for item in report["manifests"]}
        self.assertIn("express", manifests["npm"]["dependencies"])
        self.assertIn("serde", manifests["cargo"]["dependencies"])
        self.assertIn("example.test/lib", manifests["go-mod"]["dependencies"])
        self.assertRegex(manifests["npm"]["sha256"], r"^[0-9a-f]{64}$")

    def test_comments_and_literals_do_not_create_fake_calls(self):
        source = (
            "// commented_out()\n"
            "const one = 'string_call()';\n"
            "const two = `template_call()`;\n"
            "/* block_call() */\n"
            "real_call();\n"
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "app.js"
            path.write_text(source, encoding="utf-8")
            report = polyglot_ir35.analyze(path)
        self.assertEqual([item["target"] for item in report["calls"]], ["real_call"])

    def test_reports_malformed_decode_binary_and_size_gaps_without_claiming_complete(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "broken.ts").write_text("function broken( {\n", encoding="utf-8")
            (root / "invalid.php").write_bytes(b"<?php\nfunction x() {\n\xff\n}\n")
            (root / "binary.go").write_bytes(b"package x\x00ignored")
            (root / "large.java").write_text("x" * 200, encoding="utf-8")
            report = polyglot_ir35.analyze(root, max_file_bytes=100)
        kinds = {item["kind"] for item in report["parse_gaps"]}
        self.assertTrue({"parse-shape", "decode-replacement", "binary-skipped",
                         "file-too-large"} <= kinds)
        self.assertFalse(report["coverage"]["complete"])

    def test_symlink_escape_is_not_followed(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as outside:
            root = Path(folder)
            target = Path(outside) / "outside.js"
            target.write_text("escaped_call();\n", encoding="utf-8")
            link = root / "linked.js"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("file symlinks are unavailable")
            report = polyglot_ir35.analyze(root)
        self.assertEqual(report["files"], [])
        self.assertIn("path-escape", {item["kind"] for item in report["parse_gaps"]})

    def test_hostile_and_missing_roots_become_explicit_gaps(self):
        invalid = polyglot_ir35.analyze("bad\0root")
        self.assertEqual(invalid["parse_gaps"][0]["kind"], "invalid-root")
        with tempfile.TemporaryDirectory() as folder:
            missing = polyglot_ir35.analyze(Path(folder) / "missing")
        self.assertEqual(missing["parse_gaps"][0]["kind"], "invalid-root")
        self.assertFalse(missing["coverage"]["complete"])

    def test_target_code_and_package_scripts_are_never_executed(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            marker = root / "EXECUTED"
            (root / "app.php").write_text(
                "<?php file_put_contents('EXECUTED', 'bad'); ?>\n", encoding="utf-8")
            (root / "package.json").write_text(json.dumps({
                "scripts": {"postinstall": "python -c open('EXECUTED','w').write('bad')"}
            }), encoding="utf-8")
            polyglot_ir35.analyze(root)
            self.assertFalse(marker.exists())

    def test_output_and_portable_fingerprint_are_deterministic(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "b.go").write_text("package b\nfunc B(){ A() }\n", encoding="utf-8")
            (root / "a.js").write_text("export function A() {}\n", encoding="utf-8")
            first = polyglot_ir35.analyze(root)
            second = polyglot_ir35.analyze(root)
        self.assertEqual(first, second)
        self.assertEqual(polyglot_ir35.deterministic_json(first),
                         polyglot_ir35.deterministic_json(second))
        self.assertEqual(polyglot_ir35.content_fingerprint(first),
                         polyglot_ir35.content_fingerprint(second))
        self.assertEqual([item["path"] for item in first["files"]], ["a.js", "b.go"])


if __name__ == "__main__":
    unittest.main()
