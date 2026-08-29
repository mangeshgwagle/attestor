from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXTENSION = ROOT / "integrations" / "vscode"
DETECTOR = ROOT / "detector"
SERVER = EXTENSION / "server"
SUPPORTED_LANGUAGES = {
    "python", "javascript", "javascriptreact", "typescript", "typescriptreact",
    "c", "cpp", "haskell", "rust", "go", "java", "csharp", "php", "ruby",
    "shellscript",
}
SERVER_FILES = {
    "advanced_rules.py", "deepscan.py", "detect.py", "multilang.py", "nativepool.py",
    "nativescan.py", "attestor_lsp.py", "attestor_lsp41.py", "patchguard.py", "polyglot.py",
    "precision_catalog.py", "rarebugs.py", "runtime_lab.py", "scanengine.py",
    "verified_remediation.py",
}
PYTHON_BOOTSTRAP = (
    "import runpy,sys;d,p,*a=sys.argv[1:];sys.path.insert(0,d);"
    "sys.argv=[p,*a];runpy.run_path(p,run_name='__main__')"
)


class VSCodeIntegrationTests(unittest.TestCase):
    def test_manifest_exposes_live_analysis_and_preview(self):
        manifest = json.loads((EXTENSION / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["version"], "4.1.3")
        self.assertIn("Attestor 4.1.3", manifest["displayName"])
        commands = {item["command"] for item in manifest["contributes"]["commands"]}
        self.assertIn("attestor.start", commands)
        self.assertIn("attestor.previewImprovement", commands)
        self.assertIn("attestor.scanWorkspace", commands)
        self.assertEqual(
            {event.removeprefix("onCommand:") for event in manifest["activationEvents"]
             if event.startswith("onCommand:")},
            commands,
        )
        self.assertEqual(
            {event.removeprefix("onLanguage:") for event in manifest["activationEvents"]
             if event.startswith("onLanguage:")},
            SUPPORTED_LANGUAGES,
        )
        self.assertEqual(manifest["license"], "UNLICENSED")
        self.assertIs(manifest["private"], True)
        self.assertIn("server", manifest["files"])
        self.assertEqual(manifest["scripts"]["vscode:prepublish"], "npm run stage-server")

    def test_bridge_is_no_shell_preview_only_and_workspace_trusted(self):
        source = (EXTENSION / "extension.js").read_text(encoding="utf-8")
        self.assertIn("shell: false", source)
        self.assertIn("workspace.isTrusted", source)
        self.assertIn("It will not apply or write it", source)
        self.assertNotIn("cp.exec", source)
        self.assertNotIn("eval(", source)
        self.assertNotIn("writeFile", source)
        self.assertIn("const CLIENT_VERSION = '4.1.3'", source)
        self.assertIn("compatibilityServer", source)
        self.assertNotIn("'..', '..', 'detector'", source)
        self.assertIn("verifiedBundledServer(contextRef.extensionPath)", source)
        self.assertIn("'-I', '-B', '-X', 'utf8', '-c', PYTHON_BOOTSTRAP", source)
        self.assertIn("workspaceFolders: workspaceFolders()", source)
        self.assertIn("'$/cancelRequest'", source)
        self.assertIn("'$/progress'", source)
        self.assertIn("'attestor/previewWorkspaceEdit'", source)
        self.assertNotIn("workspace.applyEdit", source)
        match = re.search(r"const SUPPORTED = new Set\(\[(.*?)\]\);", source, re.DOTALL)
        self.assertIsNotNone(match)
        self.assertEqual(set(re.findall(r"'([a-z]+)'", match.group(1))), SUPPORTED_LANGUAGES)

    def test_readme_explains_live_core_and_fabric_boundary(self):
        readme = (EXTENSION / "README.md").read_text(encoding="utf-8")
        self.assertIn("Attestor 4.1.3", readme)
        self.assertIn("UTF-16-correct incremental", readme)
        self.assertIn("cancellable", readme)
        self.assertIn("every declared workspace root", readme)
        self.assertIn("never calls `workspace.applyEdit`", readme)
        self.assertIn("self-contained", readme)
        self.assertIn("integrity", readme)
        self.assertNotIn("../../detector", readme)

    def test_staged_server_is_complete_current_and_digest_verified(self):
        manifest = json.loads((SERVER / "server-manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["schema"], "attestor-vscode-server-bundle/1.0")
        self.assertEqual(manifest["version"], "4.1.3")
        self.assertEqual(manifest["entrypoint"], "attestor_lsp41.py")
        rows = {item["path"]: item for item in manifest["files"]}
        self.assertEqual(set(rows), SERVER_FILES)
        self.assertEqual({path.name for path in SERVER.iterdir()},
                         SERVER_FILES | {"server-manifest.json"})
        for name, item in rows.items():
            bundled = (SERVER / name).read_bytes()
            self.assertEqual(bundled, (DETECTOR / name).read_bytes(), name)
            self.assertEqual(item["size"], len(bundled), name)
            self.assertEqual(item["sha256"], hashlib.sha256(bundled).hexdigest(), name)

    def test_server_imports_from_an_isolated_installed_layout(self):
        with tempfile.TemporaryDirectory() as raw:
            temporary = Path(raw)
            installed_server = temporary / "installed-extension" / "server"
            shutil.copytree(SERVER, installed_server)
            env = {key: value for key, value in os.environ.items()
                   if key.upper() not in {"PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP",
                                          "PYTHONINSPECT"}}
            imported = subprocess.run(
                [sys.executable, "-I", "-B", "-X", "utf8", "-c",
                 "import sys;sys.path.insert(0,sys.argv[1]);"
                 "import attestor_lsp41,verified_remediation;print(attestor_lsp41.SERVER_VERSION)",
                 str(installed_server)],
                cwd=temporary, env=env, capture_output=True, text=True,
                timeout=30, check=False,
            )
            self.assertEqual(imported.returncode, 0, imported.stderr)
            self.assertEqual(imported.stdout.strip(), "4.1.3")
            launched = subprocess.run(
                [sys.executable, "-I", "-B", "-X", "utf8", "-c", PYTHON_BOOTSTRAP,
                 str(installed_server), str(installed_server / "attestor_lsp41.py"), "--help"],
                cwd=temporary, env=env, capture_output=True, text=True,
                timeout=30, check=False,
            )
            self.assertEqual(launched.returncode, 0, launched.stderr)
            self.assertIn("Attestor 4.1.3 bounded Language Server", launched.stdout)

    def test_staging_script_reproduces_the_bundle_when_node_is_available(self):
        node = os.environ.get("ATTESTOR_NODE") or shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable")
        with tempfile.TemporaryDirectory() as raw:
            destination = Path(raw) / "server"
            completed = subprocess.run(
                [node, str(EXTENSION / "scripts" / "stage-server.js"),
                 "--source", str(DETECTOR), "--destination", str(destination)],
                capture_output=True, text=True, timeout=30, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                json.loads((destination / "server-manifest.json").read_text(encoding="utf-8")),
                json.loads((SERVER / "server-manifest.json").read_text(encoding="utf-8")),
            )

    def test_javascript_bundle_verifier_accepts_install_and_rejects_tampering(self):
        node = os.environ.get("ATTESTOR_NODE") or shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable")
        verifier = (
            "const Module=require('module');const original=Module._load;"
            "Module._load=(request,parent,isMain)=>request==='vscode'?{}:"
            "original(request,parent,isMain);"
            "const extension=require(process.argv[1]);"
            "try{console.log(extension.__test.verifiedBundledServer(process.argv[2]));}"
            "catch(error){console.error(error.message);process.exit(7);}"
        )
        with tempfile.TemporaryDirectory() as raw:
            installed = Path(raw) / "installed-extension"
            installed.mkdir()
            shutil.copy2(EXTENSION / "extension.js", installed / "extension.js")
            shutil.copytree(SERVER, installed / "server")
            command = [node, "-e", verifier, str(installed / "extension.js"), str(installed)]
            accepted = subprocess.run(
                command, cwd=raw, capture_output=True, text=True,
                timeout=30, check=False,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(Path(accepted.stdout.strip()).resolve(),
                             (installed / "server" / "attestor_lsp41.py").resolve())
            with (installed / "server" / "detect.py").open("ab") as stream:
                stream.write(b"\n# tampered\n")
            rejected = subprocess.run(
                command, cwd=raw, capture_output=True, text=True,
                timeout=30, check=False,
            )
            self.assertEqual(rejected.returncode, 7)
            self.assertIn("failed integrity verification", rejected.stderr)
            self.assertNotIn("detect.py", rejected.stderr)

    def test_javascript_parses_when_node_is_available(self):
        node = os.environ.get("ATTESTOR_NODE") or shutil.which("node")
        if not node:
            self.skipTest("Node.js is unavailable")
        completed = subprocess.run(
            [node, "--check", str(EXTENSION / "extension.js")],
            capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)
        completed = subprocess.run(
            [node, "--check", str(EXTENSION / "scripts" / "stage-server.js")],
            capture_output=True, text=True, timeout=15, check=False)
        self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
