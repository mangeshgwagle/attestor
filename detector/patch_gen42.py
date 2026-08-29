#!/usr/bin/env python3
"""Patch generator: turns scanner findings into fix code.

Owen finds it, Owen proves it (PoC), Owen fixes it (patch). All deterministic,
all without an LLM.

Each CWE has known fix patterns per language. The patch generator selects the
right pattern, parameterizes it with the finding context, and produces
ready-to-apply code.

The output is real code — not advice, not "consider using X", not a link to
OWASP. Actual replacement code a developer pastes over the vulnerable line.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

try:
    from poc_gen42 import PocFinding, _refs
except ImportError:
    from detector.poc_gen42 import PocFinding, _refs  # type: ignore


VERSION = "4.2"


# --------------------------------------------------------------------------- #
# schema
# --------------------------------------------------------------------------- #

@dataclass
class Patch:
    """A concrete code fix for a specific CWE in a specific language."""
    cwe: int
    language: str
    title: str
    vulnerable: str
    fixed: str
    imports_required: tuple[str, ...] = ()
    explanation: str = ""
    confidence: str = "mechanical"
    diff_hint: str = ""
    references: tuple[str, ...] = ()


class PatchGenError(ValueError):
    pass


# --------------------------------------------------------------------------- #
# registry — keyed by CWE, generators handle language dispatch internally
# --------------------------------------------------------------------------- #

_REGISTRY: dict[int, Callable[[PocFinding], list[Patch]]] = {}


def patch(cwe: int):
    def decorator(fn: Callable[[PocFinding], list[Patch]]):
        _REGISTRY[cwe] = fn
        return fn
    return decorator


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #

def generate_patch(finding: PocFinding) -> list[Patch]:
    """Generate patches for a finding. Returns [] if CWE is unsupported."""
    gen = _REGISTRY.get(finding.cwe)
    if gen is None:
        return []
    result = gen(finding)
    return result if isinstance(result, list) else [result]


def supported_cwes() -> tuple[int, ...]:
    return tuple(sorted(_REGISTRY))


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _lang(f: PocFinding) -> str:
    return f.language.lower()


def _var(f: PocFinding) -> str:
    return f.source or "userInput"


def _sink(f: PocFinding) -> str:
    return f.sink or ""


# =========================================================================== #
# PATCH GENERATORS
# =========================================================================== #

# --------------------------------------------------------------------------- #
# CWE-89: SQL Injection
# --------------------------------------------------------------------------- #

@patch(89)
def _sqli(f: PocFinding) -> list[Patch]:
    var = _var(f)
    patches = []
    lang = _lang(f)

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=89, language="java",
            title="SQL Injection — use PreparedStatement",
            vulnerable=(
                '// VULNERABLE:\n'
                'Statement stmt = conn.createStatement();\n'
                'ResultSet rs = stmt.executeQuery(\n'
                '    "SELECT * FROM users WHERE id = " + %s);\n' % var
            ),
            fixed=(
                '// FIXED:\n'
                'PreparedStatement ps = conn.prepareStatement(\n'
                '    "SELECT * FROM users WHERE id = ?");\n'
                'ps.setString(1, %s);\n'
                'ResultSet rs = ps.executeQuery();\n' % var
            ),
            explanation=(
                "PreparedStatement separates SQL structure from data. "
                "The database parses the query template first, then binds "
                "the parameter — injection is structurally impossible."
            ),
            diff_hint=r'createStatement|executeQuery.*\+|executeUpdate.*\+',
            references=_refs(89, "A03:2021 Injection"),
        ))

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=89, language="python",
            title="SQL Injection — use parameterized query",
            vulnerable=(
                '# VULNERABLE:\n'
                'cursor.execute(f"SELECT * FROM users WHERE id = {%s}")\n'
                '# also vulnerable:\n'
                'cursor.execute("SELECT * FROM users WHERE id = " + %s)\n'
                'cursor.execute("SELECT * FROM users WHERE id = %%s" %% %s)\n'
                % (var, var, var)
            ),
            fixed=(
                '# FIXED:\n'
                'cursor.execute("SELECT * FROM users WHERE id = %%s", (%s,))\n'
                '# For SQLite:\n'
                'cursor.execute("SELECT * FROM users WHERE id = ?", (%s,))\n'
                % (var, var)
            ),
            explanation=(
                "Pass user data as a tuple in the second argument. "
                "The DB driver handles escaping — the value never touches "
                "the SQL string."
            ),
            diff_hint=r'execute.*f"|execute.*\+|execute.*%',
            references=_refs(89, "A03:2021 Injection"),
        ))

    if lang in ("csharp", "unknown"):
        patches.append(Patch(
            cwe=89, language="csharp",
            title="SQL Injection — use SqlParameter",
            vulnerable=(
                '// VULNERABLE:\n'
                'var cmd = new SqlCommand(\n'
                '    "SELECT * FROM users WHERE id = " + %s, conn);\n' % var
            ),
            fixed=(
                '// FIXED:\n'
                'var cmd = new SqlCommand(\n'
                '    "SELECT * FROM users WHERE id = @id", conn);\n'
                'cmd.Parameters.AddWithValue("@id", %s);\n' % var
            ),
            explanation="SqlParameter binds data separately from the query structure.",
            diff_hint=r'SqlCommand.*\+|"SELECT.*\+|"INSERT.*\+|"UPDATE.*\+|"DELETE.*\+',
            references=_refs(89, "A03:2021 Injection"),
        ))

    if lang in ("go", "unknown"):
        patches.append(Patch(
            cwe=89, language="go",
            title="SQL Injection — use query parameters",
            vulnerable=(
                '// VULNERABLE:\n'
                'rows, err := db.Query("SELECT * FROM users WHERE id = " + %s)\n' % var
            ),
            fixed=(
                '// FIXED:\n'
                'rows, err := db.Query("SELECT * FROM users WHERE id = $1", %s)\n' % var
            ),
            explanation="Positional parameters ($1, $2) are bound by the driver, not interpolated.",
            diff_hint=r'db\.Query.*\+|db\.Exec.*\+',
            references=_refs(89, "A03:2021 Injection"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-79: Cross-Site Scripting
# --------------------------------------------------------------------------- #

@patch(79)
def _xss(f: PocFinding) -> list[Patch]:
    var = _var(f)
    patches = []
    lang = _lang(f)

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=79, language="java",
            title="XSS — encode output with OWASP Encoder",
            vulnerable=(
                '// VULNERABLE:\n'
                'response.getWriter().print("<h1>" + %s + "</h1>");\n' % var
            ),
            fixed=(
                '// FIXED:\n'
                'import org.owasp.encoder.Encode;\n'
                'response.getWriter().print("<h1>" + Encode.forHtml(%s) + "</h1>");\n' % var
            ),
            imports_required=("org.owasp.encoder.Encode",),
            explanation="Encode.forHtml() escapes <, >, &, \", ' — injection is neutralized at output.",
            diff_hint=r'getWriter\(\)\.print.*\+|\.write.*\+',
            references=_refs(79, "A03:2021 Injection"),
        ))

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=79, language="python",
            title="XSS — escape output / enable autoescape",
            vulnerable=(
                '# VULNERABLE:\n'
                'return "<h1>" + %s + "</h1>"\n'
                '# also vulnerable (Jinja2):\n'
                '{{ %s | safe }}\n' % (var, var)
            ),
            fixed=(
                '# FIXED:\n'
                'import html\n'
                'return "<h1>" + html.escape(%s) + "</h1>"\n'
                '# Jinja2: remove |safe, ensure autoescape is on:\n'
                '{{ %s }}\n'
                '# In Flask:\n'
                'app.jinja_env.autoescape = True\n' % (var, var)
            ),
            imports_required=("html",),
            explanation="html.escape() encodes dangerous characters. Jinja2 autoescaping does it automatically.",
            diff_hint=r'\.safe|Markup\(|html.*\+',
            references=_refs(79, "A03:2021 Injection"),
        ))

    if lang in ("js", "unknown"):
        patches.append(Patch(
            cwe=79, language="javascript",
            title="XSS — use textContent instead of innerHTML",
            vulnerable=(
                '// VULNERABLE:\n'
                'element.innerHTML = %s;\n'
                '// also vulnerable:\n'
                'document.write(%s);\n' % (var, var)
            ),
            fixed=(
                '// FIXED:\n'
                'element.textContent = %s;\n'
                '// For HTML structure, use DOM APIs:\n'
                'const text = document.createTextNode(%s);\n'
                'element.appendChild(text);\n' % (var, var)
            ),
            explanation="textContent inserts as text, not HTML. The browser will never parse it as markup.",
            diff_hint=r'innerHTML|outerHTML|document\.write',
            references=_refs(79, "A03:2021 Injection"),
        ))

    return patches

@patch(80)
def _xss_basic(f: PocFinding) -> list[Patch]:
    return _xss(f)


# --------------------------------------------------------------------------- #
# CWE-78: OS Command Injection
# --------------------------------------------------------------------------- #

@patch(78)
def _cmdi(f: PocFinding) -> list[Patch]:
    var = _var(f)
    patches = []
    lang = _lang(f)

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=78, language="java",
            title="Command Injection — use ProcessBuilder with argument list",
            vulnerable=(
                '// VULNERABLE:\n'
                'Runtime.getRuntime().exec("cmd /c " + %s);\n'
                '// also vulnerable:\n'
                'Runtime.getRuntime().exec(new String[]{"sh", "-c", %s});\n' % (var, var)
            ),
            fixed=(
                '// FIXED — pass arguments as a list, never through a shell:\n'
                'ProcessBuilder pb = new ProcessBuilder("command", %s);\n'
                'pb.redirectErrorStream(true);\n'
                'Process p = pb.start();\n' % var
            ),
            explanation=(
                "ProcessBuilder with separate arguments never invokes a shell. "
                "The OS executes the binary directly — shell metacharacters "
                "are treated as literal data."
            ),
            diff_hint=r'Runtime\.getRuntime\(\)\.exec|"sh".*"-c"',
            references=_refs(78, "A03:2021 Injection"),
        ))

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=78, language="python",
            title="Command Injection — use subprocess with shell=False",
            vulnerable=(
                '# VULNERABLE:\n'
                'os.system("grep " + %s)\n'
                'subprocess.call("grep " + %s, shell=True)\n'
                'subprocess.run(f"grep {%s}", shell=True)\n' % (var, var, var)
            ),
            fixed=(
                '# FIXED:\n'
                'subprocess.run(["grep", %s], check=True)\n'
                '# shell=False is the default — just pass a list.\n'
                '# For complex commands, use shlex:\n'
                'import shlex\n'
                'subprocess.run(["grep"] + shlex.split(%s), check=True)\n' % (var, var)
            ),
            imports_required=("subprocess",),
            explanation=(
                "A list argument with shell=False (the default) passes each "
                "element as a separate argv entry. No shell is invoked, so "
                "shell metacharacters (;, |, &&, $()) have no special meaning."
            ),
            diff_hint=r'os\.system|shell=True|os\.popen',
            references=_refs(78, "A03:2021 Injection"),
        ))

    if lang in ("go", "unknown"):
        patches.append(Patch(
            cwe=78, language="go",
            title="Command Injection — use exec.Command with separate args",
            vulnerable=(
                '// VULNERABLE:\n'
                'exec.Command("sh", "-c", "grep " + %s)\n' % var
            ),
            fixed=(
                '// FIXED:\n'
                'exec.Command("grep", %s)\n' % var
            ),
            explanation="exec.Command with separate arguments bypasses the shell entirely.",
            diff_hint=r'exec\.Command.*"sh".*"-c"',
            references=_refs(78, "A03:2021 Injection"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-22/23/36: Path Traversal
# --------------------------------------------------------------------------- #

@patch(22)
def _path_traversal(f: PocFinding) -> list[Patch]:
    var = _var(f)
    patches = []
    lang = _lang(f)

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=22, language="java",
            title="Path Traversal — canonicalize and check prefix",
            vulnerable=(
                '// VULNERABLE:\n'
                'File f = new File(baseDir + "/" + %s);\n'
                'FileInputStream fis = new FileInputStream(f);\n' % var
            ),
            fixed=(
                '// FIXED:\n'
                'Path base = Paths.get(baseDir).toAbsolutePath().normalize();\n'
                'Path resolved = base.resolve(%s).normalize();\n'
                'if (!resolved.startsWith(base)) {\n'
                '    throw new SecurityException("path traversal blocked");\n'
                '}\n'
                'FileInputStream fis = new FileInputStream(resolved.toFile());\n' % var
            ),
            imports_required=("java.nio.file.Path", "java.nio.file.Paths"),
            explanation=(
                "normalize() collapses ../ sequences. startsWith() then "
                "verifies the result is still under the base directory. "
                "This is a canonicalize-then-check pattern."
            ),
            diff_hint=r'new File\(.*\+|Paths\.get\(.*\+',
            references=_refs(22, "A01:2021 Broken Access Control"),
        ))

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=22, language="python",
            title="Path Traversal — realpath + startswith check",
            vulnerable=(
                '# VULNERABLE:\n'
                'path = os.path.join(base_dir, %s)\n'
                'with open(path) as f:\n'
                '    data = f.read()\n' % var
            ),
            fixed=(
                '# FIXED:\n'
                'path = os.path.realpath(os.path.join(base_dir, %s))\n'
                'if not path.startswith(os.path.realpath(base_dir) + os.sep):\n'
                '    raise ValueError("path traversal blocked")\n'
                'with open(path) as f:\n'
                '    data = f.read()\n' % var
            ),
            explanation=(
                "os.path.realpath resolves symlinks and ../ sequences to "
                "an absolute path. The startswith check ensures the result "
                "is still under base_dir."
            ),
            diff_hint=r'os\.path\.join\(.*,.*\)|open\(.*\+',
            references=_refs(22, "A01:2021 Broken Access Control"),
        ))

    return patches

@patch(23)
def _path_traversal_23(f: PocFinding) -> list[Patch]:
    return _path_traversal(f)

@patch(36)
def _path_traversal_36(f: PocFinding) -> list[Patch]:
    return _path_traversal(f)


# --------------------------------------------------------------------------- #
# CWE-611: XML External Entity (XXE)
# --------------------------------------------------------------------------- #

@patch(611)
def _xxe(f: PocFinding) -> list[Patch]:
    patches = []
    lang = _lang(f)

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=611, language="java",
            title="XXE — disable external entities in DocumentBuilderFactory",
            vulnerable=(
                '// VULNERABLE:\n'
                'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n'
                'DocumentBuilder db = dbf.newDocumentBuilder();\n'
                'Document doc = db.parse(input);\n'
            ),
            fixed=(
                '// FIXED:\n'
                'DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n'
                'dbf.setFeature(\n'
                '    "http://apache.org/xml/features/disallow-doctype-decl", true);\n'
                'dbf.setFeature(\n'
                '    "http://xml.org/sax/features/external-general-entities", false);\n'
                'dbf.setFeature(\n'
                '    "http://xml.org/sax/features/external-parameter-entities", false);\n'
                'dbf.setXIncludeAware(false);\n'
                'dbf.setExpandEntityReferences(false);\n'
                'DocumentBuilder db = dbf.newDocumentBuilder();\n'
                'Document doc = db.parse(input);\n'
            ),
            explanation=(
                "Disabling doctype declarations blocks all entity processing. "
                "The additional feature flags are defense-in-depth for parsers "
                "that ignore disallow-doctype-decl."
            ),
            diff_hint=r'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory',
            references=_refs(611, "A05:2021 Security Misconfiguration"),
        ))

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=611, language="python",
            title="XXE — use defusedxml or disable entity resolution",
            vulnerable=(
                '# VULNERABLE (lxml):\n'
                'from lxml import etree\n'
                'doc = etree.parse(input_file)\n'
                '# VULNERABLE (xml.sax):\n'
                'parser = xml.sax.make_parser()\n'
                'parser.parse(input_file)\n'
            ),
            fixed=(
                '# FIXED — option 1: defusedxml (drop-in replacement):\n'
                'import defusedxml.ElementTree as ET\n'
                'doc = ET.parse(input_file)\n'
                '\n'
                '# FIXED — option 2: lxml with entities disabled:\n'
                'from lxml import etree\n'
                'parser = etree.XMLParser(resolve_entities=False, no_network=True)\n'
                'doc = etree.parse(input_file, parser)\n'
            ),
            imports_required=("defusedxml",),
            explanation=(
                "defusedxml patches all stdlib XML parsers to refuse entities. "
                "For lxml, resolve_entities=False and no_network=True block "
                "the two XXE vectors."
            ),
            diff_hint=r'etree\.parse|xml\.sax|minidom\.parse|pulldom\.parse',
            references=_refs(611, "A05:2021 Security Misconfiguration"),
        ))

    if lang in ("csharp", "unknown"):
        patches.append(Patch(
            cwe=611, language="csharp",
            title="XXE — set XmlResolver to null",
            vulnerable=(
                '// VULNERABLE:\n'
                'XmlDocument doc = new XmlDocument();\n'
                'doc.LoadXml(input);\n'
            ),
            fixed=(
                '// FIXED:\n'
                'XmlDocument doc = new XmlDocument();\n'
                'doc.XmlResolver = null;\n'
                'doc.LoadXml(input);\n'
            ),
            explanation="Setting XmlResolver to null prevents the parser from resolving any external reference.",
            diff_hint=r'XmlDocument|XmlReader|XmlTextReader',
            references=_refs(611, "A05:2021 Security Misconfiguration"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-502: Unsafe Deserialization
# --------------------------------------------------------------------------- #

@patch(502)
def _deser(f: PocFinding) -> list[Patch]:
    patches = []
    lang = _lang(f)

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=502, language="java",
            title="Deserialization — use ValidatingObjectInputStream with allowlist",
            vulnerable=(
                '// VULNERABLE:\n'
                'ObjectInputStream ois = new ObjectInputStream(inputStream);\n'
                'Object obj = ois.readObject();\n'
            ),
            fixed=(
                '// FIXED — option 1: Apache Commons IO ValidatingObjectInputStream:\n'
                'ValidatingObjectInputStream vois =\n'
                '    new ValidatingObjectInputStream(inputStream);\n'
                'vois.accept(AllowedClass1.class, AllowedClass2.class);\n'
                'Object obj = vois.readObject();\n'
                '\n'
                '// FIXED — option 2: don\'t deserialize at all — use JSON:\n'
                'ObjectMapper mapper = new ObjectMapper();\n'
                'AllowedClass obj = mapper.readValue(inputStream, AllowedClass.class);\n'
            ),
            imports_required=(
                "org.apache.commons.io.serialization.ValidatingObjectInputStream",
            ),
            explanation=(
                "ValidatingObjectInputStream only deserializes classes you "
                "explicitly allow. Better yet, switch to JSON — Jackson binds "
                "to a declared type, so arbitrary class instantiation is impossible."
            ),
            diff_hint=r'ObjectInputStream|readObject\(\)|\.readUnshared\(\)',
            references=_refs(502, "A08:2021 Software and Data Integrity"),
        ))

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=502, language="python",
            title="Deserialization — replace pickle with json or restrict unpickler",
            vulnerable=(
                '# VULNERABLE:\n'
                'import pickle\n'
                'data = pickle.loads(user_data)\n'
                '# also:\n'
                'data = pickle.load(open(path, "rb"))\n'
            ),
            fixed=(
                '# FIXED — option 1: use JSON (preferred):\n'
                'import json\n'
                'data = json.loads(user_data)\n'
                '\n'
                '# FIXED — option 2: restricted unpickler (when pickle is required):\n'
                'import io\n'
                'import pickle\n'
                '\n'
                'class RestrictedUnpickler(pickle.Unpickler):\n'
                '    ALLOWED = frozenset({\n'
                '        ("builtins", "set"),\n'
                '        ("builtins", "frozenset"),\n'
                '    })\n'
                '    def find_class(self, module, name):\n'
                '        if (module, name) not in self.ALLOWED:\n'
                '            raise pickle.UnpicklingError(\n'
                '                "forbidden: %s.%s" % (module, name))\n'
                '        return super().find_class(module, name)\n'
                '\n'
                'data = RestrictedUnpickler(io.BytesIO(user_data)).load()\n'
            ),
            explanation=(
                "pickle.loads executes arbitrary Python during deserialization. "
                "JSON has no code execution capability. If pickle is required, "
                "a restricted unpickler allowlists specific classes."
            ),
            diff_hint=r'pickle\.loads|pickle\.load|yaml\.load\(',
            references=_refs(502, "A08:2021 Software and Data Integrity"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-94: Code Injection (eval/exec)
# --------------------------------------------------------------------------- #

@patch(94)
def _code_inj(f: PocFinding) -> list[Patch]:
    var = _var(f)
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=94, language="python",
            title="Code Injection — replace eval with ast.literal_eval or remove",
            vulnerable=(
                '# VULNERABLE:\n'
                'result = eval(%s)\n'
                '# also:\n'
                'exec(%s)\n' % (var, var)
            ),
            fixed=(
                '# FIXED — for data parsing (JSON-like literals):\n'
                'import ast\n'
                'result = ast.literal_eval(%s)\n'
                '\n'
                '# FIXED — for JSON:\n'
                'import json\n'
                'result = json.loads(%s)\n'
                '\n'
                '# FIXED — for math expressions:\n'
                '# Use a safe expression evaluator, never eval().\n'
                '# Example: simpleeval library\n'
                'from simpleeval import simple_eval\n'
                'result = simple_eval(%s)\n' % (var, var, var)
            ),
            imports_required=("ast", "json"),
            explanation=(
                "eval() executes arbitrary Python code. ast.literal_eval() "
                "only parses Python literals (strings, numbers, lists, dicts) "
                "— it cannot call functions or import modules."
            ),
            diff_hint=r'\beval\(|\bexec\(',
            references=_refs(94, "A03:2021 Injection"),
        ))

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=94, language="java",
            title="Code Injection — remove ScriptEngine.eval or sandbox",
            vulnerable=(
                '// VULNERABLE:\n'
                'ScriptEngine engine = new ScriptEngineManager()\n'
                '    .getEngineByName("js");\n'
                'engine.eval(%s);\n' % var
            ),
            fixed=(
                '// FIXED — parse data, don\'t evaluate code:\n'
                '// For JSON data:\n'
                'ObjectMapper mapper = new ObjectMapper();\n'
                'JsonNode node = mapper.readTree(%s);\n'
                '\n'
                '// If scripting is truly needed, use a sandboxed engine:\n'
                '// GraalJS with restricted permissions, no host access\n' % var
            ),
            explanation=(
                "ScriptEngine.eval() executes arbitrary code. Parse data "
                "with a JSON/XML parser instead. If scripting is required, "
                "use GraalJS with host access disabled."
            ),
            diff_hint=r'\.eval\(|ScriptEngine|getEngineByName',
            references=_refs(94, "A03:2021 Injection"),
        ))

    if lang in ("js", "unknown"):
        patches.append(Patch(
            cwe=94, language="javascript",
            title="Code Injection — replace eval with JSON.parse or remove",
            vulnerable=(
                '// VULNERABLE:\n'
                'var result = eval(%s);\n'
                '// also:\n'
                'setTimeout(%s, 1000);\n'
                'new Function(%s)();\n' % (var, var, var)
            ),
            fixed=(
                '// FIXED — for JSON data:\n'
                'var result = JSON.parse(%s);\n'
                '\n'
                '// FIXED — for setTimeout:\n'
                'setTimeout(function() { /* actual logic */ }, 1000);\n' % var
            ),
            explanation=(
                "eval() executes arbitrary JavaScript. JSON.parse() only "
                "parses JSON data — it cannot execute code. setTimeout with "
                "a string argument is equivalent to eval."
            ),
            diff_hint=r'\beval\(|new Function\(|setTimeout\([^,]*["\']',
            references=_refs(94, "A03:2021 Injection"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-798: Hardcoded Credentials
# --------------------------------------------------------------------------- #

@patch(798)
def _hardcoded(f: PocFinding) -> list[Patch]:
    var = _var(f)
    patches = []
    lang = _lang(f)

    # Universal fix — works for any language
    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=798, language="python",
            title="Hardcoded Credential — use environment variable",
            vulnerable=(
                '# VULNERABLE:\n'
                'DB_PASSWORD = "hunter2"\n'
                'API_KEY = "AKIA..."\n'
            ),
            fixed=(
                '# FIXED:\n'
                'import os\n'
                'DB_PASSWORD = os.environ["DB_PASSWORD"]\n'
                'API_KEY = os.environ["API_KEY"]\n'
                '\n'
                '# With a default for development (NOT a real credential):\n'
                'DB_PASSWORD = os.environ.get("DB_PASSWORD", "")\n'
                'if not DB_PASSWORD:\n'
                '    raise RuntimeError("DB_PASSWORD not set")\n'
            ),
            imports_required=("os",),
            explanation=(
                "Environment variables keep credentials out of source code "
                "and version control. Use a secrets manager (Vault, AWS "
                "Secrets Manager, etc.) for production."
            ),
            diff_hint=r'password\s*=\s*["\']|api.?key\s*=\s*["\']|secret\s*=\s*["\']|token\s*=\s*["\']',
            references=_refs(798, "A07:2021 Identification and Authentication Failures"),
        ))

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=798, language="java",
            title="Hardcoded Credential — use environment variable or config",
            vulnerable=(
                '// VULNERABLE:\n'
                'String password = "hunter2";\n'
                'String apiKey = "AKIA...";\n'
            ),
            fixed=(
                '// FIXED:\n'
                'String password = System.getenv("DB_PASSWORD");\n'
                'if (password == null || password.isEmpty()) {\n'
                '    throw new IllegalStateException("DB_PASSWORD not set");\n'
                '}\n'
                '\n'
                '// Or use a properties file outside the source tree:\n'
                'Properties props = new Properties();\n'
                'props.load(new FileInputStream("/etc/app/secrets.properties"));\n'
                'String password = props.getProperty("db.password");\n'
            ),
            explanation="System.getenv() reads from the process environment, keeping secrets out of the jar.",
            diff_hint=r'password\s*=\s*"|apiKey\s*=\s*"|secret\s*=\s*"',
            references=_refs(798, "A07:2021 Identification and Authentication Failures"),
        ))

    if lang in ("js", "unknown"):
        patches.append(Patch(
            cwe=798, language="javascript",
            title="Hardcoded Credential — use environment variable",
            vulnerable=(
                '// VULNERABLE:\n'
                'const API_KEY = "sk-...";\n'
                'const DB_PASSWORD = "hunter2";\n'
            ),
            fixed=(
                '// FIXED:\n'
                'const API_KEY = process.env.API_KEY;\n'
                'if (!API_KEY) throw new Error("API_KEY not set");\n'
                '\n'
                'const DB_PASSWORD = process.env.DB_PASSWORD;\n'
                'if (!DB_PASSWORD) throw new Error("DB_PASSWORD not set");\n'
            ),
            explanation="process.env reads from the runtime environment. Use dotenv for local development.",
            diff_hint=r'const.*=\s*["\']sk-|password.*=\s*["\']|apiKey.*=\s*["\']',
            references=_refs(798, "A07:2021 Identification and Authentication Failures"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-917: Server-Side Template Injection
# --------------------------------------------------------------------------- #

@patch(917)
def _ssti(f: PocFinding) -> list[Patch]:
    var = _var(f)
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=917, language="python",
            title="SSTI — never render user input as a template",
            vulnerable=(
                '# VULNERABLE:\n'
                'from jinja2 import Template\n'
                'output = Template(%s).render(context)\n'
                '# also:\n'
                'template = env.from_string(%s)\n' % (var, var)
            ),
            fixed=(
                '# FIXED — option 1: use user input as DATA, not template:\n'
                'from jinja2 import Environment\n'
                'env = Environment(autoescape=True)\n'
                'template = env.from_string("{{ user_input }}")\n'
                'output = template.render(user_input=%s)\n'
                '\n'
                '# FIXED — option 2: sandboxed environment (if template is needed):\n'
                'from jinja2.sandbox import SandboxedEnvironment\n'
                'env = SandboxedEnvironment()\n'
                'template = env.from_string(%s)\n'
                'output = template.render(context)\n' % (var, var)
            ),
            explanation=(
                "User input should be a template VARIABLE, not the template "
                "itself. If you must render user-provided templates, "
                "SandboxedEnvironment restricts which attributes and methods "
                "the template can access."
            ),
            diff_hint=r'Template\(.*user|from_string\(.*user|render_template_string',
            references=_refs(917, "A03:2021 Injection"),
        ))

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=917, language="java",
            title="SSTI — never pass user input as template source",
            vulnerable=(
                '// VULNERABLE (Freemarker):\n'
                'Template t = new Template("user", new StringReader(%s), cfg);\n' % var
            ),
            fixed=(
                '// FIXED — load template from file, pass user input as data:\n'
                'Template t = cfg.getTemplate("page.ftl");\n'
                'Map<String, Object> data = new HashMap<>();\n'
                'data.put("userInput", %s);\n'
                't.process(data, out);\n' % var
            ),
            explanation="Load templates from trusted files. User input goes into the data model, never the template source.",
            diff_hint=r'new Template\(.*,.*new StringReader|from_string',
            references=_refs(917, "A03:2021 Injection"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-918: Server-Side Request Forgery
# --------------------------------------------------------------------------- #

@patch(918)
def _ssrf(f: PocFinding) -> list[Patch]:
    var = _var(f)
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=918, language="python",
            title="SSRF — validate URL against allowlist",
            vulnerable=(
                '# VULNERABLE:\n'
                'response = requests.get(%s)\n' % var
            ),
            fixed=(
                '# FIXED:\n'
                'from urllib.parse import urlparse\n'
                '\n'
                'ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}\n'
                '\n'
                'def safe_fetch(url):\n'
                '    parsed = urlparse(url)\n'
                '    if parsed.hostname not in ALLOWED_HOSTS:\n'
                '        raise ValueError("host not in allowlist: %s" % parsed.hostname)\n'
                '    if parsed.scheme not in ("http", "https"):\n'
                '        raise ValueError("scheme not allowed: %s" % parsed.scheme)\n'
                '    # Block private IPs\n'
                '    import ipaddress\n'
                '    try:\n'
                '        ip = ipaddress.ip_address(parsed.hostname)\n'
                '        if ip.is_private or ip.is_loopback or ip.is_link_local:\n'
                '            raise ValueError("private IP blocked")\n'
                '    except ValueError:\n'
                '        pass  # hostname, not IP — allowlist already checked\n'
                '    return requests.get(url, timeout=10)\n'
                '\n'
                'response = safe_fetch(%s)\n' % var
            ),
            imports_required=("urllib.parse", "ipaddress"),
            explanation=(
                "Allowlist validation ensures only approved hosts are reachable. "
                "Private IP blocking prevents access to internal services and "
                "cloud metadata endpoints."
            ),
            diff_hint=r'requests\.get\(.*user|urllib\..*open\(.*user|fetch\(.*user',
            references=_refs(918, "A10:2021 SSRF"),
        ))

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=918, language="java",
            title="SSRF — validate URL against allowlist",
            vulnerable=(
                '// VULNERABLE:\n'
                'URL url = new URL(%s);\n'
                'HttpURLConnection conn = (HttpURLConnection) url.openConnection();\n' % var
            ),
            fixed=(
                '// FIXED:\n'
                'URL url = new URL(%s);\n'
                'Set<String> allowedHosts = Set.of("api.example.com", "cdn.example.com");\n'
                'if (!allowedHosts.contains(url.getHost())) {\n'
                '    throw new SecurityException("host not in allowlist: " + url.getHost());\n'
                '}\n'
                'if (InetAddress.getByName(url.getHost()).isSiteLocalAddress()) {\n'
                '    throw new SecurityException("private IP blocked");\n'
                '}\n'
                'HttpURLConnection conn = (HttpURLConnection) url.openConnection();\n' % var
            ),
            imports_required=("java.net.InetAddress",),
            explanation="Allowlist + private-IP check blocks both known-bad hosts and internal network access.",
            diff_hint=r'new URL\(.*user|openConnection\(\)',
            references=_refs(918, "A10:2021 SSRF"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-90: LDAP Injection
# --------------------------------------------------------------------------- #

@patch(90)
def _ldap(f: PocFinding) -> list[Patch]:
    var = _var(f)
    patches = []
    lang = _lang(f)

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=90, language="java",
            title="LDAP Injection — escape special characters",
            vulnerable=(
                '// VULNERABLE:\n'
                'String filter = "(uid=" + %s + ")";\n'
                'ctx.search(baseDN, filter, controls);\n' % var
            ),
            fixed=(
                '// FIXED — escape LDAP special characters:\n'
                'public static String escapeLdap(String input) {\n'
                '    StringBuilder sb = new StringBuilder();\n'
                '    for (char c : input.toCharArray()) {\n'
                '        switch (c) {\n'
                '            case \'\\\\\':\n'
                '            case \'*\':\n'
                '            case \'(\':\n'
                '            case \')\':\n'
                '            case \'\\0\':\n'
                '                sb.append(String.format("\\\\%%02x", (int) c));\n'
                '                break;\n'
                '            default:\n'
                '                sb.append(c);\n'
                '        }\n'
                '    }\n'
                '    return sb.toString();\n'
                '}\n'
                '\n'
                'String filter = "(uid=" + escapeLdap(%s) + ")";\n'
                'ctx.search(baseDN, filter, controls);\n' % var
            ),
            explanation=(
                "LDAP filter special characters (*, (, ), \\, NUL) must be "
                "hex-escaped. This prevents filter manipulation."
            ),
            diff_hint=r'\.search\(.*\+|"\(.*\+',
            references=_refs(90, "A03:2021 Injection"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-113: HTTP Response Splitting
# --------------------------------------------------------------------------- #

@patch(113)
def _http_splitting(f: PocFinding) -> list[Patch]:
    var = _var(f)
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=113, language="python",
            title="Sanitize header values (strip CRLF)",
            vulnerable='response.headers[header_name] = %s' % var,
            fixed=(
                'import re\n'
                'clean_value = re.sub(r"[\\r\\n]", "", %s)\n'
                'response.headers[header_name] = clean_value' % var
            ),
            explanation="CRLF characters in header values enable HTTP response splitting.",
            diff_hint=r'headers\[.*\]\s*=',
            references=_refs(113, "A03:2021 Injection"),
        ))

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=113, language="java",
            title="Sanitize header values (strip CRLF)",
            vulnerable='response.setHeader(name, %s);' % var,
            fixed=(
                'String cleanValue = %s.replaceAll("[\\\\r\\\\n]", "");\n'
                'response.setHeader(name, cleanValue);' % var
            ),
            explanation="CRLF characters in header values enable HTTP response splitting.",
            diff_hint=r'setHeader\(.*\)',
            references=_refs(113, "A03:2021 Injection"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-134: Format String
# --------------------------------------------------------------------------- #

@patch(134)
def _format_string(f: PocFinding) -> list[Patch]:
    var = _var(f)
    patches = []
    lang = _lang(f)

    if lang in ("c", "cpp", "unknown"):
        patches.append(Patch(
            cwe=134, language="c",
            title="Use format specifier instead of raw user input",
            vulnerable='printf(%s);' % var,
            fixed='printf("%%s", %s);' % var,
            explanation="Passing user input directly as a format string allows arbitrary reads/writes.",
            diff_hint=r'printf\s*\(\s*[^""]',
            references=_refs(134),
        ))

    if lang in ("python", "java", "unknown"):
        patches.append(Patch(
            cwe=134, language=lang if lang in ("python", "java") else "python",
            title="Avoid user-controlled format strings",
            vulnerable='String result = String.format(%s, args);' % var,
            fixed='String result = %s.toString();  // do not use as format string' % var,
            explanation="User-controlled format strings can leak memory or crash the process.",
            diff_hint=r'String\.format\(|%\s*\(',
            references=_refs(134),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-190: Integer Overflow
# --------------------------------------------------------------------------- #

@patch(190)
def _integer_overflow(f: PocFinding) -> list[Patch]:
    var = _var(f)
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=190, language="python",
            title="Validate integer bounds before arithmetic",
            vulnerable='result = int(%s)' % var,
            fixed=(
                'raw = int(%s)\n'
                'if not (-2**31 <= raw <= 2**31 - 1):\n'
                '    raise ValueError("Integer out of safe range")\n'
                'result = raw' % var
            ),
            explanation="Unchecked integer conversion can overflow in downstream C extensions or databases.",
            diff_hint=r'int\s*\(',
            references=_refs(190, "A04:2021 Insecure Design"),
        ))

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=190, language="java",
            title="Use Math.addExact / multiplyExact for overflow detection",
            vulnerable='// VULNERABLE: silent wraparound on overflow\nint result = a + b;',
            fixed='// FIXED: throws ArithmeticException on overflow\nint result = Math.addExact(a, b);',
            explanation="Math.addExact throws ArithmeticException on overflow instead of silent wraparound.",
            diff_hint=r'\+\s*\w+;',
            references=_refs(190, "A04:2021 Insecure Design"),
        ))

    if lang in ("c", "cpp", "unknown"):
        patches.append(Patch(
            cwe=190, language="c",
            title="Check overflow before arithmetic",
            vulnerable='int result = a + b;',
            fixed=(
                'if (b > 0 && a > INT_MAX - b) { /* overflow */ abort(); }\n'
                'if (b < 0 && a < INT_MIN - b) { /* underflow */ abort(); }\n'
                'int result = a + b;'
            ),
            imports_required=("#include <limits.h>",),
            explanation="Check for overflow before performing the arithmetic operation.",
            diff_hint=r'=\s*\w+\s*[+*]\s*\w+',
            references=_refs(190),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-295: Improper Certificate Validation
# --------------------------------------------------------------------------- #

@patch(295)
def _cert_validation(f: PocFinding) -> list[Patch]:
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=295, language="python",
            title="Enable certificate verification",
            vulnerable='requests.get(url, verify=False)',
            fixed='requests.get(url, verify=True)',
            explanation="verify=False disables all certificate checks, enabling MITM attacks.",
            diff_hint=r'verify\s*=\s*False',
            references=_refs(295, "A02:2021 Cryptographic Failures"),
        ))

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=295, language="java",
            title="Use default TrustManager instead of accepting all certs",
            vulnerable=(
                'TrustManager[] trustAll = new TrustManager[] {\n'
                '    new X509TrustManager() {\n'
                '        public void checkServerTrusted(...) {}\n'
                '    }\n'
                '};'
            ),
            fixed=(
                'SSLContext ctx = SSLContext.getInstance("TLS");\n'
                'ctx.init(null, null, null);'
            ),
            explanation="Custom TrustManagers that accept all certificates bypass validation.",
            diff_hint=r'TrustManager|checkServerTrusted',
            references=_refs(295, "A02:2021 Cryptographic Failures"),
        ))

    if lang in ("javascript", "typescript", "unknown"):
        patches.append(Patch(
            cwe=295, language="javascript",
            title="Remove rejectUnauthorized: false",
            vulnerable='rejectUnauthorized: false',
            fixed='rejectUnauthorized: true',
            explanation="rejectUnauthorized: false disables TLS certificate checks.",
            diff_hint=r'rejectUnauthorized.*false',
            references=_refs(295, "A02:2021 Cryptographic Failures"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-327: Broken Cryptographic Algorithm
# --------------------------------------------------------------------------- #

@patch(327)
def _weak_crypto(f: PocFinding) -> list[Patch]:
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=327, language="python",
            title="Replace MD5/SHA1 with SHA-256",
            vulnerable='hashlib.md5(data).hexdigest()',
            fixed='hashlib.sha256(data).hexdigest()',
            explanation="MD5 and SHA-1 have known collision attacks; use SHA-256 or better.",
            diff_hint=r'hashlib\.(md5|sha1)',
            references=_refs(327, "A02:2021 Cryptographic Failures"),
        ))

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=327, language="java",
            title="Replace MD5/SHA-1 with SHA-256",
            vulnerable='MessageDigest.getInstance("MD5")',
            fixed='MessageDigest.getInstance("SHA-256")',
            explanation="MD5 and SHA-1 have known collision attacks; use SHA-256 or better.",
            diff_hint=r'getInstance\(\s*"(MD5|SHA-1)"\s*\)',
            references=_refs(327, "A02:2021 Cryptographic Failures"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-338: Weak PRNG
# --------------------------------------------------------------------------- #

@patch(338)
def _weak_prng(f: PocFinding) -> list[Patch]:
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=338, language="python",
            title="Use secrets module instead of random",
            vulnerable='import random\ntoken = random.randint(0, 2**32)',
            fixed='import secrets\ntoken = secrets.randbelow(2**32)',
            imports_required=("import secrets",),
            explanation="The random module is not cryptographically secure; use secrets for tokens/keys.",
            diff_hint=r'random\.(randint|random|choice|randrange)',
            references=_refs(338, "A02:2021 Cryptographic Failures"),
        ))

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=338, language="java",
            title="Use SecureRandom instead of Random",
            vulnerable='Random rng = new Random();',
            fixed='SecureRandom rng = new SecureRandom();',
            imports_required=("import java.security.SecureRandom;",),
            explanation="java.util.Random is predictable; use SecureRandom for security contexts.",
            diff_hint=r'new Random\(\)',
            references=_refs(338, "A02:2021 Cryptographic Failures"),
        ))

    if lang in ("javascript", "typescript", "unknown"):
        patches.append(Patch(
            cwe=338, language="javascript",
            title="Use crypto.getRandomValues instead of Math.random",
            vulnerable='const token = Math.random().toString(36);',
            fixed=(
                'const array = new Uint32Array(1);\n'
                'crypto.getRandomValues(array);\n'
                'const token = array[0].toString(36);'
            ),
            explanation="Math.random() is not cryptographically secure.",
            diff_hint=r'Math\.random\(\)',
            references=_refs(338, "A02:2021 Cryptographic Failures"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-400: Uncontrolled Resource Consumption
# --------------------------------------------------------------------------- #

@patch(400)
def _resource_consumption(f: PocFinding) -> list[Patch]:
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=400, language="python",
            title="Add input size limits",
            vulnerable='data = request.get_json()  # no size limit enforced',
            fixed=(
                'data = request.get_json()\n'
                'if request.content_length and request.content_length > 10 * 1024 * 1024:\n'
                '    abort(413)'
            ),
            explanation="Without size limits, attackers can exhaust memory with large payloads.",
            diff_hint=r'get_json\(\)|request\.data',
            references=_refs(400, "A05:2021 Security Misconfiguration"),
        ))

    if lang in ("java",):
        patches.append(Patch(
            cwe=400, language="java",
            title="Add request body size limit",
            vulnerable='// VULNERABLE: no size check on input stream\nbyte[] body = request.getInputStream().readAllBytes();',
            fixed=(
                '// FIXED: limit input size\n'
                'byte[] body = request.getInputStream().readNBytes(10 * 1024 * 1024);\n'
                'if (request.getContentLength() > 10 * 1024 * 1024) {\n'
                '    response.sendError(413, "Payload Too Large");\n'
                '    return;\n'
                '}'
            ),
            explanation="Without size limits, attackers can exhaust memory with large payloads.",
            diff_hint=r'readAllBytes\(\)|getInputStream\(\)',
            references=_refs(400, "A05:2021 Security Misconfiguration"),
        ))

    if lang in ("javascript", "typescript"):
        patches.append(Patch(
            cwe=400, language="javascript",
            title="Add body size limit",
            vulnerable="app.use(express.json());  // no size limit",
            fixed='app.use(express.json({ limit: "1mb" }));',
            explanation="Default body parser has no size limit; add explicit limits.",
            diff_hint=r'express\.json\(\)',
            references=_refs(400, "A05:2021 Security Misconfiguration"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-434: Unrestricted File Upload
# --------------------------------------------------------------------------- #

@patch(434)
def _file_upload(f: PocFinding) -> list[Patch]:
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=434, language="python",
            title="Validate file extension and sanitize filename",
            vulnerable=(
                'file = request.files["file"]\n'
                'file.save(os.path.join(UPLOAD_DIR, file.filename))'
            ),
            fixed=(
                'from werkzeug.utils import secure_filename\n'
                'ALLOWED = {".jpg", ".jpeg", ".png", ".gif", ".pdf"}\n'
                'file = request.files["file"]\n'
                'filename = secure_filename(file.filename)\n'
                'ext = os.path.splitext(filename)[1].lower()\n'
                'if ext not in ALLOWED:\n'
                '    abort(400, "File type not allowed")\n'
                'file.save(os.path.join(UPLOAD_DIR, filename))'
            ),
            imports_required=("from werkzeug.utils import secure_filename",),
            explanation="Validate file extension and sanitize filename to prevent malicious uploads.",
            diff_hint=r'\.save\(|request\.files',
            references=_refs(434, "A04:2021 Insecure Design"),
        ))

    if lang in ("java",):
        patches.append(Patch(
            cwe=434, language="java",
            title="Validate file extension on upload",
            vulnerable=(
                '// VULNERABLE: no extension check\n'
                'String filename = part.getSubmittedFileName();\n'
                'part.write(uploadDir + "/" + filename);'
            ),
            fixed=(
                'String filename = Paths.get(part.getSubmittedFileName()).getFileName().toString();\n'
                'Set<String> allowed = Set.of(".jpg", ".png", ".pdf");\n'
                'String ext = filename.substring(filename.lastIndexOf(".")).toLowerCase();\n'
                'if (!allowed.contains(ext)) throw new ServletException("File type not allowed");\n'
                'part.write(uploadDir + "/" + filename);'
            ),
            explanation="Validate file extension and strip path components from uploaded filenames.",
            diff_hint=r'getSubmittedFileName|\.write\(',
            references=_refs(434, "A04:2021 Insecure Design"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-306: Missing Authentication
# --------------------------------------------------------------------------- #

@patch(306)
def _missing_auth(f: PocFinding) -> list[Patch]:
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=306, language="python",
            title="Add authentication decorator to endpoint",
            vulnerable=(
                '@app.route("/admin")\n'
                'def admin_panel():\n'
                '    return render_template("admin.html")'
            ),
            fixed=(
                'from functools import wraps\n'
                'def login_required(f):\n'
                '    @wraps(f)\n'
                '    def decorated(*args, **kwargs):\n'
                '        if "user_id" not in session:\n'
                '            abort(401)\n'
                '        return f(*args, **kwargs)\n'
                '    return decorated\n'
                '\n'
                '@app.route("/admin")\n'
                '@login_required\n'
                'def admin_panel():\n'
                '    return render_template("admin.html")'
            ),
            explanation="Critical endpoints must verify the caller is authenticated.",
            diff_hint=r'@app\.route.*admin',
            references=_refs(306, "A07:2021 Identification and Authentication Failures"),
        ))

    if lang in ("java",):
        patches.append(Patch(
            cwe=306, language="java",
            title="Add authentication filter to endpoint",
            vulnerable=(
                '// VULNERABLE: no authentication check\n'
                '@GetMapping("/admin")\n'
                'public String adminPanel(Model model) {\n'
                '    return "admin";\n'
                '}'
            ),
            fixed=(
                '// FIXED: require authentication\n'
                '@GetMapping("/admin")\n'
                '@PreAuthorize("isAuthenticated()")\n'
                'public String adminPanel(Model model) {\n'
                '    return "admin";\n'
                '}'
            ),
            explanation="Critical endpoints must verify the caller is authenticated.",
            diff_hint=r'@GetMapping|@RequestMapping.*admin',
            references=_refs(306, "A07:2021 Identification and Authentication Failures"),
        ))

    if lang in ("javascript", "typescript"):
        patches.append(Patch(
            cwe=306, language="javascript",
            title="Add authentication middleware",
            vulnerable='app.get("/admin", adminHandler);',
            fixed='app.get("/admin", requireAuth, adminHandler);',
            explanation="Add authentication middleware before sensitive route handlers.",
            diff_hint=r'app\.(get|post)\s*\(\s*["\']/(admin|api|internal)',
            references=_refs(306, "A07:2021 Identification and Authentication Failures"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-319: Cleartext Transmission
# --------------------------------------------------------------------------- #

@patch(319)
def _cleartext_transmission(f: PocFinding) -> list[Patch]:
    patches = []
    lang = _lang(f)

    patches.append(Patch(
        cwe=319, language=lang if lang != "unknown" else "python",
        title="Use HTTPS instead of HTTP",
        vulnerable='// VULNERABLE: cleartext HTTP connection\nString url = "http://api.example.com/data";',
        fixed='// FIXED: encrypted HTTPS connection\nString url = "https://api.example.com/data";',
        explanation="HTTP transmits data in cleartext; always use HTTPS for sensitive data.",
        diff_hint=r'http://',
        references=_refs(319, "A02:2021 Cryptographic Failures"),
    ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-614: Sensitive Cookie Without Secure Flag
# --------------------------------------------------------------------------- #

@patch(614)
def _cookie_flags(f: PocFinding) -> list[Patch]:
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=614, language="python",
            title="Set Secure, HttpOnly, and SameSite on cookies",
            vulnerable='response.set_cookie("session", token)  # missing security flags',
            fixed=(
                'response.set_cookie("session", token,\n'
                '                    secure=True, httponly=True, samesite="Lax")'
            ),
            explanation="Cookies without Secure/HttpOnly/SameSite are vulnerable to theft and CSRF.",
            diff_hint=r'set_cookie\(',
            references=_refs(614, "A05:2021 Security Misconfiguration"),
        ))

    if lang in ("java",):
        patches.append(Patch(
            cwe=614, language="java",
            title="Set Secure, HttpOnly, and SameSite on cookies",
            vulnerable=(
                '// VULNERABLE: cookie without security flags\n'
                'Cookie cookie = new Cookie("session", token);\n'
                'response.addCookie(cookie);'
            ),
            fixed=(
                '// FIXED: set all security flags\n'
                'Cookie cookie = new Cookie("session", token);\n'
                'cookie.setSecure(true);\n'
                'cookie.setHttpOnly(true);\n'
                'response.setHeader("Set-Cookie",\n'
                '    cookie.getName() + "=" + cookie.getValue()\n'
                '    + "; Secure; HttpOnly; SameSite=Lax");\n'
            ),
            explanation="Cookies without Secure/HttpOnly/SameSite are vulnerable to theft and CSRF.",
            diff_hint=r'addCookie\(|new Cookie\(',
            references=_refs(614, "A05:2021 Security Misconfiguration"),
        ))

    if lang in ("javascript", "typescript"):
        patches.append(Patch(
            cwe=614, language="javascript",
            title="Set secure cookie flags",
            vulnerable='res.cookie("session", token);  // missing security flags',
            fixed='res.cookie("session", token, { secure: true, httpOnly: true, sameSite: "lax" });',
            explanation="Cookies without Secure/HttpOnly/SameSite are vulnerable to theft and CSRF.",
            diff_hint=r'\.cookie\(',
            references=_refs(614, "A05:2021 Security Misconfiguration"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-862: Missing Authorization
# --------------------------------------------------------------------------- #

@patch(862)
def _missing_authz(f: PocFinding) -> list[Patch]:
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=862, language="python",
            title="Add authorization check before resource access",
            vulnerable=(
                'def get_record(record_id):\n'
                '    return db.query(Record).get(record_id)'
            ),
            fixed=(
                'def get_record(record_id):\n'
                '    record = db.query(Record).get(record_id)\n'
                '    if record is None:\n'
                '        abort(404)\n'
                '    if record.owner_id != current_user.id:\n'
                '        abort(403)\n'
                '    return record'
            ),
            explanation="Check that the user is authorized to access the requested resource.",
            diff_hint=r'\.get\(.*_id\)',
            references=_refs(862, "A01:2021 Broken Access Control"),
        ))

    if lang in ("java",):
        patches.append(Patch(
            cwe=862, language="java",
            title="Add ownership check before returning resource",
            vulnerable=(
                '// VULNERABLE: no authorization check\n'
                'Record record = repository.findById(recordId).orElseThrow();'
            ),
            fixed=(
                '// FIXED: verify ownership\n'
                'Record record = repository.findById(recordId).orElseThrow();\n'
                'if (!record.getOwnerId().equals(currentUser.getId())) {\n'
                '    throw new AccessDeniedException("Not authorized");\n'
                '}'
            ),
            explanation="Always verify the requesting user owns or has permission to access the resource.",
            diff_hint=r'findById|findOne',
            references=_refs(862, "A01:2021 Broken Access Control"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-1321: Prototype Pollution
# --------------------------------------------------------------------------- #

@patch(1321)
def _proto_pollution(f: PocFinding) -> list[Patch]:
    return [Patch(
        cwe=1321, language="javascript",
        title="Block __proto__ and constructor in object merge",
        vulnerable=(
            'function merge(target, source) {\n'
            '  for (const key in source) {\n'
            '    target[key] = source[key];\n'
            '  }\n'
            '}'
        ),
        fixed=(
            'function merge(target, source) {\n'
            '  for (const key in source) {\n'
            '    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;\n'
            '    if (!Object.prototype.hasOwnProperty.call(source, key)) continue;\n'
            '    target[key] = source[key];\n'
            '  }\n'
            '}'
        ),
        explanation="Skip __proto__, constructor, and prototype keys to prevent prototype pollution.",
        diff_hint=r'for\s*\(\s*(const|let|var)\s+\w+\s+in\s+|Object\.assign\(',
        references=_refs(1321, "A03:2021 Injection"),
    )]


# --------------------------------------------------------------------------- #
# CWE-369: Divide By Zero
# --------------------------------------------------------------------------- #

@patch(369)
def _divide_by_zero(f: PocFinding) -> list[Patch]:
    var = _var(f)
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=369, language="python",
            title="Check for zero before division",
            vulnerable='result = numerator / %s' % var,
            fixed=(
                'if %s == 0:\n'
                '    raise ValueError("Division by zero")\n'
                'result = numerator / %s' % (var, var)
            ),
            explanation="Validate divisor is non-zero before performing division.",
            diff_hint=r'/\s*\w+',
            references=_refs(369),
        ))

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=369, language="java",
            title="Check for zero before division",
            vulnerable='// VULNERABLE: no zero check before division\nint result = a / b;',
            fixed=(
                '// FIXED: explicit zero check\n'
                'if (b == 0) throw new ArithmeticException("Division by zero");\n'
                'int result = a / b;'
            ),
            explanation="Validate divisor is non-zero before performing division.",
            diff_hint=r'/\s*\w+;',
            references=_refs(369),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-770: Allocation Without Limits
# --------------------------------------------------------------------------- #

@patch(770)
def _alloc_no_limits(f: PocFinding) -> list[Patch]:
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=770, language="python",
            title="Add pagination and size limits",
            vulnerable='items = db.query(Item).all()  # unbounded query without limit',
            fixed=(
                'MAX_PAGE_SIZE = 100\n'
                'page = max(1, request.args.get("page", 1, type=int))\n'
                'per_page = min(request.args.get("per_page", 20, type=int), MAX_PAGE_SIZE)\n'
                'items = db.query(Item).limit(per_page).offset((page - 1) * per_page).all()'
            ),
            explanation="Unbounded queries can exhaust memory; add pagination with a max page size.",
            diff_hint=r'\.all\(\)',
            references=_refs(770, "A05:2021 Security Misconfiguration"),
        ))

    if lang in ("java",):
        patches.append(Patch(
            cwe=770, language="java",
            title="Add pagination to database queries",
            vulnerable=(
                '// VULNERABLE: unbounded query\n'
                'List<Item> items = repository.findAll();'
            ),
            fixed=(
                '// FIXED: paginate results\n'
                'int maxPageSize = 100;\n'
                'Pageable pageable = PageRequest.of(page, Math.min(size, maxPageSize));\n'
                'Page<Item> items = repository.findAll(pageable);'
            ),
            explanation="Unbounded queries can exhaust memory; always add pagination limits.",
            diff_hint=r'findAll\(\)',
            references=_refs(770, "A05:2021 Security Misconfiguration"),
        ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-922: Insecure Storage
# --------------------------------------------------------------------------- #

@patch(922)
def _insecure_storage(f: PocFinding) -> list[Patch]:
    return [Patch(
        cwe=922, language="python",
        title="Use environment variables instead of hardcoded secrets",
        vulnerable='SECRET_KEY = "my-secret-key-12345"',
        fixed=(
            'import os\n'
            'SECRET_KEY = os.environ["SECRET_KEY"]'
        ),
        imports_required=("import os",),
        explanation="Secrets in source code are visible in version control; use environment variables.",
        diff_hint=r'(SECRET|KEY|PASSWORD|TOKEN)\s*=\s*["\']',
        references=_refs(922, "A02:2021 Cryptographic Failures"),
    )]


# --------------------------------------------------------------------------- #
# CWE-120: Buffer Overflow
# --------------------------------------------------------------------------- #

@patch(120)
def _buffer_overflow(f: PocFinding) -> list[Patch]:
    lang = _lang(f)
    patches = []

    patches.append(Patch(
        cwe=120, language="c" if lang in ("c", "cpp") else lang,
        title="Use size-bounded copy instead of unbounded copy",
        vulnerable='// VULNERABLE: no bounds check on copy\nstrcpy(dest, src);  // src may be larger than dest',
        fixed='strncpy(dest, src, sizeof(dest) - 1);\ndest[sizeof(dest) - 1] = \'\\0\';',
        explanation="strcpy does not check buffer bounds; use strncpy with explicit size limit.",
        diff_hint=r'strcpy\s*\(|sprintf\s*\(|gets\s*\(',
        references=_refs(120),
    ))

    return patches


# --------------------------------------------------------------------------- #
# CWE-250: Unnecessary Privileges
# --------------------------------------------------------------------------- #

@patch(250)
def _unnecessary_privileges(f: PocFinding) -> list[Patch]:
    return [Patch(
        cwe=250, language="python",
        title="Drop privileges after binding to privileged port",
        vulnerable=(
            'server.bind(("0.0.0.0", 80))\n'
            'server.listen()'
        ),
        fixed=(
            'import os\n'
            'server.bind(("0.0.0.0", 80))\n'
            'os.setgid(65534)  # nogroup\n'
            'os.setuid(65534)  # nobody\n'
            'server.listen()'
        ),
        explanation="Drop root privileges after performing operations that require them.",
        diff_hint=r'\.bind\(.*80\)|\.bind\(.*443\)',
        references=_refs(250, "A04:2021 Insecure Design"),
    )]


# --------------------------------------------------------------------------- #
# CWE-476: NULL Pointer Dereference
# --------------------------------------------------------------------------- #

@patch(476)
def _null_deref(f: PocFinding) -> list[Patch]:
    var = _var(f)
    patches = []
    lang = _lang(f)

    if lang in ("python", "unknown"):
        patches.append(Patch(
            cwe=476, language="python",
            title="Check for None before accessing attributes",
            vulnerable='result = %s.process()' % var,
            fixed=(
                'if %s is None:\n'
                '    raise ValueError("Expected non-None value")\n'
                'result = %s.process()' % (var, var)
            ),
            explanation="Accessing attributes on None raises AttributeError; validate first.",
            diff_hint=r'\.\w+\(',
            references=_refs(476),
        ))

    if lang in ("java", "unknown"):
        patches.append(Patch(
            cwe=476, language="java",
            title="Add null check before method call",
            vulnerable='result = %s.process();' % var,
            fixed=(
                'Objects.requireNonNull(%s, "%s must not be null");\n'
                'result = %s.process();' % (var, var, var)
            ),
            imports_required=("import java.util.Objects;",),
            explanation="Validate non-null before dereferencing to avoid NullPointerException.",
            diff_hint=r'\.\w+\(\)',
            references=_refs(476),
        ))

    if lang in ("c", "cpp", "unknown"):
        patches.append(Patch(
            cwe=476, language="c",
            title="Add NULL check before dereference",
            vulnerable='result = ptr->field;',
            fixed=(
                'if (ptr == NULL) { return -1; }\n'
                'result = ptr->field;'
            ),
            explanation="Dereferencing NULL causes a segfault; always check first.",
            diff_hint=r'->',
            references=_refs(476),
        ))

    return patches
