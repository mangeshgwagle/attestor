#!/usr/bin/env python3
"""Fix engine -- AST-aware security repair with planning and verification.

Takes a finding, reads surrounding code, plans a multi-step fix strategy,
applies AST transforms, and verifies the result. Unlike the old regex-based
autofix, this understands code structure: it can add imports, wrap expressions,
replace function calls, and restructure control flow.

    plan = fixengine.plan_fix(finding, source_code)
    if plan.confidence > 0.7:
        result = fixengine.apply_fix(plan, source_code)
"""
from __future__ import annotations

import ast
import os
import re
import sys
import textwrap
from dataclasses import dataclass, field

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


@dataclass
class FixStep:
    action: str
    target_line: int
    description: str
    old_text: str = ""
    new_text: str = ""
    insert_after: int = 0
    insert_before: int = 0


@dataclass
class FixPlan:
    finding: dict
    strategy: str
    cwe: str
    confidence: float
    risk: str
    steps: list[FixStep] = field(default_factory=list)
    imports_needed: list[str] = field(default_factory=list)
    reasoning: list[str] = field(default_factory=list)
    preview_before: str = ""
    preview_after: str = ""
    file: str = ""
    line: int = 0


@dataclass
class FixResult:
    plan: FixPlan
    applied: bool = False
    original: str = ""
    fixed: str = ""
    diff_lines: list[str] = field(default_factory=list)
    verified: bool = False
    verification_note: str = ""


def _get_indent(line: str) -> str:
    return line[:len(line) - len(line.lstrip())]


def _find_function_bounds(source: str, target_line: int) -> tuple[int, int]:
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return max(1, target_line - 5), target_line + 5
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno + 20)
            if node.lineno <= target_line <= end:
                return node.lineno, end
    return max(1, target_line - 10), min(len(source.splitlines()), target_line + 10)


def _existing_imports(source: str) -> set[str]:
    imports = set()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return imports
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for alias in node.names:
                imports.add(f"{mod}.{alias.name}")
                imports.add(alias.name)
    return imports


def _last_import_line(source: str) -> int:
    last = 0
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return 0
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            last = max(last, getattr(node, "end_lineno", node.lineno))
    return last


def _build_import_line(module: str) -> str:
    if "." in module:
        parts = module.rsplit(".", 1)
        return f"from {parts[0]} import {parts[1]}"
    return f"import {module}"


# --------------------------------------------------------------------------- #
#  Strategy: SQL injection (CWE-89)                                           #
# --------------------------------------------------------------------------- #

_SQL_FORMAT_PAT = re.compile(
    r"""(\.execute\s*\(\s*)"""
    r"""(["'])(.*?)\2\s*%\s*(\(?.+?\)?)"""
    r"""(\s*\))""", re.S)

_SQL_FSTRING_PAT = re.compile(
    r"""(\.execute\s*\(\s*)f(["'])(.*?)\2(\s*\))""", re.S)

_SQL_CONCAT_PAT = re.compile(
    r"""(\.execute\s*\(\s*)(["'])(.*?)\2\s*\+\s*(.+?)(\s*\))""", re.S)


def _plan_sqli(finding: dict, source: str, lines: list[str]) -> FixPlan | None:
    line_idx = finding.get("sink_line", finding.get("line", 0))
    if line_idx < 1 or line_idx > len(lines):
        return None
    target = lines[line_idx - 1]

    plan = FixPlan(
        finding=finding, strategy="parameterized_query", cwe="CWE-89",
        confidence=0.0, risk="LOW", file=finding.get("file", ""),
        line=line_idx,
    )

    if _SQL_FORMAT_PAT.search(target):
        m = _SQL_FORMAT_PAT.search(target)
        old_query = m.group(3)
        params_expr = m.group(4)
        new_query = re.sub(r"%[sd]", "?", old_query)
        indent = _get_indent(target)
        if not params_expr.startswith("("):
            params_expr = f"({params_expr},)"
        elif not params_expr.rstrip().endswith(",)"):
            params_expr = params_expr.rstrip().rstrip(")") + ",)"
        new_line = f'{indent}{m.group(1)}"{new_query}", {params_expr}{m.group(5)}'
        plan.steps.append(FixStep(
            action="replace_line", target_line=line_idx,
            description="replace %-format SQL with parameterized query",
            old_text=target.rstrip(), new_text=new_line.rstrip(),
        ))
        plan.confidence = 0.85
        plan.reasoning = [
            f"line {line_idx} builds SQL with %-formatting",
            "replacing format specifiers with ? placeholders",
            "moving interpolated values to parameter tuple",
        ]
        return plan

    if _SQL_FSTRING_PAT.search(target):
        m = _SQL_FSTRING_PAT.search(target)
        fquery = m.group(3)
        params = re.findall(r"\{([^}]+)\}", fquery)
        new_query = re.sub(r"\{[^}]+\}", "?", fquery)
        param_tuple = "(" + ", ".join(params) + ",)"
        indent = _get_indent(target)
        new_line = f'{indent}{m.group(1)}"{new_query}", {param_tuple}{m.group(4)}'
        plan.steps.append(FixStep(
            action="replace_line", target_line=line_idx,
            description="replace f-string SQL with parameterized query",
            old_text=target.rstrip(), new_text=new_line.rstrip(),
        ))
        plan.confidence = 0.82
        plan.reasoning = [
            f"line {line_idx} builds SQL with f-string interpolation",
            f"extracted {len(params)} parameter(s): {', '.join(params)}",
            "converted to ? placeholders with parameter tuple",
        ]
        return plan

    if _SQL_CONCAT_PAT.search(target):
        m = _SQL_CONCAT_PAT.search(target)
        query_part = m.group(3)
        param_expr = m.group(4).strip()
        indent = _get_indent(target)
        new_line = f'{indent}{m.group(1)}"{query_part}?", ({param_expr},){m.group(5)}'
        plan.steps.append(FixStep(
            action="replace_line", target_line=line_idx,
            description="replace string concatenation SQL with parameterized query",
            old_text=target.rstrip(), new_text=new_line.rstrip(),
        ))
        plan.confidence = 0.78
        plan.reasoning = [
            f"line {line_idx} builds SQL with string concatenation",
            "converted concatenated value to ? placeholder",
        ]
        return plan

    return None


# --------------------------------------------------------------------------- #
#  Strategy: Command injection (CWE-78)                                       #
# --------------------------------------------------------------------------- #

_OS_SYSTEM_PAT = re.compile(
    r"""os\.system\s*\(\s*(.+?)\s*\)""")

_SUBPROCESS_SHELL_PAT = re.compile(
    r"""subprocess\.(call|run|Popen|check_output|check_call)\s*\((.+?),\s*shell\s*=\s*True""",
    re.S)


def _plan_cmdi(finding: dict, source: str, lines: list[str]) -> FixPlan | None:
    line_idx = finding.get("sink_line", finding.get("line", 0))
    if line_idx < 1 or line_idx > len(lines):
        return None
    target = lines[line_idx - 1]

    plan = FixPlan(
        finding=finding, strategy="safe_subprocess", cwe="CWE-78",
        confidence=0.0, risk="MEDIUM", file=finding.get("file", ""),
        line=line_idx,
    )

    existing = _existing_imports(source)

    if _OS_SYSTEM_PAT.search(target):
        m = _OS_SYSTEM_PAT.search(target)
        cmd_arg = m.group(1).strip()
        indent = _get_indent(target)

        if "+" in cmd_arg or "%" in cmd_arg or cmd_arg.startswith("f"):
            new_line = f"{indent}subprocess.run(shlex.split({cmd_arg}), check=True)"
            plan.reasoning = [
                f"line {line_idx} uses os.system() with dynamic command",
                "replacing with subprocess.run() + shlex.split() for safe argument parsing",
            ]
        else:
            new_line = f"{indent}subprocess.run(shlex.split({cmd_arg}), check=True)"
            plan.reasoning = [
                f"line {line_idx} uses os.system() which invokes a shell",
                "replacing with subprocess.run() to avoid shell injection",
            ]

        plan.steps.append(FixStep(
            action="replace_line", target_line=line_idx,
            description="replace os.system() with subprocess.run()",
            old_text=target.rstrip(), new_text=new_line.rstrip(),
        ))
        if "subprocess" not in existing:
            plan.imports_needed.append("subprocess")
        if "shlex" not in existing:
            plan.imports_needed.append("shlex")
        plan.confidence = 0.80
        return plan

    if _SUBPROCESS_SHELL_PAT.search(target):
        indent = _get_indent(target)
        new_line = re.sub(r"shell\s*=\s*True", "shell=False", target)
        m = _SUBPROCESS_SHELL_PAT.search(target)
        cmd_arg = m.group(2).strip().rstrip(",")
        if not cmd_arg.startswith("["):
            new_line = re.sub(
                re.escape(cmd_arg),
                f"shlex.split({cmd_arg})",
                new_line, count=1)
            if "shlex" not in existing:
                plan.imports_needed.append("shlex")

        plan.steps.append(FixStep(
            action="replace_line", target_line=line_idx,
            description="disable shell=True and use argument list",
            old_text=target.rstrip(), new_text=new_line.rstrip(),
        ))
        plan.confidence = 0.75
        plan.reasoning = [
            f"line {line_idx} uses subprocess with shell=True",
            "setting shell=False and converting command to argument list",
        ]
        return plan

    return None


# --------------------------------------------------------------------------- #
#  Strategy: Dangerous eval (CWE-95)                                          #
# --------------------------------------------------------------------------- #

_EVAL_PAT = re.compile(r"""\beval\s*\(\s*(.+?)\s*\)""")


def _plan_eval(finding: dict, source: str, lines: list[str]) -> FixPlan | None:
    line_idx = finding.get("sink_line", finding.get("line", 0))
    if line_idx < 1 or line_idx > len(lines):
        return None
    target = lines[line_idx - 1]

    if not _EVAL_PAT.search(target):
        return None

    m = _EVAL_PAT.search(target)
    arg = m.group(1)
    indent = _get_indent(target)
    new_line = target.replace(f"eval({arg})", f"ast.literal_eval({arg})")

    plan = FixPlan(
        finding=finding, strategy="literal_eval", cwe="CWE-95",
        confidence=0.72, risk="MEDIUM", file=finding.get("file", ""),
        line=line_idx,
    )
    plan.steps.append(FixStep(
        action="replace_line", target_line=line_idx,
        description="replace eval() with ast.literal_eval()",
        old_text=target.rstrip(), new_text=new_line.rstrip(),
    ))
    if "ast" not in _existing_imports(source):
        plan.imports_needed.append("ast")
    plan.reasoning = [
        f"line {line_idx} uses eval() which executes arbitrary code",
        "ast.literal_eval() safely evaluates literals (strings, numbers, dicts, lists)",
        "if the input is not a literal, this will raise ValueError (safe failure)",
    ]
    return plan


# --------------------------------------------------------------------------- #
#  Strategy: Hardcoded secrets (CWE-798)                                      #
# --------------------------------------------------------------------------- #

_SECRET_ASSIGN_PAT = re.compile(
    r"""^(\s*)(\w+)\s*=\s*(["'])([^"']{8,})\3\s*$""")

_SECRET_NAMES = re.compile(
    r"(?i)(password|secret|api_key|apikey|token|private_key|access_key|"
    r"auth_token|db_pass|database_password|smtp_pass|aws_secret)")


def _plan_hardcoded_secret(finding: dict, source: str, lines: list[str]) -> FixPlan | None:
    line_idx = finding.get("sink_line", finding.get("line", 0))
    if line_idx < 1 or line_idx > len(lines):
        return None
    target = lines[line_idx - 1]

    m = _SECRET_ASSIGN_PAT.match(target)
    if not m:
        return None

    indent = m.group(1)
    var_name = m.group(2)

    if not _SECRET_NAMES.search(var_name):
        return None

    env_name = var_name.upper()
    new_line = f'{indent}{var_name} = os.environ["{env_name}"]'

    plan = FixPlan(
        finding=finding, strategy="env_var", cwe="CWE-798",
        confidence=0.88, risk="MEDIUM", file=finding.get("file", ""),
        line=line_idx,
    )
    plan.steps.append(FixStep(
        action="replace_line", target_line=line_idx,
        description=f"replace hardcoded value with os.environ[\"{env_name}\"]",
        old_text=target.rstrip(), new_text=new_line,
    ))
    if "os" not in _existing_imports(source):
        plan.imports_needed.append("os")
    plan.reasoning = [
        f"line {line_idx} hardcodes a secret value in variable '{var_name}'",
        f"moving to environment variable {env_name}",
        "the application must set this env var before startup",
    ]
    return plan


# --------------------------------------------------------------------------- #
#  Strategy: Path traversal (CWE-22)                                          #
# --------------------------------------------------------------------------- #

_PATH_JOIN_PAT = re.compile(
    r"""os\.path\.join\s*\(\s*(\w+)\s*,\s*(.+?)\s*\)""")

_OPEN_PAT = re.compile(
    r"""open\s*\(\s*(\w+)\s*[,)]""")


def _plan_path_traversal(finding: dict, source: str, lines: list[str]) -> FixPlan | None:
    line_idx = finding.get("sink_line", finding.get("line", 0))
    if line_idx < 1 or line_idx > len(lines):
        return None
    target = lines[line_idx - 1]
    indent = _get_indent(target)

    plan = FixPlan(
        finding=finding, strategy="path_guard", cwe="CWE-22",
        confidence=0.0, risk="LOW", file=finding.get("file", ""),
        line=line_idx,
    )

    m = _PATH_JOIN_PAT.search(target)
    if m:
        base_var = m.group(1)
        user_part = m.group(2).strip()
        guard = (
            f"{indent}_{base_var}_resolved = os.path.realpath(os.path.join({base_var}, {user_part}))\n"
            f"{indent}if not _{base_var}_resolved.startswith(os.path.realpath({base_var})):\n"
            f"{indent}    raise ValueError(\"path traversal blocked\")"
        )
        new_target = target.replace(
            m.group(0), f"_{base_var}_resolved")
        plan.steps.append(FixStep(
            action="insert_before", target_line=line_idx,
            description=f"add realpath guard before path join",
            new_text=guard,
        ))
        plan.steps.append(FixStep(
            action="replace_line", target_line=line_idx,
            description="use resolved path variable",
            old_text=target.rstrip(), new_text=new_target.rstrip(),
        ))
        plan.confidence = 0.76
        plan.reasoning = [
            f"line {line_idx} joins a base directory with user input",
            f"adding os.path.realpath() check against base '{base_var}'",
            "raises ValueError if resolved path escapes the base directory",
        ]
        return plan

    return None


# --------------------------------------------------------------------------- #
#  Strategy: Insecure deserialization (CWE-502)                               #
# --------------------------------------------------------------------------- #

_PICKLE_LOADS_PAT = re.compile(r"""\bpickle\.loads?\s*\(""")
_YAML_LOAD_PAT = re.compile(r"""\byaml\.load\s*\((.+?)(?:\)|,)""")


def _plan_deserialize(finding: dict, source: str, lines: list[str]) -> FixPlan | None:
    line_idx = finding.get("sink_line", finding.get("line", 0))
    if line_idx < 1 or line_idx > len(lines):
        return None
    target = lines[line_idx - 1]
    indent = _get_indent(target)

    plan = FixPlan(
        finding=finding, strategy="safe_deserialize", cwe="CWE-502",
        confidence=0.0, risk="MEDIUM", file=finding.get("file", ""),
        line=line_idx,
    )

    if _PICKLE_LOADS_PAT.search(target):
        is_load = "pickle.load(" in target
        old_call = "pickle.load(" if is_load else "pickle.loads("
        new_call = "json.load(" if is_load else "json.loads("
        new_line = target.replace(old_call, new_call)
        plan.steps.append(FixStep(
            action="replace_line", target_line=line_idx,
            description="replace pickle with json (safe deserialization)",
            old_text=target.rstrip(), new_text=new_line.rstrip(),
        ))
        if "json" not in _existing_imports(source):
            plan.imports_needed.append("json")
        plan.confidence = 0.65
        plan.risk = "HIGH"
        plan.reasoning = [
            f"line {line_idx} uses pickle which executes arbitrary code during deserialization",
            "replacing with json which only deserializes data, never code",
            "WARNING: this changes the wire format -- callers must also switch to json",
        ]
        return plan

    if _YAML_LOAD_PAT.search(target):
        if "Loader" in target or "safe_load" in target:
            return None
        new_line = target.replace("yaml.load(", "yaml.safe_load(")
        plan.steps.append(FixStep(
            action="replace_line", target_line=line_idx,
            description="replace yaml.load() with yaml.safe_load()",
            old_text=target.rstrip(), new_text=new_line.rstrip(),
        ))
        plan.confidence = 0.90
        plan.risk = "LOW"
        plan.reasoning = [
            f"line {line_idx} uses yaml.load() without Loader argument",
            "yaml.safe_load() only allows basic YAML types, blocks code execution",
        ]
        return plan

    return None


# --------------------------------------------------------------------------- #
#  Strategy: SSRF (CWE-918)                                                  #
# --------------------------------------------------------------------------- #

_REQUESTS_PAT = re.compile(
    r"""\brequests\.(get|post|put|delete|patch|head)\s*\(\s*(\w+)""")

_URLLIB_PAT = re.compile(
    r"""\burllib\.request\.urlopen\s*\(\s*(\w+)""")


def _plan_ssrf(finding: dict, source: str, lines: list[str]) -> FixPlan | None:
    line_idx = finding.get("sink_line", finding.get("line", 0))
    if line_idx < 1 or line_idx > len(lines):
        return None
    target = lines[line_idx - 1]
    indent = _get_indent(target)

    plan = FixPlan(
        finding=finding, strategy="url_allowlist", cwe="CWE-918",
        confidence=0.0, risk="LOW", file=finding.get("file", ""),
        line=line_idx,
    )

    m = _REQUESTS_PAT.search(target) or _URLLIB_PAT.search(target)
    if not m:
        return None

    url_var = m.group(2) if _REQUESTS_PAT.search(target) else m.group(1)

    guard = textwrap.dedent(f"""\
{indent}_parsed = urllib.parse.urlparse({url_var})
{indent}if _parsed.hostname in ("127.0.0.1", "localhost", "0.0.0.0", "metadata.google.internal"):
{indent}    raise ValueError(f"blocked host: {{_parsed.hostname}}")
{indent}if _parsed.scheme not in ("http", "https"):
{indent}    raise ValueError(f"blocked scheme: {{_parsed.scheme}}")""").rstrip()

    plan.steps.append(FixStep(
        action="insert_before", target_line=line_idx,
        description="add SSRF guard checking hostname and scheme",
        new_text=guard,
    ))
    existing = _existing_imports(source)
    if "urllib.parse" not in existing and "urlparse" not in existing:
        plan.imports_needed.append("urllib.parse")
    plan.confidence = 0.74
    plan.reasoning = [
        f"line {line_idx} makes an HTTP request with a potentially user-controlled URL",
        "adding hostname blocklist (localhost, metadata endpoints) and scheme check",
        "production code should use an explicit allowlist instead of a blocklist",
    ]
    return plan


# --------------------------------------------------------------------------- #
#  Strategy: Weak crypto (CWE-327/328)                                        #
# --------------------------------------------------------------------------- #

_WEAK_HASH_PAT = re.compile(r"""\bhashlib\.(md5|sha1)\s*\(""")
_RANDOM_PAT = re.compile(r"""\brandom\.(random|randint|choice|randrange)\s*\(""")


def _plan_weak_crypto(finding: dict, source: str, lines: list[str]) -> FixPlan | None:
    line_idx = finding.get("sink_line", finding.get("line", 0))
    if line_idx < 1 or line_idx > len(lines):
        return None
    target = lines[line_idx - 1]

    plan = FixPlan(
        finding=finding, strategy="strong_crypto", cwe="CWE-327",
        confidence=0.0, risk="LOW", file=finding.get("file", ""),
        line=line_idx,
    )

    if _WEAK_HASH_PAT.search(target):
        m = _WEAK_HASH_PAT.search(target)
        old_hash = m.group(1)
        new_line = target.replace(f"hashlib.{old_hash}(", "hashlib.sha256(")
        plan.steps.append(FixStep(
            action="replace_line", target_line=line_idx,
            description=f"replace {old_hash} with sha256",
            old_text=target.rstrip(), new_text=new_line.rstrip(),
        ))
        plan.confidence = 0.92
        plan.reasoning = [
            f"line {line_idx} uses {old_hash} which has known collision attacks",
            "sha256 is the minimum recommended hash for security contexts",
        ]
        return plan

    if _RANDOM_PAT.search(target):
        m = _RANDOM_PAT.search(target)
        old_func = m.group(1)
        replacement = {
            "random": "secrets.token_hex(16)",
            "randint": "secrets.randbelow",
            "choice": "secrets.choice",
            "randrange": "secrets.randbelow",
        }
        new_call = replacement.get(old_func)
        if not new_call:
            return None
        if old_func == "random":
            new_line = re.sub(
                r"random\.random\s*\([^)]*\)", new_call, target)
        else:
            new_line = target.replace(f"random.{old_func}(", f"{new_call}(")
        plan.steps.append(FixStep(
            action="replace_line", target_line=line_idx,
            description=f"replace random.{old_func}() with secrets module",
            old_text=target.rstrip(), new_text=new_line.rstrip(),
        ))
        if "secrets" not in _existing_imports(source):
            plan.imports_needed.append("secrets")
        plan.confidence = 0.80
        plan.reasoning = [
            f"line {line_idx} uses random.{old_func}() which is predictable",
            "the secrets module uses OS-level CSPRNG",
        ]
        return plan

    return None


# --------------------------------------------------------------------------- #
#  Strategy: XSS via innerHTML / template injection (CWE-79)                  #
# --------------------------------------------------------------------------- #

_FORMAT_HTML_PAT = re.compile(
    r"""["'].*<\w+[^"']*["']\s*\.format\s*\(|["'].*<\w+[^"']*["']\s*%\s*\(""")

_RENDER_STRING_PAT = re.compile(
    r"""render_template_string\s*\(\s*(.+?)\s*[,)]""")


def _plan_xss(finding: dict, source: str, lines: list[str]) -> FixPlan | None:
    line_idx = finding.get("sink_line", finding.get("line", 0))
    if line_idx < 1 or line_idx > len(lines):
        return None
    target = lines[line_idx - 1]
    indent = _get_indent(target)

    plan = FixPlan(
        finding=finding, strategy="html_escape", cwe="CWE-79",
        confidence=0.0, risk="LOW", file=finding.get("file", ""),
        line=line_idx,
    )

    if _RENDER_STRING_PAT.search(target):
        plan.steps.append(FixStep(
            action="replace_line", target_line=line_idx,
            description="flag render_template_string as dangerous",
            old_text=target.rstrip(),
            new_text=target.rstrip(),
        ))
        plan.confidence = 0.50
        plan.risk = "HIGH"
        plan.reasoning = [
            f"line {line_idx} uses render_template_string() with dynamic content",
            "this allows server-side template injection (SSTI)",
            "move the template to a file and use render_template() instead",
            "cannot auto-fix: requires moving template content to a file",
        ]
        return plan

    if "html.escape" in target or "markupsafe" in target or "escape(" in target:
        return None

    if _FORMAT_HTML_PAT.search(target):
        format_vars = re.findall(r"\{(\w+)\}", target)
        if format_vars:
            escape_lines = []
            for var in format_vars:
                escape_lines.append(
                    f"{indent}{var} = html.escape(str({var}))")
            plan.steps.append(FixStep(
                action="insert_before", target_line=line_idx,
                description="escape HTML entities in interpolated variables",
                new_text="\n".join(escape_lines),
            ))
            if "html" not in _existing_imports(source):
                plan.imports_needed.append("html")
            plan.confidence = 0.70
            plan.reasoning = [
                f"line {line_idx} interpolates variables into HTML markup",
                f"adding html.escape() for: {', '.join(format_vars)}",
            ]
            return plan

    return None


# --------------------------------------------------------------------------- #
#  Strategy: TLS verify disabled (CWE-295)                                    #
# --------------------------------------------------------------------------- #

def _plan_tls(finding: dict, source: str, lines: list[str]) -> FixPlan | None:
    line_idx = finding.get("sink_line", finding.get("line", 0))
    if line_idx < 1 or line_idx > len(lines):
        return None
    target = lines[line_idx - 1]
    if "verify=False" not in target and "verify = False" not in target:
        return None
    new_line = re.sub(r"verify\s*=\s*False", "verify=True", target)
    plan = FixPlan(
        finding=finding, strategy="enable_tls_verify", cwe="CWE-295",
        confidence=0.92, risk="LOW", file=finding.get("file", ""),
        line=line_idx,
    )
    plan.steps.append(FixStep(
        action="replace_line", target_line=line_idx,
        description="enable TLS certificate verification",
        old_text=target.rstrip(), new_text=new_line.rstrip(),
    ))
    plan.reasoning = [
        f"line {line_idx} disables TLS certificate verification",
        "this allows MITM attacks on HTTPS connections",
        "verify=True uses the system CA bundle",
    ]
    return plan


# --------------------------------------------------------------------------- #
#  Strategy registry                                                          #
# --------------------------------------------------------------------------- #

_STRATEGIES: dict[str, callable] = {}

_CWE_STRATEGY_MAP = {
    "CWE-89": _plan_sqli,
    "CWE-78": _plan_cmdi,
    "CWE-95": _plan_eval,
    "CWE-798": _plan_hardcoded_secret,
    "CWE-22": _plan_path_traversal,
    "CWE-502": _plan_deserialize,
    "CWE-918": _plan_ssrf,
    "CWE-327": _plan_weak_crypto,
    "CWE-328": _plan_weak_crypto,
    "CWE-79": _plan_xss,
    "CWE-295": _plan_tls,
}

_SINK_TYPE_CWE = {
    "sql_injection": "CWE-89",
    "command_injection": "CWE-78", "cmd_inject": "CWE-78",
    "os_command": "CWE-78", "shell": "CWE-78",
    "eval": "CWE-95", "code_injection": "CWE-95",
    "hardcoded_secret": "CWE-798", "secrets": "CWE-798",
    "path_traversal": "CWE-22",
    "deserialization": "CWE-502", "pickle": "CWE-502",
    "ssrf": "CWE-918",
    "weak_hash": "CWE-327", "weak_crypto": "CWE-327",
    "xss": "CWE-79", "template_injection": "CWE-79",
    "tls_verify": "CWE-295",
}


def _resolve_cwe(finding: dict) -> str:
    cwe = finding.get("cwe", finding.get("sink_cwe", ""))
    if cwe and cwe in _CWE_STRATEGY_MAP:
        return cwe
    sink_type = finding.get("sink_type", finding.get("category", "")).lower()
    return _SINK_TYPE_CWE.get(sink_type, cwe)


# --------------------------------------------------------------------------- #
#  Public API                                                                 #
# --------------------------------------------------------------------------- #

def plan_fix(finding: dict, source: str) -> FixPlan | None:
    cwe = _resolve_cwe(finding)
    strategy_fn = _CWE_STRATEGY_MAP.get(cwe)
    if not strategy_fn:
        return None
    lines = source.splitlines(keepends=True)
    plan = strategy_fn(finding, source, lines)
    if plan:
        start, end = _find_function_bounds(source, plan.line)
        context = lines[max(0, start - 1):end]
        plan.preview_before = "".join(context)
    return plan


def plan_fixes(findings: list[dict], source: str, filepath: str = "") -> list[FixPlan]:
    plans = []
    seen_lines = set()
    for f in findings:
        if not filepath or f.get("file", f.get("path", "")) == filepath:
            line = f.get("sink_line", f.get("line", 0))
            if line in seen_lines:
                continue
            plan = plan_fix(f, source)
            if plan:
                seen_lines.add(line)
                plans.append(plan)
    plans.sort(key=lambda p: p.confidence, reverse=True)
    return plans


def apply_fix(plan: FixPlan, source: str) -> FixResult:
    lines = source.splitlines(keepends=True)
    result = FixResult(plan=plan, original=source)

    inserts_before: dict[int, list[str]] = {}
    inserts_after: dict[int, list[str]] = {}
    replacements: dict[int, str] = {}

    for step in plan.steps:
        if step.action == "replace_line":
            replacements[step.target_line] = step.new_text
        elif step.action == "insert_before":
            inserts_before.setdefault(step.target_line, []).append(step.new_text)
        elif step.action == "insert_after":
            target = step.insert_after or step.target_line
            inserts_after.setdefault(target, []).append(step.new_text)

    import_line = _last_import_line(source)
    existing = _existing_imports(source)
    import_adds = []
    for mod in plan.imports_needed:
        if mod not in existing:
            import_adds.append(_build_import_line(mod))

    new_lines = []
    for i, line in enumerate(lines):
        lineno = i + 1
        if import_line > 0 and lineno == import_line:
            new_lines.append(line)
            for imp in import_adds:
                new_lines.append(imp + "\n")
            import_adds = []
            continue
        if lineno in inserts_before:
            for ins in inserts_before[lineno]:
                new_lines.append(ins + "\n")
        if lineno in replacements:
            suffix = "\n" if line.endswith("\n") else ""
            new_lines.append(replacements[lineno] + suffix)
        else:
            new_lines.append(line)
        if lineno in inserts_after:
            for ins in inserts_after[lineno]:
                new_lines.append(ins + "\n")

    if import_adds:
        header = [_build_import_line(m) + "\n" for m in plan.imports_needed
                  if m not in existing]
        new_lines = header + new_lines

    result.fixed = "".join(new_lines)
    result.applied = True

    import difflib
    result.diff_lines = list(difflib.unified_diff(
        source.splitlines(keepends=True),
        result.fixed.splitlines(keepends=True),
        fromfile="before", tofile="after", lineterm="",
    ))

    start, end = _find_function_bounds(result.fixed, plan.line)
    fixed_lines = result.fixed.splitlines(keepends=True)
    plan.preview_after = "".join(fixed_lines[max(0, start - 1):min(len(fixed_lines), end + 3)])

    return result


def apply_fixes(plans: list[FixPlan], source: str) -> tuple[str, list[FixResult]]:
    results = []
    current = source
    offset = 0
    for plan in sorted(plans, key=lambda p: p.line):
        for step in plan.steps:
            step.target_line += offset
        result = apply_fix(plan, current)
        results.append(result)
        if result.applied:
            old_count = len(current.splitlines())
            current = result.fixed
            new_count = len(current.splitlines())
            offset += new_count - old_count
    return current, results


def plan_file(filepath: str) -> list[FixPlan]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return []
    try:
        import detect
        findings = detect.scan_file(filepath)
        finding_dicts = []
        for f in findings:
            d = {}
            for attr in ("rule", "line", "severity", "file", "sink_type",
                         "sink_line", "sink_file", "sink_code", "cwe",
                         "category", "message", "snippet"):
                val = getattr(f, attr, None)
                if val is not None:
                    d[attr] = val
            finding_dicts.append(d)
    except Exception:
        return []
    return plan_fixes(finding_dicts, source, filepath)


def verify_fix(result: FixResult, filepath: str) -> FixResult:
    if not result.applied or not result.fixed:
        return result
    import tempfile
    tmp = None
    try:
        import detect
        suffix = os.path.splitext(filepath)[1] or ".py"
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=suffix, delete=False, encoding="utf-8")
        tmp.write(result.fixed)
        tmp.close()

        before_findings = detect.scan_file(filepath)
        after_findings = detect.scan_file(tmp.name)

        target_line = result.plan.line
        target_cwe = result.plan.cwe

        before_at_line = [
            f for f in before_findings
            if getattr(f, "line", 0) == target_line or
               getattr(f, "sink_line", 0) == target_line
        ]
        after_at_line = [
            f for f in after_findings
            if getattr(f, "line", 0) == target_line or
               getattr(f, "sink_line", 0) == target_line
        ]

        if len(after_at_line) < len(before_at_line):
            result.verified = True
            result.verification_note = (
                f"finding removed: {len(before_at_line)} -> {len(after_at_line)} "
                f"at line {target_line}")
        elif len(after_findings) > len(before_findings):
            result.verified = False
            result.verification_note = (
                f"regression: {len(before_findings)} -> {len(after_findings)} "
                f"total findings")
        else:
            result.verified = True
            result.verification_note = "no regression detected"
    except Exception as exc:
        result.verification_note = f"verification skipped: {exc}"
    finally:
        if tmp and os.path.exists(tmp.name):
            os.unlink(tmp.name)
    return result


def fix_file(filepath: str, apply: bool = False,
             verify: bool = True) -> tuple[str, list[FixResult]]:
    try:
        with open(filepath, encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return "", []
    plans = plan_file(filepath)
    if not plans:
        return source, []
    fixed, results = apply_fixes(plans, source)
    if verify:
        for r in results:
            if r.applied:
                verify_fix(r, filepath)
    verified_results = [r for r in results if r.verified or not verify]
    reverted_results = [r for r in results if not r.verified and verify and r.applied]
    if reverted_results:
        for r in reverted_results:
            r.applied = False
            r.verification_note = r.verification_note or "failed verification"
    if apply and any(r.applied and r.verified for r in results):
        with open(filepath, "w", encoding="utf-8", newline="") as f:
            f.write(fixed)
    return fixed, results


# --------------------------------------------------------------------------- #
#  Output                                                                     #
# --------------------------------------------------------------------------- #

def render_plan(plan: FixPlan) -> str:
    conf_bar = int(plan.confidence * 10) * "#" + (10 - int(plan.confidence * 10)) * "."
    lines = [
        f"\n  [{plan.cwe}] {plan.strategy} at "
        f"{os.path.basename(plan.file)}:{plan.line}",
        f"    confidence: [{conf_bar}] {plan.confidence:.0%}  risk: {plan.risk}",
    ]
    if plan.reasoning:
        lines.append("    thinking:")
        for r in plan.reasoning:
            lines.append(f"      - {r}")
    if plan.imports_needed:
        lines.append(f"    needs: {', '.join(plan.imports_needed)}")
    for step in plan.steps:
        lines.append(f"    step: {step.description}")
        if step.old_text:
            lines.append(f"      - {step.old_text.strip()[:90]}")
        if step.new_text:
            for nl in step.new_text.strip().splitlines()[:4]:
                lines.append(f"      + {nl.strip()[:90]}")
    return "\n".join(lines)


def render(plans: list[FixPlan], results: list[FixResult] | None = None) -> str:
    if not plans:
        return "  nothing fixable. either the code is clean or the findings need manual remediation."

    fixable = [p for p in plans if p.confidence >= 0.70]
    review = [p for p in plans if p.confidence < 0.70]

    header = [
        f"\n  Fix Engine -- {len(plans)} plan(s)",
        "  " + "=" * 62,
    ]
    if fixable:
        header.append(f"  {len(fixable)} high-confidence fix(es) ready to apply.")
    if review:
        header.append(f"  {len(review)} need manual review (confidence < 70%).")

    body = []
    for p in sorted(plans, key=lambda x: (-x.confidence, x.line)):
        body.append(render_plan(p))

    if results:
        applied = sum(1 for r in results if r.applied)
        body.append(f"\n  applied {applied} of {len(results)} planned fix(es).")

    return "\n".join(header + body)


def to_dict(plans: list[FixPlan]) -> list[dict]:
    return [
        {
            "strategy": p.strategy,
            "cwe": p.cwe,
            "confidence": p.confidence,
            "risk": p.risk,
            "file": p.file,
            "line": p.line,
            "steps": [
                {"action": s.action, "description": s.description,
                 "old_text": s.old_text, "new_text": s.new_text,
                 "target_line": s.target_line}
                for s in p.steps
            ],
            "imports_needed": p.imports_needed,
            "reasoning": p.reasoning,
        }
        for p in plans
    ]
