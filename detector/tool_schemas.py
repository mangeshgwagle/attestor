"""Attestor 4.2 tool definitions for Owen Coder agent mode.

These definitions are used by ai_engine.agent_loop to tell the model
what tools are available and how to invoke them.
"""

TOOL_DEFINITIONS = [
    {
        "name": "scan_file",
        "description": "Run Attestor static analysis on a single source file. Returns findings with rule IDs, line numbers, severity, and messages.",
        "parameters": {
            "file_path": {"type": "string", "required": True, "description": "Path to the source file"},
            "language": {"type": "string", "required": False, "description": "Language hint (python, java, javascript, go, c, cpp, rust, csharp, ruby, php)"},
            "rules": {"type": "array", "required": False, "description": "Rule ID glob patterns to filter (e.g. ['PY-SEC-*'])"},
            "cwe_filter": {"type": "array", "required": False, "description": "Only report findings matching these CWE IDs"},
        },
    },
    {
        "name": "scan_directory",
        "description": "Recursively scan a directory for vulnerabilities. Returns per-file finding counts and totals.",
        "parameters": {
            "directory": {"type": "string", "required": True, "description": "Directory path to scan"},
            "language": {"type": "string", "required": False, "description": "Filter to a specific language"},
            "recursive": {"type": "boolean", "required": False, "description": "Recurse into subdirectories (default true)"},
            "cwe_filter": {"type": "array", "required": False, "description": "Only report findings matching these CWE IDs"},
        },
    },
    {
        "name": "search_rules",
        "description": "Search Attestor's rule database by keyword, CWE ID, language, or severity.",
        "parameters": {
            "query": {"type": "string", "required": False, "description": "Free-text search (e.g. 'SQL injection')"},
            "cwe": {"type": "string", "required": False, "description": "CWE ID to filter (e.g. 'CWE-89')"},
            "language": {"type": "string", "required": False, "description": "Language to filter rules for"},
            "severity": {"type": "string", "required": False, "description": "Severity level (CRITICAL, HIGH, MEDIUM, LOW)"},
        },
    },
    {
        "name": "get_rule_detail",
        "description": "Get full details for a specific Attestor rule by ID.",
        "parameters": {
            "rule_id": {"type": "string", "required": True, "description": "The rule ID (e.g. 'PY-SEC-001')"},
        },
    },
    {
        "name": "explain_finding",
        "description": "Get an AI-powered explanation of a specific finding, including impact, exploitability, and remediation.",
        "parameters": {
            "file_path": {"type": "string", "required": False, "description": "File where the finding was detected"},
            "line": {"type": "integer", "required": False, "description": "Line number of the finding"},
            "rule_id": {"type": "string", "required": False, "description": "Attestor rule ID"},
            "finding_type": {"type": "string", "required": False, "description": "Type of vulnerability (e.g. 'sql_injection')"},
            "code_snippet": {"type": "string", "required": False, "description": "Code snippet to analyze"},
        },
    },
    {
        "name": "suggest_fix",
        "description": "Generate a fix suggestion for a specific vulnerability finding.",
        "parameters": {
            "file_path": {"type": "string", "required": True, "description": "File to fix"},
            "line": {"type": "integer", "required": True, "description": "Line number of the vulnerability"},
            "vulnerability": {"type": "string", "required": False, "description": "Type of vulnerability"},
            "rule_id": {"type": "string", "required": False, "description": "Attestor rule ID"},
        },
    },
]
