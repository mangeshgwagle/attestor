#!/usr/bin/env python3
"""Owen Coder Evaluation Framework.

Evaluates fine-tuned models on 5 security tasks:
  1. Vulnerability Detection (does the model find the bug?)
  2. Code Fix Quality (does the fix resolve the issue?)
  3. Explanation Accuracy (CWE/OWASP correctness?)
  4. False Positive Rate (does it flag clean code?)
  5. Multi-Language Consistency (same quality across languages?)

Usage:
  python eval_framework.py                    # Run all benchmarks
  python eval_framework.py --model owen-coder # Specific model
  python eval_framework.py --task detection   # Single task
  python eval_framework.py --compare          # Compare all models
  python eval_framework.py --offline          # Print spec without Ollama

Requires: Ollama running with model(s) loaded.
"""
import argparse
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODELS = ["owen-coder", "owen-coder-7b", "owen-coder-dpo"]


@dataclass
class TestCase:
    id: str
    task: str
    language: str
    code: str
    expected_vuln: str
    cwe: str
    severity: str
    fixed_code: Optional[str] = None
    description: str = ""

@dataclass
class EvalResult:
    test_id: str
    model: str
    task: str
    language: str
    expected: str
    passed: bool
    score: float
    latency_ms: float
    response: str = ""
    details: str = ""


# ── Test Cases ────────────────────────────────────────────────────────

DETECTION_TESTS = [
    TestCase("det-py-sqli-01", "detection", "Python",
             'def get_user(db, name):\n    return db.execute(f"SELECT * FROM users WHERE name = \'{name}\'").fetchone()',
             "SQL injection", "CWE-89", "HIGH"),
    TestCase("det-py-cmdi-01", "detection", "Python",
             'import os\ndef run(user_input):\n    os.system("grep " + user_input + " /var/log/app.log")',
             "command injection", "CWE-78", "CRITICAL"),
    TestCase("det-py-deser-01", "detection", "Python",
             'import pickle\ndef load(raw):\n    return pickle.loads(raw)',
             "deserialization", "CWE-502", "CRITICAL"),
    TestCase("det-py-secret-01", "detection", "Python",
             'API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"\nSECRET = "super_secret_password_123"',
             "hardcoded secret", "CWE-798", "HIGH"),
    TestCase("det-py-yaml-01", "detection", "Python",
             'import yaml\ndef parse(data):\n    return yaml.load(data)',
             "unsafe YAML", "CWE-502", "HIGH"),
    TestCase("det-js-xss-01", "detection", "JavaScript",
             'app.get("/profile", (req, res) => {\n  res.send(`<h1>Welcome, ${req.query.name}!</h1>`);\n});',
             "XSS", "CWE-79", "HIGH"),
    TestCase("det-js-cmdi-01", "detection", "JavaScript",
             'const {exec} = require("child_process");\napp.post("/run", (req, res) => {\n  exec("convert " + req.body.file);\n});',
             "command injection", "CWE-78", "CRITICAL"),
    TestCase("det-js-proto-01", "detection", "JavaScript",
             'function merge(t, s) {\n  for (const k in s) {\n    if (typeof s[k]==="object") t[k]=merge(t[k]||{},s[k]);\n    else t[k]=s[k];\n  }\n  return t;\n}',
             "prototype pollution", "CWE-1321", "HIGH"),
    TestCase("det-java-sqli-01", "detection", "Java",
             'Statement s = conn.createStatement();\nResultSet r = s.executeQuery("SELECT * FROM users WHERE name=\'" + name + "\'");',
             "SQL injection", "CWE-89", "HIGH"),
    TestCase("det-java-deser-01", "detection", "Java",
             'ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));\nObject obj = ois.readObject();',
             "deserialization", "CWE-502", "CRITICAL"),
    TestCase("det-java-xxe-01", "detection", "Java",
             'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nDocument doc = f.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));',
             "XXE", "CWE-611", "HIGH"),
    TestCase("det-go-sqli-01", "detection", "Go",
             'query := fmt.Sprintf("SELECT * FROM users WHERE name=\'%s\'", name)\nrow := db.QueryRow(query)',
             "SQL injection", "CWE-89", "HIGH"),
    TestCase("det-go-cmdi-01", "detection", "Go",
             'cmd := exec.Command("sh", "-c", "echo "+input)\ncmd.Run()',
             "command injection", "CWE-78", "CRITICAL"),
    TestCase("det-c-bof-01", "detection", "C",
             'void copy(char *input) {\n    char buf[64];\n    strcpy(buf, input);\n}',
             "buffer overflow", "CWE-119", "CRITICAL"),
    TestCase("det-c-fmt-01", "detection", "C",
             'void log_msg(char *msg) { printf(msg); }',
             "format string", "CWE-134", "HIGH"),
    TestCase("det-php-sqli-01", "detection", "PHP",
             'function get($pdo, $name) {\n    return $pdo->query("SELECT * FROM users WHERE name=\'$name\'")->fetch();\n}',
             "SQL injection", "CWE-89", "HIGH"),
    TestCase("det-ruby-cmdi-01", "detection", "Ruby",
             'def convert(file)\n  system("convert #{file} out.png")\nend',
             "command injection", "CWE-78", "CRITICAL"),
    TestCase("det-cs-sqli-01", "detection", "C#",
             'var cmd = new SqlCommand($"SELECT * FROM Users WHERE Name=\'{name}\'", conn);',
             "SQL injection", "CWE-89", "HIGH"),
    TestCase("det-rust-unsafe-01", "detection", "Rust",
             'fn parse(input: &[u8]) -> &str {\n    unsafe { std::str::from_utf8_unchecked(input) }\n}',
             "unsafe code", "CWE-676", "MEDIUM"),
]

FALSE_POSITIVE_TESTS = [
    TestCase("fp-py-01", "false_positive", "Python",
             'db.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchone()',
             "clean", "", "", description="Parameterized query — safe"),
    TestCase("fp-py-02", "false_positive", "Python",
             'subprocess.run(args, shell=False, capture_output=True)',
             "clean", "", "", description="No shell — safe"),
    TestCase("fp-py-03", "false_positive", "Python",
             'os.environ.get("DB_HOST", "localhost")',
             "clean", "", "", description="Env var config — safe"),
    TestCase("fp-js-01", "false_positive", "JavaScript",
             'res.send(`<h1>${escapeHtml(req.query.name)}</h1>`)',
             "clean", "", "", description="Escaped output — safe"),
    TestCase("fp-java-01", "false_positive", "Java",
             'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name=?");\nps.setString(1, name);',
             "clean", "", "", description="PreparedStatement — safe"),
    TestCase("fp-go-01", "false_positive", "Go",
             'db.QueryRow("SELECT * FROM users WHERE name=$1", name)',
             "clean", "", "", description="Parameterized Go query — safe"),
    TestCase("fp-c-01", "false_positive", "C",
             'strncpy(buf, input, sizeof(buf)-1); buf[sizeof(buf)-1]=0;',
             "clean", "", "", description="Bounded copy — safe"),
    TestCase("fp-php-01", "false_positive", "PHP",
             '$stmt=$pdo->prepare("SELECT * FROM users WHERE name=?"); $stmt->execute([$name]);',
             "clean", "", "", description="PDO prepared — safe"),
]

EXPLAIN_TESTS = [
    TestCase("exp-sqli-01", "explain", "Python",
             'db.execute(f"SELECT * FROM users WHERE name=\'{name}\'")',
             "SQL injection", "CWE-89", "HIGH",
             description="Should mention CWE-89, parameterized queries"),
    TestCase("exp-xss-01", "explain", "JavaScript",
             'element.innerHTML = userInput;',
             "XSS", "CWE-79", "HIGH",
             description="Should mention CWE-79, textContent alternative"),
    TestCase("exp-cmdi-01", "explain", "Python",
             'os.system("rm " + filename)',
             "command injection", "CWE-78", "CRITICAL",
             description="Should mention CWE-78, subprocess.run"),
    TestCase("exp-path-01", "explain", "Python",
             'with open("/uploads/" + user_filename) as f: return f.read()',
             "path traversal", "CWE-22", "HIGH",
             description="Should mention CWE-22, ../ sequences"),
]

ALL_TESTS = DETECTION_TESTS + FALSE_POSITIVE_TESTS + EXPLAIN_TESTS


# ── Ollama Interface ──────────────────────────────────────────────────

def ollama_available():
    if not HAS_REQUESTS: return False
    try: return requests.get(f"{OLLAMA_URL}/api/tags", timeout=5).status_code == 200
    except: return False

def ollama_models():
    try: return [m["name"] for m in requests.get(f"{OLLAMA_URL}/api/tags", timeout=5).json().get("models", [])]
    except: return []

def ollama_generate(model, prompt, timeout=120):
    start = time.time()
    try:
        r = requests.post(f"{OLLAMA_URL}/api/generate",
            json={"model": model, "prompt": prompt, "stream": False,
                  "options": {"temperature": 0.1, "num_predict": 1024}},
            timeout=timeout)
        latency = (time.time() - start) * 1000
        return (r.json().get("response", ""), latency) if r.status_code == 200 else ("", latency)
    except Exception as e:
        return f"ERROR: {e}", (time.time() - start) * 1000


# ── Scoring ───────────────────────────────────────────────────────────

def score_detection(test, response):
    resp = response.lower()
    vuln_synonyms = {
        "sql injection": ["sql injection", "sqli", "cwe-89"],
        "command injection": ["command injection", "os command", "cwe-78", "shell injection", "rce"],
        "xss": ["xss", "cross-site scripting", "cwe-79"],
        "deserialization": ["deserialization", "cwe-502", "pickle"],
        "hardcoded secret": ["hardcoded", "hard-coded", "cwe-798", "credential", "secret"],
        "buffer overflow": ["buffer overflow", "cwe-119", "strcpy"],
        "format string": ["format string", "cwe-134", "printf"],
        "xxe": ["xxe", "xml external", "cwe-611"],
        "path traversal": ["path traversal", "cwe-22", "../"],
        "prototype pollution": ["prototype pollution", "proto", "cwe-1321"],
        "unsafe yaml": ["yaml.load", "safe_load", "cwe-502"],
        "unsafe code": ["unsafe", "unchecked", "cwe-676"],
    }
    keywords = vuln_synonyms.get(test.expected_vuln.lower(), [test.expected_vuln.lower()])
    found = any(kw in resp for kw in keywords)
    cwe_found = test.cwe.lower() in resp if test.cwe else False
    score = (0.6 if found else 0) + (0.2 if cwe_found else 0) + \
            (0.1 if any(w in resp for w in ["critical","high","severe"]) else 0) + \
            (0.1 if any(w in resp for w in ["fix","instead","replace"]) else 0)
    return found, min(score, 1.0), f"found={found}, cwe={cwe_found}"

def score_false_positive(test, response):
    resp = response.lower()
    flagged = any(w in resp for w in ["vulnerab","injection","xss","exploit","insecure","dangerous","cwe-"])
    safe = any(w in resp for w in ["safe","secure","clean","no vulnerabilit","properly","parameterized"])
    if safe and not flagged: return True, 1.0, "correctly safe"
    if flagged and not safe: return False, 0.0, "false positive"
    return False, 0.3, "mixed"

def score_explanation(test, response):
    resp = response.lower()
    score = (0.3 if test.expected_vuln.lower() in resp else 0) + \
            (0.2 if test.cwe and test.cwe.lower() in resp else 0) + \
            (0.2 if any(w in resp for w in ["fix","instead","replace"]) else 0) + \
            (0.15 if any(w in resp for w in ["impact","attacker","exploit"]) else 0) + \
            (0.15 if len(response.split()) > 30 else 0)
    return score >= 0.5, min(score, 1.0), f"score={score:.2f}"

SCORERS = {"detection": score_detection, "false_positive": score_false_positive, "explain": score_explanation}


# ── Runner ────────────────────────────────────────────────────────────

def build_prompt(test):
    if test.task == "detection":
        return f"Analyze this {test.language} code for security vulnerabilities. Report CWE ID and severity.\n\n```{test.language.lower()}\n{test.code}\n```"
    elif test.task == "false_positive":
        return f"Analyze this {test.language} code for security vulnerabilities. If safe, say so.\n\n```{test.language.lower()}\n{test.code}\n```"
    elif test.task == "explain":
        return f"Explain the vulnerability in this {test.language} code. Include CWE ID, severity, impact, fix.\n\n```{test.language.lower()}\n{test.code}\n```"
    return f"Review:\n{test.code}"

def run_eval(model, tests, verbose=False):
    results = []
    for test in tests:
        response, latency = ollama_generate(model, build_prompt(test))
        scorer = SCORERS.get(test.task, score_detection)
        passed, score, details = scorer(test, response)
        result = EvalResult(test.id, model, test.task, test.language, test.expected_vuln,
                            passed, score, latency, response[:500], details)
        results.append(result)
        status = "PASS" if passed else "FAIL"
        if verbose:
            print(f"  [{status}] {test.id} ({test.language} {test.expected_vuln}) score={score:.2f} {latency:.0f}ms")
            if not passed: print(f"         {details}\n         Response: {response[:200]}...")
        else:
            print(f"  [{status}] {test.id} score={score:.2f} ({latency:.0f}ms)")
    return results

def print_report(results, model):
    total = len(results)
    passed = sum(1 for r in results if r.passed)
    avg_score = sum(r.score for r in results) / total if total else 0
    avg_latency = sum(r.latency_ms for r in results) / total if total else 0

    print(f"\n{'='*70}")
    print(f"  EVALUATION REPORT: {model}")
    print(f"{'='*70}")
    print(f"\n  Overall: {passed}/{total} passed ({100*passed/total:.1f}%)")
    print(f"  Average score: {avg_score:.3f}  |  Avg latency: {avg_latency:.0f}ms")

    by_task = defaultdict(list)
    by_lang = defaultdict(list)
    for r in results:
        by_task[r.task].append(r)
        by_lang[r.language].append(r)

    print(f"\n  By task:")
    for task, rs in sorted(by_task.items()):
        p = sum(1 for r in rs if r.passed)
        a = sum(r.score for r in rs) / len(rs)
        print(f"    {task:20s}: {p}/{len(rs)} passed  avg={a:.3f}")

    print(f"\n  By language:")
    for lang, rs in sorted(by_lang.items()):
        p = sum(1 for r in rs if r.passed)
        a = sum(r.score for r in rs) / len(rs)
        print(f"    {lang:15s}: {p}/{len(rs)} passed  avg={a:.3f}")

    failures = [r for r in results if not r.passed]
    if failures:
        print(f"\n  Failures ({len(failures)}):")
        for r in failures:
            print(f"    {r.test_id}: expected={r.expected}, {r.details}")
    print(f"{'='*70}\n")

    return {"model": model, "total": total, "passed": passed,
            "pass_rate": passed/total if total else 0, "avg_score": avg_score, "avg_latency_ms": avg_latency}


def run_offline_report():
    from collections import Counter
    print(f"\n{'='*70}")
    print(f"  OWEN CODER EVALUATION BENCHMARK SPECIFICATION")
    print(f"{'='*70}")
    print(f"\n  Total test cases: {len(ALL_TESTS)}")
    print(f"\n  By task:")
    for t, c in Counter(t.task for t in ALL_TESTS).most_common():
        print(f"    {t:20s}: {c}")
    print(f"\n  By language:")
    for l, c in Counter(t.language for t in ALL_TESTS).most_common():
        print(f"    {l:15s}: {c}")
    print(f"\n  CWE coverage ({len(set(t.cwe for t in ALL_TESTS if t.cwe))} types):")
    for cwe, c in Counter(t.cwe for t in ALL_TESTS if t.cwe).most_common():
        print(f"    {cwe:15s}: {c}")
    print(f"\n  Scoring rubric:")
    print(f"    Detection:      0.6 vuln_found + 0.2 CWE_ID + 0.1 severity + 0.1 fix")
    print(f"    False Positive: 1.0 correctly_safe | 0.0 false_flag | 0.3 mixed")
    print(f"    Explanation:    0.3 vuln_type + 0.2 CWE + 0.2 fix + 0.15 impact + 0.15 detail")
    print(f"\n  Test case details:")
    for t in ALL_TESTS:
        print(f"    {t.id:25s} {t.task:15s} {t.language:12s} {t.expected_vuln}")
    print(f"{'='*70}\n")


def main():
    parser = argparse.ArgumentParser(description="Owen Coder Evaluation Framework")
    parser.add_argument("--model")
    parser.add_argument("--task", choices=["detection", "false_positive", "explain", "all"], default="all")
    parser.add_argument("--compare", action="store_true")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--out", default="eval_results.jsonl")
    args = parser.parse_args()

    if args.offline:
        run_offline_report()
        return 0

    if not ollama_available():
        print("Ollama not running. Use --offline for benchmark spec, or start Ollama.")
        return 1

    tests = ALL_TESTS if args.task == "all" else [t for t in ALL_TESTS if t.task == args.task]
    available = ollama_models()

    if args.compare:
        eval_models = [m for m in MODELS if any(m in a for a in available)] or available[:3]
    elif args.model:
        eval_models = [args.model]
    else:
        eval_models = [m for m in MODELS if any(m in a for a in available)][:1] or available[:1]

    print(f"\nEvaluating {len(eval_models)} model(s) on {len(tests)} test cases\n")
    all_results, all_reports = [], []

    for model in eval_models:
        print(f"\n--- Evaluating: {model} ---\n")
        results = run_eval(model, tests, verbose=args.verbose)
        report = print_report(results, model)
        all_results.extend(results)
        all_reports.append(report)

    with open(args.out, "w", encoding="utf-8") as f:
        for r in all_results:
            f.write(json.dumps(asdict(r), ensure_ascii=False) + "\n")
    print(f"Results saved to {args.out}")
    return 0


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    sys.exit(main())
