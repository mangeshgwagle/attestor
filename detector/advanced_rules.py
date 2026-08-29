#!/usr/bin/env python3
"""Attestor 3.0's scalable, self-proving advanced rule pack.

The original engines remain the precision core.  This module broadens coverage
with conservative, declarative checks for modern application languages, CI/CD,
cloud configuration, containers, shell code, and smart contracts.  Every rule
ships with a positive fixture and metadata, so catalog growth is measurable and
testable instead of being an inflated regex count.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import re
import tokenize
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass(frozen=True)
class Rule:
    rid: str
    language: str
    severity: str
    pattern: str
    message: str
    fix: str
    category: str
    cwe: str
    path_hint: str
    example: str
    confidence: float = 0.88
    view: str = "code"

    def regex(self):
        return re.compile(self.pattern, re.IGNORECASE)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    language: str
    rule: str
    severity: str
    message: str
    fix: str
    category: str
    cwe: str
    owasp: str
    confidence: float
    evidence: str
    pack: str = "advanced-2.2"


OWASP_BY_CWE = {
    "CWE-20": "A04:2021 Insecure Design",
    "CWE-22": "A01:2021 Broken Access Control",
    "CWE-73": "A01:2021 Broken Access Control",
    "CWE-78": "A03:2021 Injection",
    "CWE-79": "A03:2021 Injection",
    "CWE-89": "A03:2021 Injection",
    "CWE-94": "A03:2021 Injection",
    "CWE-95": "A03:2021 Injection",
    "CWE-200": "A01:2021 Broken Access Control",
    "CWE-209": "A05:2021 Security Misconfiguration",
    "CWE-242": "A04:2021 Insecure Design",
    "CWE-250": "A04:2021 Insecure Design",
    "CWE-276": "A01:2021 Broken Access Control",
    "CWE-295": "A07:2021 Identification and Authentication Failures",
    "CWE-319": "A02:2021 Cryptographic Failures",
    "CWE-326": "A02:2021 Cryptographic Failures",
    "CWE-327": "A02:2021 Cryptographic Failures",
    "CWE-330": "A02:2021 Cryptographic Failures",
    "CWE-347": "A08:2021 Software and Data Integrity Failures",
    "CWE-352": "A01:2021 Broken Access Control",
    "CWE-362": "A04:2021 Insecure Design",
    "CWE-400": "A04:2021 Insecure Design",
    "CWE-477": "A06:2021 Vulnerable and Outdated Components",
    "CWE-489": "A05:2021 Security Misconfiguration",
    "CWE-502": "A08:2021 Software and Data Integrity Failures",
    "CWE-601": "A01:2021 Broken Access Control",
    "CWE-611": "A05:2021 Security Misconfiguration",
    "CWE-732": "A01:2021 Broken Access Control",
    "CWE-798": "A07:2021 Identification and Authentication Failures",
    "CWE-918": "A10:2021 Server-Side Request Forgery",
}


RULES: list[Rule] = []


def _add(language: str, path_hint: str, category: str, cwe: str, fix: str,
         rows: list[tuple]) -> None:
    for row in rows:
        rid, severity, pattern, message, example, *extra = row
        view = extra[0] if extra else "code"
        confidence = float(extra[1]) if len(extra) > 1 else 0.88
        RULES.append(Rule(rid, language, severity, pattern, message, fix,
                          category, cwe, path_hint, example, confidence, view))


# Python: security boundaries plus async/concurrency and correctness traps.
_add("python", "sample.py", "archive/filesystem", "CWE-22",
     "validate every member path against the destination before extraction.", [
    ("adv-py-tar-extractall", "HIGH", r"\.extractall\s*\(",
     "bulk archive extraction can write outside the destination", "archive.extractall(dst)"),
    ("adv-py-tempfile-mktemp", "HIGH", r"\btempfile\.mktemp\s*\(",
     "mktemp has a race between name creation and use", "path = tempfile.mktemp()"),
    ("adv-py-world-writable", "HIGH", r"\bos\.chmod\s*\([^\n,]+,\s*0o?777\b",
     "world-writable permissions are assigned", "os.chmod(path, 0o777)"),
])
_add("python", "sample.py", "deserialization", "CWE-502",
     "use a schema-based format and reject untrusted object graphs.", [
    ("adv-py-marshal-load", "HIGH", r"\bmarshal\.loads?\s*\(",
     "marshal is not safe for untrusted data", "value = marshal.loads(data)"),
    ("adv-py-numpy-pickle", "HIGH", r"\b(?:numpy|np)\.load\s*\([^\n]*\ballow_pickle\s*=\s*True",
     "NumPy object loading enables pickle deserialization", "arr = np.load(path, allow_pickle=True)"),
])
_add("python", "sample.py", "transport-security", "CWE-295",
     "use normal certificate and hostname validation with a trusted CA store.", [
    ("adv-py-unverified-ssl-context", "HIGH", r"\bssl\._create_unverified_context\s*\(",
     "an unverified TLS context disables certificate validation", "ctx = ssl._create_unverified_context()"),
    ("adv-py-ssl-no-hostname", "HIGH", r"\.check_hostname\s*=\s*False\b",
     "TLS hostname validation is disabled", "context.check_hostname = False"),
    ("adv-py-aiohttp-no-tls", "HIGH", r"\bTCPConnector\s*\([^\n]*\bssl\s*=\s*False",
     "aiohttp TLS verification is disabled", "conn = TCPConnector(ssl=False)"),
    ("adv-py-httpx-no-tls", "HIGH", r"\bhttpx\.(?:Client|AsyncClient|get|post)\s*\([^\n]*\bverify\s*=\s*False",
     "HTTPX certificate verification is disabled", "client = httpx.Client(verify=False)"),
])
_add("python", "sample.py", "authentication/crypto", "CWE-347",
     "verify signatures, algorithms, issuer, audience, and expiry before trusting claims.", [
    ("adv-py-jwt-signature-off", "CRITICAL", r"\bjwt\.decode\s*\([^\n]*\boptions\s*=\s*\{[^\n]*:\s*False",
     "JWT signature verification is explicitly disabled", "claims = jwt.decode(token, options={verify_signature: False})"),
    ("adv-py-jwt-unverified", "HIGH", r"\bget_unverified_(?:header|claims)\s*\(",
     "unverified JWT data is consumed", "claims = get_unverified_claims(token)"),
])
_add("python", "sample.py", "web-security", "CWE-79",
     "preserve framework escaping and sanitize only through a reviewed policy.", [
    ("adv-py-django-mark-safe", "HIGH", r"\bmark_safe\s*\(",
     "Django output escaping is bypassed", "return mark_safe(value)"),
    ("adv-py-jinja-autoescape-off", "HIGH", r"\bEnvironment\s*\([^\n]*\bautoescape\s*=\s*False",
     "Jinja autoescaping is disabled", "env = Environment(autoescape=False)"),
])
_add("python", "sample.py", "access-control", "CWE-352",
     "keep CSRF protection and use narrow, reviewed exemptions only when unavoidable.", [
    ("adv-py-django-csrf-exempt", "MEDIUM", r"@csrf_exempt\b",
     "a Django endpoint bypasses CSRF protection", "@csrf_exempt\ndef update(request): pass"),
])
_add("python", "sample.py", "availability", "CWE-400",
     "set finite timeouts and bound all externally controlled work.", [
    ("adv-py-requests-timeout-none", "MEDIUM", r"\brequests\.(?:get|post|put|patch|delete|request)\s*\([^\n]*\btimeout\s*=\s*None",
     "the HTTP request explicitly has no deadline", "requests.get(url, timeout=None)"),
    ("adv-py-regex-user-compile", "MEDIUM", r"\bre\.compile\s*\(\s*(?:user_(?:pattern|regex)|request\.)",
     "an untrusted regular expression can cause excessive backtracking", "rx = re.compile(user_pattern)"),
])
_add("python", "sample.py", "async/concurrency", "CWE-400",
     "use non-blocking APIs and keep task references until completion.", [
    ("adv-py-blocking-sleep-async", "MEDIUM", r"\btime\.sleep\s*\(",
     "time.sleep can block an async event loop", "async def work(): time.sleep(1)"),
    ("adv-py-blocking-http-async", "MEDIUM", r"\brequests\.(?:get|post|request)\s*\(",
     "synchronous HTTP can block an async event loop", "async def work(): requests.get(url)"),
    ("adv-py-task-reference-lost", "LOW", r"^\s*asyncio\.create_task\s*\(",
     "a fire-and-forget task has no retained reference or error observer", "asyncio.create_task(worker())"),
])
_add("python", "sample.py", "correctness", "CWE-20",
     "represent the intended state explicitly and preserve failure semantics.", [
    ("adv-py-bool-env", "MEDIUM", r"\bbool\s*\(\s*os\.(?:getenv|environ\.get)\s*\(",
     "bool('false') is true, so environment flags are parsed incorrectly", "enabled = bool(os.getenv(KEY))"),
    ("adv-py-return-finally", "HIGH", r"^\s*return\b", "return inside finally can suppress exceptions",
     "try: work()\nfinally:\n    return result", "raw", 0.82),
    ("adv-py-naive-datetime-now", "LOW", r"\bdatetime\.(?:datetime\.)?now\s*\(\s*\)",
     "a naive local datetime is ambiguous across zones and DST", "stamp = datetime.now()"),
])

# JavaScript / TypeScript and browser frameworks.
_add("javascript", "client.js", "code-injection", "CWE-78",
     "invoke a fixed executable with an argument array and shell disabled.", [
    ("adv-js-child-process-exec", "HIGH", r"\bchild_process\.exec(?:Sync)?\s*\(",
     "child_process.exec interprets a command string through a shell", "child_process.exec(command)"),
    ("adv-js-spawn-shell", "HIGH", r"\bspawn(?:Sync)?\s*\([^\n]*\bshell\s*:\s*true",
     "spawn is configured to use a command shell", "spawn(tool, args, {shell: true})"),
])
_add("javascript", "client.js", "code-injection", "CWE-95",
     "parse structured data and use explicit dispatch instead of runtime compilation.", [
    ("adv-js-function-constructor", "HIGH", r"\bnew\s+Function\s*\(",
     "Function constructs executable code from strings", "const fn = new Function(source)"),
    ("adv-js-vm-run-string", "HIGH", r"\bvm\.runIn(?:This|New)Context\s*\(",
     "Node VM execution is not a security boundary for hostile code", "vm.runInNewContext(source)"),
])
_add("javascript", "client.js", "cross-site-scripting", "CWE-79",
     "write text or use a vetted sanitizer and a strict rendering boundary.", [
    ("adv-js-document-write", "HIGH", r"\bdocument\.write(?:ln)?\s*\(",
     "document.write creates an HTML injection sink", "document.write(value)"),
    ("adv-js-react-dangerous-html", "HIGH", r"\bdangerouslySetInnerHTML\s*=",
     "React's escaping boundary is explicitly bypassed", "return <div dangerouslySetInnerHTML={props} />"),
    ("adv-js-angular-bypass-security", "HIGH", r"\bbypassSecurityTrust(?:Html|Script|Url|ResourceUrl)\s*\(",
     "Angular sanitization is explicitly bypassed", "safe = sanitizer.bypassSecurityTrustHtml(value)"),
    ("adv-js-vue-v-html", "HIGH", r"\bv-html\s*=", "Vue renders a value as raw HTML",
     "<div v-html=content></div>", "raw"),
])
_add("javascript", "client.js", "transport-security", "CWE-295",
     "retain normal TLS verification and a trusted certificate chain.", [
    ("adv-js-reject-unauthorized-false", "HIGH", r"\brejectUnauthorized\s*:\s*false",
     "Node TLS certificate verification is disabled", "https.get(url, {rejectUnauthorized: false})"),
    ("adv-js-node-tls-env-off", "CRITICAL", r"\bNODE_TLS_REJECT_UNAUTHORIZED\b\s*=",
     "the process-wide Node TLS verification switch is modified", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = zero"),
])
_add("javascript", "client.js", "authentication/session", "CWE-347",
     "verify the token cryptographically and enforce issuer, audience, algorithm, and expiry.", [
    ("adv-js-jwt-decode-auth", "HIGH", r"\bjwt\.decode\s*\(",
     "JWT payload is decoded without signature verification", "const claims = jwt.decode(token)"),
    ("adv-js-cookie-secure-off", "HIGH", r"\b(?:cookie|session)[^\n]*\bsecure\s*:\s*false",
     "a cookie is allowed over cleartext transport", "res.cookie(name, value, {secure: false})"),
    ("adv-js-cookie-httponly-off", "MEDIUM", r"\b(?:cookie|session)[^\n]*\bhttpOnly\s*:\s*false",
     "a session-like cookie is readable by scripts", "res.cookie(name, value, {httpOnly: false})"),
])
_add("javascript", "client.js", "browser-security", "CWE-79",
     "use a specific trusted origin and validate message shape and sender.", [
    ("adv-js-postmessage-star", "HIGH", r"\.postMessage\s*\([^\n]+,\s*[\"']\*[\"']\s*\)",
     "postMessage sends sensitive data to every origin", "frame.postMessage(data, '*')", "raw"),
    ("adv-js-message-no-origin", "MEDIUM", r"addEventListener\s*\(\s*[\"']message[\"']",
     "a message handler requires an explicit event.origin check", "addEventListener('message', event => handle(event.data))", "raw", 0.76),
])
_add("javascript", "client.js", "cryptography", "CWE-330",
     "use crypto.randomBytes/getRandomValues for security-sensitive values.", [
    ("adv-js-math-random-token", "HIGH", r"\b(?:token|secret|nonce|session|password)\w*\s*=\s*Math\.random\s*\(",
     "Math.random is predictable for a security-sensitive value", "const token = Math.random()"),
])
_add("javascript", "client.js", "correctness", "CWE-20",
     "use an iteration/control-flow primitive whose semantics match the intent.", [
    ("adv-js-async-promise-executor", "MEDIUM", r"new\s+Promise\s*\(\s*async\b",
     "an async Promise executor can lose thrown errors", "return new Promise(async resolve => work())"),
    ("adv-js-async-react-effect", "MEDIUM", r"\buseEffect\s*\(\s*async\b",
     "an async React effect returns a Promise instead of a cleanup function", "useEffect(async () => load(), [])"),
    ("adv-js-array-fill-object", "MEDIUM", r"\.fill\s*\(\s*\{",
     "Array.fill reuses the same object in every slot", "const rows = Array(5).fill({value: 0})"),
    ("adv-js-delete-array-slot", "LOW", r"\bdelete\s+\w+\s*\[[^\]]+\]",
     "delete leaves a sparse hole in an array", "delete items[index]"),
    ("adv-js-number-unsafe-integer", "HIGH", r"\b\d{16,}\b",
     "the integer literal may exceed Number's exact range", "const id = 9007199254740993"),
])

# Java and Kotlin/JVM.
_add("java", "Sample.java", "deserialization", "CWE-502",
     "use schema-based serialization with explicit allowed types.", [
    ("adv-java-jackson-default-typing", "HIGH", r"\.enableDefaultTyping\s*\(",
     "Jackson polymorphic default typing expands the deserialization attack surface", "mapper.enableDefaultTyping()"),
    ("adv-java-xstream-any-type", "HIGH", r"\.allowTypesByWildcard\s*\(",
     "broad XStream type wildcards permit dangerous object construction", "xstream.allowTypesByWildcard(types)"),
])
_add("java", "Sample.java", "xml-security", "CWE-611",
     "disable DTDs/external entities and enable secure XML processing.", [
    ("adv-java-xml-external-entities", "HIGH", r"setFeature\s*\([^\n]*external-(?:general|parameter)-entities[^\n]*true",
     "external XML entities are enabled", "factory.setFeature(external-general-entities, true)"),
    ("adv-java-schema-external-all", "HIGH", r"ACCESS_EXTERNAL_(?:DTD|SCHEMA)[^\n]*ALL",
     "XML schema processing permits arbitrary external resources", "factory.setProperty(ACCESS_EXTERNAL_DTD, ALL)"),
])
_add("java", "Sample.java", "transport-security", "CWE-295",
     "use the platform trust manager and verify hostnames normally.", [
    ("adv-java-hostname-verifier-true", "CRITICAL", r"HostnameVerifier[^\n]*->\s*true",
     "the hostname verifier accepts every host", "HostnameVerifier verifier = (host, session) -> true"),
    ("adv-java-trust-all-manager", "CRITICAL", r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}",
     "the custom trust manager accepts every certificate", "void checkServerTrusted(X509Certificate[] c, String a) { }"),
])
_add("java", "Sample.java", "cryptography", "CWE-327",
     "use a modern approved algorithm and authenticated encryption.", [
    ("adv-java-weak-message-digest", "HIGH", r"MessageDigest\.getInstance\s*\(\s*[\"'](?:MD5|SHA-?1)[\"']",
     "a broken digest algorithm is selected", "MessageDigest.getInstance('MD5')", "raw"),
    ("adv-java-ecb-cipher", "HIGH", r"Cipher\.getInstance\s*\(\s*[\"'][^\"']*/ECB/",
     "ECB mode leaks plaintext patterns", "Cipher.getInstance('AES/ECB/PKCS5Padding')", "raw"),
])
_add("java", "Sample.java", "injection", "CWE-78",
     "invoke a fixed executable using ProcessBuilder's argument list.", [
    ("adv-java-script-engine-eval", "HIGH", r"\b(?:engine|scriptEngine)\.eval\s*\(",
     "a scripting engine evaluates runtime text", "engine.eval(source)"),
    ("adv-java-shell-processbuilder", "HIGH", r"new\s+ProcessBuilder\s*\(\s*[\"'](?:sh|bash|cmd|powershell)",
     "ProcessBuilder invokes a command shell", "new ProcessBuilder('sh', '-c', command)", "raw"),
])
_add("java", "Sample.java", "web-security", "CWE-352",
     "retain CSRF protection and configure narrowly scoped CORS.", [
    ("adv-java-spring-csrf-off", "HIGH", r"\.csrf\s*\([^;\n]*\.disable\s*\(",
     "Spring Security CSRF protection is disabled", "http.csrf(config -> config.disable())"),
    ("adv-java-cors-any-origin", "HIGH", r"addAllowedOrigin\s*\(\s*[\"']\*[\"']",
     "CORS permits every origin", "config.addAllowedOrigin('*')", "raw"),
])
_add("java", "Sample.java", "correctness", "CWE-20",
     "use value-aware APIs and preserve thread interruption semantics.", [
    ("adv-java-string-reference-equality", "MEDIUM", r"\b(?:name|text|value|input|token)\s*==\s*(?:name|text|value|input|token)\b",
     "Java == compares String/object identity rather than value", "if (name == input) accept()"),
    ("adv-java-bigdecimal-double", "MEDIUM", r"new\s+BigDecimal\s*\(\s*\d+\.\d+",
     "BigDecimal(double) preserves binary floating-point error", "BigDecimal amount = new BigDecimal(0.1)"),
    ("adv-java-thread-stop", "HIGH", r"\.stop\s*\(\s*\)",
     "Thread.stop can leave shared state inconsistent", "worker.stop()"),
    ("adv-java-synchronized-string", "MEDIUM", r"synchronized\s*\(\s*[\"']",
     "locking on an interned String creates accidental lock sharing", "synchronized ('lock') { work(); }", "raw"),
])

_add("kotlin", "Sample.kt", "mobile/web-security", "CWE-79",
     "keep WebView capabilities off unless strictly required and isolate untrusted content.", [
    ("adv-kotlin-webview-javascript", "HIGH", r"javaScriptEnabled\s*=\s*true",
     "Android WebView JavaScript execution is enabled", "web.settings.javaScriptEnabled = true"),
    ("adv-kotlin-webview-file-access", "HIGH", r"allowFileAccess\s*=\s*true",
     "Android WebView can access local files", "web.settings.allowFileAccess = true"),
    ("adv-kotlin-add-javascript-interface", "HIGH", r"\.addJavascriptInterface\s*\(",
     "a native object is exposed to WebView JavaScript", "web.addJavascriptInterface(bridge, name)"),
])
_add("kotlin", "Sample.kt", "injection", "CWE-78",
     "invoke the executable directly with a fixed argument list.", [
    ("adv-kotlin-runtime-exec", "HIGH", r"Runtime\.getRuntime\s*\(\s*\)\.exec\s*\(",
     "Runtime.exec is a command-injection boundary", "Runtime.getRuntime().exec(command)"),
])
_add("kotlin", "Sample.kt", "correctness", "CWE-20",
     "avoid forced nullable operations and blocking calls in coroutines.", [
    ("adv-kotlin-global-scope", "MEDIUM", r"\bGlobalScope\.(?:launch|async)\s*\(",
     "GlobalScope creates work with an unmanaged lifetime", "GlobalScope.launch({ work() })"),
    ("adv-kotlin-runblocking-suspend", "MEDIUM", r"\brunBlocking\s*\(",
     "runBlocking can stall a request/UI thread", "runBlocking({ service.load() })"),
])

# C# / .NET.
_add("csharp", "Sample.cs", "injection", "CWE-89",
     "use parameterized commands and keep data separate from SQL text.", [
    ("adv-csharp-sql-concat", "HIGH", r"new\s+SqlCommand\s*\([^\n]*(?:\+|\$[\"'])",
     "SQL command text is dynamically assembled", "var cmd = new SqlCommand(query + input)"),
])
_add("csharp", "Sample.cs", "transport-security", "CWE-295",
     "use the platform certificate validator and normal hostname verification.", [
    ("adv-csharp-cert-callback-true", "CRITICAL", r"ServerCertificateCustomValidationCallback[^\n]*=>\s*true",
     "the HTTP certificate callback accepts every certificate", "handler.ServerCertificateCustomValidationCallback = (a,b,c,d) => true"),
    ("adv-csharp-cert-policy-any", "CRITICAL", r"DangerousAcceptAnyServerCertificateValidator",
     "the built-in accept-any certificate validator is used", "handler.ServerCertificateCustomValidationCallback = DangerousAcceptAnyServerCertificateValidator"),
])
_add("csharp", "Sample.cs", "cryptography", "CWE-327",
     "use SHA-256+ for hashes and AES-GCM/ChaCha20-Poly1305 for encryption.", [
    ("adv-csharp-md5", "HIGH", r"\bMD5\.(?:Create|HashData)\s*\(",
     "MD5 is cryptographically broken", "using var hash = MD5.Create()"),
    ("adv-csharp-des", "HIGH", r"\b(?:DES|TripleDES)\.Create\s*\(",
     "DES-family encryption is obsolete", "using var cipher = DES.Create()"),
])
_add("csharp", "Sample.cs", "web-security", "CWE-79",
     "retain output encoding and configure explicit trusted origins.", [
    ("adv-csharp-html-raw", "HIGH", r"\bHtml\.Raw\s*\(",
     "Razor output encoding is bypassed", "@Html.Raw(Model.Content)"),
    ("adv-csharp-cors-any", "HIGH", r"\.AllowAnyOrigin\s*\(",
     "ASP.NET CORS permits every origin", "policy.AllowAnyOrigin()"),
])
_add("csharp", "Sample.cs", "deserialization", "CWE-502",
     "use System.Text.Json with explicit DTOs and disallow runtime type metadata.", [
    ("adv-csharp-netdatacontract", "HIGH", r"\bNetDataContractSerializer\b",
     "runtime type metadata enables unsafe object deserialization", "var serializer = new NetDataContractSerializer()"),
    ("adv-csharp-json-typename-all", "HIGH", r"TypeNameHandling\s*=\s*TypeNameHandling\.(?:All|Auto)",
     "JSON.NET type-name handling permits attacker-selected types", "settings.TypeNameHandling = TypeNameHandling.All"),
])
_add("csharp", "Sample.cs", "correctness", "CWE-362",
     "use await, preserve stack traces, and lock on a private dedicated object.", [
    ("adv-csharp-sync-over-async", "MEDIUM", r"\b(?:task|\w+Task|operation)\.(?:Result|Wait\s*\(\s*\))",
     "blocking on an asynchronous operation can deadlock", "var value = task.Result"),
    ("adv-csharp-lock-this", "MEDIUM", r"\block\s*\(\s*this\s*\)",
     "locking on this exposes the lock to external code", "lock (this) { Update(); }"),
    ("adv-csharp-throw-ex", "MEDIUM", r"\bthrow\s+ex\s*;",
     "throw ex resets the original stack trace", "catch (Exception ex) { throw ex; }"),
    ("adv-csharp-regex-no-timeout", "MEDIUM", r"new\s+Regex\s*\([^,;)]+\)",
     "a regex without a timeout can consume unbounded CPU", "var rx = new Regex(pattern)"),
])

# Go.
_add("go", "sample.go", "cryptography", "CWE-327",
     "use SHA-256+ and crypto/rand for security-sensitive operations.", [
    ("adv-go-weak-hash", "HIGH", r"\b(?:md5|sha1)\.New\s*\(",
     "a broken hash primitive is used", "h := md5.New()"),
    ("adv-go-math-rand-token", "HIGH", r"\b(?:token|secret|nonce|session)\w*\s*:?=\s*rand\.(?:Int|Intn|Uint64|Read)\s*\(",
     "math/rand generates a security-sensitive value", "token := rand.Int()"),
])
_add("go", "sample.go", "injection", "CWE-89",
     "use database placeholders and pass values separately.", [
    ("adv-go-sql-format", "HIGH", r"(?:Query|Exec)(?:Context)?\s*\(\s*fmt\.Sprintf\s*\(",
     "SQL is assembled with fmt.Sprintf", "db.Query(fmt.Sprintf(query, input))"),
])
_add("go", "sample.go", "filesystem/access", "CWE-732",
     "use least-privilege modes such as 0600/0700.", [
    ("adv-go-chmod-777", "HIGH", r"\bos\.(?:Chmod|MkdirAll|WriteFile)\s*\([^\n]*0?777\b",
     "world-writable permissions are requested", "os.Chmod(path, 0777)"),
])
_add("go", "sample.go", "availability", "CWE-400",
     "apply explicit size/deadline limits to network and body operations.", [
    ("adv-go-readall-body", "MEDIUM", r"\b(?:io|ioutil)\.ReadAll\s*\(\s*(?:r\.)?Body\s*\)",
     "an HTTP body is read without a visible size limit", "data, err := io.ReadAll(r.Body)"),
    ("adv-go-http-no-timeout", "MEDIUM", r"\bhttp\.(?:Get|Post)\s*\(",
     "the package-level HTTP client has no request timeout", "resp, err := http.Get(url)"),
    ("adv-go-serve-no-timeouts", "MEDIUM", r"http\.Server\s*\{\s*Addr\s*:",
     "the HTTP server literal has no visible read/write/header timeouts", "srv := http.Server{Addr: addr}"),
])
_add("go", "sample.go", "correctness/concurrency", "CWE-362",
     "place cleanup outside loops, propagate errors, and use bounded timers.", [
    ("adv-go-defer-in-loop", "MEDIUM", r"\bfor\b[^{]*\{[^}]*\bdefer\b", "defer inside a loop can retain resources until function exit",
     "for rows.Next() { defer rows.Close() }", "raw", 0.78),
    ("adv-go-time-tick", "MEDIUM", r"\btime\.Tick\s*\(",
     "time.Tick cannot be stopped and can leak resources", "ticks := time.Tick(time.Second)"),
    ("adv-go-ignored-serve-error", "MEDIUM", r"^\s*(?:http\.)?ListenAndServe\s*\(",
     "the server's terminal error is ignored", "http.ListenAndServe(addr, handler)"),
])

# Rust.
_add("rust", "sample.rs", "transport-security", "CWE-295",
     "retain certificate and hostname validation.", [
    ("adv-rust-invalid-certs", "CRITICAL", r"danger_accept_invalid_certs\s*\(\s*true",
     "the HTTP client accepts invalid certificates", "builder.danger_accept_invalid_certs(true)"),
    ("adv-rust-invalid-hostnames", "CRITICAL", r"danger_accept_invalid_hostnames\s*\(\s*true",
     "the HTTP client accepts invalid hostnames", "builder.danger_accept_invalid_hostnames(true)"),
])
_add("rust", "sample.rs", "memory-safety", "CWE-242",
     "encapsulate unsafe ownership operations behind a reviewed safe invariant.", [
    ("adv-rust-from-raw", "HIGH", r"\b(?:Box|Vec|CString)::from_raw\s*\(",
     "raw ownership reconstruction can double-free or use invalid memory", "let value = Box::from_raw(ptr)"),
    ("adv-rust-get-unchecked", "HIGH", r"\.get_unchecked(?:_mut)?\s*\(",
     "unchecked indexing bypasses Rust bounds guarantees", "let value = slice.get_unchecked(index)"),
    ("adv-rust-static-mut", "HIGH", r"\bstatic\s+mut\b",
     "mutable static state can create data races", "static mut COUNT: usize = 0"),
    ("adv-rust-mem-forget", "MEDIUM", r"\b(?:std::mem::)?forget\s*\(",
     "forget deliberately skips destructors and can leak critical resources", "std::mem::forget(value)"),
])
_add("rust", "sample.rs", "cryptography", "CWE-327",
     "use a modern reviewed cryptographic crate and algorithm.", [
    ("adv-rust-weak-hash", "HIGH", r"\b(?:md5|sha1)::(?:compute|Sha1|Context)\b",
     "a broken hash algorithm is used", "let digest = md5::compute(data)"),
])
_add("rust", "sample.rs", "injection", "CWE-89",
     "use bound query parameters rather than format macros.", [
    ("adv-rust-sql-format", "HIGH", r"(?:query|execute)\s*\(\s*(?:&)?format!\s*\(",
     "SQL text is built with format!", "sqlx::query(&format!(query, value))"),
])
_add("rust", "sample.rs", "correctness/concurrency", "CWE-362",
     "use async-aware primitives and propagate recoverable failures.", [
    ("adv-rust-blocking-sleep-async", "MEDIUM", r"std::thread::sleep\s*\(",
     "thread sleep can block an async executor worker", "async fn wait() { std::thread::sleep(delay); }"),
    ("adv-rust-lock-unwrap", "MEDIUM", r"\.lock\s*\(\s*\)\.unwrap\s*\(",
     "a poisoned lock causes a secondary panic", "let guard = state.lock().unwrap()"),
    ("adv-rust-lossy-integer-cast", "LOW", r"\b(?:input|value|length|count|size)\s+as\s+(?:u8|u16|u32|usize)\b",
     "an unchecked narrowing/sign-changing cast can silently wrap", "let size = input as usize", "code", 0.68),
])

# Ruby and PHP.
_add("ruby", "sample.rb", "code/injection", "CWE-95",
     "use explicit dispatch and argument arrays; never evaluate untrusted text.", [
    ("adv-ruby-eval", "HIGH", r"\b(?:eval|class_eval|module_eval|instance_eval)\s*\(",
     "Ruby evaluates runtime text as code", "result = eval(source)"),
    ("adv-ruby-system-string", "HIGH", r"\b(?:system|exec|spawn)\s*\(\s*[^,)]*\+",
     "a shell/process command is assembled dynamically", "system(command + input)"),
    ("adv-ruby-backtick-interpolation", "HIGH", r"`[^`]*#\{",
     "an interpolated backtick command invokes a shell", "output = `tool #{input}`", "raw"),
])
_add("ruby", "sample.rb", "deserialization", "CWE-502",
     "use JSON or safe_load with a strict primitive type allowlist.", [
    ("adv-ruby-yaml-load", "HIGH", r"\bYAML\.(?:load|unsafe_load)\s*\(",
     "YAML object deserialization is unsafe for untrusted input", "value = YAML.load(data)"),
    ("adv-ruby-marshal-load", "HIGH", r"\bMarshal\.load\s*\(",
     "Marshal can instantiate attacker-controlled objects", "value = Marshal.load(data)"),
])
_add("ruby", "sample.rb", "web-security", "CWE-79",
     "preserve Rails escaping and parameterize database operations.", [
    ("adv-ruby-html-safe", "HIGH", r"\.html_safe\b",
     "Rails output escaping is bypassed", "render html: params[:value].html_safe"),
    ("adv-ruby-skip-csrf", "HIGH", r"skip_before_action\s+.*verify_authenticity_token",
     "Rails CSRF verification is skipped", "skip_before_action :verify_authenticity_token"),
    ("adv-ruby-sql-interpolation", "HIGH", r"\b(?:where|find_by_sql|execute)\s*\([^\n]*#\{",
     "SQL includes Ruby interpolation", "User.where('name = #{params[:name]}')", "raw"),
])
_add("ruby", "sample.rb", "cryptography", "CWE-327",
     "use SHA-256+ or a password-specific KDF as appropriate.", [
    ("adv-ruby-weak-digest", "HIGH", r"Digest::(?:MD5|SHA1)\b",
     "a broken digest algorithm is used", "digest = Digest::MD5.hexdigest(data)"),
])
_add("ruby", "sample.rb", "correctness", "CWE-20",
     "rescue narrowly and preserve the original failure context.", [
    ("adv-ruby-rescue-exception", "MEDIUM", r"^\s*rescue\s+Exception\b",
     "rescuing Exception catches process-level signals and fatal errors", "rescue Exception => error", "raw"),
    ("adv-ruby-symbol-user-input", "MEDIUM", r"(?:params|request|input)[^\n]*\.to_sym\b",
     "interning unbounded user-derived strings can exhaust memory", "key = params[:key].to_sym", "code", 0.74),
])

_add("php", "sample.php", "code-injection", "CWE-95",
     "remove runtime evaluation and use explicit validated dispatch.", [
    ("adv-php-eval", "CRITICAL", r"\beval\s*\(", "PHP evaluates runtime text as code", "eval($source)"),
    ("adv-php-assert-code", "HIGH", r"\bassert\s*\(\s*\$",
     "assert may evaluate attacker-controlled expressions on legacy runtimes", "assert($expression)"),
    ("adv-php-preg-e", "HIGH", r"preg_replace\s*\(\s*[\"'][^\"']*/e[\"']",
     "the legacy /e regex modifier evaluates replacement code", "preg_replace('/x/e', $value, $input)", "raw"),
])
_add("php", "sample.php", "command-injection", "CWE-78",
     "avoid a shell; use a fixed executable and validated argument vector.", [
    ("adv-php-command-exec", "HIGH", r"\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$",
     "a variable reaches a command execution primitive", "system($command)"),
    ("adv-php-backtick-variable", "HIGH", r"`[^`]*\$",
     "a variable is interpolated into a shell command", "$out = `tool $input`", "raw"),
])
_add("php", "sample.php", "deserialization", "CWE-502",
     "use JSON and explicit schema validation for untrusted data.", [
    ("adv-php-unserialize", "HIGH", r"\bunserialize\s*\(",
     "PHP object deserialization can trigger gadget chains", "$value = unserialize($data)"),
])
_add("php", "sample.php", "file-inclusion", "CWE-98",
     "map an allowlisted identifier to a fixed local file path.", [
    ("adv-php-variable-include", "CRITICAL", r"\b(?:include|require)(?:_once)?\s*\(?\s*\$",
     "a variable controls a PHP include path", "include($page)"),
])
_add("php", "sample.php", "injection", "CWE-89",
     "use prepared statements and bind every value.", [
    ("adv-php-sql-variable", "HIGH", r"\b(?:query|exec)\s*\(\s*[\"'][^\"']*\$",
     "a PHP variable is interpolated into SQL", "$db->query('SELECT * FROM users WHERE id=$id')", "raw"),
])
_add("php", "sample.php", "cryptography", "CWE-327",
     "use password_hash/password_verify or SHA-256+ as appropriate.", [
    ("adv-php-weak-hash", "HIGH", r"\b(?:md5|sha1)\s*\(",
     "a broken hash algorithm is used", "$digest = md5($data)"),
    ("adv-php-weak-random-token", "HIGH", r"\b(?:token|secret|nonce|session)\w*\s*=\s*(?:mt_rand|rand)\s*\(",
     "a predictable PRNG generates a security-sensitive value", "$token = mt_rand()"),
])
_add("php", "sample.php", "security-configuration", "CWE-209",
     "disable detailed production errors and send them to protected logs.", [
    ("adv-php-display-errors", "MEDIUM", r"ini_set\s*\(\s*[\"']display_errors[\"']\s*,\s*[\"']?1",
     "detailed PHP errors are displayed to clients", "ini_set('display_errors', '1')", "raw"),
])
_add("php", "sample.php", "correctness", "CWE-20",
     "use strict comparisons and explicit input mapping.", [
    ("adv-php-loose-comparison", "MEDIUM", r"(?<![=!])==(?!=)",
     "PHP loose comparison performs surprising type juggling", "if ($token == $expected) allow()"),
    ("adv-php-extract", "MEDIUM", r"\bextract\s*\(",
     "extract turns input keys into local variables and can overwrite state", "extract($_POST)"),
])

# Swift / Apple platforms.
_add("swift", "Sample.swift", "transport-security", "CWE-319",
     "use HTTPS and enforce normal platform trust evaluation.", [
    ("adv-swift-cleartext-url", "HIGH", r"URL\s*\(\s*string\s*:\s*[\"']http://",
     "a cleartext HTTP URL is embedded", "let url = URL(string: 'http://example.test')", "raw"),
    ("adv-swift-server-trust-usecredential", "HIGH", r"\.useCredential\b",
     "a custom URL authentication challenge handler needs trust-policy review", "completionHandler(.useCredential, credential)", "code", 0.68),
])
_add("swift", "Sample.swift", "code-injection", "CWE-95",
     "avoid evaluating dynamic JavaScript from untrusted input.", [
    ("adv-swift-evaluate-javascript", "HIGH", r"\.evaluateJavaScript\s*\(",
     "a WebView evaluates runtime JavaScript", "webView.evaluateJavaScript(source)"),
])
_add("swift", "Sample.swift", "data-protection", "CWE-922",
     "store secrets in Keychain with an appropriate accessibility class.", [
    ("adv-swift-userdefaults-secret", "HIGH", r"UserDefaults[^\n]*(?:token|secret|password|credential)",
     "a secret-looking value is stored in UserDefaults", "UserDefaults.standard.set(token, forKey: credentialKey)"),
    ("adv-swift-keychain-always", "HIGH", r"kSecAttrAccessibleAlways\b",
     "the Keychain item uses an obsolete always-accessible class", "attrs[kSecAttrAccessible] = kSecAttrAccessibleAlways"),
])
_add("swift", "Sample.swift", "correctness", "CWE-20",
     "handle recoverable errors explicitly and avoid locale-sensitive state.", [
    ("adv-swift-force-try", "MEDIUM", r"\btry!\s+", "try! turns a recoverable error into a crash", "let data = try! load()"),
    ("adv-swift-force-unwrap", "LOW", r"\w+!\.(?:count|first|last|value|data)\b",
     "forced optional unwrapping can crash on valid absence", "let size = result!.count"),
])

# Shell and PowerShell.  These use raw lines because quoting is semantically
# significant; comment-only lines are excluded by analyze().
_add("shell", "script.sh", "command-injection", "CWE-78",
     "avoid eval/shell composition and pass validated values as arguments.", [
    ("adv-shell-eval-variable", "HIGH", r"\beval\s+.*\$", "eval reparses variable data as shell code", "eval \"$input\"", "raw"),
    ("adv-shell-curl-pipe", "CRITICAL", r"\bcurl\b[^|]*\|\s*(?:ba)?sh\b", "downloaded content is executed directly", "curl -fsSL $url | sh", "raw"),
    ("adv-shell-wget-pipe", "CRITICAL", r"\bwget\b[^|]*\|\s*(?:ba)?sh\b", "downloaded content is executed directly", "wget -qO- $url | bash", "raw"),
    ("adv-shell-base64-exec", "HIGH", r"base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba)?sh\b", "decoded data is executed as shell code", "base64 --decode payload | sh", "raw"),
])
_add("shell", "script.sh", "filesystem", "CWE-73",
     "quote paths, validate roots, and use safe temporary-file APIs.", [
    ("adv-shell-insecure-tmp", "HIGH", r"/tmp/[A-Za-z0-9_.-]*\$\$", "a predictable PID-based temporary path is used", "tmp=/tmp/app.$$", "raw"),
    ("adv-shell-rm-variable-root", "HIGH", r"\brm\s+-[^\n]*r[^\n]*\s+\$\{?\w+\}?/?\s*$", "recursive deletion depends on an unvalidated variable", "rm -rf $TARGET", "raw"),
    ("adv-shell-world-writable", "HIGH", r"\bchmod\s+(?:-R\s+)?777\b", "world-writable permissions are assigned", "chmod -R 777 $dir", "raw"),
])
_add("shell", "script.sh", "transport/security", "CWE-295",
     "verify host keys and certificates against trusted identities.", [
    ("adv-shell-ssh-hostkey-off", "HIGH", r"StrictHostKeyChecking\s*=\s*no", "SSH host-key verification is disabled", "ssh -o StrictHostKeyChecking=no host", "raw"),
    ("adv-shell-curl-insecure", "HIGH", r"\bcurl\b[^\n]*(?:\s-k\b|--insecure\b)", "curl certificate verification is disabled", "curl --insecure https://host", "raw"),
])
_add("shell", "script.sh", "secret-exposure", "CWE-532",
     "disable tracing around secrets and pass credentials through protected channels.", [
    ("adv-shell-xtrace", "MEDIUM", r"^\s*set\s+-[^\n]*x", "shell tracing can print secrets and tokens", "set -x", "raw"),
    ("adv-shell-password-argument", "HIGH", r"--(?:password|token|secret)(?:=|\s+)\$", "a secret is exposed in process arguments", "tool --password $PASSWORD", "raw"),
])

_add("powershell", "script.ps1", "code-injection", "CWE-95",
     "use direct cmdlet invocation with validated parameters.", [
    ("adv-ps-invoke-expression", "CRITICAL", r"\b(?:Invoke-Expression|iex)\b", "PowerShell evaluates runtime text as code", "Invoke-Expression $command", "raw"),
    ("adv-ps-download-execute", "CRITICAL", r"(?:DownloadString|Invoke-WebRequest|iwr)[^|;]*(?:\||;)\s*(?:iex|Invoke-Expression)", "downloaded text is executed", "iwr $url | iex", "raw"),
    ("adv-ps-encoded-command", "HIGH", r"-(?:EncodedCommand|enc)\b", "an encoded PowerShell command obscures executable content", "powershell -EncodedCommand $payload", "raw"),
])
_add("powershell", "script.ps1", "credential-protection", "CWE-798",
     "source credentials from a secure vault and never convert plaintext into a credential.", [
    ("adv-ps-securestring-plaintext", "HIGH", r"ConvertTo-SecureString[^\n]*-AsPlainText[^\n]*-Force", "plaintext is relabeled as a SecureString", "ConvertTo-SecureString $password -AsPlainText -Force", "raw"),
    ("adv-ps-credential-literal", "HIGH", r"New-Object\s+.*PSCredential[^\n]*[\"'][^\"']+[\"']", "a credential is assembled with a literal secret", "New-Object PSCredential('user', 'password')", "raw"),
])
_add("powershell", "script.ps1", "security-control", "CWE-693",
     "keep platform security controls enabled and use signed trusted automation.", [
    ("adv-ps-executionpolicy-bypass", "HIGH", r"ExecutionPolicy\s+(?:Bypass|Unrestricted)", "PowerShell execution policy is bypassed", "powershell -ExecutionPolicy Bypass script.ps1", "raw"),
    ("adv-ps-disable-defender", "CRITICAL", r"Set-MpPreference[^\n]*DisableRealtimeMonitoring\s+\$?true", "real-time malware protection is disabled", "Set-MpPreference -DisableRealtimeMonitoring $true", "raw"),
    ("adv-ps-cert-validation-off", "CRITICAL", r"ServerCertificateValidationCallback[^\n]*\$?true", "TLS certificate validation is replaced with accept-all", "ServerCertificateValidationCallback = { $true }", "raw"),
])

# Solidity smart contracts.
_add("solidity", "Contract.sol", "authorization", "CWE-346",
     "authorize against msg.sender and an explicit role/owner mapping.", [
    ("adv-sol-tx-origin-auth", "CRITICAL", r"\btx\.origin\s*==", "tx.origin authorization is vulnerable to phishing contracts", "require(tx.origin == owner)"),
])
_add("solidity", "Contract.sol", "external-call", "CWE-829",
     "use vetted interfaces, checks-effects-interactions, and explicit call-result handling.", [
    ("adv-sol-delegatecall", "CRITICAL", r"\.delegatecall\s*\(", "delegatecall executes foreign code in this contract's storage context", "target.delegatecall(data)"),
    ("adv-sol-selfdestruct", "HIGH", r"\bselfdestruct\s*\(", "selfdestruct creates irreversible availability and fund risks", "selfdestruct(payable(owner))"),
    ("adv-sol-call-value-unchecked", "CRITICAL", r"\.call\s*\{\s*value\s*:", "low-level value transfer requires result and reentrancy checks", "recipient.call{value: amount}(data)"),
    ("adv-sol-send", "HIGH", r"\.send\s*\(", "send has brittle gas/error semantics", "recipient.send(amount)"),
])
_add("solidity", "Contract.sol", "randomness", "CWE-330",
     "use a commit-reveal protocol or a verifiable randomness oracle.", [
    ("adv-sol-block-random", "HIGH", r"\b(?:block\.timestamp|blockhash|prevrandao)\b[^;]*(?:%|keccak256)", "miner/validator-influenced values are used as randomness", "uint winner = uint(block.timestamp) % players.length"),
])
_add("solidity", "Contract.sol", "correctness", "CWE-20",
     "pin reviewed compiler constraints and bound all state-dependent iteration.", [
    ("adv-sol-floating-pragma", "MEDIUM", r"pragma\s+solidity\s+\^", "a floating compiler pragma permits unreviewed compiler behavior", "pragma solidity ^0.8.0", "raw"),
    ("adv-sol-assembly", "MEDIUM", r"\bassembly\s*\{", "inline assembly bypasses Solidity safety checks", "assembly { value := mload(ptr) }"),
    ("adv-sol-loop-storage-length", "MEDIUM", r"for\s*\([^;]*;[^;]*<\s*\w+\.length", "iteration over unbounded storage can exceed block gas", "for (uint i=0; i<users.length; i++) { pay(users[i]); }"),
])

# Terraform, Kubernetes/YAML, GitHub Actions, Docker, SQL, and server config.
_add("terraform", "main.tf", "cloud-access", "CWE-732",
     "grant only required actions/resources and restrict network exposure.", [
    ("adv-tf-iam-star-action", "CRITICAL", r"[\"']Action[\"']\s*:\s*[\"']\*[\"']", "IAM policy grants every action", "policy = { 'Action': '*', 'Resource': arn }", "raw"),
    ("adv-tf-iam-star-resource", "HIGH", r"[\"']Resource[\"']\s*:\s*[\"']\*[\"']", "IAM policy targets every resource", "policy = { 'Action': action, 'Resource': '*' }", "raw"),
    ("adv-tf-all-ports", "HIGH", r"from_port\s*=\s*0[^\n]*to_port\s*=\s*0", "a security-group rule exposes all ports/protocols", "from_port = 0  to_port = 0", "raw"),
    ("adv-tf-rds-public", "CRITICAL", r"publicly_accessible\s*=\s*true", "a managed database is publicly reachable", "publicly_accessible = true", "raw"),
    ("adv-tf-public-ip", "HIGH", r"associate_public_ip_address\s*=\s*true", "a compute instance receives a public IP", "associate_public_ip_address = true", "raw"),
])
_add("terraform", "main.tf", "cloud-encryption", "CWE-311",
     "enable encryption at rest with a managed, rotated key.", [
    ("adv-tf-storage-unencrypted", "HIGH", r"(?:storage_encrypted|encrypted)\s*=\s*false", "cloud storage encryption is disabled", "storage_encrypted = false", "raw"),
    ("adv-tf-kms-rotation-off", "MEDIUM", r"enable_key_rotation\s*=\s*false", "KMS automatic key rotation is disabled", "enable_key_rotation = false", "raw"),
])
_add("terraform", "main.tf", "cloud-metadata", "CWE-918",
     "require IMDSv2/session tokens and block legacy metadata access.", [
    ("adv-tf-imdsv1", "HIGH", r"http_tokens\s*=\s*[\"']optional[\"']", "EC2 metadata tokens are optional, allowing IMDSv1", "http_tokens = 'optional'", "raw"),
])
_add("terraform", "main.tf", "audit-logging", "CWE-778",
     "enable immutable, centralized security and access logging.", [
    ("adv-tf-flowlogs-off", "MEDIUM", r"enable_logging\s*=\s*false", "resource audit/access logging is disabled", "enable_logging = false", "raw", 0.72),
])

_add("yaml", "deployment.yaml", "container-isolation", "CWE-250",
     "run as a non-root UID with no privilege escalation and a read-only root filesystem.", [
    ("adv-k8s-run-as-root", "CRITICAL", r"^\s*runAsUser\s*:\s*0\s*$", "the container explicitly runs as root", "runAsUser: 0", "raw"),
    ("adv-k8s-run-as-nonroot-off", "HIGH", r"^\s*runAsNonRoot\s*:\s*false\s*$", "the non-root requirement is disabled", "runAsNonRoot: false", "raw"),
    ("adv-k8s-privilege-escalation", "HIGH", r"^\s*allowPrivilegeEscalation\s*:\s*true\s*$", "the container may gain additional privileges", "allowPrivilegeEscalation: true", "raw"),
    ("adv-k8s-rootfs-writable", "MEDIUM", r"^\s*readOnlyRootFilesystem\s*:\s*false\s*$", "the container root filesystem is writable", "readOnlyRootFilesystem: false", "raw"),
    ("adv-k8s-sys-admin", "CRITICAL", r"^\s*-\s*SYS_ADMIN\s*$", "the broad SYS_ADMIN capability is granted", "- SYS_ADMIN", "raw"),
])
_add("yaml", "deployment.yaml", "host-isolation", "CWE-250",
     "keep workloads out of host namespaces and narrowly scope host mounts.", [
    ("adv-k8s-host-pid", "HIGH", r"^\s*hostPID\s*:\s*true\s*$", "the pod shares the host PID namespace", "hostPID: true", "raw"),
    ("adv-k8s-host-ipc", "HIGH", r"^\s*hostIPC\s*:\s*true\s*$", "the pod shares the host IPC namespace", "hostIPC: true", "raw"),
    ("adv-k8s-root-hostpath", "CRITICAL", r"^\s*path\s*:\s*/\s*$", "a hostPath volume mounts the host root", "hostPath:\n  path: /", "raw"),
    ("adv-k8s-seccomp-unconfined", "HIGH", r"seccompProfile[^\n]*Unconfined|seccomp\.security\.alpha\.kubernetes\.io[^\n]*unconfined", "the seccomp syscall filter is disabled", "seccompProfile: Unconfined", "raw"),
])
_add("yaml", "deployment.yaml", "identity", "CWE-250",
     "disable automatic service-account tokens unless the workload needs the API.", [
    ("adv-k8s-auto-token", "MEDIUM", r"automountServiceAccountToken\s*:\s*true", "a Kubernetes API token is mounted automatically", "automountServiceAccountToken: true", "raw"),
])

_add("github-actions", ".github/workflows/ci.yml", "supply-chain", "CWE-829",
     "pin third-party actions to a reviewed full commit SHA.", [
    ("adv-gha-unpinned-action", "HIGH", r"^\s*uses\s*:\s*[^\s@]+@(?:main|master|HEAD|v?\d+(?:\.\d+)*)\s*$", "a GitHub Action is pinned to a mutable ref", "uses: vendor/action@v2", "raw"),
    ("adv-gha-docker-latest", "HIGH", r"^\s*uses\s*:\s*docker://[^\s]+:latest", "a workflow runs a mutable latest container", "uses: docker://tool/image:latest", "raw"),
])
_add("github-actions", ".github/workflows/ci.yml", "workflow-permissions", "CWE-732",
     "grant read-only defaults and elevate only the exact job permission required.", [
    ("adv-gha-write-all", "CRITICAL", r"^\s*permissions\s*:\s*write-all\s*$", "the workflow grants write access to every token scope", "permissions: write-all", "raw"),
    ("adv-gha-checkout-credentials", "MEDIUM", r"persist-credentials\s*:\s*true", "checkout credentials remain available to later steps", "persist-credentials: true", "raw"),
])
_add("github-actions", ".github/workflows/ci.yml", "workflow-injection", "CWE-78",
     "move event data into an environment variable and quote it as data.", [
    ("adv-gha-event-script-injection", "CRITICAL", r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|head_commit)[^}]*\}\}", "untrusted event text is interpolated into a workflow step", "run: echo ${{ github.event.issue.title }}", "raw"),
    ("adv-gha-self-hosted-pr", "CRITICAL", r"runs-on\s*:\s*self-hosted", "self-hosted runners require strict isolation from untrusted pull requests", "runs-on: self-hosted", "raw", 0.76),
])

_add("docker", "Dockerfile", "build-supply-chain", "CWE-494",
     "download separately, verify a pinned digest/signature, and use reproducible versions.", [
    ("adv-docker-curl-pipe", "CRITICAL", r"^\s*RUN\s+.*\bcurl\b[^|]*\|\s*(?:ba)?sh\b", "the image build executes downloaded content directly", "RUN curl -fsSL https://host/install | sh", "raw"),
    ("adv-docker-wget-pipe", "CRITICAL", r"^\s*RUN\s+.*\bwget\b[^|]*\|\s*(?:ba)?sh\b", "the image build executes downloaded content directly", "RUN wget -qO- https://host/install | bash", "raw"),
    ("adv-docker-unpinned-apt", "LOW", r"^\s*RUN\s+.*apt-get\s+install\s+(?![^\n]*=)", "OS packages are installed without visible version pins", "RUN apt-get install curl", "raw", 0.68),
])
_add("docker", "Dockerfile", "container-secrets", "CWE-798",
     "inject secrets at runtime or with BuildKit secret mounts, never image metadata.", [
    ("adv-docker-secret-env", "CRITICAL", r"^\s*(?:ARG|ENV)\s+(?:\w*TOKEN|\w*PASSWORD|\w*SECRET|\w*API_KEY)\b", "a secret is placed in an image layer/build argument", "ENV API_TOKEN=value", "raw"),
])
_add("docker", "Dockerfile", "container-hardening", "CWE-732",
     "use least privilege, narrow copy inputs, and restrictive permissions.", [
    ("adv-docker-chmod-777", "HIGH", r"^\s*RUN\s+.*\bchmod\s+(?:-R\s+)?777\b", "the image grants world-writable permissions", "RUN chmod -R 777 /app", "raw"),
    ("adv-docker-sudo", "MEDIUM", r"^\s*RUN\s+.*\bsudo\b", "sudo in a container build hides an unnecessary privilege assumption", "RUN sudo install tool", "raw"),
    ("adv-docker-copy-all", "LOW", r"^\s*COPY\s+\.\s+\.\s*$", "COPY . . can include secrets and unneeded build context", "COPY . .", "raw", 0.66),
])

_add("sql", "schema.sql", "database-command", "CWE-78",
     "disable database OS-command features and isolate database service identities.", [
    ("adv-sql-xp-cmdshell", "CRITICAL", r"\bxp_cmdshell\b", "SQL Server OS command execution is invoked", "EXEC xp_cmdshell command", "raw"),
    ("adv-sql-copy-program", "CRITICAL", r"\bCOPY\b[^;]*\bPROGRAM\b", "PostgreSQL COPY PROGRAM executes an OS command", "COPY results FROM PROGRAM command", "raw"),
])
_add("sql", "schema.sql", "database-access", "CWE-732",
     "grant the smallest privileges to explicit roles.", [
    ("adv-sql-grant-all-public", "CRITICAL", r"\bGRANT\s+ALL(?:\s+PRIVILEGES)?\b[^;]*\bTO\s+PUBLIC\b", "all database users receive broad privileges", "GRANT ALL PRIVILEGES ON users TO PUBLIC", "raw"),
    ("adv-sql-user-password-literal", "CRITICAL", r"\bCREATE\s+(?:USER|ROLE)\b[^;]*\bPASSWORD\s+[\"'][^\"']+[\"']", "a database credential is embedded in SQL", "CREATE USER app PASSWORD 'secret-value'", "raw"),
])
_add("sql", "schema.sql", "database-files", "CWE-22",
     "disable database file primitives and expose only fixed reviewed resources.", [
    ("adv-sql-load-file", "HIGH", r"\bLOAD_FILE\s*\(", "the database reads a server-side filesystem path", "SELECT LOAD_FILE(path)", "raw"),
    ("adv-sql-local-infile", "HIGH", r"\bLOAD\s+DATA\s+LOCAL\s+INFILE\b", "LOCAL INFILE can expose client-side files", "LOAD DATA LOCAL INFILE file INTO TABLE rows", "raw"),
])
_add("sql", "schema.sql", "database-security", "CWE-426",
     "set a trusted immutable search_path in every SECURITY DEFINER function.", [
    ("adv-sql-security-definer", "HIGH", r"\bSECURITY\s+DEFINER\b", "privileged function behavior depends on a safe search_path", "CREATE FUNCTION f() RETURNS void SECURITY DEFINER", "raw", 0.72),
])

_add("nginx", "nginx.conf", "server-hardening", "CWE-200",
     "disable directory listing and obsolete protocols; add strict transport controls.", [
    ("adv-nginx-autoindex", "HIGH", r"\bautoindex\s+on\s*;", "directory listing is enabled", "autoindex on;", "raw"),
    ("adv-nginx-old-tls", "HIGH", r"\bssl_protocols\b[^;]*(?:SSLv3|TLSv1(?:\.0)?)(?:\s|;)", "an obsolete TLS protocol is enabled", "ssl_protocols TLSv1 TLSv1.2;", "raw"),
    ("adv-nginx-server-tokens", "LOW", r"\bserver_tokens\s+on\s*;", "server version tokens are exposed", "server_tokens on;", "raw"),
])
_add("npm-config", "package.json", "supply-chain", "CWE-829",
     "avoid install-time code where possible and review every lifecycle script.", [
    ("adv-npm-preinstall-script", "HIGH", r"[\"'](?:preinstall|postinstall)[\"']\s*:", "an npm lifecycle hook executes during installation", "'postinstall': 'node install.js'", "raw", 0.78),
    ("adv-npm-wildcard-dependency", "MEDIUM", r"[\"'][^\"']+[\"']\s*:\s*[\"'](?:\*|latest)[\"']", "a dependency is unpinned", "'dependencies': {\n  'library': 'latest'", "raw"),
])


LANGUAGE_BY_EXTENSION = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript",
    ".cjs": "javascript", ".ts": "javascript", ".tsx": "javascript",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin",
    ".cs": "csharp", ".go": "go", ".rs": "rust", ".rb": "ruby",
    ".php": "php", ".swift": "swift", ".sh": "shell", ".bash": "shell",
    ".zsh": "shell", ".ps1": "powershell", ".sol": "solidity",
    ".tf": "terraform", ".tfvars": "terraform", ".yaml": "yaml",
    ".yml": "yaml", ".sql": "sql",
}
RAW_LANGUAGES = {"shell", "powershell", "terraform", "yaml", "github-actions",
                 "docker", "sql", "nginx", "npm-config"}
STRUCTURED_RAW_LANGUAGES = {"terraform", "yaml", "github-actions", "docker",
                            "sql", "nginx", "npm-config"}
COMMENT_PREFIXES = {
    "shell": ("#",), "powershell": ("#",), "terraform": ("#", "//"),
    "yaml": ("#",), "github-actions": ("#",), "docker": ("#",),
    "sql": ("--",), "nginx": ("#",),
}


def languages_for(path: str) -> set[str]:
    normalized = path.replace("\\", "/").lower()
    name = os.path.basename(normalized)
    if name.startswith(("dockerfile", "containerfile")):
        return {"docker"}
    if "/.github/workflows/" in "/" + normalized or normalized.startswith(".github/workflows/"):
        return {"yaml", "github-actions"}
    if name == "package.json":
        return {"npm-config"}
    if name in {"nginx.conf", "nginx.config"} or name.endswith(".nginx"):
        return {"nginx"}
    language = LANGUAGE_BY_EXTENSION.get(Path(name).suffix.lower(), "")
    return {language} if language else set()


def _mask_python(text: str) -> str:
    chars = list(text)
    lines = text.splitlines(keepends=True)
    offsets = []
    total = 0
    for line in lines:
        offsets.append(total); total += len(line)
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for token in tokens:
            if token.type not in {tokenize.STRING, tokenize.COMMENT}:
                continue
            (sl, sc), (el, ec) = token.start, token.end
            start = offsets[sl - 1] + sc
            end = offsets[el - 1] + ec
            for index in range(start, min(end, len(chars))):
                if chars[index] not in "\r\n":
                    chars[index] = " "
    except (tokenize.TokenError, IndentationError):
        return _mask_generic(text)
    return "".join(chars)


def _mask_generic(text: str, mask_backticks: bool = True) -> str:
    chars = list(text)
    index = 0
    quote = ""
    block = False
    escaped = False
    while index < len(chars):
        char = chars[index]
        nxt = chars[index + 1] if index + 1 < len(chars) else ""
        if block:
            if char == "*" and nxt == "/":
                chars[index] = chars[index + 1] = " "; block = False; index += 2; continue
            if char not in "\r\n": chars[index] = " "
            index += 1; continue
        if quote:
            if char not in "\r\n": chars[index] = " "
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = ""
            index += 1; continue
        if char == "/" and nxt == "*":
            chars[index] = chars[index + 1] = " "; block = True; index += 2; continue
        if char == "/" and nxt == "/":
            while index < len(chars) and chars[index] not in "\r\n":
                chars[index] = " "; index += 1
            continue
        quotes = {"'", '"', "`"} if mask_backticks else {"'", '"'}
        if char in quotes:
            quote = char; chars[index] = " "; index += 1; continue
        index += 1
    return "".join(chars)


def _code_view(text: str, languages: set[str]) -> str:
    if "python" in languages:
        return _mask_python(text)
    return _mask_generic(text, mask_backticks=not bool(languages & {"ruby", "php"}))


def _inside_python_async(raw_lines: list[str], line_no: int) -> bool:
    current = raw_lines[line_no - 1]
    if re.search(r"\basync\s+def\b", current):
        return True
    indent = len(current) - len(current.lstrip())
    for index in range(line_no - 2, -1, -1):
        line = raw_lines[index]
        if not line.strip():
            continue
        other_indent = len(line) - len(line.lstrip())
        if other_indent < indent and re.match(r"\s*(?:async\s+)?def\b", line):
            return bool(re.match(r"\s*async\s+def\b", line))
        if other_indent < indent and re.match(r"\s*(?:class|def)\b", line):
            return False
    return False


def _inside_python_finally(raw_lines: list[str], line_no: int) -> bool:
    current = raw_lines[line_no - 1]
    indent = len(current) - len(current.lstrip())
    if "finally:" in current and "return" in current:
        return True
    for index in range(line_no - 2, -1, -1):
        line = raw_lines[index]
        if not line.strip():
            continue
        other_indent = len(line) - len(line.lstrip())
        if other_indent < indent:
            return bool(re.match(r"\s*finally\s*:", line))
    return False


def _raw_match_starts_in_code(rule: Rule, match: re.Match, code_line: str) -> bool:
    if rule.language in STRUCTURED_RAW_LANGUAGES:
        return True
    start, end = match.span()
    raw_part = match.group(0)
    for offset, char in enumerate(raw_part):
        if char.isalnum() or char in "@.$`<":
            pos = start + offset
            return pos < len(code_line) and not code_line[pos].isspace()
    return end > start


def _context_ok(rule: Rule, raw_lines: list[str], code_lines: list[str],
                line_no: int, match: re.Match) -> bool:
    rid = rule.rid
    if rid in {"adv-py-blocking-sleep-async", "adv-py-blocking-http-async"}:
        return _inside_python_async(raw_lines, line_no)
    if rid == "adv-py-return-finally":
        return _inside_python_finally(raw_lines, line_no)
    if rid == "adv-js-message-no-origin":
        window = "\n".join(raw_lines[line_no - 1:line_no + 12])
        return not bool(re.search(r"\b(?:event|e)\.origin\b", window))
    if rid == "adv-js-number-unsafe-integer":
        try:
            return int(match.group(0)) > 9_007_199_254_740_991
        except ValueError:
            return False
    if rid == "adv-k8s-root-hostpath":
        window = "\n".join(raw_lines[max(0, line_no - 8):line_no])
        return bool(re.search(r"^\s*hostPath\s*:", window, re.MULTILINE))
    if rid == "adv-npm-wildcard-dependency":
        window = "\n".join(raw_lines[max(0, line_no - 30):line_no])
        return bool(re.search(r"[\"'](?:devD|d)ependencies[\"']\s*:", window))
    if rule.view == "raw" and rule.language not in STRUCTURED_RAW_LANGUAGES:
        code_line = code_lines[line_no - 1] if line_no <= len(code_lines) else ""
        return _raw_match_starts_in_code(rule, match, code_line)
    return True


def analyze(text: str, path: str) -> list[Finding]:
    languages = languages_for(path)
    if not languages:
        return []
    code = _code_view(text, languages)
    raw_lines = text.splitlines()
    code_lines = code.splitlines()
    findings: list[Finding] = []
    for rule in RULES:
        if rule.language not in languages:
            continue
        regex = rule.regex()
        lines = raw_lines if rule.view == "raw" or rule.language in RAW_LANGUAGES else code_lines
        prefixes = COMMENT_PREFIXES.get(rule.language, ())
        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or (prefixes and stripped.startswith(prefixes)):
                continue
            match = regex.search(line)
            if not match or not _context_ok(rule, raw_lines, code_lines, line_no, match):
                continue
            evidence = raw_lines[line_no - 1].strip() if line_no <= len(raw_lines) else stripped
            if len(evidence) > 240:
                evidence = evidence[:237] + "..."
            findings.append(Finding(
                path, line_no, rule.language, rule.rid, rule.severity,
                rule.message, rule.fix, rule.category, rule.cwe,
                OWASP_BY_CWE.get(rule.cwe, ""), rule.confidence, evidence,
            ))
    unique = {(item.line, item.rule): item for item in findings}
    rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return sorted(unique.values(), key=lambda item: (-rank.get(item.severity, 0), item.line, item.rule))


def validate_catalog() -> list[str]:
    errors = []
    seen = set()
    for rule in RULES:
        if rule.rid in seen:
            errors.append("duplicate rule id: " + rule.rid)
        seen.add(rule.rid)
        if rule.severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
            errors.append("bad severity: " + rule.rid)
        try:
            rule.regex()
        except re.error as exc:
            errors.append("bad regex %s: %s" % (rule.rid, exc))
        found = {item.rule for item in analyze(rule.example, rule.path_hint)}
        if rule.rid not in found:
            errors.append("positive fixture did not trigger: " + rule.rid)
    return errors


def catalog_summary() -> dict:
    by_language: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_category: dict[str, int] = {}
    for rule in RULES:
        by_language[rule.language] = by_language.get(rule.language, 0) + 1
        by_severity[rule.severity] = by_severity.get(rule.severity, 0) + 1
        by_category[rule.category] = by_category.get(rule.category, 0) + 1
    return {"pack": "advanced-2.2", "rules": len(RULES),
            "languages": dict(sorted(by_language.items())),
            "severities": dict(sorted(by_severity.items())),
            "categories": dict(sorted(by_category.items()))}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--list-rules", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        errors = validate_catalog()
        print(json.dumps({"ok": not errors, **catalog_summary(), "errors": errors}, indent=2))
        return 1 if errors else 0
    if args.list_rules:
        payload = [asdict(rule) for rule in RULES]
        print(json.dumps(payload, indent=2) if args.json else "\n".join(
            "%s [%s] %s %s" % (r.rid, r.severity, r.language, r.message) for r in RULES))
        return 0
    if not args.paths:
        print(json.dumps(catalog_summary(), indent=2))
        return 0
    findings = []
    for raw in args.paths:
        path = Path(raw)
        candidates = [path] if path.is_file() else path.rglob("*") if path.is_dir() else []
        for item in candidates:
            if not item.is_file() or not languages_for(str(item)):
                continue
            try:
                findings.extend(analyze(item.read_text(encoding="utf-8", errors="replace"), str(item)))
            except OSError as exc:
                print("advanced rule scan error: %s: %s" % (item, exc), file=os.sys.stderr)
                return 2
    if args.json:
        print(json.dumps([asdict(item) for item in findings], indent=2))
    else:
        for item in findings:
            print("%s:%d [%s] %s - %s" % (
                item.path, item.line, item.severity, item.rule, item.message))
    return min(len(findings), 250)


if __name__ == "__main__":
    raise SystemExit(main())
