#!/usr/bin/env python3
"""Expand training data with additional vulnerability types, edge cases,
Attestor-specific patterns, and multi-language coverage gaps.

Sections:
  1. Authentication & Authorization flaws
  2. Open Redirect / URL validation
  3. Information Disclosure / Error Handling
  4. Unsafe Regex (ReDoS)
  5. Mass Assignment / Over-posting
  6. Attestor-specific rule output formatting
  7. Clean code (safe examples — reduces false positives)
  8. Multi-vuln analysis (code with >1 issue)

Output: training_data_expanded.jsonl
"""
import json
import os
import hashlib
from collections import Counter

SECTIONS = {}

SECTIONS["auth_bypass"] = [
    {"lang": "Python", "vuln": "Authentication Bypass", "cwe": "CWE-287", "sev": "CRITICAL",
     "code": '@app.route("/admin")\ndef admin_panel():\n    if request.cookies.get("is_admin") == "true":\n        return render_template("admin.html")',
     "fix": '@app.route("/admin")\n@login_required\ndef admin_panel():\n    if not current_user.is_admin:\n        abort(403)\n    return render_template("admin.html")',
     "desc": "Client-side cookies can be forged. Use server-side session authentication."},
    {"lang": "JavaScript", "vuln": "JWT None Algorithm", "cwe": "CWE-327", "sev": "CRITICAL",
     "code": 'const decoded = jwt.decode(token);\nif (decoded.role === "admin") grantAccess();',
     "fix": 'const decoded = jwt.verify(token, SECRET_KEY, { algorithms: ["HS256"] });\nif (decoded.role === "admin") grantAccess();',
     "desc": "jwt.decode does not verify signature — use jwt.verify with explicit algorithm."},
    {"lang": "Python", "vuln": "Broken Password Reset", "cwe": "CWE-640", "sev": "HIGH",
     "code": '@app.route("/reset/<token>")\ndef reset(token):\n    user = User.query.filter_by(reset_token=token).first()\n    user.password = request.form["new_pw"]',
     "fix": '@app.route("/reset/<token>")\ndef reset(token):\n    user = User.query.filter_by(reset_token=token).first()\n    if not user or user.token_expires < datetime.utcnow():\n        abort(400)\n    user.password = bcrypt.hashpw(request.form["new_pw"].encode(), bcrypt.gensalt())\n    user.reset_token = None',
     "desc": "Reset tokens must expire and be single-use. Hash new passwords."},
    {"lang": "Java", "vuln": "Broken Access Control", "cwe": "CWE-862", "sev": "HIGH",
     "code": '@GetMapping("/api/users/{id}/settings")\npublic Settings getUserSettings(@PathVariable Long id) {\n    return settingsRepo.findByUserId(id);\n}',
     "fix": '@GetMapping("/api/users/{id}/settings")\npublic Settings getUserSettings(@PathVariable Long id, @AuthenticationPrincipal User user) {\n    if (!user.getId().equals(id)) throw new AccessDeniedException("Forbidden");\n    return settingsRepo.findByUserId(id);\n}',
     "desc": "Always verify the authenticated user owns the requested resource."},
    {"lang": "Go", "vuln": "Missing Auth Middleware", "cwe": "CWE-306", "sev": "HIGH",
     "code": 'http.HandleFunc("/api/delete-user", func(w http.ResponseWriter, r *http.Request) {\n    userID := r.URL.Query().Get("id")\n    db.Exec("DELETE FROM users WHERE id=$1", userID)\n})',
     "fix": 'http.Handle("/api/delete-user", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {\n    claims := r.Context().Value("claims").(*Claims)\n    if !claims.IsAdmin {\n        http.Error(w, "forbidden", 403); return\n    }\n    db.Exec("DELETE FROM users WHERE id=$1", r.URL.Query().Get("id"))\n})))',
     "desc": "Destructive endpoints must require authentication and authorization."},
    {"lang": "Python", "vuln": "Timing Attack on Auth", "cwe": "CWE-208", "sev": "MEDIUM",
     "code": 'def check_token(provided, actual):\n    return provided == actual',
     "fix": 'import hmac\ndef check_token(provided, actual):\n    return hmac.compare_digest(provided.encode(), actual.encode())',
     "desc": "String comparison leaks length via timing. Use constant-time compare."},
]

SECTIONS["open_redirect"] = [
    {"lang": "Python", "vuln": "Open Redirect", "cwe": "CWE-601", "sev": "MEDIUM",
     "code": '@app.route("/login")\ndef login():\n    next_url = request.args.get("next", "/")\n    return redirect(next_url)',
     "fix": '@app.route("/login")\ndef login():\n    next_url = request.args.get("next", "/")\n    if not next_url.startswith("/") or next_url.startswith("//"):\n        next_url = "/"\n    return redirect(next_url)',
     "desc": "Validate redirect URLs are relative paths to prevent phishing."},
    {"lang": "JavaScript", "vuln": "Open Redirect", "cwe": "CWE-601", "sev": "MEDIUM",
     "code": 'app.get("/redirect", (req, res) => {\n  res.redirect(req.query.url);\n});',
     "fix": 'app.get("/redirect", (req, res) => {\n  const url = new URL(req.query.url, `${req.protocol}://${req.get("host")}`);\n  if (url.host !== req.get("host")) return res.status(400).send("Invalid redirect");\n  res.redirect(url.pathname);\n});',
     "desc": "Validate redirect target matches the application host."},
    {"lang": "Java", "vuln": "Open Redirect", "cwe": "CWE-601", "sev": "MEDIUM",
     "code": 'String url = request.getParameter("returnUrl");\nresponse.sendRedirect(url);',
     "fix": 'String url = request.getParameter("returnUrl");\nif (url == null || !url.startsWith("/") || url.startsWith("//")) url = "/";\nresponse.sendRedirect(url);',
     "desc": "Only allow relative path redirects."},
]

SECTIONS["info_disclosure"] = [
    {"lang": "Python", "vuln": "Stack Trace Exposure", "cwe": "CWE-209", "sev": "MEDIUM",
     "code": '@app.errorhandler(500)\ndef error(e):\n    return str(e), 500',
     "fix": '@app.errorhandler(500)\ndef error(e):\n    app.logger.exception("Internal error")\n    return "An internal error occurred", 500',
     "desc": "Don't expose exception details to users. Log internally."},
    {"lang": "JavaScript", "vuln": "Verbose Error Response", "cwe": "CWE-209", "sev": "MEDIUM",
     "code": 'app.use((err, req, res, next) => {\n  res.status(500).json({ error: err.message, stack: err.stack });\n});',
     "fix": 'app.use((err, req, res, next) => {\n  console.error(err);\n  res.status(500).json({ error: "Internal server error" });\n});',
     "desc": "Never return stack traces to the client."},
    {"lang": "Java", "vuln": "Exception Info Leak", "cwe": "CWE-209", "sev": "MEDIUM",
     "code": 'catch (SQLException e) {\n    response.getWriter().write("Error: " + e.getMessage());\n}',
     "fix": 'catch (SQLException e) {\n    logger.error("DB error", e);\n    response.sendError(500, "Internal server error");\n}',
     "desc": "SQL exception messages can reveal schema details."},
    {"lang": "Python", "vuln": "Debug Mode in Production", "cwe": "CWE-215", "sev": "HIGH",
     "code": 'app.run(host="0.0.0.0", port=5000, debug=True)',
     "fix": 'app.run(host="0.0.0.0", port=5000, debug=False)',
     "desc": "Debug mode exposes Werkzeug debugger with code execution."},
    {"lang": "Go", "vuln": "Verbose Errors", "cwe": "CWE-209", "sev": "MEDIUM",
     "code": 'if err != nil {\n    http.Error(w, fmt.Sprintf("DB error: %v", err), 500)\n}',
     "fix": 'if err != nil {\n    log.Printf("DB error: %v", err)\n    http.Error(w, "Internal server error", 500)\n}',
     "desc": "Log errors server-side, return generic messages."},
]

SECTIONS["redos"] = [
    {"lang": "Python", "vuln": "ReDoS", "cwe": "CWE-1333", "sev": "MEDIUM",
     "code": 'import re\npattern = re.compile(r"(a+)+$")\nif pattern.match(user_input): pass',
     "fix": 'import re\npattern = re.compile(r"a+$")\nif len(user_input) > 1000: raise ValueError("Input too long")\nif pattern.match(user_input): pass',
     "desc": "Nested quantifiers cause exponential backtracking. Simplify regex and limit input."},
    {"lang": "JavaScript", "vuln": "ReDoS", "cwe": "CWE-1333", "sev": "MEDIUM",
     "code": 'const emailRegex = /^([a-zA-Z0-9_\\.-]+)@([\\da-zA-Z\\.-]+)\\.([a-zA-Z\\.]{2,6})$/;\nif (emailRegex.test(input)) {}',
     "fix": 'const { isEmail } = require("validator");\nif (isEmail(input)) {}',
     "desc": "Complex email regexes are prone to ReDoS. Use a validated library."},
    {"lang": "Java", "vuln": "ReDoS", "cwe": "CWE-1333", "sev": "MEDIUM",
     "code": 'Pattern p = Pattern.compile("(.*a){20}");\nif (p.matcher(input).matches()) {}',
     "fix": 'if (input.length() > 1000) throw new IllegalArgumentException("Too long");\nPattern p = Pattern.compile("a{20}");\nif (p.matcher(input).find()) {}',
     "desc": "Avoid catastrophic backtracking with bounded, non-nested patterns."},
]

SECTIONS["mass_assignment"] = [
    {"lang": "Python", "vuln": "Mass Assignment", "cwe": "CWE-915", "sev": "HIGH",
     "code": '@app.route("/update", methods=["POST"])\ndef update_profile():\n    user = User.query.get(current_user.id)\n    for k, v in request.json.items():\n        setattr(user, k, v)\n    db.session.commit()',
     "fix": 'ALLOWED = {"name", "email", "bio"}\n@app.route("/update", methods=["POST"])\ndef update_profile():\n    user = User.query.get(current_user.id)\n    for k, v in request.json.items():\n        if k in ALLOWED:\n            setattr(user, k, v)\n    db.session.commit()',
     "desc": "Allowlist attributes to prevent role/admin escalation."},
    {"lang": "JavaScript", "vuln": "Mass Assignment", "cwe": "CWE-915", "sev": "HIGH",
     "code": 'app.put("/api/user", async (req, res) => {\n  await User.findByIdAndUpdate(req.user.id, req.body);\n  res.json({ ok: true });\n});',
     "fix": 'app.put("/api/user", async (req, res) => {\n  const { name, email, bio } = req.body;\n  await User.findByIdAndUpdate(req.user.id, { name, email, bio });\n  res.json({ ok: true });\n});',
     "desc": "Destructure only allowed fields from request body."},
    {"lang": "Ruby", "vuln": "Mass Assignment", "cwe": "CWE-915", "sev": "HIGH",
     "code": 'def update\n  @user.update(params[:user])\nend',
     "fix": 'def update\n  @user.update(user_params)\nend\n\nprivate\ndef user_params\n  params.require(:user).permit(:name, :email, :bio)\nend',
     "desc": "Use strong parameters to whitelist attributes."},
]

SECTIONS["attestor_format"] = [
    {"lang": "Python", "vuln": "SQL Injection", "cwe": "CWE-89", "sev": "HIGH",
     "code": 'def search_users(name):\n    return db.execute(f"SELECT * FROM users WHERE name LIKE \'%{name}%\'")',
     "fix": 'def search_users(name):\n    return db.execute("SELECT * FROM users WHERE name LIKE ?", (f"%{name}%",))',
     "desc": "Use parameterized LIKE queries."},
    {"lang": "JavaScript", "vuln": "Prototype Pollution", "cwe": "CWE-1321", "sev": "HIGH",
     "code": 'function merge(target, source) {\n  for (const key in source) {\n    if (typeof source[key] === "object" && source[key] !== null) {\n      target[key] = merge(target[key] || {}, source[key]);\n    } else {\n      target[key] = source[key];\n    }\n  }\n  return target;\n}',
     "fix": 'function merge(target, source) {\n  for (const key of Object.keys(source)) {\n    if (key === "__proto__" || key === "constructor" || key === "prototype") continue;\n    if (typeof source[key] === "object" && source[key] !== null) {\n      target[key] = merge(target[key] || {}, source[key]);\n    } else {\n      target[key] = source[key];\n    }\n  }\n  return target;\n}',
     "desc": "Block __proto__, constructor, prototype keys to prevent pollution."},
    {"lang": "Python", "vuln": "SSRF via PDF Generator", "cwe": "CWE-918", "sev": "HIGH",
     "code": 'from weasyprint import HTML\ndef render(url):\n    return HTML(url=url).write_pdf()',
     "fix": 'from weasyprint import HTML\nfrom urllib.parse import urlparse\ndef render(url):\n    parsed = urlparse(url)\n    if parsed.hostname in ("localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254"):\n        raise ValueError("Blocked internal URL")\n    return HTML(url=url).write_pdf()',
     "desc": "PDF generators that fetch URLs can be used for SSRF."},
    {"lang": "Go", "vuln": "Insecure TLS", "cwe": "CWE-295", "sev": "HIGH",
     "code": 'client := &http.Client{\n    Transport: &http.Transport{\n        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},\n    },\n}',
     "fix": 'client := &http.Client{}',
     "desc": "Never skip TLS verification in production."},
    {"lang": "Python", "vuln": "Insecure Temp File", "cwe": "CWE-377", "sev": "MEDIUM",
     "code": 'f = open("/tmp/upload_" + filename, "wb")\nf.write(data)',
     "fix": 'import tempfile\nwith tempfile.NamedTemporaryFile(dir="/tmp", delete=False) as f:\n    f.write(data)',
     "desc": "Use tempfile module for safe temporary file creation."},
]

SECTIONS["safe_code"] = [
    {"lang": "Python", "vuln": "SAFE", "cwe": "", "sev": "",
     "code": 'db.execute("SELECT * FROM users WHERE name=?", (name,))',
     "fix": "",
     "desc": "This code uses parameterized queries and is safe from SQL injection."},
    {"lang": "Python", "vuln": "SAFE", "cwe": "", "sev": "",
     "code": 'subprocess.run(["grep", pattern, filename], capture_output=True)',
     "fix": "",
     "desc": "Using subprocess with a list of arguments (no shell=True) is safe from command injection."},
    {"lang": "JavaScript", "vuln": "SAFE", "cwe": "", "sev": "",
     "code": 'element.textContent = userInput;',
     "fix": "",
     "desc": "textContent does not parse HTML, making it safe from XSS."},
    {"lang": "Java", "vuln": "SAFE", "cwe": "", "sev": "",
     "code": 'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id=?");\nps.setInt(1, userId);\nResultSet rs = ps.executeQuery();',
     "fix": "",
     "desc": "PreparedStatement with parameterized queries is safe from SQL injection."},
    {"lang": "Go", "vuln": "SAFE", "cwe": "", "sev": "",
     "code": 'db.QueryRow("SELECT * FROM users WHERE email=$1", email)',
     "fix": "",
     "desc": "Go parameterized queries prevent SQL injection."},
    {"lang": "Python", "vuln": "SAFE", "cwe": "", "sev": "",
     "code": 'import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
     "fix": "",
     "desc": "bcrypt is a strong password hashing algorithm. This is the correct approach."},
    {"lang": "Rust", "vuln": "SAFE", "cwe": "", "sev": "",
     "code": 'let name: String = row.get("name");\nconn.execute("SELECT * FROM users WHERE name=$1", &[&name])?;',
     "fix": "",
     "desc": "Parameterized Rust SQL queries are safe from injection."},
    {"lang": "C#", "vuln": "SAFE", "cwe": "", "sev": "",
     "code": 'var cmd = new SqlCommand("SELECT * FROM Users WHERE Id=@id", conn);\ncmd.Parameters.AddWithValue("@id", userId);',
     "fix": "",
     "desc": "SqlCommand with parameters prevents SQL injection."},
    {"lang": "PHP", "vuln": "SAFE", "cwe": "", "sev": "",
     "code": '$stmt = $pdo->prepare("SELECT * FROM users WHERE email=?");\n$stmt->execute([$email]);',
     "fix": "",
     "desc": "PDO prepared statements prevent SQL injection."},
    {"lang": "Ruby", "vuln": "SAFE", "cwe": "", "sev": "",
     "code": 'User.where(email: params[:email]).first',
     "fix": "",
     "desc": "ActiveRecord parameterized queries are safe."},
    {"lang": "JavaScript", "vuln": "SAFE", "cwe": "", "sev": "",
     "code": 'const bcrypt = require("bcrypt");\nconst hash = await bcrypt.hash(password, 12);',
     "fix": "",
     "desc": "bcrypt with cost factor 12 is secure password hashing."},
    {"lang": "Python", "vuln": "SAFE", "cwe": "", "sev": "",
     "code": 'import yaml\nconfig = yaml.safe_load(config_text)',
     "fix": "",
     "desc": "yaml.safe_load prevents arbitrary code execution — this is safe."},
    {"lang": "Go", "vuln": "SAFE", "cwe": "", "sev": "",
     "code": 'func handler(w http.ResponseWriter, r *http.Request) {\n    name := html.EscapeString(r.URL.Query().Get("name"))\n    fmt.Fprintf(w, "<h1>Hello, %s</h1>", name)\n}',
     "fix": "",
     "desc": "html.EscapeString properly prevents XSS."},
    {"lang": "Java", "vuln": "SAFE", "cwe": "", "sev": "",
     "code": 'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nf.setFeature("http://xml.org/sax/features/external-general-entities", false);\nDocument doc = f.newDocumentBuilder().parse(input);',
     "fix": "",
     "desc": "Disabling DTD and external entities prevents XXE."},
]

SECTIONS["multi_vuln"] = [
    {"lang": "Python", "vuln": "SQL Injection + Debug Mode", "cwe": "CWE-89, CWE-215", "sev": "CRITICAL",
     "code": 'app = Flask(__name__)\n\n@app.route("/search")\ndef search():\n    q = request.args.get("q")\n    results = db.execute(f"SELECT * FROM products WHERE name LIKE \'%{q}%\'")\n    return jsonify([dict(r) for r in results])\n\napp.run(debug=True)',
     "fix": 'app = Flask(__name__)\n\n@app.route("/search")\ndef search():\n    q = request.args.get("q")\n    results = db.execute("SELECT * FROM products WHERE name LIKE ?", (f"%{q}%",))\n    return jsonify([dict(r) for r in results])\n\napp.run(debug=False)',
     "desc": "Two issues: (1) SQL injection via f-string in query, (2) Debug mode exposes Werkzeug console."},
    {"lang": "JavaScript", "vuln": "XSS + Open Redirect", "cwe": "CWE-79, CWE-601", "sev": "HIGH",
     "code": 'app.get("/welcome", (req, res) => {\n  const name = req.query.name;\n  const next = req.query.next;\n  res.send(`<h1>Welcome ${name}!</h1><a href="${next}">Continue</a>`);\n});',
     "fix": 'const escapeHtml = s => s.replace(/[&<>"\']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",\'"\':"&quot;","\'":"&#39;"}[c]));\napp.get("/welcome", (req, res) => {\n  const name = escapeHtml(req.query.name || "");\n  let next = req.query.next || "/";\n  if (!next.startsWith("/") || next.startsWith("//")) next = "/";\n  res.send(`<h1>Welcome ${name}!</h1><a href="${next}">Continue</a>`);\n});',
     "desc": "Two issues: (1) Reflected XSS via unescaped name, (2) Open redirect via unvalidated next URL."},
    {"lang": "Python", "vuln": "Command Injection + Path Traversal", "cwe": "CWE-78, CWE-22", "sev": "CRITICAL",
     "code": '@app.route("/convert")\ndef convert():\n    filename = request.args.get("file")\n    path = f"/uploads/{filename}"\n    os.system(f"convert {path} /tmp/output.png")\n    return send_file("/tmp/output.png")',
     "fix": '@app.route("/convert")\ndef convert():\n    filename = secure_filename(request.args.get("file"))\n    path = os.path.join("/uploads", filename)\n    if not os.path.realpath(path).startswith("/uploads"):\n        abort(403)\n    subprocess.run(["convert", path, "/tmp/output.png"], check=True)\n    return send_file("/tmp/output.png")',
     "desc": "Three issues: (1) Path traversal via filename, (2) Command injection via os.system, (3) Predictable temp file."},
]


def generate_pairs():
    pairs = []
    for section_name, items in SECTIONS.items():
        for item in items:
            lang = item["lang"]
            vuln = item["vuln"]
            cwe = item["cwe"]
            sev = item["sev"]
            code = item["code"]
            fix = item.get("fix", "")
            desc = item["desc"]

            if vuln == "SAFE":
                pairs.append({
                    "instruction": f"Analyze this {lang} code for security vulnerabilities:\n```{lang.lower()}\n{code}\n```",
                    "output": f"**No vulnerabilities found.** {desc}",
                })
                pairs.append({
                    "instruction": f"Is this {lang} code secure?\n```{lang.lower()}\n{code}\n```",
                    "output": f"**Yes, this code is secure.** {desc}",
                })
                pairs.append({
                    "instruction": f"Review this {lang} code for security issues:\n```{lang.lower()}\n{code}\n```",
                    "output": f"This code follows security best practices. {desc}",
                })
                continue

            pairs.append({
                "instruction": f"Review this {lang} code for security vulnerabilities:\n```{lang.lower()}\n{code}\n```",
                "output": f"**{vuln}** ({cwe}) [{sev}]\n\n{desc}\n\n**Fixed:**\n```{lang.lower()}\n{fix}\n```",
            })
            pairs.append({
                "instruction": f"Fix the security issue in this {lang} code:\n```{lang.lower()}\n{code}\n```",
                "output": f"**{vuln}** ({cwe}) fixed:\n```{lang.lower()}\n{fix}\n```\n\n{desc}",
            })
            pairs.append({
                "instruction": f"What vulnerabilities does this {lang} code have?\n```{lang.lower()}\n{code}\n```",
                "output": f"**{vuln}** ({cwe}, {sev})\n\n{desc}\n\nRemediation:\n```{lang.lower()}\n{fix}\n```",
            })
            pairs.append({
                "instruction": f"Is this {lang} code safe to deploy?\n```{lang.lower()}\n{code}\n```",
                "output": f"**No.** This code has a {sev.lower()}-severity {vuln.lower()} vulnerability ({cwe}).\n\n{desc}\n\nDeploy this instead:\n```{lang.lower()}\n{fix}\n```",
            })
            pairs.append({
                "instruction": f"Explain the security risk in this code:\n```{lang.lower()}\n{code}\n```",
                "output": f"**{vuln}** ({cwe}) — Severity: {sev}\n\nRisk: {desc}\n\nFix:\n```{lang.lower()}\n{fix}\n```",
            })
            if "CWE-" in cwe:
                pairs.append({
                    "instruction": f"Does this {lang} code contain a {cwe} vulnerability?\n```{lang.lower()}\n{code}\n```",
                    "output": f"Yes — this is a {cwe} ({vuln}) vulnerability, rated {sev}.\n\n{desc}\n\nFixed version:\n```{lang.lower()}\n{fix}\n```",
                })
    return pairs


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    pairs = generate_pairs()

    seen = set()
    unique = []
    for p in pairs:
        key = hashlib.md5(p["instruction"].encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            unique.append(p)

    out = "training_data_expanded.jsonl"
    with open(out, "w", encoding="utf-8") as f:
        for p in unique:
            f.write(json.dumps(p, ensure_ascii=False) + "\n")

    print(f"\n{'='*60}")
    print(f"  EXPANDED TRAINING DATA REPORT")
    print(f"{'='*60}")
    print(f"\n  Total pairs: {len(unique)}")
    print(f"  Sections: {len(SECTIONS)}")
    for name, items in SECTIONS.items():
        print(f"    {name:25s}: {len(items)} templates")
    print(f"  Output: {out} ({os.path.getsize(out)/1024:.0f} KB)")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
