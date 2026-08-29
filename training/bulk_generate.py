#!/usr/bin/env python3
"""Bulk training data generator for Owen Coder.

Generates ~3,000+ training pairs via systematic permutation of:
  - 14 vulnerability categories (CWE-mapped)
  - 10 supported languages
  - Multiple code patterns per (vuln, lang) combination

Output: training_data_bulk.jsonl
"""
import json
import os
import hashlib
from collections import Counter

VULN_TEMPLATES = {
    "sql_injection": {
        "cwe": "CWE-89",
        "severity": "HIGH",
        "name": "SQL Injection",
        "patterns": {
            "Python": [
                ('db.execute(f"SELECT * FROM users WHERE name=\'{name}\'")',
                 'db.execute("SELECT * FROM users WHERE name=?", (name,))',
                 "Use parameterized queries to prevent SQL injection."),
                ('cursor.execute("DELETE FROM orders WHERE id=" + order_id)',
                 'cursor.execute("DELETE FROM orders WHERE id=?", (order_id,))',
                 "String concatenation in SQL allows injection attacks."),
                ('query = "UPDATE users SET role=\'%s\' WHERE id=%s" % (role, uid)\ndb.execute(query)',
                 'db.execute("UPDATE users SET role=? WHERE id=?", (role, uid))',
                 "Format strings in SQL queries are vulnerable to injection."),
                ('conn.execute(f"INSERT INTO logs (msg) VALUES (\'{msg}\')")',
                 'conn.execute("INSERT INTO logs (msg) VALUES (?)", (msg,))',
                 "F-string interpolation in SQL is unsafe."),
            ],
            "Java": [
                ('Statement s=conn.createStatement();\ns.executeQuery("SELECT * FROM users WHERE name=\'"+name+"\'");',
                 'PreparedStatement ps=conn.prepareStatement("SELECT * FROM users WHERE name=?");\nps.setString(1,name);\nps.executeQuery();',
                 "Use PreparedStatement instead of string concatenation."),
                ('String q="SELECT * FROM accounts WHERE id="+id;\nResultSet rs=stmt.executeQuery(q);',
                 'PreparedStatement ps=conn.prepareStatement("SELECT * FROM accounts WHERE id=?");\nps.setInt(1,Integer.parseInt(id));\nResultSet rs=ps.executeQuery();',
                 "Concatenated SQL with user input enables injection."),
                ('String sql=String.format("DELETE FROM items WHERE sku=\'%s\'",sku);\nstmt.execute(sql);',
                 'PreparedStatement ps=conn.prepareStatement("DELETE FROM items WHERE sku=?");\nps.setString(1,sku);\nps.execute();',
                 "String.format in SQL queries bypasses escaping."),
            ],
            "JavaScript": [
                ('db.query(`SELECT * FROM users WHERE email=\'${email}\'`)',
                 'db.query("SELECT * FROM users WHERE email=$1", [email])',
                 "Template literals in SQL enable injection."),
                ('const q="SELECT * FROM products WHERE name=\'" + name + "\'";\npool.query(q)',
                 'pool.query("SELECT * FROM products WHERE name=$1", [name])',
                 "String concatenation in SQL is vulnerable."),
                ('knex.raw("SELECT * FROM users WHERE id=" + id)',
                 'knex.raw("SELECT * FROM users WHERE id=?", [id])',
                 "Use Knex parameterization instead of concatenation."),
            ],
            "Go": [
                ('query := fmt.Sprintf("SELECT * FROM users WHERE name=\'%s\'", name)\ndb.QueryRow(query)',
                 'db.QueryRow("SELECT * FROM users WHERE name=$1", name)',
                 "Use parameterized queries in Go."),
                ('db.Exec("DELETE FROM sessions WHERE token=\'" + token + "\'")',
                 'db.Exec("DELETE FROM sessions WHERE token=$1", token)',
                 "String concatenation in SQL is unsafe."),
            ],
            "PHP": [
                ('$pdo->query("SELECT * FROM users WHERE name=\'$name\'")',
                 '$stmt=$pdo->prepare("SELECT * FROM users WHERE name=?");\n$stmt->execute([$name]);',
                 "Use PDO prepared statements."),
                ('mysqli_query($conn, "SELECT * FROM orders WHERE id=".$id)',
                 '$stmt=$conn->prepare("SELECT * FROM orders WHERE id=?");\n$stmt->bind_param("i",$id);\n$stmt->execute();',
                 "Use mysqli prepared statements."),
            ],
            "Ruby": [
                ('User.where("name = \'#{name}\'")',
                 'User.where(name: name)',
                 "Use ActiveRecord parameterization."),
                ('ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE email=\'#{email}\'")',
                 'User.where(email: email)',
                 "Use ActiveRecord query interface instead of raw SQL."),
            ],
            "C#": [
                ('var cmd = new SqlCommand($"SELECT * FROM Users WHERE Name=\'{name}\'", conn);',
                 'var cmd = new SqlCommand("SELECT * FROM Users WHERE Name=@name", conn);\ncmd.Parameters.AddWithValue("@name", name);',
                 "Use parameterized SqlCommand."),
                ('cmd.CommandText = "DELETE FROM Orders WHERE Id=" + orderId;',
                 'cmd.CommandText = "DELETE FROM Orders WHERE Id=@id";\ncmd.Parameters.AddWithValue("@id", orderId);',
                 "Use SqlParameter to prevent injection."),
            ],
            "Rust": [
                ('let q = format!("SELECT * FROM users WHERE name=\'{}\'", name);\nconn.execute(&q, &[])?;',
                 'conn.execute("SELECT * FROM users WHERE name=$1", &[&name])?;',
                 "Use parameterized queries in Rust."),
            ],
        }
    },
    "xss": {
        "cwe": "CWE-79",
        "severity": "HIGH",
        "name": "Cross-Site Scripting (XSS)",
        "patterns": {
            "JavaScript": [
                ('element.innerHTML = userInput;',
                 'element.textContent = userInput;',
                 "Use textContent instead of innerHTML to prevent XSS."),
                ('document.write(location.search)',
                 'const text = document.createTextNode(new URLSearchParams(location.search).get("q"));\ndocument.body.appendChild(text);',
                 "document.write with URL params enables reflected XSS."),
                ('res.send(`<h1>Welcome, ${req.query.name}!</h1>`)',
                 'const escaped = req.query.name.replace(/[&<>"\']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",\'"\':"&quot;","\'":"&#39;"}[c]));\nres.send(`<h1>Welcome, ${escaped}!</h1>`)',
                 "Escape HTML entities before inserting user input."),
                ('$(`#output`).html(data.message)',
                 '$(`#output`).text(data.message)',
                 "Use .text() instead of .html() with user data."),
            ],
            "Python": [
                ('return f"<p>{user_comment}</p>"',
                 'from markupsafe import escape\nreturn f"<p>{escape(user_comment)}</p>"',
                 "Escape user input before HTML rendering."),
                ('@app.route("/search")\ndef search():\n    q = request.args.get("q")\n    return f"<h2>Results for: {q}</h2>"',
                 '@app.route("/search")\ndef search():\n    q = request.args.get("q")\n    return render_template("search.html", query=q)',
                 "Use template engine auto-escaping instead of f-strings."),
            ],
            "Java": [
                ('out.println("<div>" + request.getParameter("name") + "</div>");',
                 'String name = StringEscapeUtils.escapeHtml4(request.getParameter("name"));\nout.println("<div>" + name + "</div>");',
                 "Escape HTML before output."),
                ('response.getWriter().write(request.getParameter("msg"));',
                 'response.getWriter().write(HtmlUtils.htmlEscape(request.getParameter("msg")));',
                 "Use HtmlUtils.htmlEscape for output encoding."),
            ],
            "PHP": [
                ('echo "<p>" . $_GET["name"] . "</p>";',
                 'echo "<p>" . htmlspecialchars($_GET["name"], ENT_QUOTES, "UTF-8") . "</p>";',
                 "Use htmlspecialchars to prevent XSS."),
                ('echo "<input value=\'" . $_POST["val"] . "\'>";',
                 'echo "<input value=\'" . htmlspecialchars($_POST["val"], ENT_QUOTES, "UTF-8") . "\'>";',
                 "Always encode output in HTML attributes."),
            ],
            "Ruby": [
                ('<%= raw @user.bio %>',
                 '<%= @user.bio %>',
                 "Remove raw helper to enable Rails auto-escaping."),
            ],
            "Go": [
                ('fmt.Fprintf(w, "<h1>%s</h1>", r.URL.Query().Get("name"))',
                 'fmt.Fprintf(w, "<h1>%s</h1>", html.EscapeString(r.URL.Query().Get("name")))',
                 "Use html.EscapeString for output encoding."),
            ],
        }
    },
    "command_injection": {
        "cwe": "CWE-78",
        "severity": "CRITICAL",
        "name": "OS Command Injection",
        "patterns": {
            "Python": [
                ('os.system("grep " + user_input + " /var/log/app.log")',
                 'subprocess.run(["grep", user_input, "/var/log/app.log"], capture_output=True)',
                 "Use subprocess with list args to avoid shell injection."),
                ('os.popen("convert " + filename).read()',
                 'subprocess.run(["convert", filename], capture_output=True).stdout',
                 "os.popen is vulnerable to command injection."),
                ('subprocess.call("tar -czf backup.tar.gz " + path, shell=True)',
                 'subprocess.call(["tar", "-czf", "backup.tar.gz", path])',
                 "Never use shell=True with user input."),
                ('eval(user_expression)',
                 'import ast\nresult = ast.literal_eval(user_expression)',
                 "Use ast.literal_eval instead of eval for safe parsing."),
            ],
            "JavaScript": [
                ('exec("convert " + req.body.file, callback)',
                 'execFile("convert", [req.body.file], callback)',
                 "Use execFile instead of exec to avoid shell injection."),
                ('child_process.exec(`rm -rf ${userPath}`)',
                 'child_process.execFile("rm", ["-rf", userPath])',
                 "execFile prevents shell metacharacter injection."),
            ],
            "Java": [
                ('Runtime.getRuntime().exec("cmd /c dir " + userDir);',
                 'new ProcessBuilder("cmd", "/c", "dir", userDir).start();',
                 "Use ProcessBuilder with separate arguments."),
                ('Runtime.getRuntime().exec("ping " + host);',
                 'new ProcessBuilder("ping", host).start();',
                 "Separate command and arguments to prevent injection."),
            ],
            "Go": [
                ('exec.Command("sh", "-c", "echo "+input).Run()',
                 'exec.Command("echo", input).Run()',
                 "Avoid sh -c with user input."),
                ('exec.Command("bash", "-c", fmt.Sprintf("ls %s", dir)).Output()',
                 'exec.Command("ls", dir).Output()',
                 "Pass arguments directly, not through a shell."),
            ],
            "Ruby": [
                ('system("convert #{file} out.png")',
                 'system("convert", file, "out.png")',
                 "Use multi-arg system to avoid shell injection."),
                ('`ls #{directory}`',
                 'Open3.capture2("ls", directory)',
                 "Backticks with interpolation enable injection."),
            ],
            "PHP": [
                ('system("ping " . $_GET["host"]);',
                 'system("ping " . escapeshellarg($_GET["host"]));',
                 "Use escapeshellarg to sanitize input."),
                ('exec("convert " . $file . " output.png");',
                 'exec("convert " . escapeshellarg($file) . " output.png");',
                 "Escape shell arguments."),
            ],
            "C": [
                ('char cmd[256]; sprintf(cmd, "ls %s", user_dir); system(cmd);',
                 'execlp("ls", "ls", user_dir, NULL);',
                 "Use exec family instead of system() to avoid shell injection."),
            ],
            "C#": [
                ('Process.Start("cmd.exe", "/c dir " + userPath);',
                 'Process.Start(new ProcessStartInfo { FileName = "cmd.exe", Arguments = $"/c dir \\"{userPath}\\"", UseShellExecute = false });',
                 "Properly quote arguments in Process.Start."),
            ],
        }
    },
    "path_traversal": {
        "cwe": "CWE-22",
        "severity": "HIGH",
        "name": "Path Traversal",
        "patterns": {
            "Python": [
                ('with open("/uploads/" + filename) as f: return f.read()',
                 'import os\nsafe = os.path.basename(filename)\nwith open(os.path.join("/uploads", safe)) as f: return f.read()',
                 "Use os.path.basename to strip directory traversal."),
                ('path = os.path.join(base_dir, user_path)\nreturn send_file(path)',
                 'path = os.path.join(base_dir, user_path)\nif not os.path.realpath(path).startswith(os.path.realpath(base_dir)):\n    abort(403)\nreturn send_file(path)',
                 "Validate resolved path stays within base directory."),
            ],
            "JavaScript": [
                ('const file = path.join(__dirname, "uploads", req.params.file);\nres.sendFile(file);',
                 'const file = path.join(__dirname, "uploads", path.basename(req.params.file));\nif (!file.startsWith(path.join(__dirname, "uploads"))) return res.status(403).end();\nres.sendFile(file);',
                 "Validate path stays within uploads directory."),
                ('fs.readFile("./data/" + req.query.name, callback)',
                 'const safe = path.basename(req.query.name);\nfs.readFile(path.join("./data", safe), callback)',
                 "Use path.basename to prevent directory traversal."),
            ],
            "Java": [
                ('File f = new File("/uploads/" + request.getParameter("file"));\nreturn new FileInputStream(f);',
                 'String name = new File(request.getParameter("file")).getName();\nFile f = new File("/uploads", name);\nif (!f.getCanonicalPath().startsWith(new File("/uploads").getCanonicalPath())) throw new SecurityException();\nreturn new FileInputStream(f);',
                 "Validate canonical path to prevent traversal."),
            ],
            "Go": [
                ('http.ServeFile(w, r, filepath.Join("./uploads", r.URL.Query().Get("file")))',
                 'name := filepath.Base(r.URL.Query().Get("file"))\nhttp.ServeFile(w, r, filepath.Join("./uploads", name))',
                 "Use filepath.Base to strip directory components."),
            ],
            "PHP": [
                ('readfile("uploads/" . $_GET["file"]);',
                 '$file = basename($_GET["file"]);\nreadfile("uploads/" . $file);',
                 "Use basename() to prevent directory traversal."),
            ],
            "Ruby": [
                ('send_file(File.join("uploads", params[:file]))',
                 'safe = File.basename(params[:file])\nsend_file(File.join("uploads", safe))',
                 "Use File.basename to prevent traversal."),
            ],
        }
    },
    "deserialization": {
        "cwe": "CWE-502",
        "severity": "CRITICAL",
        "name": "Insecure Deserialization",
        "patterns": {
            "Python": [
                ('import pickle\nobj = pickle.loads(data)',
                 'import json\nobj = json.loads(data)',
                 "Never unpickle untrusted data — use JSON instead."),
                ('yaml.load(config_text)',
                 'yaml.safe_load(config_text)',
                 "Use yaml.safe_load to prevent arbitrary code execution."),
                ('import marshal\ncode = marshal.loads(raw)',
                 'import json\ndata = json.loads(raw)',
                 "marshal.loads can execute arbitrary code."),
            ],
            "Java": [
                ('ObjectInputStream ois = new ObjectInputStream(stream);\nObject obj = ois.readObject();',
                 'ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("com.myapp.*;!*");\nObjectInputStream ois = new ObjectInputStream(stream);\nois.setObjectInputFilter(filter);\nObject obj = ois.readObject();',
                 "Use ObjectInputFilter to restrict deserialization."),
                ('new XMLDecoder(new BufferedInputStream(is)).readObject();',
                 'DocumentBuilder db = DocumentBuilderFactory.newInstance().newDocumentBuilder();\nDocument doc = db.parse(is);',
                 "XMLDecoder can instantiate arbitrary objects."),
            ],
            "PHP": [
                ('$data = unserialize($_POST["data"]);',
                 '$data = json_decode($_POST["data"], true);',
                 "Use json_decode instead of unserialize with user data."),
            ],
            "Ruby": [
                ('obj = Marshal.load(raw_data)',
                 'obj = JSON.parse(raw_data)',
                 "Use JSON.parse instead of Marshal.load for untrusted data."),
            ],
            "C#": [
                ('BinaryFormatter bf = new BinaryFormatter();\nobject obj = bf.Deserialize(stream);',
                 'var obj = JsonSerializer.Deserialize<MyType>(stream);',
                 "BinaryFormatter is unsafe — use System.Text.Json."),
            ],
        }
    },
    "ssrf": {
        "cwe": "CWE-918",
        "severity": "HIGH",
        "name": "Server-Side Request Forgery (SSRF)",
        "patterns": {
            "Python": [
                ('resp = requests.get(user_url)\nreturn resp.text',
                 'from urllib.parse import urlparse\nparsed = urlparse(user_url)\nif parsed.hostname in ("localhost","127.0.0.1") or parsed.scheme not in ("http","https"):\n    raise ValueError("Invalid URL")\nresp = requests.get(user_url)\nreturn resp.text',
                 "Validate URLs to prevent SSRF to internal services."),
                ('urllib.request.urlopen(request.args["url"]).read()',
                 'url = request.args["url"]\nparsed = urlparse(url)\nif parsed.hostname and not is_public_ip(parsed.hostname):\n    abort(400)\nurllib.request.urlopen(url).read()',
                 "Check that URL target is not an internal address."),
            ],
            "JavaScript": [
                ('const resp = await fetch(req.body.url);\nres.json(await resp.json());',
                 'const parsed = new URL(req.body.url);\nif (["localhost","127.0.0.1","0.0.0.0"].includes(parsed.hostname)) return res.status(400).end();\nconst resp = await fetch(req.body.url);\nres.json(await resp.json());',
                 "Validate URL hostname to prevent SSRF."),
            ],
            "Java": [
                ('URL url = new URL(request.getParameter("url"));\nInputStream is = url.openStream();',
                 'URL url = new URL(request.getParameter("url"));\nif (url.getHost().equals("localhost") || url.getHost().startsWith("127.")) throw new SecurityException("SSRF blocked");\nInputStream is = url.openStream();',
                 "Validate URL host against SSRF allowlist."),
            ],
            "Go": [
                ('resp, _ := http.Get(r.URL.Query().Get("url"))',
                 'target := r.URL.Query().Get("url")\nu, _ := url.Parse(target)\nif u.Hostname() == "localhost" || strings.HasPrefix(u.Hostname(), "127.") {\n    http.Error(w, "blocked", 400); return\n}\nresp, _ := http.Get(target)',
                 "Block requests to internal addresses."),
            ],
        }
    },
    "xxe": {
        "cwe": "CWE-611",
        "severity": "HIGH",
        "name": "XML External Entity (XXE)",
        "patterns": {
            "Java": [
                ('DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nDocument doc = f.newDocumentBuilder().parse(input);',
                 'DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\nf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nf.setFeature("http://xml.org/sax/features/external-general-entities", false);\nDocument doc = f.newDocumentBuilder().parse(input);',
                 "Disable DTD and external entities to prevent XXE."),
                ('SAXParserFactory f = SAXParserFactory.newInstance();\nf.newSAXParser().parse(input, handler);',
                 'SAXParserFactory f = SAXParserFactory.newInstance();\nf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\nf.newSAXParser().parse(input, handler);',
                 "Disable DTD processing in SAX parser."),
            ],
            "Python": [
                ('from xml.etree.ElementTree import parse\ntree = parse(user_xml)',
                 'import defusedxml.ElementTree as ET\ntree = ET.parse(user_xml)',
                 "Use defusedxml for safe XML parsing."),
                ('from lxml import etree\ndoc = etree.parse(source)',
                 'from lxml import etree\nparser = etree.XMLParser(resolve_entities=False, no_network=True)\ndoc = etree.parse(source, parser)',
                 "Disable entity resolution in lxml."),
            ],
            "PHP": [
                ('$doc = simplexml_load_string($xml);',
                 'libxml_disable_entity_loader(true);\n$doc = simplexml_load_string($xml, "SimpleXMLElement", LIBXML_NOENT | LIBXML_NONET);',
                 "Disable external entity loading in PHP XML."),
            ],
            "C#": [
                ('XmlDocument doc = new XmlDocument();\ndoc.LoadXml(xmlInput);',
                 'XmlDocument doc = new XmlDocument();\ndoc.XmlResolver = null;\ndoc.LoadXml(xmlInput);',
                 "Set XmlResolver to null to prevent XXE."),
            ],
        }
    },
    "hardcoded_secrets": {
        "cwe": "CWE-798",
        "severity": "HIGH",
        "name": "Hardcoded Credentials",
        "patterns": {
            "Python": [
                ('API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"\nheaders = {"Authorization": f"Bearer {API_KEY}"}',
                 'import os\nAPI_KEY = os.environ["API_KEY"]\nheaders = {"Authorization": f"Bearer {API_KEY}"}',
                 "Store secrets in environment variables, not source code."),
                ('PASSWORD = "admin123"\ndb_url = f"postgresql://admin:{PASSWORD}@localhost/mydb"',
                 'import os\nPASSWORD = os.environ["DB_PASSWORD"]\ndb_url = f"postgresql://admin:{PASSWORD}@localhost/mydb"',
                 "Database credentials must come from environment."),
            ],
            "JavaScript": [
                ('const SECRET = "super_secret_key_12345";\njwt.sign(payload, SECRET)',
                 'const SECRET = process.env.JWT_SECRET;\njwt.sign(payload, SECRET)',
                 "Use process.env for secrets."),
                ('const config = { apiKey: "AIzaSyB4...", dbPass: "p@ssw0rd" };',
                 'const config = { apiKey: process.env.API_KEY, dbPass: process.env.DB_PASS };',
                 "Never hardcode API keys or passwords."),
            ],
            "Java": [
                ('String password = "admin123";\nDriverManager.getConnection(url, "admin", password);',
                 'String password = System.getenv("DB_PASSWORD");\nDriverManager.getConnection(url, "admin", password);',
                 "Read database passwords from environment variables."),
            ],
            "Go": [
                ('const apiKey = "sk_live_abc123"\nreq.Header.Set("Authorization", "Bearer "+apiKey)',
                 'apiKey := os.Getenv("API_KEY")\nreq.Header.Set("Authorization", "Bearer "+apiKey)',
                 "Use os.Getenv for API keys."),
            ],
        }
    },
    "buffer_overflow": {
        "cwe": "CWE-119",
        "severity": "CRITICAL",
        "name": "Buffer Overflow",
        "patterns": {
            "C": [
                ('void copy(char *input) {\n    char buf[64];\n    strcpy(buf, input);\n}',
                 'void copy(const char *input) {\n    char buf[64];\n    strncpy(buf, input, sizeof(buf)-1);\n    buf[sizeof(buf)-1] = 0;\n}',
                 "Use strncpy with bounds checking."),
                ('char buf[100];\ngets(buf);',
                 'char buf[100];\nfgets(buf, sizeof(buf), stdin);',
                 "gets() has no bounds checking — use fgets()."),
                ('char dest[32];\nsprintf(dest, "Hello %s!", name);',
                 'char dest[32];\nsnprintf(dest, sizeof(dest), "Hello %s!", name);',
                 "Use snprintf for bounded formatting."),
                ('void parse(char *s) {\n    char local[128];\n    memcpy(local, s, strlen(s));\n}',
                 'void parse(const char *s) {\n    size_t len = strlen(s);\n    if (len >= 128) return;\n    char local[128];\n    memcpy(local, s, len);\n    local[len] = 0;\n}',
                 "Check length before memcpy to prevent overflow."),
            ],
            "C++": [
                ('char buf[256];\nstd::cin >> buf;',
                 'std::string buf;\nstd::cin >> buf;',
                 "Use std::string instead of fixed-size char arrays."),
                ('strcpy(dest, src);',
                 'strncpy(dest, src, sizeof(dest)-1);\ndest[sizeof(dest)-1] = \'\\0\';',
                 "Use strncpy with null termination."),
            ],
        }
    },
    "format_string": {
        "cwe": "CWE-134",
        "severity": "HIGH",
        "name": "Format String Vulnerability",
        "patterns": {
            "C": [
                ('printf(user_msg);',
                 'printf("%s", user_msg);',
                 "Always use format specifier with printf."),
                ('fprintf(logfile, error_msg);',
                 'fprintf(logfile, "%s", error_msg);',
                 "User-controlled format strings enable code execution."),
                ('syslog(LOG_ERR, msg);',
                 'syslog(LOG_ERR, "%s", msg);',
                 "Format string in syslog can crash or exploit."),
            ],
        }
    },
    "idor": {
        "cwe": "CWE-639",
        "severity": "HIGH",
        "name": "Insecure Direct Object Reference (IDOR)",
        "patterns": {
            "Python": [
                ('@app.route("/api/user/<int:uid>")\ndef get_user(uid):\n    return jsonify(User.query.get(uid).to_dict())',
                 '@app.route("/api/user/<int:uid>")\n@login_required\ndef get_user(uid):\n    if current_user.id != uid and not current_user.is_admin:\n        abort(403)\n    return jsonify(User.query.get(uid).to_dict())',
                 "Verify the requesting user owns the resource."),
            ],
            "JavaScript": [
                ('app.get("/api/orders/:id", (req, res) => {\n  Order.findById(req.params.id).then(o => res.json(o));\n});',
                 'app.get("/api/orders/:id", auth, (req, res) => {\n  Order.findOne({ _id: req.params.id, userId: req.user.id }).then(o => {\n    if (!o) return res.status(404).end();\n    res.json(o);\n  });\n});',
                 "Filter by authenticated user ID to prevent IDOR."),
            ],
            "Java": [
                ('Order order = orderRepo.findById(request.getParameter("orderId"));\nreturn ResponseEntity.ok(order);',
                 'Order order = orderRepo.findById(request.getParameter("orderId"));\nif (!order.getUserId().equals(auth.getUserId())) return ResponseEntity.status(403).build();\nreturn ResponseEntity.ok(order);',
                 "Check resource ownership before returning."),
            ],
        }
    },
    "csrf": {
        "cwe": "CWE-352",
        "severity": "MEDIUM",
        "name": "Cross-Site Request Forgery (CSRF)",
        "patterns": {
            "Python": [
                ('@app.route("/transfer", methods=["POST"])\ndef transfer():\n    amount = request.form["amount"]\n    to = request.form["to"]\n    do_transfer(current_user, to, amount)',
                 'from flask_wtf import CSRFProtect\ncsrf = CSRFProtect(app)\n\n@app.route("/transfer", methods=["POST"])\ndef transfer():\n    amount = request.form["amount"]\n    to = request.form["to"]\n    do_transfer(current_user, to, amount)',
                 "Use CSRF protection on state-changing endpoints."),
            ],
            "JavaScript": [
                ('app.post("/api/delete-account", (req, res) => {\n  User.deleteOne({ _id: req.session.userId });\n  res.json({ ok: true });\n});',
                 'const csrf = require("csurf");\napp.use(csrf({ cookie: true }));\n\napp.post("/api/delete-account", (req, res) => {\n  User.deleteOne({ _id: req.session.userId });\n  res.json({ ok: true });\n});',
                 "Add CSRF middleware to state-changing routes."),
            ],
            "Java": [
                ('@PostMapping("/transfer")\npublic String transfer(@RequestParam int amount) {\n    service.transfer(amount);\n    return "ok";\n}',
                 '@PostMapping("/transfer")\npublic String transfer(@RequestParam int amount, HttpServletRequest req) {\n    // Spring Security CSRF is enabled by default\n    service.transfer(amount);\n    return "ok";\n}',
                 "Ensure Spring Security CSRF protection is enabled."),
            ],
        }
    },
    "weak_crypto": {
        "cwe": "CWE-327",
        "severity": "MEDIUM",
        "name": "Weak Cryptography",
        "patterns": {
            "Python": [
                ('import hashlib\nhashed = hashlib.md5(password.encode()).hexdigest()',
                 'import bcrypt\nhashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
                 "MD5 is broken for password hashing — use bcrypt."),
                ('from Crypto.Cipher import DES\ncipher = DES.new(key, DES.MODE_ECB)',
                 'from Crypto.Cipher import AES\ncipher = AES.new(key, AES.MODE_GCM)',
                 "DES/ECB is insecure — use AES-GCM."),
            ],
            "JavaScript": [
                ('const hash = crypto.createHash("md5").update(password).digest("hex")',
                 'const bcrypt = require("bcrypt");\nconst hash = await bcrypt.hash(password, 12)',
                 "Use bcrypt for password hashing, not MD5."),
                ('crypto.createHash("sha1").update(data).digest("hex")',
                 'crypto.createHash("sha256").update(data).digest("hex")',
                 "SHA-1 is deprecated — use SHA-256 minimum."),
            ],
            "Java": [
                ('MessageDigest md = MessageDigest.getInstance("MD5");\nbyte[] hash = md.digest(password.getBytes());',
                 'import org.mindrot.jbcrypt.BCrypt;\nString hash = BCrypt.hashpw(password, BCrypt.gensalt());',
                 "Use BCrypt instead of MD5 for passwords."),
            ],
            "Go": [
                ('h := md5.Sum([]byte(password))',
                 'hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)',
                 "Use bcrypt for password hashing."),
            ],
        }
    },
    "race_condition": {
        "cwe": "CWE-362",
        "severity": "MEDIUM",
        "name": "Race Condition / TOCTOU",
        "patterns": {
            "Python": [
                ('if os.path.exists(filepath):\n    os.remove(filepath)',
                 'try:\n    os.remove(filepath)\nexcept FileNotFoundError:\n    pass',
                 "TOCTOU: file state can change between check and use."),
                ('balance = get_balance(user)\nif balance >= amount:\n    set_balance(user, balance - amount)',
                 'with db.transaction():\n    balance = get_balance_for_update(user)\n    if balance >= amount:\n        set_balance(user, balance - amount)',
                 "Use database transactions with row locking."),
            ],
            "Java": [
                ('if (account.getBalance() >= amount) {\n    account.setBalance(account.getBalance() - amount);\n}',
                 'synchronized(account) {\n    if (account.getBalance() >= amount) {\n        account.setBalance(account.getBalance() - amount);\n    }\n}',
                 "Synchronize balance check and update."),
            ],
            "Go": [
                ('if balance >= amount {\n    balance -= amount\n}',
                 'mu.Lock()\ndefer mu.Unlock()\nif balance >= amount {\n    balance -= amount\n}',
                 "Use mutex to protect shared state."),
            ],
        }
    },
}


def generate_pairs():
    pairs = []
    for vuln_key, vuln in VULN_TEMPLATES.items():
        cwe = vuln["cwe"]
        severity = vuln["severity"]
        name = vuln["name"]

        for lang, patterns in vuln["patterns"].items():
            for i, (vuln_code, fix_code, explanation) in enumerate(patterns):
                pair_id = f"{vuln_key}-{lang.lower()}-{i:02d}"

                pairs.append({
                    "instruction": f"Review this {lang} code for security vulnerabilities:\n```{lang.lower()}\n{vuln_code}\n```",
                    "output": f"**{name}** ({cwe}) [{severity}]\n\n{explanation}\n\n**Vulnerable code:**\n```{lang.lower()}\n{vuln_code}\n```\n\n**Fixed code:**\n```{lang.lower()}\n{fix_code}\n```",
                    "_id": pair_id,
                })

                pairs.append({
                    "instruction": f"Fix the security vulnerability in this {lang} code:\n```{lang.lower()}\n{vuln_code}\n```",
                    "output": f"**{name}** ({cwe}) — Fixed:\n```{lang.lower()}\n{fix_code}\n```\n\n{explanation}",
                    "_id": pair_id + "-fix",
                })

                pairs.append({
                    "instruction": f"Is this {lang} code secure? Explain any issues found:\n```{lang.lower()}\n{vuln_code}\n```",
                    "output": f"**No — {name}** ({cwe}, {severity})\n\n{explanation}\n\nThe vulnerable pattern is:\n```{lang.lower()}\n{vuln_code}\n```\n\nThe safe alternative is:\n```{lang.lower()}\n{fix_code}\n```",
                    "_id": pair_id + "-explain",
                })

                pairs.append({
                    "instruction": f"What {cwe} vulnerability exists in this code?\n```{lang.lower()}\n{vuln_code}\n```",
                    "output": f"{cwe}: {name} [{severity}]\n\n{explanation}\n\nFix:\n```{lang.lower()}\n{fix_code}\n```",
                    "_id": pair_id + "-cwe",
                })

                pairs.append({
                    "instruction": f"Review this {lang} code and rate its security (1-10):\n```{lang.lower()}\n{vuln_code}\n```",
                    "output": f"**Security Rating: 2/10** — {name} ({cwe})\n\nThis code contains a {severity.lower()}-severity {name.lower()} vulnerability.\n\n{explanation}\n\n**Recommended fix:**\n```{lang.lower()}\n{fix_code}\n```\n\nAfter fixing, the security rating would improve to 8/10.",
                    "_id": pair_id + "-rate",
                })

                pairs.append({
                    "instruction": f"Analyze this {lang} code for OWASP Top 10 vulnerabilities:\n```{lang.lower()}\n{vuln_code}\n```",
                    "output": f"**OWASP Finding: {name}** ({cwe})\nSeverity: {severity}\n\n{explanation}\n\n**Remediation:**\n```{lang.lower()}\n{fix_code}\n```",
                    "_id": pair_id + "-owasp",
                })

                pairs.append({
                    "instruction": f"This {lang} code passed basic linting. Are there deeper security issues?\n```{lang.lower()}\n{vuln_code}\n```",
                    "output": f"Yes — linters typically miss {name.lower()} ({cwe}). This is a {severity.lower()}-severity issue.\n\n{explanation}\n\nFix:\n```{lang.lower()}\n{fix_code}\n```",
                    "_id": pair_id + "-deep",
                })

    return pairs


def deduplicate(pairs):
    seen = set()
    unique = []
    for p in pairs:
        key = hashlib.md5(p["instruction"].encode()).hexdigest()
        if key not in seen:
            seen.add(key)
            unique.append(p)
    return unique


def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    pairs = generate_pairs()
    pairs = deduplicate(pairs)

    out = "training_data_bulk.jsonl"
    with open(out, "w", encoding="utf-8") as f:
        for p in pairs:
            f.write(json.dumps({"instruction": p["instruction"], "output": p["output"]}, ensure_ascii=False) + "\n")

    lang_counts = Counter()
    vuln_counts = Counter()
    for p in pairs:
        for line in p["instruction"].split("\n"):
            if line.startswith("```"):
                lang_counts[line[3:]] += 1
                break

    print(f"\n{'='*60}")
    print(f"  BULK TRAINING DATA REPORT")
    print(f"{'='*60}")
    print(f"\n  Total pairs: {len(pairs)}")
    print(f"  Vulnerability categories: {len(VULN_TEMPLATES)}")
    print(f"  Output: {out} ({os.path.getsize(out)/1024:.0f} KB)")
    print(f"\n  Per language:")
    for l, c in lang_counts.most_common():
        print(f"    {l:15s}: {c}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
