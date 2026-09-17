# CWE Coverage Map — Attestor vs. Juliet C/C++ 1.3

Derived from `corpus/scorecard.json` (3,054 samples, 40 CWEs, balanced vuln/safe).

**Overall**: Precision 85.8%, Recall 15.1%, F1 0.256
**Confusion**: TP=230, FP=38, FN=1,297, TN=1,489

> **Interpretation**: A non-zero recall means Attestor has at least one rule that fires on that CWE's testcases. Precision < 100% means the rule also fires on safe variants (false positives). 0% recall = **no rule covers this CWE at all**.

---

## CWEs with Non-Zero Recall (Attestor Detects)

| CWE | Name | Recall | Precision | F1 | TP / FN | Notes |
|-----|------|--------|-----------|----|---------|-------|
| **CWE-197** | Numeric Truncation | **100%** | 100% | 1.00 | 42 / 0 | `c-numeric-truncation`, `native-atoi` catch all |
| **CWE-252** | Unchecked Return Value | **100%** | 100% | 1.00 | 50 / 0 | `c-unchecked-return` perfect |
| **CWE-190** | Integer Overflow | 84% | 100% | 0.91 | 32 / 6 | `c-integer-overflow`, `unsigned-underflow` |
| **CWE-23** | Relative Path Traversal | 81% | 100% | 0.90 | 34 / 8 | `c-path-traversal` |
| **CWE-36** | Absolute Path Traversal | 81% | 100% | 0.90 | 34 / 8 | same rule covers both |
| **CWE-134** | Uncontrolled Format String | 100% | 50% | 0.67 | 38 / 0 | `native-format-string` catches all but 38 FPs on safe variants |

**Total detected CWEs**: 6 / 40 (15%)

---

## CWEs with Zero Recall (Attestor Misses Entirely)

| CWE | Name | Samples (vuln) | Gap Type |
|-----|------|----------------|----------|
| CWE-114 | Process Control / Command Injection | 42 | Windows `LoadLibrary` / `CreateProcess` |
| CWE-121 | Stack-based Buffer Overflow | 38 | `strcpy`/`strcat`/`sprintf` into stack buf |
| CWE-122 | Heap-based Buffer Overflow | 50 | `strcpy`/`malloc`+`strcpy` into heap buf |
| CWE-123 | Write-What-Where | 42 | Pointer arithmetic + write |
| CWE-124 | Buffer Underwrite | 38 | Pointer decrement before write |
| CWE-126 | Buffer Over-read | 38 | `memcpy`/`strlen` past end |
| CWE-127 | Buffer Under-read | 38 | Pointer decrement before read |
| CWE-15 | External Control of System Config | 29 | Config file / env var injection |
| CWE-176 | Unicode Handling | 29 | UTF-8/16 conversion flaws |
| CWE-188 | Reliance on Data/Memory Layout | 38 | Struct padding / alignment |
| CWE-191 | Integer Underflow | 38 | `unsigned - 1` wraparound |
| CWE-194 | Unexpected Sign Extension | 42 | `char` → `int` sign extend |
| CWE-195 | Signed-to-Unsigned Conversion | 42 | Negative value becomes large unsigned |
| CWE-196 | Unsigned-to-Signed Conversion | 20 | Large unsigned → negative signed |
| CWE-222 | Truncation of Security Attributes | 19 | Privilege bits truncated |
| CWE-223 | Omission of Security Attributes | 19 | Missing ACL / capability |
| CWE-226 | Sensitive Data in Resource | 50 | Info leak via debug / temp file |
| CWE-242 | Use of Inherently Dangerous Function | 20 | `gets`, `sprintf`, etc. (partial) |
| CWE-244 | Improper Clearing of Heap Memory | 50 | `free` without zeroize |
| CWE-247 | DEPRECATED (Signal Handler Race) | 19 | — |
| CWE-253 | Incorrect Check of Return Value | 50 | `if (func())` vs `if (func() == 0)` |
| CWE-256 | Plaintext Password Storage | 38 | Hardcoded credentials |
| CWE-259 | Hardcoded Password | 42 | In source / config |
| CWE-272 | Least Privilege Violation | 50 | Running as root / admin |
| CWE-273 | Improper Access Control Check | 37 | Missing authorization |
| CWE-284 | Improper Access Control | 50 | Broken ACL / RBAC |
| CWE-319 | Cleartext Transmission | 38 | HTTP / FTP / Telnet |
| CWE-321 | Hardcoded Cryptographic Key | 42 | AES / RSA key in source |
| CWE-325 | Missing Crypto Step | 50 | Skip sign / verify / encrypt |
| CWE-327 | Broken/Weak Crypto Algorithm | 50 | DES / RC4 / MD5 / SHA-1 |
| CWE-328 | Reversible One-Way Hash | 50 | Hash used where MAC needed |
| CWE-338 | Weak PRNG | 19 | `rand()` / `Random` for secrets |
| CWE-364 | Signal Handler Race Condition | 20 | `signal()` + non-async-safe call |
| CWE-366 | Race Condition in File Check | 38 | TOCTOU `access()` → `open()` |
| CWE-367 | TOCTOU File Time Check | 38 | `stat()` → `open()` race |
| CWE-369 | Divide by Zero | 38 | Unchecked divisor |
| CWE-377 | Insecure Temp File | 146 | Predictable `/tmp` name |
| CWE-390 | Empty Catch Block | 92 | `catch (...) {}` |
| CWE-391 | Unchecked Error Condition | 56 | Ignored error code |
| CWE-396 | Overly Broad Catch | 56 | `catch (Exception)` |
| CWE-397 | Overly Broad Throw | 22 | `throw Exception()` |
| CWE-398 | Code Quality / Maintainability | 150 | Not a security CWE |
| CWE-400 | Uncontrolled Resource Consumption | 38 | DoS via alloc / loop |
| CWE-401 | Memory Leak | 38 | `malloc` without `free` |
| CWE-404 | Improper Resource Shutdown | 38 | Leaked FD / handle |
| CWE-415 | Double Free | 38 | `free(p); free(p);` |
| CWE-416 | Use After Free | 50 | `free(p); *p = x;` |
| CWE-426 | Untrusted Search Path | 38 | `PATH` / `LD_LIBRARY_PATH` |
| CWE-427 | Uncontrolled Search Path Element | 42 | Relative path in search |
| CWE-440 | Expected Behavior Violation | 3 | Logic bug, no clear CWE |
| CWE-457 | Uninitialized Variable | 150 | `int x; use(x);` |
| CWE-459 | Incomplete Cleanup | 38 | Partial `free` / `close` |
| CWE-464 | Data Structure Sentinel | 30 | Off-by-one in sentinel |
| CWE-467 | `sizeof` on Pointer | 56 | `sizeof(ptr)` not `sizeof(*ptr)` |

**Total missed CWEs**: 34 / 40 (85%)

---

## Top 5 Highest-Value Coverage Gaps to Fix Next

1.  **CWE-121 / CWE-122** (Stack/Heap Buffer Overflow) — 88 samples combined, **0% recall**. Core memory-safety class; adding `native-strcpy`/`native-strcat`/`native-sprintf` rules would close this.
2.  **CWE-416** (Use After Free) — 50 samples, **0% recall**. Critical exploit primitive; needs heap lifetime tracking.
3.  **CWE-415** (Double Free) — 38 samples, **0% recall**. Related to UAF; same heap analysis.
4.  **CWE-114 / CWE-78** (Command Injection) — 42 samples, **0% recall**. Windows `LoadLibrary`/`CreateProcess` with tainted data; add `LoadLibrary` / `CreateProcess` sink rules.
5.  **CWE-377** (Insecure Temp File) — 146 samples, **0% recall**. Predictable `tmpnam`/`tempnam`/`GetTempFileName`; easy pattern rule.