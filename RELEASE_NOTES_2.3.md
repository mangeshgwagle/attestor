# Attestor 2.3 release notes

Attestor 2.3 is a separate, offline-first upgrade. The packaged Attestor 2.2 release is
not overwritten.

## 15,313 explicit rules

Attestor now reports 15,313 unique explicit rules:

- 64 original core rules
- 24 native rules
- 23 extended-language rules
- 202 self-proving advanced 2.2 rules
- 15,000 precision-flow 2.3 rules

The new pack is not 15,000 renamed copies of one expression. It represents a
semantic source-to-sink matrix: 25 documented web ecosystems, 12 concrete
request channels per ecosystem, and 50 dangerous operations per supported
language. Five language adapters contribute 3,000 rules each; ten vulnerability
families contribute 1,500 rules each.

Each flow rule has a stable ID and SHA-256 semantic fingerprint, ecosystem,
language, source and sink signatures, severity, confidence, CWE, CWE Top 25:2025
rank when applicable, OWASP Top 10:2025 category, verified ASVS 5.0.0 references,
description, remediation, and primary documentation links.

Rules are materialized lazily. A scan first activates framework profiles from
real import markers, then evaluates only 12 indexed sources and 50 sinks for the
file's language. Direct argument flows and bounded same-variable flows are
supported. Reassignment, recognized sanitization, SQL parameter position,
comments, strings, inactive frameworks, and overlapping Host/Authorization
header channels have explicit negative guards.

Validate or list the pack:

```sh
python3 detector/precision_catalog.py --self-test
python3 detector/precision_catalog.py --list-rules --json
python3 detector/codearena.py --json
```

## Cybersecurity engine

The defensive posture engine adds:

- value-redacting secret detection for provider formats, private-key material,
  high-confidence named credentials, paired cloud/account credentials, and
  package-registry configuration;
- no raw secret, prefix, suffix, or value-derived hash in findings or reports;
- CI/CD and runner-boundary checks, immutable-action coverage, dependency and
  lockfile coverage, mutable or cleartext dependency sources, and install hooks;
- containers, Kubernetes, Terraform/cloud IAM and public exposure, web/API,
  mobile, cryptography, password derivation, JWT, OAuth, and transport checks;
- repository attack-surface components, STRIDE trust boundaries, evidence-backed
  attack paths, and static reachability/exploitability scoring;
- OWASP Top 10:2025 as the primary application taxonomy, exact CWE Top 25:2025
  weighting, versioned OWASP ASVS 5.0.0 IDs, and NIST SSDF 1.1 mappings;
- deterministic finding fingerprints and baseline documents;
- auditable suppressions requiring an exact fingerprint, a printable reason,
  and an ISO expiry date. Suppressed, expired, invalid, and unmatched entries
  remain visible in JSON, Markdown, and SARIF.

Examples:

```sh
python3 detector/security_posture.py PROJECT --format json
python3 detector/security_posture.py PROJECT --format sarif
python3 detector/security_posture.py PROJECT --format baseline > baseline.json
python3 detector/security_posture.py PROJECT --baseline baseline.json --suppressions suppressions.json
```

The engine remains defensive and offline: it does not exploit targets, probe
networks, resolve packages, install dependencies, or execute target code.
Dependency versions are inventoried locally; advisory status is never guessed
without a vulnerability feed.

The bundled Darwin research corpus is rendered strictly as inert text under a
no-inline-script CSP. Extractor-machine paths were removed and upstream
PayloadsAllTheThings attribution is recorded in `THIRD_PARTY_NOTICES.md`.

The older standalone `secmax.py` command remains available for compatibility,
but its raw line-oriented heuristic findings are no longer promoted into the 2.3
posture score. The unified scanner and contextual engine cover those classes with
comment/string awareness, redaction, reachability, and stronger negative guards;
the report records how many legacy findings were observed and promoted.

## Security workbench UI

The local UI is now a responsive Attestor 2.3 security workbench with:

- outcome-first security overview and severity visualization;
- installed precision-rule count from the secured local health endpoint;
- configurable analysis modes and quick/standard/deep profiles;
- live bounded-job progress and cancellation;
- parsing of up to 15,000 findings with 50, 100, or 200-row pages;
- search, severity filtering, sorting, grouping, and a focused finding drawer;
- local session history, scan comparison, and JSON/Markdown/SARIF/HTML export;
- explicit preview-only labels when persisted output is truncated, so partial
  history is never presented as a complete regression verdict;
- dark/light themes, responsive navigation, keyboard shortcuts, focus handling,
  and ARIA landmarks;
- camera track cleanup on every route away from the optional local camera view.

The server binds to loopback only; remote use requires an operator-controlled,
authenticated tunnel. Requests use a per-launch token,
Host and Origin validation, JSON-only mutation endpoints, bounded queues,
connection limits, subprocess timeouts, and process-tree cancellation. The UI
uses external same-origin JavaScript and CSS under a CSP with no inline script,
no inline style permission, and no `unsafe-eval`.

## Compatibility and CI

- The 313 previous rules and the 42-bug ground-truth corpus remain in place.
- Workspace cache schema and engine version were bumped for the new catalog.
- Workspace JSON, Markdown, HTML, and SARIF preserve new flow metadata.
- Coding Mayhem reports use schema `attestor-coding-mayhem/2.3`.
- CI validates unit tests, the original detector self-test, all advanced fixtures,
  the 15K precision catalog, UI JavaScript syntax, a dry workspace scan, and the
  dry quality gate on Windows and Ubuntu with Python 3.11 and 3.13.

## Standards baseline

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/0x00_2025-Introduction/)
- [2025 CWE Top 25](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html)
- [OWASP ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/)
- [NIST SSDF 1.1 / SP 800-218](https://csrc.nist.gov/pubs/sp/800/218/final)

## Honest limits

- Static findings are evidence for triage, not proof of exploitability.
- The 15K pack currently focuses on Python, JavaScript/TypeScript, Java, C#, and
  PHP web ecosystems. Attestor's other language engines remain active separately.
- The flow engine deliberately follows only direct expressions and one local
  variable for six subsequent executable statements; deeper interprocedural
  flows remain the repository-intelligence engine's job.
- A clean scan is not proof of absence. Coverage, parser/compiler verification,
  skipped files, truncation, and operational errors remain separate report data.
