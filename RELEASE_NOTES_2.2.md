# Attestor 2.2 release notes

Attestor 2.2 is a separate, offline-first upgrade. Attestor 2.1 is not overwritten.

## Maximum detector expansion

- 313 unique explicit catalog rules: 64 core, 24 native, 23 extended-language,
  and 202 advanced 2.2 rules.
- The advanced pack covers Python, JavaScript/TypeScript, Java, Kotlin, C#, Go,
  Rust, Ruby, PHP, Swift, shell, PowerShell, Solidity, Terraform, Kubernetes/YAML,
  GitHub Actions, Docker, SQL, Nginx, and npm configuration.
- Every advanced rule includes a positive fixture, severity, category, confidence,
  fix guidance, and CWE/OWASP metadata where applicable.
- Comment/string masking, context checks, numeric validation, and self-scanning
  reduce noise. `python detector/advanced_rules.py --self-test` proves the pack.
- Parser/compiler failures, binary files, oversized files, unsupported inputs, and
  operational errors are distinct from clean results.

## Coding Mayhem

`python detector/superattestor.py --mayhem PROJECT`

Coding Mayhem combines:

- cached parallel multi-language scanning;
- Python and native A–F grading;
- syntax/compiler adapters when explicitly enabled;
- imports, calls, inheritance, entry points, reachability, cycles, config use, and
  source-to-sink repository intelligence;
- defensive cybersecurity posture and a CycloneDX dependency inventory;
- differential mutation scoring that ignores pre-existing findings;
- an enforceable quality policy and optional bounded argv-list tests;
- optional isolated whole-file candidate verification through Patch Guard.

The readiness score publishes every deduction. It is a gate heuristic, never a
claim that software is defect-free.

## Cybersecurity Mayhem

`python detector/superattestor.py --cybermayhem PROJECT --format sarif`

The posture engine fuses code, cloud, CI/CD, container, authentication, crypto,
injection, deserialization, transport, secret, supply-chain, and taint findings.
It produces risk/severity/category/CWE/OWASP summaries, attack-surface inventory,
threat-model context, prioritized remediation, SBOM, SARIF, JSON, or Markdown.
It never exploits targets, probes networks, installs packages, or invents offline
CVE status.

## Transactional patch safety

Patch Guard copies the project into isolated before/after workspaces, calculates a
complete diff, compares normalized finding deltas, runs syntax/compiler checks,
and optionally runs an explicitly authorized shell-free test argv. Accepted
patches are still dry by default. Applying requires a separate explicit flag,
checks that the project has not changed, creates a durable backup, writes
atomically, verifies the result, and can roll back.

Model-generated code in Forge, Patch Forge, and mutation analysis is not executed
by default. `--execute-generated`, `--execute-mutants`, or `--run-tests` is an
explicit trust decision, and execution remains bounded/restricted.

## Better responses and UI

- Responses lead with the outcome, measured evidence, prioritized next action,
  and an assurance boundary.
- Styles: `professional`, `concise`, `mentor`, `direct`, `executive`, and `classic`.
- The secure local UI adds Mayhem, Cybersecurity Mayhem, Quality Gate, Patch Guard,
  response-style selection, bounded/cancellable jobs, history, filtering, diff,
  and JSON/Markdown/SARIF/HTML export.
- The UI is loopback-only by default, uses a per-launch token, validates Host and
  Origin, applies a strict content-security policy, bounds request/output/queue
  sizes, and terminates subprocess trees on cancel or timeout.

## Security and configuration

- Repository `.env` files are never trusted as provider credentials.
- Use the allowlisted trusted `keys.env`/`ATTESTOR_ENV_FILE` location documented in
  `detector/keys.env.example`.
- Provider/model names are validated exactly; API redirects/proxies are blocked.
- Web scanning rejects credentials, non-HTTP schemes, private/loopback/link-local/
  reserved destinations, and revalidates redirects with DNS pinning.
- Any key that appeared in an older plaintext file must be revoked at its provider;
  deleting the file does not revoke the credential.

## Verification commands

```sh
python -m unittest discover -s detector -p "test_*.py"
python detector/attestor.py --self-test --seed 0
python detector/advanced_rules.py --self-test
python detector/codearena.py
python detector/scanengine.py detector --no-cache --format json
```

CI runs on Windows and Ubuntu, uses read-only permissions, disables checkout
credential persistence, and pins third-party actions to full commit SHAs.
