import hashlib, json, sys
sys.path.insert(0, "detector")
import case_file42 as cf

subject = "src/api/PaymentDao.java"
sha = hashlib.sha256(b"select * from payments where id = ' + userInput").hexdigest()
case = cf.open_case(subject_path=subject, subject_sha256=sha, rule="java-sql-injection", summary="TCS demo: request param flows to executeQuery without sanitizer")

case = cf.append(case, stage="discovery", basis=cf.MEASURED, summary="taint src/api/PaymentDao.java:42 -> executeQuery", evidence={"path": subject, "line": 42, "sink": "executeQuery", "source_sha256": sha})
case = cf.append(case, stage="validation", basis=cf.MEASURED, summary="minimal PoC reproduces on synthetic DB", evidence={"reproduced": True, "poc_sha256": "b"*64})
case = cf.append(case, stage="severity", basis=cf.HYPOTHESIS, summary="CVSS 8.1 High: no auth on route", evidence={"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", "rationale": "unauthenticated endpoint"})
case = cf.append(case, stage="exploitability", basis=cf.MEASURED, summary="reachable-from-unauthenticated-entrypoint via /api/payments", evidence={"triage": "reachable-from-unauthenticated-entrypoint", "route": "/api/payments", "sanitizer_observed": False, "runtime_exploitability": "unverified"})
case = cf.append(case, stage="root_cause", basis=cf.HYPOTHESIS, summary="string concatenation in DAO, missing prepared statement", evidence={"file": subject, "line": 42})
case = cf.append(case, stage="remediation", basis=cf.MEASURED, summary="parameterised query with ? placeholder", evidence={"diff_sha256": "c"*64, "file": subject})
case = cf.append(case, stage="regression", basis=cf.MEASURED, summary="test fails before, passes after", evidence={"fails_before_fix": True, "passes_after_fix": True, "test": "PaymentDaoTest.testInjection"})
case = cf.append(case, stage="documentation", basis=cf.MEASURED, summary="advisory draft with evidence IDs", evidence={"advisory_id": "AT-2026-001", "evidence_refs": 7})

print(cf.render(case))
print("\n--- VERIFY ---")
ok, problems = cf.verify(case)
print("verify:", ok, problems)
print("proven:", cf.is_proven(case))
print("measured entries:", len(cf.measured_only(case)))
print("missing:", cf.stages_missing(case))

print("\n--- TAMPER DEMO ---")
tampered = json.loads(json.dumps(case))
tampered["entries"][0]["summary"] = "nothing to see here"
ok2, probs2 = cf.verify(tampered)
print("after edit verify:", ok2, probs2[:1])

print("\n--- SECRET REDACTION DEMO ---")
c2 = cf.open_case(subject_path="src/config.py", subject_sha256="d"*64, rule="py-hardcoded-secret", summary="secret demo")
c2 = cf.append(c2, stage="discovery", basis=cf.MEASURED, summary="found", evidence={"api_key": "AKIAIOSFODNN7EXAMPLE", "line": 12})
print("stored evidence:", c2["entries"][0]["evidence"])

print("\n--- HONESTY GATE DEMO ---")
try:
    bad = cf.open_case(subject_path=subject, subject_sha256=sha, rule="java-sql-injection", summary="bad")
    bad = cf.append(bad, stage="regression", basis=cf.MEASURED, summary="passes only", evidence={"passes_after_fix": True})
except Exception as e:
    print("gate blocked:", e)

print("\n--- CANONICAL DIGEST ---")
print("case_id:", case["case_id"])
print("final entry sha256:", case["entries"][-1]["entry_sha256"])
