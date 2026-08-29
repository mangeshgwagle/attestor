"""Tests for triage/vendored noise suppression and the engine benchmark."""
import textwrap

import triage
import vendored
import bench_compare


def test_vendored_node_modules_suppressed():
    c = vendored.classify("project/node_modules/lib/index.js")
    assert c.category == "vendored"
    assert c.weight == 0.0


def test_vendored_site_packages_suppressed():
    c = vendored.classify("app/.venv/lib/site-packages/foo.py")
    assert c.category == "vendored"


def test_pwntools_syscall_table_downweighted(tmp_path):
    f = tmp_path / "constants.py"
    f.write_text("from pwnlib.constants import Constant\n" +
                 "\n".join(f"SYS_{i} = {i}" for i in range(60)), encoding="utf-8")
    c = vendored.classify(str(f))
    assert c.weight < 0.2, "syscall/pwntools table must be heavily downweighted"


def test_first_party_code_kept():
    c = vendored.classify("src/app/auth.py")
    assert c.category == "first_party"
    assert c.weight == 1.0


def test_triage_suppresses_noise_keeps_real(tmp_path):
    real = tmp_path / "auth.py"
    real.write_text("x = 1\n", encoding="utf-8")
    vend = tmp_path / "node_modules" / "l.js"
    vend.parent.mkdir(parents=True)
    vend.write_text("x=1\n", encoding="utf-8")

    findings = [
        {"rule_id": "SEC-AWS-KEY", "severity": "CRITICAL", "path": str(real), "line": 1},
        {"rule_id": "EXP-ROOTKIT-SYSCALL", "severity": "CRITICAL", "path": str(vend), "line": 1},
    ]
    triaged = {t.finding["rule_id"]: t.action for t in triage.triage_all(findings)}
    assert triaged["SEC-AWS-KEY"] == "report"
    assert triaged["EXP-ROOTKIT-SYSCALL"] == "suppress"


def test_dataflow_beats_legacy_on_benchmark():
    scores = {s.tool: s for s in bench_compare.run()}
    df = next(s for k, s in scores.items() if k.startswith("dataflow"))
    legacy = next(s for k, s in scores.items() if k.startswith("taint"))
    assert df.recall == 1.0, "dataflow must catch every labeled vulnerable case"
    assert df.precision == 1.0, "dataflow must not flag any safe case"
    assert df.recall > legacy.recall, "dataflow must beat the legacy scanner on recall"
