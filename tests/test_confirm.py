"""Tests for dynamic confirmation -- proves flows fire WITHOUT detonating them."""
import os
import textwrap

import confirm


def test_confirms_and_does_not_detonate(tmp_path):
    canary = tmp_path / "DETONATED"
    target = tmp_path / "vuln.py"
    target.write_text(textwrap.dedent(f"""
        import os
        def run(cmd):
            os.system(cmd)
        def main():
            data = input('cmd: ')
            run('touch {canary.as_posix()}; ' + data)
    """), encoding="utf-8")

    results = confirm.confirm_paths([str(target)])
    assert results, "there should be a finding to confirm"
    assert any(r.status == "CONFIRMED" for r in results), \
        "the command-injection flow must be dynamically confirmed"
    # The whole point: the sink was recorded, never executed.
    assert not canary.exists(), "confirmation must NOT detonate the sink"


def test_confirmed_result_reports_payload(tmp_path):
    target = tmp_path / "vuln.py"
    target.write_text(textwrap.dedent("""
        import os
        def run(cmd):
            os.system(cmd)
        def main():
            run(input('x: '))
    """), encoding="utf-8")
    results = confirm.confirm_paths([str(target)])
    confirmed = [r for r in results if r.status == "CONFIRMED"]
    assert confirmed
    assert confirmed[0].payload == confirm.MARKER
