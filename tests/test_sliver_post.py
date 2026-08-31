"""Tests for Sliver bridge post-exploitation expansion."""
import sliver_bridge


def _make_plan(os_target="windows"):
    findings = [
        {"sink_type": "command_injection", "cwe": "CWE-78",
         "sink_file": "app.py", "sink_line": 42,
         "severity": "CRITICAL"},
    ]
    return sliver_bridge.build_plan(findings, "10.0.0.1", "192.168.1.100",
                                     "443", os_target)


def test_post_exploit_section_present():
    plan = _make_plan()
    script = sliver_bridge.generate_console_script(plan)
    assert "POST-EXPLOITATION" in script


def test_situational_awareness_commands():
    plan = _make_plan()
    script = sliver_bridge.generate_console_script(plan)
    assert "whoami" in script
    assert "getuid" in script
    assert "ps -a" in script
    assert "netstat" in script


def test_cred_harvest_windows():
    plan = _make_plan("windows")
    script = sliver_bridge.generate_console_script(plan)
    assert "hashdump" in script
    assert "procdump" in script
    assert "cmdkey" in script


def test_cred_harvest_linux():
    plan = _make_plan("linux")
    script = sliver_bridge.generate_console_script(plan)
    assert "/etc/shadow" in script
    assert "id_rsa" in script


def test_process_injection_windows():
    plan = _make_plan("windows")
    script = sliver_bridge.generate_console_script(plan)
    assert "migrate" in script
    assert "shellcode" in script


def test_pivot_section():
    plan = _make_plan()
    script = sliver_bridge.generate_console_script(plan)
    assert "socks5" in script
    assert "rportfwd" in script
    assert "portfwd" in script


def test_bof_section_windows():
    plan = _make_plan("windows")
    script = sliver_bridge.generate_console_script(plan)
    assert "BOF" in script
    assert "sa-whoami" in script


def test_bof_section_absent_linux():
    plan = _make_plan("linux")
    script = sliver_bridge.generate_console_script(plan)
    assert "BOF" not in script


def test_armory_section():
    plan = _make_plan()
    script = sliver_bridge.generate_console_script(plan)
    assert "armory" in script
    assert "sharp-hound-4" in script
    assert "seatbelt" in script
    assert "rubeus" in script


def test_persistence_windows():
    plan = _make_plan("windows")
    script = sliver_bridge.generate_console_script(plan)
    assert "service" in script.lower()
    assert "schtasks" in script or "scheduled" in script.lower()


def test_persistence_linux():
    plan = _make_plan("linux")
    script = sliver_bridge.generate_console_script(plan)
    assert "cron" in script.lower()
    assert "systemd" in script.lower()


def test_screenshot_command():
    plan = _make_plan()
    script = sliver_bridge.generate_console_script(plan)
    assert "screenshot" in script


def test_gate_still_works():
    rc = sliver_bridge.main(["--findings", "/dev/null", "--target", "x"])
    assert rc == 2


def test_delivery_notes_still_present():
    plan = _make_plan()
    script = sliver_bridge.generate_console_script(plan)
    assert "delivery notes" in script.lower() or "finding 1" in script
