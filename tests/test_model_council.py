"""Tests for model council -- ensemble adjudication."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detector"))
import model_council


def _sqli():
    return {"category": "sql_injection", "severity": "HIGH", "cwe": "CWE-89",
            "file": "app.py", "line": 42, "description": "SQL injection via user input",
            "code": "query = f\"SELECT * FROM users WHERE id = {user_id}\""}


def _xss():
    return {"category": "xss", "severity": "MEDIUM", "cwe": "CWE-79",
            "file": "view.py", "line": 15, "description": "reflected XSS"}


def _cmdi():
    return {"category": "command_injection", "severity": "CRITICAL", "cwe": "CWE-78",
            "file": "exec.py", "line": 7, "description": "OS command injection",
            "trace": [
                {"file": "handler.py", "line": 3, "note": "user input"},
                {"file": "exec.py", "line": 7, "note": "os.system sink"},
            ]}


def _fake_member(name, verdict="EXPLOITABLE", confidence=85):
    raw = (f"VERDICT: {verdict}\nCONFIDENCE: {confidence}\n"
           f"WHY: test reason\nEXPLOIT: test scenario\nFIX: use parameterized queries")

    def gen(prompt):
        return raw

    return model_council.CouncilMember(
        name=name, backend="test", model_id="test",
        role="coder", weight=1.0, _generate=gen)


def _failing_member(name):
    def gen(prompt):
        raise RuntimeError("model crashed")
    return model_council.CouncilMember(
        name=name, backend="test", model_id="test",
        role="coder", weight=1.0, _generate=gen)


def _empty_member(name):
    def gen(prompt):
        return ""
    return model_council.CouncilMember(
        name=name, backend="test", model_id="test",
        role="coder", weight=1.0, _generate=gen)


# ── Council construction ────────────────────────────────────────

def test_empty_council():
    c = model_council.Council()
    assert len(c) == 0


def test_add_member():
    c = model_council.Council()
    c.add_member(_fake_member("test-1"))
    assert len(c) == 1
    assert c.members[0].name == "test-1"


def test_roster():
    c = model_council.Council()
    c.add_member(_fake_member("a"))
    c.add_member(_fake_member("b"))
    r = c.roster()
    assert len(r) == 2
    assert r[0]["name"] == "a"
    assert r[1]["name"] == "b"


def test_repr():
    c = model_council.Council()
    c.add_member(_fake_member("alpha"))
    assert "alpha" in repr(c)


# ── Prompt building ────────────────────────────────────────────

def test_build_prompt_basic():
    prompt = model_council.build_council_prompt(_sqli())
    assert "sql_injection" in prompt
    assert "CWE-89" in prompt
    assert "app.py" in prompt
    assert "VERDICT" in prompt


def test_build_prompt_with_trace():
    prompt = model_council.build_council_prompt(_cmdi())
    assert "handler.py" in prompt
    assert "exec.py" in prompt
    assert "user input" in prompt
    assert "os.system" in prompt


def test_build_prompt_with_code():
    prompt = model_council.build_council_prompt(_sqli())
    assert "SELECT * FROM users" in prompt


def test_build_prompt_interprocedural():
    finding = _cmdi()
    finding["interprocedural"] = True
    prompt = model_council.build_council_prompt(finding)
    assert "cross-function" in prompt.lower() or "interprocedural" in prompt.lower()


def test_build_prompt_minimal():
    prompt = model_council.build_council_prompt({"category": "test"})
    assert "VERDICT" in prompt


# ── Opinion parsing ────────────────────────────────────────────

def test_parse_exploitable():
    text = ("VERDICT: EXPLOITABLE\nCONFIDENCE: 90\n"
            "WHY: direct injection\nEXPLOIT: send payload\nFIX: parameterize")
    v, c, w, e, f = model_council._parse_opinion(text)
    assert v == "EXPLOITABLE"
    assert c == 0.9
    assert "injection" in w
    assert "payload" in e
    assert "parameterize" in f


def test_parse_not_exploitable():
    text = "VERDICT: NOT_EXPLOITABLE\nCONFIDENCE: 75\nWHY: sanitized\nFIX: none"
    v, c, w, e, f = model_council._parse_opinion(text)
    assert v == "NOT_EXPLOITABLE"
    assert c == 0.75


def test_parse_uncertain():
    text = "VERDICT: UNCERTAIN\nCONFIDENCE: 50\nWHY: unclear flow"
    v, c, w, e, f = model_council._parse_opinion(text)
    assert v == "UNCERTAIN"
    assert c == 0.5


def test_parse_garbage():
    v, c, w, e, f = model_council._parse_opinion("this is nonsense")
    assert v == "UNCERTAIN"
    assert c == 0.5


def test_parse_clamps_confidence():
    text = "VERDICT: EXPLOITABLE\nCONFIDENCE: 150"
    v, c, w, e, f = model_council._parse_opinion(text)
    assert c == 1.0

    text2 = "VERDICT: EXPLOITABLE\nCONFIDENCE: 0"
    v2, c2, w2, e2, f2 = model_council._parse_opinion(text2)
    assert c2 == 0.0


def test_parse_case_insensitive():
    text = "verdict: exploitable\nconfidence: 80\nwhy: test\nfix: test"
    v, c, w, e, f = model_council._parse_opinion(text)
    assert v == "EXPLOITABLE"


# ── Single finding evaluation ────────────────────────────────

def test_evaluate_single_member():
    c = model_council.Council()
    c.add_member(_fake_member("judge-1"))
    v = c.evaluate_finding(_sqli(), parallel=False)
    assert v.verdict == "EXPLOITABLE"
    assert v.quorum == 1
    assert v.consensus is True
    assert len(v.opinions) == 1


def test_evaluate_unanimous():
    c = model_council.Council()
    c.add_member(_fake_member("a", "EXPLOITABLE", 90))
    c.add_member(_fake_member("b", "EXPLOITABLE", 80))
    c.add_member(_fake_member("c", "EXPLOITABLE", 85))
    v = c.evaluate_finding(_sqli(), parallel=False)
    assert v.verdict == "EXPLOITABLE"
    assert v.consensus is True
    assert len(v.dissent) == 0
    assert v.quorum == 3


def test_evaluate_majority_vote():
    c = model_council.Council()
    c.add_member(_fake_member("a", "EXPLOITABLE", 90))
    c.add_member(_fake_member("b", "EXPLOITABLE", 80))
    c.add_member(_fake_member("c", "NOT_EXPLOITABLE", 60))
    v = c.evaluate_finding(_sqli(), parallel=False)
    assert v.verdict == "EXPLOITABLE"
    assert v.consensus is False
    assert len(v.dissent) == 1
    assert "c" in v.dissent[0]


def test_evaluate_confidence_weighted():
    c = model_council.Council()
    c.add_member(_fake_member("a", "EXPLOITABLE", 30))
    c.add_member(_fake_member("b", "NOT_EXPLOITABLE", 95))
    v = c.evaluate_finding(_sqli(), parallel=False)
    assert v.verdict == "NOT_EXPLOITABLE"


def test_evaluate_empty_council():
    c = model_council.Council()
    v = c.evaluate_finding(_sqli())
    assert v.verdict == "UNCERTAIN"
    assert v.quorum == 0


def test_evaluate_failing_member_skipped():
    c = model_council.Council()
    c.add_member(_fake_member("good", "EXPLOITABLE", 90))
    c.add_member(_failing_member("bad"))
    v = c.evaluate_finding(_sqli(), parallel=False)
    assert v.verdict == "EXPLOITABLE"
    assert v.quorum == 1


def test_evaluate_empty_response_skipped():
    c = model_council.Council()
    c.add_member(_fake_member("good", "EXPLOITABLE", 90))
    c.add_member(_empty_member("empty"))
    v = c.evaluate_finding(_sqli(), parallel=False)
    assert v.quorum == 1


def test_evaluate_all_fail():
    c = model_council.Council()
    c.add_member(_failing_member("bad1"))
    c.add_member(_failing_member("bad2"))
    v = c.evaluate_finding(_sqli(), parallel=False)
    assert v.verdict == "UNCERTAIN"
    assert v.quorum == 0


def test_evaluate_parallel():
    c = model_council.Council()
    c.add_member(_fake_member("a", "EXPLOITABLE", 90))
    c.add_member(_fake_member("b", "EXPLOITABLE", 80))
    v = c.evaluate_finding(_sqli(), parallel=True)
    assert v.verdict == "EXPLOITABLE"
    assert v.quorum == 2


# ── Batch adjudication ────────────────────────────────────────

def test_adjudicate_multiple():
    c = model_council.Council()
    c.add_member(_fake_member("judge", "EXPLOITABLE", 90))
    verdicts = c.adjudicate([_sqli(), _xss(), _cmdi()], parallel=False)
    assert len(verdicts) == 3


def test_adjudicate_sorted():
    def _member_mixed(name):
        call_count = [0]
        def gen(prompt):
            call_count[0] += 1
            if "command_injection" in prompt:
                return "VERDICT: EXPLOITABLE\nCONFIDENCE: 95\nWHY: rce\nFIX: none"
            if "sql_injection" in prompt:
                return "VERDICT: EXPLOITABLE\nCONFIDENCE: 70\nWHY: sqli\nFIX: param"
            return "VERDICT: NOT_EXPLOITABLE\nCONFIDENCE: 80\nWHY: safe\nFIX: none"
        return model_council.CouncilMember(
            name=name, backend="test", model_id="test",
            role="coder", weight=1.0, _generate=gen)

    c = model_council.Council()
    c.add_member(_member_mixed("judge"))
    verdicts = c.adjudicate([_xss(), _sqli(), _cmdi()], parallel=False)
    assert verdicts[0].verdict == "EXPLOITABLE"
    assert verdicts[-1].verdict == "NOT_EXPLOITABLE"


def test_adjudicate_limit():
    c = model_council.Council()
    c.add_member(_fake_member("judge"))
    findings = [_sqli() for _ in range(10)]
    verdicts = c.adjudicate(findings, limit=3, parallel=False)
    assert len(verdicts) == 3


def test_adjudicate_empty():
    c = model_council.Council()
    c.add_member(_fake_member("judge"))
    verdicts = c.adjudicate([], parallel=False)
    assert verdicts == []


# ── Render ────────────────────────────────────────────────────

def test_render_empty():
    out = model_council.render([])
    assert "No findings" in out


def test_render_basic():
    c = model_council.Council()
    c.add_member(_fake_member("alpha", "EXPLOITABLE", 90))
    c.add_member(_fake_member("beta", "EXPLOITABLE", 85))
    verdicts = c.adjudicate([_sqli()], parallel=False)
    out = model_council.render(verdicts)
    assert "Model Council" in out
    assert "alpha" in out
    assert "beta" in out
    assert "EXPLOIT" in out
    assert "UNANIMOUS" in out


def test_render_dissent():
    c = model_council.Council()
    c.add_member(_fake_member("a", "EXPLOITABLE", 90))
    c.add_member(_fake_member("b", "NOT_EXPLOITABLE", 60))
    verdicts = c.adjudicate([_sqli()], parallel=False)
    out = model_council.render(verdicts)
    assert "dissent" in out


def test_render_multiple():
    c = model_council.Council()
    c.add_member(_fake_member("judge"))
    verdicts = c.adjudicate([_sqli(), _xss()], parallel=False)
    out = model_council.render(verdicts)
    assert "2 finding(s)" in out


# ── to_dict ────────────────────────────────────────────────────

def test_to_dict_basic():
    c = model_council.Council()
    c.add_member(_fake_member("judge", "EXPLOITABLE", 90))
    verdicts = c.adjudicate([_sqli()], parallel=False)
    dicts = model_council.to_dict(verdicts)
    assert len(dicts) == 1
    d = dicts[0]
    assert d["verdict"] == "EXPLOITABLE"
    assert d["cwe"] == "CWE-89"
    assert d["consensus"] is True
    assert len(d["opinions"]) == 1


def test_to_dict_opinions():
    c = model_council.Council()
    c.add_member(_fake_member("a", "EXPLOITABLE", 90))
    c.add_member(_fake_member("b", "NOT_EXPLOITABLE", 60))
    verdicts = c.adjudicate([_sqli()], parallel=False)
    dicts = model_council.to_dict(verdicts)
    assert len(dicts[0]["opinions"]) == 2
    assert dicts[0]["dissent"]


def test_to_dict_empty():
    assert model_council.to_dict([]) == []


# ── Discover (offline -- no models available) ────────────────

def test_discover_returns_council():
    c = model_council.Council.discover()
    assert isinstance(c, model_council.Council)


# ── MemberOpinion dataclass ──────────────────────────────────

def test_member_opinion_fields():
    op = model_council.MemberOpinion(
        member="test", backend="gguf", verdict="EXPLOITABLE",
        confidence=0.9, explanation="test", fix="test",
        exploit_scenario="test", latency_ms=100)
    assert op.member == "test"
    assert op.latency_ms == 100


# ── CouncilVerdict dataclass ─────────────────────────────────

def test_council_verdict_defaults():
    v = model_council.CouncilVerdict(
        finding={}, verdict="UNCERTAIN", confidence=0.5,
        explanation="", fix="", exploit_scenario="")
    assert v.opinions == []
    assert v.consensus is False
    assert v.dissent == []
    assert v.quorum == 0


# ── Edge: sink_type/sink_file fallback keys ──────────────────

def test_build_prompt_sink_keys():
    finding = {"sink_type": "sql_injection", "sink_file": "db.py",
               "sink_line": 99, "cwe": "CWE-89"}
    prompt = model_council.build_council_prompt(finding)
    assert "sql_injection" in prompt
    assert "db.py" in prompt


def test_to_dict_sink_keys():
    c = model_council.Council()
    c.add_member(_fake_member("judge"))
    finding = {"sink_type": "xss", "sink_file": "view.py",
               "sink_line": 5, "cwe": "CWE-79"}
    verdicts = c.adjudicate([finding], parallel=False)
    d = model_council.to_dict(verdicts)
    assert d[0]["category"] == "xss"
    assert d[0]["file"] == "view.py"
    assert d[0]["line"] == 5
