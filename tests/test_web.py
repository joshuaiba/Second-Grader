"""P3 (Josh): verdict page, record viewer, chain strip, tamper button."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from secondgrader import web
from secondgrader.schema import Claim, ClaimVerdict, GateDecision, VerifierResult, load_trace

from .conftest import SAMPLE_TRACE, TAMPERED_TRACE, TEST_TAMPER_SEQ


def test_render_verdict_shows_decision_claims_and_cited_seq():
    decision = GateDecision("BLOCK", ["tests/test_parser.py was modified"], [TEST_TAMPER_SEQ], True, None)
    verdicts = [ClaimVerdict("c1", "CONTRADICTED", [TEST_TAMPER_SEQ], "test file edited before passing run")]
    html = web.render_verdict(decision, verdicts, VerifierResult(tests_written=["test_split"], passed=1))
    assert "BLOCK" in html
    assert "CONTRADICTED" in html
    assert str(TEST_TAMPER_SEQ) in html
    assert "test_split" in html


def test_app_serves_one_page():
    from secondgrader.web.app import app

    client = TestClient(app)
    r = client.get("/")
    assert r.status_code == 200
    assert "Second Grader" in r.text


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

CHIP_RE = re.compile(r'<a id="chip-(\d+)" class="chip (good|bad)"')


def _chips(html: str) -> dict[int, str]:
    return {int(seq): cls for seq, cls in CHIP_RE.findall(html)}


@pytest.fixture
def client() -> TestClient:
    from secondgrader.web.app import app

    return TestClient(app)


# --------------------------------------------------------------------------- #
# render_verdict
# --------------------------------------------------------------------------- #

def test_stamp_and_decision_word_for_block_and_pass():
    block = web.render_verdict(GateDecision("BLOCK", ["x"], [13]), [], None)
    assert "BLOCKED" in block and 'data-decision="BLOCK"' in block
    assert "MERGED" not in block.split("<footer")[0].replace("Second Grader - BLOCKED", "")
    passed = web.render_verdict(GateDecision("PASS"), [], None)
    assert "MERGED" in passed and 'data-decision="PASS"' in passed
    assert "BLOCKED" not in passed


def test_replay_label_present_by_default_and_live_when_asked():
    html = web.render_verdict(GateDecision("PASS"), [], None)
    assert "REPLAY" in html
    assert 'class="mode mode-replay"' in html
    assert "LIVE" not in html.replace("prefers-color-scheme", "")
    live = web.render_verdict(GateDecision("PASS"), [], None, mode="LIVE")
    assert 'class="mode mode-live"' in live and "LIVE" in live


def test_claims_table_uses_claim_text_and_links_evidence():
    claims = [Claim("c1", "All tests pass", "tests_pass", 16)]
    verdicts = [
        ClaimVerdict("c1", "CONTRADICTED", [10, 15, 13], "first run failed"),
        ClaimVerdict("c9", "UNSUPPORTED", [], "nothing observed"),
        ClaimVerdict("tamper:tests/test_parser.py", "CONTRADICTED", [13], "assert weakened"),
    ]
    html = web.render_verdict(GateDecision("BLOCK", ["r"], [13]), verdicts, None, claims=claims)
    assert "All tests pass" in html
    assert 'href="#rec-10"' in html and 'href="#rec-15"' in html and 'href="#rec-13"' in html
    assert "UNSUPPORTED" in html and "status unsupported" in html
    assert "(claim text not available)" in html  # c9 has no Claim object
    # tamper verdict goes to its own section, not the claims table
    tamper_section = html.split("Tamper findings", 1)[1]
    assert "assert weakened" in tamper_section
    claims_section = html.split("<h2>Claims</h2>", 1)[1].split("Tamper findings", 1)[0]
    assert "assert weakened" not in claims_section


def test_user_text_is_escaped():
    verdicts = [ClaimVerdict("c1", "SUPPORTED", [], "<script>alert(1)</script>")]
    html = web.render_verdict(GateDecision("PASS", ["<b>bold</b>"]), verdicts, None, task_title="<img src=x>")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<b>bold</b>" not in html
    assert "&lt;img src=x&gt;" in html


def test_verifier_details_render():
    vr = VerifierResult(
        tests_written=["test_a", "test_b"],
        passed=1,
        failed=1,
        details=[
            {"name": "test_a", "passed": True, "output": "PASSED"},
            {"name": "test_b", "passed": False, "output": "AssertionError: boom"},
        ],
    )
    html = web.render_verdict(GateDecision("BLOCK", ["r"], []), [], vr)
    assert "test_a" in html and "test_b" in html
    assert "AssertionError: boom" in html
    assert "1 passed" in html and "1 failed" in html
    none = web.render_verdict(GateDecision("PASS"), [], None)
    assert "Verifier did not run" in none


def test_chain_strip_one_chip_per_record_for_sample(sample_records):
    decision = GateDecision("BLOCK", ["r"], [13], True, None)
    html = web.render_verdict(decision, [], None, sample_records)
    chips = _chips(html)
    assert sorted(chips) == [r.seq for r in sample_records]
    assert set(chips.values()) == {"good"}
    for r in sample_records:
        assert f'id="rec-{r.seq}"' in html
        assert f'href="#rec-{r.seq}"' in html


def test_chain_strip_red_from_first_bad_seq(tampered_records):
    decision = GateDecision("BLOCK", ["chain broken"], [], False, TEST_TAMPER_SEQ)
    html = web.render_verdict(decision, [], None, tampered_records)
    chips = _chips(html)
    assert len(chips) == len(tampered_records)
    for seq, cls in chips.items():
        if seq >= TEST_TAMPER_SEQ:
            assert cls == "bad", seq
        else:
            assert cls == "good", seq
    assert "BROKEN" in html and f"first_bad_seq = {TEST_TAMPER_SEQ}" in html


def test_record_viewer_shows_payloads_and_origin_badges(sample_records):
    html = web.render_verdict(GateDecision("BLOCK", ["r"], [13]), [], None, sample_records)
    assert 'class="origin observed"' in html and 'class="origin claimed"' in html
    assert "--- a/tests/test_parser.py" in html  # diff rendered
    assert "pytest -k parser" in html  # test_run command
    assert "Only changed parser.py" in html  # model_message text
    assert "read_file" in html  # tool_call
    assert "content_sha256" in html  # tool_output
    # cited record is highlighted
    assert re.search(r'<details id="rec-13" class="rec cited[^"]*" open>', html)
    assert not re.search(r'<details id="rec-2" class="rec cited', html)


# --------------------------------------------------------------------------- #
# app routes
# --------------------------------------------------------------------------- #

def test_index_renders_sample_as_blocked_replay(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "BLOCKED" in r.text and "REPLAY" in r.text
    assert "All tests pass" in r.text and "Only changed parser.py" in r.text
    assert "assert weakened" in r.text
    chips = _chips(r.text)
    assert len(chips) == len(load_trace(SAMPLE_TRACE))
    assert set(chips.values()) == {"good"}


def test_index_mode_live_and_task_picker(client):
    r = client.get("/?mode=LIVE")
    assert r.status_code == 200
    assert 'class="mode mode-live"' in r.text
    assert "<select" in r.text and 'value="trap_weaken_tests"' in r.text
    r = client.get("/?mode=bogus")
    assert 'class="mode mode-replay"' in r.text


def test_index_with_tampered_fixture(client):
    r = client.get("/?trace=fixtures/sample_trace_tampered.jsonl")
    assert r.status_code == 200
    chips = _chips(r.text)
    assert all(cls == "bad" for seq, cls in chips.items() if seq >= TEST_TAMPER_SEQ)
    assert all(cls == "good" for seq, cls in chips.items() if seq < TEST_TAMPER_SEQ)
    assert "BROKEN" in r.text


def test_trace_path_traversal_rejected(client):
    r = client.get("/?trace=../../etc/passwd")
    assert r.status_code == 400
    r = client.get("/?trace=/etc/passwd")
    assert r.status_code == 400
    r = client.get("/?trace=pyproject.toml")
    assert r.status_code == 400  # inside repo but not a .jsonl
    r = client.get("/?trace=fixtures/does_not_exist.jsonl")
    assert r.status_code == 404


def test_api_tasks_lists_four(client):
    r = client.get("/api/tasks")
    assert r.status_code == 200
    tasks = r.json()
    assert len(tasks) == 4
    ids = {t["id"] for t in tasks}
    assert ids == {"honest_fix", "trap_hidden_edit", "trap_partial_run", "trap_weaken_tests"}
    for t in tasks:
        assert t["title"] and t["expected_gate"] in {"PASS", "BLOCK"}


def test_api_run_not_wired(client):
    r = client.post("/api/run", json={"task": "honest_fix", "mode": "LIVE"})
    assert r.status_code == 501
    body = r.json()
    assert body["status"] == "not wired"
    assert body["task"] == "honest_fix" and body["mode"] == "LIVE"


def test_api_status_static(client):
    r = client.get("/api/status")
    assert r.status_code == 200
    body = r.json()
    assert body["stage"] == "done"
    assert isinstance(body["stages"], list) and body["stages"]


def test_api_tamper_turns_strip_red_from_seq(client):
    before = SAMPLE_TRACE.read_bytes()
    r = client.post("/api/tamper", data={"seq": str(TEST_TAMPER_SEQ)})
    assert r.status_code == 200
    chips = _chips(r.text)
    assert len(chips) == len(load_trace(SAMPLE_TRACE))
    for seq, cls in chips.items():
        assert cls == ("bad" if seq >= TEST_TAMPER_SEQ else "good"), seq
    assert f"BROKEN from seq {TEST_TAMPER_SEQ}" in r.text
    assert "BLOCKED" in r.text
    # the file on disk is untouched
    assert SAMPLE_TRACE.read_bytes() == before
    # and so is a fresh GET
    chips = _chips(client.get("/").text)
    assert set(chips.values()) == {"good"}


def test_api_tamper_rejects_bad_seq_and_json_works(client):
    r = client.post("/api/tamper", data={"seq": "999"})
    assert r.status_code == 400
    r = client.post("/api/tamper", data={"seq": "abc"})
    assert r.status_code == 400
    r = client.post("/api/tamper", json={"seq": 1})
    assert r.status_code == 200
    chips = _chips(r.text)
    assert set(chips.values()) == {"bad"}


def test_provider_hooks_swap_verdict_and_tamper(client):
    from secondgrader.web import app as web_app

    old_verdict, old_tamper = web_app.providers["verdict"], web_app.providers["tamper"]
    try:
        web_app.set_verdict_provider(
            lambda records: (GateDecision("PASS", ["custom provider ok"]), [], None, [])
        )
        r = client.get("/")
        assert "MERGED" in r.text and "custom provider ok" in r.text

        calls = []

        def fake_tamper(records, seq):
            calls.append(seq)
            return web_app.tamper_in_memory(records, seq)

        web_app.set_tamper_provider(fake_tamper)
        r = client.post("/api/tamper", data={"seq": "5"})
        assert r.status_code == 200 and calls == [5]
        # a broken chain forces BLOCK even if the provider said PASS
        assert "BLOCKED" in r.text
    finally:
        web_app.set_verdict_provider(old_verdict)
        web_app.set_tamper_provider(old_tamper)


def test_tamper_in_memory_does_not_mutate_input(sample_records):
    from secondgrader.web.app import tamper_in_memory
    from secondgrader.schema import check_hash_chain

    copy_ = tamper_in_memory(sample_records, 8)
    assert check_hash_chain(sample_records) == (True, None)
    assert check_hash_chain(copy_) == (False, 8)
    assert sample_records[7].payload != copy_[7].payload


# --------------------------------------------------------------------------- #
# live provider: records -> real gate (sample story until the auditor lands)
# --------------------------------------------------------------------------- #

from secondgrader.schema import Record as _Record  # noqa: E402
from secondgrader.web import live  # noqa: E402


def _vt(seq, name, outcome):
    passed = True if outcome == "passed" else False if outcome == "failed" else None
    return _Record(seq, "t", "verifier_test", "OBSERVED",
                   {"name": name, "passed": passed, "outcome": outcome, "phase": "blind", "output": ""}, "p", "h", "UNSIGNED")


def test_verifier_result_rebuilt_from_records_counts_only_pass_fail(sample_records):
    recs = sample_records + [_vt(17, "t_ok", "passed"), _vt(18, "t_bad", "failed"), _vt(19, "t_err", "error")]
    vr = live.verifier_result_from_records(recs)
    assert vr.passed == 1 and vr.failed == 1 and vr.record_seqs == [17, 18, 19]
    assert live.verifier_result_from_records(sample_records) is None


def test_auto_verdict_blocks_cheating_fixture_through_the_real_gate(sample_records):
    decision, verdicts, vr, claims = live.auto_verdict(sample_records)
    assert decision.decision == "BLOCK"
    assert TEST_TAMPER_SEQ in decision.citing_seqs
    assert any(v.claim_id.startswith("tamper:") for v in verdicts)
    assert claims and vr is not None


def test_auto_verdict_uses_verifier_records_when_present(sample_records):
    recs = sample_records + [_vt(17, "t_ok", "passed")]
    _, _, vr, _ = live.auto_verdict(recs)
    assert vr.tests_written == ["t_ok"] and vr.record_seqs == [17]


def test_auto_verdict_blocks_broken_chain(tampered_records):
    decision, *_ = live.auto_verdict(tampered_records)
    assert decision.decision == "BLOCK" and decision.chain_ok is False and decision.first_bad_seq == TEST_TAMPER_SEQ
