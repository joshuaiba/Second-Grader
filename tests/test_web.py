"""P3 (Josh): verdict page, record viewer, chain strip, tamper button."""

from __future__ import annotations

import re

import pytest
from fastapi.testclient import TestClient

from secondgrader import web
from secondgrader.schema import Claim, ClaimVerdict, GateDecision, VerifierResult, load_trace

from .conftest import ROOT, SAMPLE_TRACE, TAMPERED_TRACE, TEST_TAMPER_SEQ


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

CHIP_RE = re.compile(r'<a id="chip-(\d+)" class="chip (good|bad|untrusted)"')
HONEST = ROOT / "fixtures" / "samples" / "honest.jsonl"
TAMPERED_SAMPLE = ROOT / "fixtures" / "samples" / "tampered.jsonl"


def _chips(html: str) -> dict[int, str]:
    return {int(seq): cls for seq, cls in CHIP_RE.findall(html)}


def _assert_broken_from(chips: dict[int, str], first_bad: int) -> None:
    """Chip ``first_bad`` is red, everything after is red or amber, everything before is green."""
    assert chips[first_bad] == "bad"
    for seq, cls in chips.items():
        if seq < first_bad:
            assert cls == "good", seq
        else:
            assert cls in {"bad", "untrusted"}, seq


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
    assert len(chips) == len(load_trace(TAMPERED_TRACE))
    _assert_broken_from(chips, TEST_TAMPER_SEQ)
    assert "BROKEN" in r.text
    # the recorder's reason and detail are shown
    assert "does not match its hash" in r.text


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
    _assert_broken_from(chips, TEST_TAMPER_SEQ)
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
    assert chips[1] == "bad" and "good" not in chips.values()


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

        def fake_tamper(records, seq):  # legacy two-argument provider, plain list back
            calls.append(seq)
            return web_app.tamper_in_memory(records, seq)

        web_app.set_tamper_provider(fake_tamper)
        r = client.post("/api/tamper", data={"seq": "5"})
        assert r.status_code == 200 and calls == [5]
        # a broken chain forces BLOCK even if the provider said PASS
        assert "BLOCKED" in r.text
        chips = _chips(r.text)
        assert chips[5] == "bad" and chips[4] == "good"

        seen = []

        def new_tamper(records, seq, *, trace_path):  # new protocol: (records, report)
            seen.append((seq, trace_path))
            return web_app.tamper_via_recorder(records, seq, trace_path=trace_path)

        web_app.set_tamper_provider(new_tamper)
        r = client.post("/api/tamper", data={"seq": "7"})
        assert r.status_code == 200
        assert seen == [(7, SAMPLE_TRACE)]
        _assert_broken_from(_chips(r.text), 7)
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


def test_ground_truth_only_counts_full_final_phase(sample_records):
    def gt(seq, phase, exit_code):
        payload = {"command": "pytest -q", "exit_code": exit_code, "ground_truth": True, "source": "ground_truth"}
        if phase is not None:
            payload["phase"] = phase
        return _Record(seq, "t", "test_run", "OBSERVED", payload, "p", "h", "UNSIGNED")

    base = sample_records
    # collection runs are not the ground truth, even though they come last and exit 0
    recs = base + [gt(17, "full_final", 1), gt(18, "collect_base", 0), gt(19, "collect_final", 0)]
    assert live.ground_truth_from_records(recs) == (False, 17)
    # the real one wins
    recs = base + [gt(17, "collect_base", 0), gt(18, "collect_final", 0), gt(19, "full_final", 0)]
    assert live.ground_truth_from_records(recs) == (True, 19)
    # only collection runs: no ground truth at all
    recs = base + [gt(17, "collect_base", 0), gt(18, "collect_final", 0)]
    assert live.ground_truth_from_records(recs) == (None, None)
    # older traces without a phase key still count
    assert live.ground_truth_from_records(base + [gt(17, None, 0)]) == (True, 17)
    # the honest sample: seq 18 is full_final, 16/17 are collection
    assert live.ground_truth_from_records(load_trace(HONEST)) == (True, 18)


# --------------------------------------------------------------------------- #
# P3.9 / P3.10: the recorder's chain report and tamper backend on the page
# --------------------------------------------------------------------------- #

def _repo_files() -> set[str]:
    return {str(p) for p in ROOT.iterdir()} | {str(p) for p in (ROOT / "fixtures").rglob("*")}


def test_honest_sample_via_env_is_intact_with_head_hash(client, monkeypatch):
    from secondgrader import recorder

    monkeypatch.setenv("SG_TRACE_PATH", str(HONEST))
    r = client.get("/")
    assert r.status_code == 200
    assert "INTACT" in r.text and "BROKEN" not in r.text
    report = recorder.verify_report(HONEST)
    assert report.ok and report.count == 18
    assert report.head_hash[:12] in r.text
    assert f'title="{report.head_hash}"' in r.text  # full hash in the title attribute
    assert "UNSIGNED fixture" in r.text  # hand-written sample: no signatures, no seal
    chips = _chips(r.text)
    assert len(chips) == 18 and set(chips.values()) == {"good"}
    assert "fixtures/samples/honest.jsonl" in r.text
    # the seal is absent, so the task comes from the prompt record
    assert 'value="honest_fix" selected' in r.text


def test_tampered_sample_shows_report_reason_and_untrusted_tail(client):
    from secondgrader import recorder

    r = client.get("/?trace=fixtures/samples/tampered.jsonl")
    assert r.status_code == 200
    report = recorder.verify_report(TAMPERED_SAMPLE)
    assert not report.ok and report.first_bad_seq == 5
    chips = _chips(r.text)
    assert len(chips) == 18
    _assert_broken_from(chips, 5)
    # per-record statuses drive the chips: 5 is the edited record, 6..18 are untrusted
    assert chips[5] == "bad" and all(chips[s] == "untrusted" for s in range(6, 19))
    assert all(chips[s] == "good" for s in range(1, 5))
    assert "BLOCKED" in r.text and "BROKEN" in r.text
    assert report.detail.split("seq 5", 1)[1].strip() in r.text  # detail text (seq is linkified)
    assert f'<code class="reason">{report.reason}</code>' in r.text
    assert "first_bad_seq = 5" in r.text


def test_api_tamper_on_honest_sample_uses_recorder_and_leaves_no_files(client):
    before_bytes = HONEST.read_bytes()
    before_files = _repo_files()
    r = client.post("/api/tamper", data={"seq": "10", "trace": "fixtures/samples/honest.jsonl"})
    assert r.status_code == 200
    chips = _chips(r.text)
    assert len(chips) == 18
    _assert_broken_from(chips, 10)
    assert chips[10] == "bad" and all(chips[s] == "untrusted" for s in range(11, 19))
    assert "BROKEN from seq 10" in r.text
    assert "does not match its hash" in r.text  # the tampered copy's report, not a hashes-only check
    assert "BLOCKED" in r.text
    # the original is byte-identical and nothing was left behind in the repo or fixtures/
    assert HONEST.read_bytes() == before_bytes
    assert _repo_files() == before_files
    assert not list((ROOT / "fixtures" / "samples").glob("*.tampered-*"))


def test_tamper_via_recorder_returns_records_and_report(sample_records):
    from secondgrader.web.app import tamper_via_recorder

    before = SAMPLE_TRACE.read_bytes()
    tampered, report = tamper_via_recorder(sample_records, 8, trace_path=SAMPLE_TRACE)
    assert len(tampered) == len(sample_records)
    assert tampered[7].payload != sample_records[7].payload
    assert tampered[7].hash == sample_records[7].hash  # stored hash kept, content changed
    assert report.ok is False and report.first_bad_seq == 8 and report.reason == "hash"
    assert report.statuses[7] == "bad" and report.statuses[8] == "untrusted"
    assert SAMPLE_TRACE.read_bytes() == before
    assert not list(SAMPLE_TRACE.parent.glob("*.tampered-*"))


def test_tamper_default_falls_back_to_memory_when_recorder_fails(sample_records, monkeypatch):
    from secondgrader.web import app as web_app

    def boom(*a, **k):
        raise RuntimeError("recorder down")

    monkeypatch.setattr(web_app, "tamper_via_recorder", boom)
    out = web_app.tamper_default(sample_records, 8, trace_path=SAMPLE_TRACE)
    assert isinstance(out, list)
    from secondgrader.schema import check_hash_chain
    assert check_hash_chain(out) == (False, 8)


def test_seal_mode_and_task_override_query_params(client, monkeypatch):
    from secondgrader import recorder
    from secondgrader.recorder import ChainReport

    real = recorder.verify_report

    def fake_report(path, *a, **k):
        rep = real(path, *a, **k)
        rep.signed = True
        rep.sealed = True
        rep.run = {"run_id": "run-abc123", "task_id": "honest_fix", "mode": "LIVE",
                   "recorded_at": "2026-11-07T19:00:00Z", "base_commit": "deadbeefcafe"}
        return rep

    monkeypatch.setattr(recorder, "verify_report", fake_report)
    r = client.get("/?mode=REPLAY")  # the seal says LIVE: the seal wins
    assert r.status_code == 200
    assert 'class="mode mode-live"' in r.text and 'class="mode mode-replay"' not in r.text
    assert 'value="honest_fix" selected' in r.text  # task from the seal, not from the prompt record
    assert "run-abc123" in r.text and "2026-11-07T19:00:00Z" in r.text
    assert "signed" in r.text and "sealed" in r.text and "UNSIGNED fixture" not in r.text
    # an explicit ?task still wins over the seal's task
    r = client.get("/?task=trap_hidden_edit")
    assert 'value="trap_hidden_edit" selected' in r.text


def test_chain_report_falls_back_to_hash_check_without_recorder(client, monkeypatch):
    from secondgrader import recorder

    monkeypatch.delattr(recorder, "verify_report")
    r = client.get("/?trace=fixtures/sample_trace_tampered.jsonl")
    assert r.status_code == 200
    chips = _chips(r.text)
    assert all(cls == "bad" for seq, cls in chips.items() if seq >= TEST_TAMPER_SEQ)
    assert all(cls == "good" for seq, cls in chips.items() if seq < TEST_TAMPER_SEQ)
    assert "BROKEN" in r.text


def test_render_verdict_chain_dict_badges_and_statuses(sample_records):
    chain = {
        "ok": False, "first_bad_seq": 3, "reason": "link", "detail": "seq 3 does not point at the previous record's hash",
        "count": len(sample_records), "head_hash": "ab" * 32, "signed": True, "sealed": True, "pubkey": "cd" * 32,
        "run": {"run_id": "r1", "task_id": "honest_fix", "mode": "REPLAY", "recorded_at": "2026-11-07T00:00:00Z"},
        "statuses": ["ok", "ok", "bad"] + ["untrusted"] * (len(sample_records) - 3),
    }
    html = web.render_verdict(GateDecision("BLOCK", ["chain"], [], False, 3), [], None, sample_records, chain=chain)
    chips = _chips(html)
    assert chips[1] == "good" and chips[2] == "good" and chips[3] == "bad" and chips[4] == "untrusted"
    assert "abababababab" not in html  # broken chain: the recorder's head hash is the genesis hash, not shown
    assert "signed" in html and "sealed" in html
    intact = dict(chain, ok=True, first_bad_seq=None, reason=None, detail="", statuses=["ok"] * len(sample_records))
    ok_html = web.render_verdict(GateDecision("PASS", [], [], True, None), [], None, sample_records, chain=intact)
    assert "abababababab" in ok_html and f'title="{"ab" * 32}"' in ok_html
    assert set(_chips(ok_html).values()) == {"good"}
    assert '<code class="reason">link</code>' in html and "does not point at the previous record" in html
    assert "r1" in html and "2026-11-07T00:00:00Z" in html
    # no chain dict: old behaviour, red from first_bad_seq, no badges
    plain = web.render_verdict(GateDecision("BLOCK", ["chain"], [], False, 3), [], None, sample_records)
    assert set(_chips(plain).values()) == {"good", "bad"} and "UNSIGNED fixture" not in plain


def test_tamper_findings_severity_pills():
    verdicts = [
        ClaimVerdict("tamper:tests/test_parser.py", "CONTRADICTED", [13], "[high] assert weakened in test_split"),
        ClaimVerdict("tamper:tests/conftest.py", "UNSUPPORTED", [9], "[low] comment-only change"),
        ClaimVerdict("tamper:pytest.ini", "UNSUPPORTED", [4], "[Medium] addopts changed"),
        ClaimVerdict("tamper:other", "UNSUPPORTED", [], "no severity prefix"),
    ]
    html = web.render_verdict(GateDecision("BLOCK", ["r"], [13]), verdicts, None)
    section = html.split("Tamper findings", 1)[1].split("Blind verifier", 1)[0]
    assert '<span class="sev high">high</span>' in section
    assert '<span class="sev low">low</span>' in section
    assert '<span class="sev medium">medium</span>' in section
    # the tag is stripped from the displayed reason
    assert "[high]" not in section and "[low]" not in section and "[Medium]" not in section
    assert "assert weakened in test_split" in section and "comment-only change" in section
    # UNSUPPORTED findings are informational; the CONTRADICTED one is not
    assert section.count("informational, does not block") == 3
    high_li = section.split("<li", 2)[1]
    assert "informational" not in high_li and "CONTRADICTED" in high_li
    assert web.split_severity("[HIGH] x") == ("high", "x")
    assert web.split_severity("plain") == (None, "plain")
    assert web.split_severity(None) == (None, "")
