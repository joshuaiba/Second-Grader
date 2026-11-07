"""P3 end to end: P1's runner (scripted agent) -> audit -> verify -> gate -> git. No Muse Code, no network."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from secondgrader import recorder
from secondgrader.gate import pipeline
from secondgrader.schema import GateDecision, load_trace

from .conftest import FIXTURES

SAMPLES = FIXTURES / "samples"


@pytest.fixture
def run_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SG_SIGNING_KEY_PATH", str(tmp_path / "keys" / "k.pem"))
    monkeypatch.delenv("SG_TRACE_PATH", raising=False)
    return tmp_path


def _git(repo, *args):
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True).stdout.strip()


def test_live_run_with_an_idle_agent_passes_and_merges(run_env):
    traces = run_env / "traces"
    stages = []
    res = pipeline.run_live("honest_fix", agent_cmd=["true"], traces=traces, no_verify=True,
                            on_stage=lambda s, d: stages.append(s))
    assert res.mode == "LIVE"
    assert res.decision.decision == "PASS", res.decision.reasons
    assert stages[0] == "record" and stages[-1] == "done"
    # The verdict is the last record and the chain still verifies, signed and sealed.
    recs = load_trace(res.trace_path)
    assert recs[-1].kind == "verdict" and recs[-1].payload["decision"] == "PASS"
    assert res.verdict_seq == recs[-1].seq
    report = recorder.verify_report(res.trace_path, require_signed=True)
    assert report.ok, (report.reason, report.detail)
    # Git: merged with --no-ff into the clone's main, chain head in the message.
    work = Path(res.run["work_dir"])
    assert res.git_outcome == "merged into main"
    msg = _git(work, "log", "-1", "--format=%B", "main")
    assert "PASS" in msg and report.head_hash in msg
    parents = _git(work, "rev-list", "--parents", "-n", "1", "main").split()[1:]
    assert len(parents) == 2
    # Ground truth was read from the full_final record.
    gt_ok, gt_seq = pipeline.ground_truth(recs)
    assert gt_ok is True and gt_seq is not None


def test_trace_with_broken_chain_blocks_and_quarantines(run_env, tmp_path):
    # A throwaway clone standing in for the agent's work dir.
    work = tmp_path / "work"
    work.mkdir()
    _git(work, "init", "-q", "-b", "main")
    (work / "f").write_text("base")
    _git(work, "add", "f")
    _git(work, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base")
    _git(work, "checkout", "-qb", "agent/x")
    (work / "f").write_text("changed")
    _git(work, "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qam", "agent")
    main_before = _git(work, "rev-parse", "main")

    trace = tmp_path / "t.jsonl"
    trace.write_bytes((SAMPLES / "tampered.jsonl").read_bytes())
    task = pipeline.load_task("honest_fix")
    res = pipeline.run_trace(task, trace, final_code=FIXTURES.parent / "demo_repo", work_dir=work, branch="agent/x",
                             no_verify=True)
    assert res.decision.decision == "BLOCK"
    assert res.first_bad_seq == 5 and 5 in res.decision.citing_seqs
    assert res.git_outcome and res.git_outcome.startswith("quarantined at refs/quarantine/agent/x-")
    assert _git(work, "rev-parse", "main") == main_before
    assert subprocess.run(["git", "rev-parse", "--verify", "agent/x"], cwd=work, capture_output=True).returncode != 0
    # Unsealed fixture: nothing could be chained, and the pipeline said so instead of failing.
    assert res.verdict_seq is None
    assert any("not written to the chain" in w for w in res.warnings)


def test_result_to_dict_is_json_friendly(run_env, tmp_path):
    import json
    trace = tmp_path / "t.jsonl"
    trace.write_bytes((SAMPLES / "honest.jsonl").read_bytes())
    res = pipeline.run_trace(pipeline.load_task("honest_fix"), trace, final_code=FIXTURES.parent / "demo_repo",
                             no_verify=True)
    d = res.to_dict()
    json.dumps(d)
    assert d["decision"]["decision"] == "PASS" and d["mode"] == "REPLAY" and d["chain_report"]["count"] == 18


def test_seal_mode_overrides_the_label(run_env):
    res = pipeline.run_live("honest_fix", agent_cmd=["true"], traces=run_env / "traces", no_verify=True)
    # run_trace was told mode=res.mode ("LIVE"), and the seal agrees; a REPLAY seal would win over any label.
    assert res.mode == "LIVE" and res.chain_report.run["mode"] == "LIVE"
    assert isinstance(res.decision, GateDecision)
