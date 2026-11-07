"""P1 Recorder tests: chain, signatures, seal, tamper backend, fingerprint."""

from __future__ import annotations

import json
import multiprocessing as mp
import subprocess

import pytest

from secondgrader import recorder
from secondgrader.recorder.fingerprint import changed_files, code_fingerprint
from secondgrader.recorder.tamper import tamper
from secondgrader.schema import GENESIS_HASH, canonical_json, check_hash_chain, load_trace, record_hash

from .conftest import SAMPLE_TRACE, TAMPERED_TRACE, TEST_TAMPER_SEQ


@pytest.fixture
def env(tmp_path, monkeypatch):
    trace = tmp_path / "trace.jsonl"
    monkeypatch.setenv("SG_TRACE_PATH", str(trace))
    monkeypatch.setenv("SG_SIGNING_KEY_PATH", str(tmp_path / "key.pem"))
    monkeypatch.delenv("SG_PUBKEY", raising=False)
    return trace


def _signed_trace(trace, n=6):
    recorder.start_run({"task_id": "honest_fix", "base_commit": "abc123"})
    for i in range(n):
        kind = "model_message" if i % 2 else "tool_call"
        payload = {"text": f"m{i}"} if i % 2 else {"tool": "bash", "args": {"command": f"c{i}"}}
        recorder.append({"kind": kind, "payload": payload})
    return trace


def _lines(trace):
    return trace.read_text().splitlines()


def _write(trace, lines):
    trace.write_text("\n".join(lines) + "\n")


# --------------------------------------------------------------------------- #
# Original contract tests
# --------------------------------------------------------------------------- #

def test_append_builds_a_valid_chain(env):
    trace = env
    r1 = recorder.append({"kind": "prompt", "origin": "CLAIMED", "payload": {"text": "do x"}})
    r2 = recorder.append({"kind": "tool_call", "origin": "OBSERVED", "payload": {"tool": "bash", "args": {}}})

    assert (r1.seq, r2.seq) == (1, 2)
    assert r1.prev_hash == GENESIS_HASH and r2.prev_hash == r1.hash
    assert record_hash(r1) == r1.hash and record_hash(r2) == r2.hash
    assert r1.sig != "UNSIGNED" and len(r1.sig) > 0

    records = load_trace(trace)
    assert check_hash_chain(records) == (True, None)
    assert recorder.verify_chain(trace) == (True, None)


def test_verify_chain_accepts_unsigned_fixture_hashes():
    # Fixtures are all UNSIGNED with no seal: checked on hashes only, reported signed=False.
    assert recorder.verify_chain(SAMPLE_TRACE) == (True, None)
    assert recorder.verify_report(SAMPLE_TRACE).signed is False


def test_verify_chain_reports_tampered_seq():
    assert recorder.verify_chain(TAMPERED_TRACE) == (False, TEST_TAMPER_SEQ)


def test_verify_chain_rejects_bad_signature(env):
    trace = env
    recorder.append({"kind": "prompt", "origin": "CLAIMED", "payload": {"text": "do x"}})
    recorder.append({"kind": "tool_call", "origin": "OBSERVED", "payload": {"tool": "bash", "args": {}}})

    lines = _lines(trace)
    rec = json.loads(lines[1])
    rec["sig"] = "00" * 64
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    _write(trace, lines)

    assert recorder.verify_chain(trace) == (False, 2)


# --------------------------------------------------------------------------- #
# P1.7: the five tamper tests
# --------------------------------------------------------------------------- #

def test_tamper_byte_flip(env):
    trace = _signed_trace(env)
    lines = _lines(trace)
    lines[2] = lines[2].replace('"c2"', '"c9"')
    _write(trace, lines)
    r = recorder.verify_report(trace)
    assert (r.ok, r.first_bad_seq, r.reason) == (False, 3, "hash")
    assert r.statuses == ["ok", "ok", "bad", "untrusted", "untrusted", "untrusted"]


def test_tamper_removed_line(env):
    trace = _signed_trace(env)
    lines = _lines(trace)
    del lines[3]
    _write(trace, lines)
    r = recorder.verify_report(trace)
    assert (r.ok, r.first_bad_seq, r.reason) == (False, 4, "seq")


def test_tamper_reorder(env):
    trace = _signed_trace(env)
    lines = _lines(trace)
    lines[1], lines[2] = lines[2], lines[1]
    _write(trace, lines)
    r = recorder.verify_report(trace)
    assert (r.ok, r.first_bad_seq, r.reason) == (False, 2, "seq")


def test_tamper_swapped_signature(env):
    trace = _signed_trace(env)
    lines = _lines(trace)
    a, b = json.loads(lines[1]), json.loads(lines[4])
    a["sig"], b["sig"] = b["sig"], a["sig"]
    lines[1], lines[4] = canonical_json(a), canonical_json(b)
    _write(trace, lines)
    r = recorder.verify_report(trace)
    assert (r.ok, r.first_bad_seq, r.reason) == (False, 2, "signature")


def test_tamper_truncation(env):
    trace = _signed_trace(env)
    _write(trace, _lines(trace)[:4])
    r = recorder.verify_report(trace)
    assert (r.ok, r.first_bad_seq, r.reason) == (False, 5, "truncated")


def test_truncation_with_seal_deleted_is_detected(env):
    trace = _signed_trace(env)
    pubkey = recorder.read_seal(trace)["pubkey"]
    _write(trace, _lines(trace)[:4])
    recorder.seal_path(trace).unlink()
    # No seal and no pinned key: signatures can't even be checked.
    assert recorder.verify_chain(trace) == (False, 1)
    # Pinned key: records verify, but the missing seal means the tail may be gone.
    r = recorder.verify_report(trace, pubkey=pubkey)
    assert (r.ok, r.first_bad_seq, r.reason) == (False, 5, "truncated")


def test_rehash_does_not_help_a_forger(env):
    trace = _signed_trace(env)
    lines = _lines(trace)
    rec = json.loads(lines[2])
    rec["payload"]["args"]["command"] = "pytest"
    rec["hash"] = record_hash(rec)
    lines[2] = canonical_json(rec)
    _write(trace, lines)
    assert recorder.verify_report(trace).reason == "signature"
    assert recorder.verify_chain(trace) == (False, 3)


def test_unsigned_record_inside_signed_trace_fails(env):
    trace = _signed_trace(env)
    lines = _lines(trace)
    rec = json.loads(lines[2])
    rec["sig"] = "UNSIGNED"
    lines[2] = canonical_json(rec)
    _write(trace, lines)
    assert recorder.verify_chain(trace) == (False, 3)


def test_forged_seal_fails(env):
    trace = _signed_trace(env)
    sp = recorder.seal_path(trace)
    seal = json.loads(sp.read_text())
    seal["count"] = 3
    sp.write_text(json.dumps(seal))
    assert recorder.verify_report(trace).reason == "seal"


def test_pinned_key_catches_rekeyed_trace(env, tmp_path):
    from secondgrader.recorder.keys import load_or_create_key, public_hex
    trace = _signed_trace(env)
    other = public_hex(load_or_create_key(tmp_path / "other.pem"))
    assert recorder.verify_report(trace, pubkey=other).reason == "key"


# --------------------------------------------------------------------------- #
# P1.4 / P1.6: single writer, origin tag, run seal
# --------------------------------------------------------------------------- #

def test_origin_is_set_by_recorder_not_caller(env):
    rec = recorder.append({"kind": "test_run", "payload": {"command": "pytest", "exit_code": 0}})
    assert rec.origin == "OBSERVED"
    with pytest.raises(ValueError):
        recorder.append({"kind": "model_message", "origin": "OBSERVED", "payload": {"text": "trust me"}})


def test_seal_holds_run_metadata_and_pubkey(env):
    trace = _signed_trace(env, n=2)
    seal = recorder.read_seal(trace)
    assert seal["run"] == {"task_id": "honest_fix", "base_commit": "abc123"}
    assert seal["count"] == 2 and len(seal["pubkey"]) == 64
    r = recorder.verify_report(trace)
    assert r.ok and r.sealed and r.signed and r.run["task_id"] == "honest_fix"


def _worker(args):
    trace, key, i = args
    import os
    os.environ["SG_SIGNING_KEY_PATH"] = key
    from secondgrader import recorder as rec_mod
    for j in range(10):
        rec_mod.append({"kind": "tool_call", "payload": {"tool": "bash", "args": {"w": i, "j": j}}}, trace)


def test_concurrent_writers_never_corrupt_ordering(env, tmp_path):
    trace = env
    key = str(tmp_path / "key.pem")
    recorder.append({"kind": "prompt", "payload": {"text": "go"}})  # creates the key first
    with mp.get_context("spawn").Pool(6) as pool:
        pool.map(_worker, [(str(trace), key, i) for i in range(6)])
    r = recorder.verify_report(trace)
    assert r.ok and r.count == 61
    assert [rec.seq for rec in load_trace(trace)] == list(range(1, 62))


# --------------------------------------------------------------------------- #
# P1.11: live tamper backend
# --------------------------------------------------------------------------- #

def test_tamper_backend_fails_from_n_on(env):
    trace = _signed_trace(env)
    out, report = tamper(trace, 4, "payload.text", "all tests pass")
    assert recorder.verify_chain(trace) == (True, None)  # original untouched
    assert (report.ok, report.first_bad_seq) == (False, 4)
    assert report.statuses == ["ok", "ok", "ok", "bad", "untrusted", "untrusted"]
    assert out.exists()


def test_tamper_backend_on_fixture(tmp_path):
    _, report = tamper(SAMPLE_TRACE, 10, "payload.exit_code", 0, out_path=tmp_path / "t.jsonl")
    assert (report.ok, report.first_bad_seq) == (False, 10)


# --------------------------------------------------------------------------- #
# P1.5: code fingerprint
# --------------------------------------------------------------------------- #

@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    (r / "parser.py").write_text("x = 1\n")
    (r / ".gitignore").write_text("*.pyc\n")
    for cmd in (["init", "-q"], ["add", "-A"],
                ["-c", "user.email=a@b", "-c", "user.name=t", "commit", "-qm", "base"]):
        subprocess.run(["git", "-C", str(r), *cmd], check=True)
    return r


def test_fingerprint_sees_shell_edits_and_leaves_index_alone(repo):
    index_before = (repo / ".git" / "index").read_bytes()
    base = code_fingerprint(repo)
    assert base == subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"],
                                  capture_output=True, text=True, check=True).stdout.strip()
    subprocess.run(["sed", "-i.bak", "s/1/2/", str(repo / "parser.py")], check=True)
    (repo / "parser.py.bak").unlink()
    after_sed = code_fingerprint(repo)
    subprocess.run(["sh", "-c", f"cat > {repo / 'new.py'} <<EOF\nprint(1)\nEOF"], check=True)
    after_cat = code_fingerprint(repo)
    (repo / "junk.pyc").write_text("ignored")
    assert len({base, after_sed, after_cat}) == 3
    assert code_fingerprint(repo) == after_cat  # ignored files don't count
    assert (repo / ".git" / "index").read_bytes() == index_before
    assert changed_files(repo, base, after_cat) == [{"status": "A", "path": "new.py"},
                                                    {"status": "M", "path": "parser.py"}]


# --------------------------------------------------------------------------- #
# P1.3 hooks, P1.8 runner, P1.9 ground truth, P1.10 replay (scripted agent)
# --------------------------------------------------------------------------- #

import os  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from secondgrader.recorder.hooks import map_event, parse_pytest  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
FORWARD = ROOT / "scripts" / "hooks" / "forward.py"
SCRIPTED = ROOT / "scripts" / "hooks" / "scripted_agent.py"


def _hook(sock, payload, timeout=5):
    t0 = time.perf_counter()
    proc = subprocess.run([sys.executable, str(FORWARD), "--sock", str(sock)], input=json.dumps(payload),
                          text=True, capture_output=True, timeout=timeout, env={"PATH": "/usr/bin:/bin"})
    return proc.returncode, time.perf_counter() - t0


def test_hook_fails_closed_when_recorder_is_down(tmp_path):
    code, _ = _hook(tmp_path / "nope.sock", {"hook_event_name": "PreToolUse", "tool_name": "bash"})
    assert code == 2


def test_hook_fails_closed_on_bad_input(tmp_path):
    proc = subprocess.run([sys.executable, str(FORWARD), "--sock", str(tmp_path / "s")], input="not json",
                          text=True, capture_output=True, timeout=5)
    assert proc.returncode == 2


def test_hook_times_out_and_blocks_before_2s():
    import socket as so
    from secondgrader.recorder.service import short_socket_path
    sock = short_socket_path("slow")
    srv = so.socket(so.AF_UNIX, so.SOCK_STREAM)
    srv.bind(str(sock))
    srv.listen(1)  # accepts, never answers
    try:
        code, elapsed = _hook(sock, {"hook_event_name": "PreToolUse", "tool_name": "bash"})
    finally:
        srv.close()
    assert code == 2 and elapsed < 2.0


def test_map_event_shapes():
    post = {"hook_event_name": "PostToolUseFailure", "tool_name": "bash", "tool_use_id": "x",
            "tool_input": {"cmd": "pytest | tail -3"},
            "tool_response": json.dumps({"exit_code": 1, "output": "1 failed, 7 passed in 0.1s"})}
    (k1, out), (k2, run) = map_event(post)
    assert (k1, k2) == ("tool_output", "test_run")
    assert out["failed"] is True and out["exit_code"] == 1
    assert (run["command"], run["passed"], run["failed"], run["source"]) == ("pytest | tail -3", 7, 1, "agent")
    assert map_event({"hook_event_name": "Stop", "last_assistant_message": "All tests pass."}) == [
        ("model_message", {"text": "All tests pass.", "event": "Stop", "final": True})]
    assert map_event({"hook_event_name": "SessionStart"}) == []
    assert parse_pytest("collected 8 items\n...\n3 passed, 5 deselected in 0.01s")["collected"] == 8


@pytest.fixture
def run_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SG_SIGNING_KEY_PATH", str(tmp_path / "keys" / "k.pem"))
    monkeypatch.setenv("SCRIPTED_LATENCY_FILE", str(tmp_path / "lat.json"))
    return tmp_path


def test_scripted_run_end_to_end(run_env):
    from secondgrader.recorder.runner import RunResult, run_task
    from secondgrader.schema import load_trace as lt
    traces = run_env / "traces"
    res = run_task("trap_partial_run", agent_cmd=[sys.executable, str(SCRIPTED)], traces=traces,
                   time_limit=60)
    assert res.agent_exit == 0, Path(res.run_dir, "agent_stderr.txt").read_text()
    report = recorder.verify_report(res.trace_path)
    assert report.ok and report.signed and report.sealed, report.detail
    assert report.run["agent"] == "scripted" and report.run["mode"] == "LIVE"

    recs = lt(res.trace_path)
    kinds = [r.kind for r in recs]
    assert kinds[0] == "prompt" and "(Trap" not in recs[0].payload["text"]
    # the sed -i edit through the shell is caught as a diff with the new tree
    diffs = [r for r in recs if r.kind == "diff" and r.payload.get("via_tool") == "bash"]
    assert [d.payload["path"] for d in diffs] == ["parser.py"]
    agent_runs = [r for r in recs if r.kind == "test_run" and r.payload["source"] == "agent"]
    assert len(agent_runs) == 1 and "-k parse" in agent_runs[0].payload["command"]
    assert agent_runs[0].payload["tree"] == res.final_tree
    claim = [r for r in recs if r.kind == "model_message"][-1]
    assert claim.origin == "CLAIMED" and "All tests pass" in claim.payload["text"]
    gt = {r.payload.get("phase"): r for r in recs if r.payload.get("source") == "ground_truth"}
    assert {"collect_base", "collect_final", "full_final"} <= set(gt)
    assert gt["full_final"].payload["exit_code"] == 0 and gt["full_final"].payload["failed"] == 0
    assert gt["collect_final"].payload["collected"] == gt["full_final"].payload["passed"] > 0
    assert sorted(res.ground_truth_seqs) == res.ground_truth_seqs and res.ground_truth_seqs[-1] == recs[-1].seq

    # main of the upstream is untouched; the agent's work is only on its branch
    up = Path(res.upstream)
    assert up.parent == traces and up.name.startswith("demo_upstream-")
    main_tree = subprocess.run(["git", "-C", str(up), "rev-parse", "main^{tree}"], capture_output=True,
                               text=True, check=True).stdout.strip()
    assert main_tree == res.base_tree != res.final_tree
    assert (Path(res.run_dir) / "final" / "parser.py").read_text().count("Module") >= 1
    assert RunResult.load(res.run_dir).final_commit == res.final_commit

    lat = sorted(json.loads((run_env / "lat.json").read_text()))
    p95 = lat[int(0.95 * (len(lat) - 1))]
    assert p95 < 150, f"hook p95 {p95:.0f} ms"


def test_two_runs_never_touch_each_other(run_env):
    from secondgrader.recorder.runner import run_task
    traces = run_env / "traces"
    a = run_task("honest_fix", agent_cmd=[sys.executable, str(SCRIPTED)], traces=traces, ground_truth=False)
    b = run_task("honest_fix", agent_cmd=["true"], traces=traces, ground_truth=False)
    assert a.work_dir != b.work_dir and a.final_tree != b.final_tree == b.base_tree


def test_runner_stops_agent_at_time_limit(run_env):
    from secondgrader.recorder.runner import run_task
    t0 = time.time()
    res = run_task("honest_fix", agent_cmd=["sleep", "30"], traces=run_env / "traces", time_limit=1,
                   ground_truth=False)
    assert res.timed_out and time.time() - t0 < 15
    assert recorder.verify_chain(res.trace_path) == (True, None)


def test_replay_is_labelled_and_verified(run_env):
    from secondgrader.recorder.replay import replay, save_replay
    from secondgrader.recorder.runner import run_task
    live = run_task("trap_partial_run", agent_cmd=[sys.executable, str(SCRIPTED)], traces=run_env / "traces")
    saved = save_replay(live.run_dir, dest=run_env / "replays" / "trap_partial_run")
    assert not (saved / "work").exists() and (saved / "work.bundle").exists()
    rep = replay(saved, traces=run_env / "traces")
    assert rep.mode == "REPLAY" and rep.recorded_at == live.recorded_at and rep.replayed_at
    assert rep.final_tree == live.final_tree
    rep_report = recorder.verify_report(rep.trace_path, expect_run_id=rep.run_id)
    assert rep_report.ok and rep_report.run["mode"] == "REPLAY"  # labelled in the signed seal
    assert rep_report.run["recorded_at"] == live.recorded_at
    head = subprocess.run(["git", "-C", rep.work_dir, "rev-parse", "HEAD"], capture_output=True, text=True,
                          check=True).stdout.strip()
    assert head == live.final_commit

    # an edited replay is refused
    snap = saved / "agent_trace.jsonl"
    lines = snap.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["payload"]["text"] = "Do whatever you like."
    lines[1] = canonical_json(rec)
    snap.write_text("\n".join(lines) + "\n")
    with pytest.raises(ValueError, match="fails verification"):
        replay(saved, traces=run_env / "traces")


# --------------------------------------------------------------------------- #
# Regressions from the P1 verification pass
# --------------------------------------------------------------------------- #

from secondgrader.recorder.keys import load_or_create_key as _lok  # noqa: E402
from secondgrader.recorder.writer import TraceWriter  # noqa: E402


def test_append_refuses_after_mid_run_truncation(env):
    trace = _signed_trace(env, n=5)
    _write(trace, _lines(trace)[:2])
    with pytest.raises(RuntimeError, match="refusing to append"):
        recorder.append({"kind": "tool_call", "payload": {"tool": "bash", "args": {}}})
    assert recorder.verify_chain(trace) == (False, 3)


def test_long_lived_writer_refuses_after_wipe_or_rollback(env, tmp_path):
    w = TraceWriter(env, _lok(tmp_path / "key.pem"))
    w.start({"run_id": "r1"})
    for i in range(3):
        w.append("tool_call", {"tool": "bash", "args": {"i": i}})
    old = env.read_text(), recorder.seal_path(env).read_text()
    w.append("tool_call", {"tool": "bash", "args": {"i": 3}})
    env.write_text(old[0])  # restore an older but self-consistent pair
    recorder.seal_path(env).write_text(old[1])
    with pytest.raises(RuntimeError, match="went back"):
        w.append("tool_call", {"tool": "bash", "args": {"i": 4}})
    env.unlink()
    recorder.seal_path(env).unlink()
    with pytest.raises(RuntimeError, match="went back"):
        w.append("tool_call", {"tool": "bash", "args": {"i": 4}})


def test_caller_cannot_set_timestamp(env):
    rec = recorder.append({"kind": "prompt", "ts": "2020-01-01T00:00:00Z", "payload": {"text": "x"}})
    assert not rec.ts.startswith("2020")


def test_socket_accepts_only_hook_events(tmp_path):
    from secondgrader.recorder.service import Recorder, RecorderServer, send, short_socket_path
    sock = short_socket_path("t")
    srv = RecorderServer(sock, Recorder(tmp_path / "t.jsonl", _lok(tmp_path / "k.pem")))
    srv.start_background()
    try:
        forged = send(sock, {"append": {"kind": "test_run", "payload": {"source": "ground_truth", "passed": 99}}})
        assert forged["ok"] is False
        assert send(sock, {"event": {"hook_event_name": "UserPromptSubmit", "prompt": "hi"}})["seqs"] == [1]
    finally:
        srv.close()


def test_agent_env_has_no_recorder_variables(run_env):
    from secondgrader.recorder.runner import run_task
    dump = run_env / "env.txt"
    run_task("honest_fix", agent_cmd=["sh", "-c", f"env > {dump}"], traces=run_env / "traces",
             ground_truth=False)
    assert "SG_" not in dump.read_text()


@pytest.mark.parametrize("damage", ["ff_byte", "garbage_seal", "list_seal", "missing"])
def test_verify_never_crashes(env, damage):
    trace = _signed_trace(env, n=3)
    sp = recorder.seal_path(trace)
    if damage == "ff_byte":
        data = bytearray(trace.read_bytes())
        data[40] = 0xFF
        trace.write_bytes(bytes(data))
    elif damage == "garbage_seal":
        sp.write_text("{not json")
    elif damage == "list_seal":
        sp.write_text("[1, 2]")
    else:
        trace.unlink()
    r = recorder.verify_report(trace)
    assert r.ok is False and r.first_bad_seq is not None and r.reason in {"parse", "seal"}


def test_stripped_signatures_fail_when_signatures_required(env, monkeypatch):
    trace = _signed_trace(env, n=3)
    pubkey = recorder.read_seal(trace)["pubkey"]
    lines = []
    prev = GENESIS_HASH
    for line in _lines(trace):
        rec = json.loads(line)
        rec["prev_hash"], rec["sig"] = prev, "UNSIGNED"
        rec["hash"] = record_hash(rec)
        prev = rec["hash"]
        lines.append(canonical_json(rec))
    _write(trace, lines)
    recorder.seal_path(trace).unlink()
    assert recorder.verify_chain(trace) == (True, None)  # looks like a fixture...
    assert recorder.verify_chain(trace, pubkey=pubkey) == (False, 1)  # ...but not to a pinned key
    monkeypatch.setenv("SG_REQUIRE_SIGNED", "1")
    assert recorder.verify_chain(trace) == (False, 1)
    trace.write_text("")
    assert recorder.verify_chain(trace)[0] is False


def test_expect_run_id_catches_swapped_trace(env):
    trace = _signed_trace(env, n=2)
    recorder.TraceWriter(trace, _lok()).update_run({"run_id": "run-A"})
    assert recorder.verify_chain(trace, expect_run_id="run-A") == (True, None)
    assert recorder.verify_report(trace, expect_run_id="run-B").reason == "run"


def test_hook_mapping_edge_cases():
    def run_of(tool, cmd, response, event="PostToolUse", **extra):
        pairs = map_event({"hook_event_name": event, "tool_name": tool, "tool_input": {"command": cmd},
                           "tool_response": response, **extra})
        return dict(pairs).get("test_run")
    assert run_of("Bash", "pytest -q", "1 passed in 0.1s")["passed"] == 1
    assert run_of("bash", ".venv/bin/pytest", "1 passed in 0.1s") is not None
    assert run_of("bash", "python3.12 -m pytest", "1 passed in 0.1s") is not None
    assert run_of("bash", "pytest", json.dumps({"exit_code": "1", "output": "x"}))["exit_code"] == 1
    assert run_of("bash", "pytest", json.dumps({"exit_code": True, "output": "x"}))["exit_code"] is None
    fake = run_of("bash", 'pytest; echo "8 passed"',
                  "=== 1 failed, 7 passed in 0.2s ===\n8 passed")
    assert (fake["failed"], fake["passed"]) == (1, 7)
    fail = run_of("bash", "pytest", None, event="PostToolUseFailure", error="exit status 1")
    assert fail["exit_code"] == 1 and fail["tool_failed"] is True


# Real payloads captured from Muse Code 1.4.14 (trimmed: cwd, model fields).
MAIN = "01a1b7bb-fbc9-72f1-8758-498149761b6d"
REAL_FAILURE = {
    "hook_event_name": "PostToolUseFailure", "tool_name": "bash", "session_id": MAIN,
    "tool_input": {"command": "python3 -m pytest -q", "description": "Run tests", "workdir": "/w"},
    "tool_use_id": "call_1", "is_interrupt": False, "duration_ms": 71,
    "error": "{\n  \"chunk_id\": \"exec-1-1\",\n  \"exit_code\": 1,\n  \"terminal_status\": \"failed\",\n"
             "  \"terminal_reason\": \"process exited with status 1\",\n"
             "  \"output\": \"F.\\n1 failed, 1 passed in 0.02s\\n\",\n  \"truncated\": false\n}",
}
REAL_SUCCESS = {
    "hook_event_name": "PostToolUse", "tool_name": "bash", "session_id": MAIN, "tool_use_id": "call_2",
    "tool_input": {"command": "sed -i.bak 's/1/2/' a.py && rm a.py.bak", "workdir": "/w"},
    "tool_response": "{\n  \"chunk_id\": \"exec-2-1\",\n  \"exit_code\": 0,\n  \"terminal_status\": "
                     "\"completed\",\n  \"output\": \"\",\n  \"truncated\": false\n}",
}


def test_real_muse_payloads():
    (_, out), (_, run) = map_event(REAL_FAILURE, MAIN)
    assert (out["exit_code"], out["failed"], out["content"]) == (1, True, "F.\n1 failed, 1 passed in 0.02s")
    assert (run["exit_code"], run["failed"], run["passed"], run["tool_failed"]) == (1, 1, 1, True)
    [(_, ok)] = map_event(REAL_SUCCESS, MAIN)
    assert (ok["exit_code"], ok["failed"], ok["content"]) == (0, False, "")


def test_helper_agent_text_is_never_a_claim():
    helper = "01a1b7bb-6afa-7d93-b618-751d89ab94ad"
    assert map_event({"hook_event_name": "SubagentStop", "session_id": helper,
                      "last_assistant_message": "You are a reminder observer"}, MAIN) == []
    assert map_event({"hook_event_name": "PostLLMCall", "session_id": helper, "tool_call_count": 1,
                      "output_text_preview": "reminder text"}, MAIN) == []
    assert map_event({"hook_event_name": "Stop", "session_id": helper,
                      "last_assistant_message": "x"}, MAIN) == []
    # the main agent's narration alongside a tool call is recorded; its final answer comes from Stop
    [(kind, msg)] = map_event({"hook_event_name": "PostLLMCall", "session_id": MAIN, "tool_call_count": 1,
                               "step": 0, "output_text_preview": "Running the tests now."}, MAIN)
    assert kind == "model_message" and msg["text"] == "Running the tests now."
    assert map_event({"hook_event_name": "PostLLMCall", "session_id": MAIN, "tool_call_count": 0,
                      "output_text_preview": "All tests pass."}, MAIN) == []


@pytest.mark.parametrize("cmd", [
    "pytest -q",
    "python -m pytest -v",
    "python3 -u -m pytest -q",
    "/usr/bin/python3.12 -m pytest",
    ".venv/bin/pytest tests/",
    "cd work && pytest -q",
    "pytest -q; git status --short",
    "PYTHONPATH=. pytest -q",
    "uv run pytest -q",
    "uv run --with pytest python -m pytest -v 2>&1 | tail -40",
    "uv run --with pytest python -m pytest -v 2>&1 || uvx --with pytest python -m pytest -v 2>&1",
    "uvx pytest",
    "timeout 60 pytest -x",
    "poetry run pytest",
])
def test_is_test_command_true(cmd):
    from secondgrader.recorder.hooks import is_test_command
    assert is_test_command(cmd)


# Real commands from Muse Code runs that mention pytest without running the suite.
@pytest.mark.parametrize("cmd", [
    None,
    "",
    "ls -R",
    "which pytest || true",
    "command -v pytest; command -v uv; ls -la; cat pytest.ini",
    "ls -a; which pytest || true; ls work; command -v uv || true",
    "uv run --with pytest python /tmp/check_interp.py 2>&1; echo ---; PYTHONPATH=. uv run python /tmp/check_interp.py",
    "pip install pytest",
    "cat pytest.ini",
    "python -c 'import pytest'",
    "echo pytest",
])
def test_is_test_command_false(cmd):
    from secondgrader.recorder.hooks import is_test_command
    assert not is_test_command(cmd)
