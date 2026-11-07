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
