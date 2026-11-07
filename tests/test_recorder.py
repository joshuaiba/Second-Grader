"""Owner A. Un-skip as you implement."""

from __future__ import annotations

import pytest

from secondgrader import recorder
from secondgrader.schema import GENESIS_HASH, check_hash_chain, load_trace, record_hash

from .conftest import NOT_IMPLEMENTED, SAMPLE_TRACE, TAMPERED_TRACE, TEST_TAMPER_SEQ

pytestmark = pytest.mark.skip(reason=NOT_IMPLEMENTED)


def test_append_builds_a_valid_chain(tmp_path, monkeypatch):
    trace = tmp_path / "trace.jsonl"
    monkeypatch.setenv("SG_TRACE_PATH", str(trace))
    monkeypatch.setenv("SG_SIGNING_KEY_PATH", str(tmp_path / "key.pem"))

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
    # Fixtures carry sig="UNSIGNED". verify_chain must still check hashes and
    # report the chain intact; how it treats UNSIGNED sigs is owner A's call
    # (document it), but hashes alone must pass here.
    ok, first_bad = recorder.verify_chain(SAMPLE_TRACE)
    assert ok is True and first_bad is None


def test_verify_chain_reports_tampered_seq():
    assert recorder.verify_chain(TAMPERED_TRACE) == (False, TEST_TAMPER_SEQ)


def test_verify_chain_rejects_bad_signature(tmp_path, monkeypatch):
    trace = tmp_path / "trace.jsonl"
    monkeypatch.setenv("SG_TRACE_PATH", str(trace))
    monkeypatch.setenv("SG_SIGNING_KEY_PATH", str(tmp_path / "key.pem"))
    recorder.append({"kind": "prompt", "origin": "CLAIMED", "payload": {"text": "do x"}})
    recorder.append({"kind": "tool_call", "origin": "OBSERVED", "payload": {"tool": "bash", "args": {}}})

    lines = trace.read_text().splitlines()
    import json
    rec = json.loads(lines[1])
    rec["sig"] = "00" * 64
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    trace.write_text("\n".join(lines) + "\n")

    assert recorder.verify_chain(trace) == (False, 2)
