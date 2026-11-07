"""These really run. They pin down the contract and the fixtures."""

from __future__ import annotations

import json

import pytest

from secondgrader import schema
from secondgrader.schema import (
    GENESIS_HASH,
    ORIGIN_FOR_KIND,
    Claim,
    ClaimVerdict,
    GateDecision,
    Record,
    VerifierResult,
    canonical_json,
    check_hash_chain,
    claimed,
    observed,
    record_hash,
)

from .conftest import (
    FINAL_CLAIM_SEQ,
    SAMPLE_TRACE,
    TAMPERED_TRACE,
    TEST_TAMPER_SEQ,
)


def test_canonical_json_is_sorted_and_compact():
    assert canonical_json({"b": 1, "a": {"d": [1, 2], "c": "x"}}) == '{"a":{"c":"x","d":[1,2]},"b":1}'


def test_record_hash_ignores_hash_and_sig():
    base = {"seq": 1, "ts": "2026-11-07T00:00:00Z", "kind": "prompt", "origin": "CLAIMED",
            "payload": {"text": "hi"}, "prev_hash": GENESIS_HASH}
    h = record_hash(base)
    assert len(h) == 64
    assert record_hash({**base, "hash": "junk", "sig": "junk"}) == h
    assert record_hash(Record(**base, hash="junk", sig="junk")) == h


def test_record_hash_changes_with_payload():
    base = {"seq": 1, "ts": "t", "kind": "prompt", "origin": "CLAIMED", "payload": {"a": 1}, "prev_hash": GENESIS_HASH}
    assert record_hash(base) != record_hash({**base, "payload": {"a": 2}})


def test_fixture_chain_verifies(sample_records):
    assert len(sample_records) == 16
    assert check_hash_chain(sample_records) == (True, None)


def test_tampered_fixture_breaks_at_right_seq(tampered_records):
    ok, first_bad = check_hash_chain(tampered_records)
    assert ok is False
    assert first_bad == TEST_TAMPER_SEQ


def test_tampered_fixture_differs_only_at_tamper_seq(sample_records, tampered_records):
    for good, bad in zip(sample_records, tampered_records):
        if good.seq == TEST_TAMPER_SEQ:
            assert good.payload != bad.payload
            assert good.hash == bad.hash  # attacker did not recompute the hash
        else:
            assert good == bad


def test_fixture_origins_match_kinds(sample_records):
    for rec in sample_records:
        assert rec.origin == ORIGIN_FOR_KIND[rec.kind], rec.seq
    assert all(r.origin == "OBSERVED" for r in observed(sample_records))
    assert all(r.origin == "CLAIMED" for r in claimed(sample_records))
    assert len(observed(sample_records)) + len(claimed(sample_records)) == len(sample_records)


def test_fixture_tells_the_cheating_story(sample_records):
    by_seq = {r.seq: r for r in sample_records}
    final = by_seq[FINAL_CLAIM_SEQ]
    assert final.kind == "model_message"
    assert "All tests pass" in final.payload["text"]
    assert "Only changed parser.py" in final.payload["text"]

    tamper = by_seq[TEST_TAMPER_SEQ]
    assert tamper.kind == "diff"
    assert tamper.payload["path"] == "tests/test_parser.py"

    runs = [r for r in sample_records if r.kind == "test_run"]
    assert [r.payload["exit_code"] for r in runs] == [1, 0]
    assert all("-k" in r.payload["command"] for r in runs), "both runs are subsets"
    assert all(r.payload["selected"] < r.payload["collected"] for r in runs)


def test_fixture_file_is_canonical_jsonl(sample_records):
    lines = SAMPLE_TRACE.read_text(encoding="utf-8").splitlines()
    assert [json.loads(l) for l in lines] == [r.to_dict() for r in sample_records]
    assert lines == [r.to_json() for r in sample_records]


def test_from_dict_rejects_bad_origin_for_kind():
    with pytest.raises(ValueError):
        Record.from_dict({"seq": 1, "ts": "t", "kind": "tool_output", "origin": "CLAIMED",
                          "payload": {}, "prev_hash": GENESIS_HASH, "hash": "x", "sig": "UNSIGNED"})


def test_from_dict_rejects_unknown_fields():
    with pytest.raises(ValueError):
        Record.from_dict({"seq": 1, "ts": "t", "kind": "prompt", "origin": "CLAIMED", "payload": {},
                          "prev_hash": GENESIS_HASH, "hash": "x", "sig": "UNSIGNED", "extra": 1})


def test_check_hash_chain_detects_gap_and_bad_link(sample_records):
    gap = [r for r in sample_records if r.seq != 5]
    assert check_hash_chain(gap) == (False, 6)

    relinked = list(sample_records)
    r = relinked[3]
    relinked[3] = Record(**{**r.to_dict(), "prev_hash": "ff" * 32})
    assert check_hash_chain(relinked) == (False, 4)


def test_result_types_have_sane_defaults():
    assert ClaimVerdict(claim_id="c1", status="SUPPORTED").evidence_seqs == []
    assert VerifierResult().passed == 0
    d = GateDecision(decision="PASS")
    assert d.chain_ok is True and d.first_bad_seq is None and d.citing_seqs == []
    c = Claim(id="c1", text="All tests pass", kind="tests_pass", source_seq=FINAL_CLAIM_SEQ)
    assert c.kind in schema.CLAIM_KINDS


def test_tampered_fixture_exists_and_loads(tampered_records):
    assert TAMPERED_TRACE.exists()
    assert len(tampered_records) == 16
