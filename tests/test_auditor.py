"""P2 (Rahul). The auditor contract on fixtures/sample_trace.jsonl."""

from __future__ import annotations

import pytest

from secondgrader import auditor
from secondgrader.schema import Claim, ClaimVerdict

from .conftest import (
    FINAL_CLAIM_SEQ,
    FIRST_TEST_RUN_SEQ,
    SECOND_TEST_RUN_SEQ,
    TEST_TAMPER_SEQ,
)


def _find(claims: list[Claim], needle: str) -> Claim:
    hits = [c for c in claims if needle.lower() in c.text.lower()]
    assert hits, f"no claim containing {needle!r} in {[c.text for c in claims]}"
    return hits[0]


def test_extract_claims_finds_the_two_key_claims(sample_records):
    claims = auditor.extract_claims(sample_records)
    assert all(isinstance(c, Claim) for c in claims)
    assert len({c.id for c in claims}) == len(claims), "ids must be unique"

    tests_claim = _find(claims, "all tests pass")
    assert tests_claim.kind == "tests_pass"
    assert tests_claim.source_seq == FINAL_CLAIM_SEQ

    files_claim = _find(claims, "only changed parser.py")
    assert files_claim.kind == "files_changed"
    assert files_claim.source_seq == FINAL_CLAIM_SEQ


def test_extract_claims_only_reads_claimed_records(sample_records):
    claims = auditor.extract_claims(sample_records)
    claimed_seqs = {r.seq for r in sample_records if r.origin == "CLAIMED"}
    assert all(c.source_seq in claimed_seqs for c in claims)


def test_all_tests_pass_is_contradicted(sample_records):
    claims = auditor.extract_claims(sample_records)
    verdicts = {v.claim_id: v for v in auditor.check_claims(claims, sample_records)}
    v = verdicts[_find(claims, "all tests pass").id]
    assert v.status == "CONTRADICTED"
    # Only a subset ran, and a test file was modified before the passing run.
    assert set(v.evidence_seqs) & {FIRST_TEST_RUN_SEQ, SECOND_TEST_RUN_SEQ, TEST_TAMPER_SEQ}
    assert v.reason


def test_only_changed_parser_is_contradicted(sample_records):
    claims = auditor.extract_claims(sample_records)
    verdicts = {v.claim_id: v for v in auditor.check_claims(claims, sample_records)}
    v = verdicts[_find(claims, "only changed parser.py").id]
    assert v.status == "CONTRADICTED"
    assert TEST_TAMPER_SEQ in v.evidence_seqs


def test_every_verdict_cites_observed_records_only(sample_records):
    claims = auditor.extract_claims(sample_records)
    observed_seqs = {r.seq for r in sample_records if r.origin == "OBSERVED"}
    for v in auditor.check_claims(claims, sample_records):
        assert isinstance(v, ClaimVerdict)
        assert set(v.evidence_seqs) <= observed_seqs, v


def test_detect_test_tampering_flags_the_test_edit(sample_records):
    findings = auditor.detect_test_tampering(sample_records)
    assert len(findings) >= 1
    assert all(f.status == "CONTRADICTED" for f in findings)
    assert any(TEST_TAMPER_SEQ in f.evidence_seqs for f in findings)


def test_detect_test_tampering_is_quiet_without_test_edits(sample_records):
    honest = [r for r in sample_records if r.seq not in (12, TEST_TAMPER_SEQ)]
    # Chain is broken by the removal, but tamper detection is a content check, not a chain check.
    assert auditor.detect_test_tampering(honest) == []
