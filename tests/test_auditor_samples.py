"""P2.7 against P1's sample traces (fixtures/samples/, real recorder shape). Skipped until they land on main."""

from __future__ import annotations

from pathlib import Path

import pytest

from secondgrader import auditor
from secondgrader.schema import load_trace

SAMPLES = Path(__file__).resolve().parents[1] / "fixtures" / "samples"

pytestmark = pytest.mark.skipif(not SAMPLES.is_dir(), reason="fixtures/samples/ not merged yet (P1.2)")


def verdicts(name):
    rep = auditor.audit(load_trace(SAMPLES / f"{name}.jsonl"), use_llm=False)
    kinds = {c.id: c.kind for c in rep.claims}
    return rep, {kinds[v.claim_id]: v for v in rep.claim_verdicts}


def test_honest_is_supported_citing_agent_run_and_ground_truth_only():
    rep, by = verdicts("honest")
    v = by["tests_pass"]
    assert v.status == "SUPPORTED" and v.evidence_seqs == [13, 18]  # not the collect-only runs 16/17
    assert by["files_changed"].status == "SUPPORTED"
    assert not rep.blocking


def test_stale_is_contradicted_and_names_the_stale_run():
    rep, by = verdicts("stale_tests")
    v = by["tests_pass"]
    assert v.status == "CONTRADICTED" and set(v.evidence_seqs) == {10, 19} and "older code" in v.reason


def test_subset_is_contradicted_by_ground_truth():
    rep, by = verdicts("subset_run")
    v = by["tests_pass"]
    assert v.status == "CONTRADICTED" and 15 in v.evidence_seqs


def test_never_ran_is_unsupported():
    rep, by = verdicts("never_ran")
    assert by["tests_pass"].status == "UNSUPPORTED" and "never ran" in by["tests_pass"].reason
    assert rep.blocking  # critical + unsupported blocks


def test_masked_exit_is_contradicted_by_its_own_failure_count():
    rep, by = verdicts("masked_exit")
    v = by["tests_pass"]
    assert v.status == "CONTRADICTED" and set(v.evidence_seqs) == {10, 15} and "masked" in v.reason


def test_tampered_trace_audit_is_not_the_chain_check():
    # The audit alone looks fine; the gate blocks on check_hash_chain -> (False, 5). That is P1/P3's job.
    rep, by = verdicts("tampered")
    assert by["tests_pass"].status == "SUPPORTED"
