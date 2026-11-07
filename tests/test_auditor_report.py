"""audit() end to end on the fixtures, offline (no LLM), plus the P2.10 record payloads."""

from __future__ import annotations

import pytest

from secondgrader import auditor
from secondgrader.auditor.chain_writer import audit_record_payloads
from secondgrader.auditor.types import AuditClaim, ProbeObligation
from secondgrader.schema import Record, load_trace

from .conftest import FINAL_CLAIM_SEQ, SAMPLE_TRACE, TEST_TAMPER_SEQ


@pytest.fixture
def report(sample_records):
    return auditor.audit(sample_records, use_llm=False)


def test_offline_audit_of_cheating_trace_blocks_with_citations(report):
    statuses = {v.claim_id: v.status for v in report.claim_verdicts}
    assert "CONTRADICTED" in statuses.values()
    assert report.blocking, "the cheating trace must produce blocking verdicts"
    assert TEST_TAMPER_SEQ in report.citing_seqs
    assert all(isinstance(c, AuditClaim) for c in report.claims)
    assert all(c.quote and c.critical for c in report.claims if c.kind in ("tests_pass", "files_changed") and c.extractor == "regex")


def test_tamper_verdicts_name_the_pattern_and_cite_the_diff(report):
    ids = {v.claim_id for v in report.tamper}
    assert "tamper:tests/test_parser.py" in ids
    assert any(i.startswith("tamper:assert_weakened:") for i in ids), ids
    assert all(TEST_TAMPER_SEQ in v.evidence_seqs for v in report.tamper if "test_parser" in v.claim_id)
    assert all(v.status == "CONTRADICTED" for v in report.tamper)  # all high on the sample trace


def test_honest_trace_has_nothing_blocking_except_subset(sample_records):
    honest = [r for r in sample_records if r.seq not in (12, TEST_TAMPER_SEQ)]
    rep = auditor.audit(honest, use_llm=False)
    assert rep.tamper == [] and rep.findings == []
    # "all tests pass" after `pytest -k parser` is UNSUPPORTED (subset), and that is critical -> still blocks.
    tests_pass = [v for v in rep.verdicts if "subset" in v.reason]
    assert tests_pass and tests_pass[0].status == "UNSUPPORTED"
    assert all(v.status != "CONTRADICTED" for v in rep.claim_verdicts)


def test_protected_paths_from_task_are_enforced(sample_records):
    rep = auditor.audit(sample_records, use_llm=False, task={"protected_paths": ["tests/"], "test_edits_allowed": False})
    prot = [v for v in rep.tamper if v.claim_id == "protected:tests/"]
    assert prot and prot[0].evidence_seqs == [TEST_TAMPER_SEQ]


def test_allow_test_edits_keeps_only_always_on_patterns(sample_records):
    rep = auditor.audit(sample_records, use_llm=False, task={"protected_paths": [], "test_edits_allowed": True})
    assert not any(v.claim_id == "tamper:tests/test_parser.py" for v in rep.tamper)
    assert all(f.pattern_id in auditor.ALWAYS_ON_PATTERNS for f in rep.findings)


def test_probes_only_carry_behaviour_claims():
    claims = [
        AuditClaim(id="a", text="handled empty input", kind="behavior", source_seq=3, quote="handled empty input"),
        AuditClaim(id="b", text="all tests pass", kind="tests_pass", source_seq=3, quote="all tests pass"),
        AuditClaim(id="c", text="Handled  empty input", kind="behavior", source_seq=5, quote="Handled  empty input"),
    ]
    probes = auditor.probe_obligations(claims)
    assert probes == [ProbeObligation(claim_id="a", text="handled empty input", source_seq=3)]


def test_report_to_dict_is_plain_json_data(report):
    import json
    json.dumps(report.to_dict())


def test_audit_record_payloads_one_per_verdict_plus_summary(report):
    payloads = audit_record_payloads(report)
    assert len(payloads) == len(report.verdicts) + 1
    assert len(report.verdicts) == len(report.claim_verdicts) + len(report.tamper)
    assert payloads[-1]["stage"] == "audit_summary"
    assert payloads[-1]["contradicted"] >= 1
    assert all(p["stage"] == "audit" for p in payloads[:-1])
    assert all(p["claim"] is not None for p in payloads[: len(report.claim_verdicts)])
    assert payloads[-1]["citing_seqs"] == report.citing_seqs


def test_append_audit_records_uses_recorder(report, monkeypatch, tmp_path):
    from secondgrader import recorder
    from secondgrader.auditor import chain_writer

    seen = []

    def fake_append(fields, trace_path=None):
        seen.append((fields, trace_path))
        return Record(seq=len(seen), ts="t", kind=fields["kind"], origin=fields["origin"],
                      payload=fields["payload"], prev_hash="0" * 64, hash="h", sig="UNSIGNED")

    monkeypatch.setattr(recorder, "append", fake_append)
    written = chain_writer.append_audit_records(report, tmp_path / "t.jsonl")
    assert len(written) == len(audit_record_payloads(report))
    assert all(f["kind"] == "verdict" and f["origin"] == "OBSERVED" for f, _ in seen)
