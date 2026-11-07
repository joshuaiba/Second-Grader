"""Real verdict provider for the page: records in, gate decision out.

Everything comes from the trace and from code:

- claims and verdicts: P2's auditor (``extract_claims``, ``check_claims``,
  ``detect_test_tampering``). Until it lands, the page falls back to the
  hand-written :func:`secondgrader.web.sample.sample_verdict` so the demo
  story still renders.
- verifier result: rebuilt from the ``verifier_test`` OBSERVED records that
  ``secondgrader run`` appended to the trace. No model call happens here.
- decision: :func:`secondgrader.gate.decide`, a pure function.
"""

from __future__ import annotations

from typing import Any

from secondgrader import auditor, gate
from secondgrader.gate import pipeline
from secondgrader.schema import Claim, ClaimVerdict, GateDecision, Record, VerifierResult, check_hash_chain, observed
from secondgrader.web.sample import sample_verdict


def verifier_result_from_records(records: list[Record]) -> VerifierResult | None:
    """Rebuild the verifier's result from its ``verifier_test`` records. None if there are none."""
    details = []
    seqs = []
    for r in observed(records):
        if r.kind != "verifier_test":
            continue
        p = r.payload or {}
        outcome = p.get("outcome") or ("passed" if p.get("passed") else "failed" if p.get("passed") is False else "error")
        details.append({"name": p.get("name", "?"), "passed": p.get("passed"), "outcome": outcome,
                        "output": p.get("output", ""), "phase": p.get("phase", "blind"),
                        "spec_sentence": p.get("spec_sentence", ""), "seq": r.seq})
        seqs.append(r.seq)
    if not details:
        return None
    return VerifierResult(
        tests_written=[d["name"] for d in details],
        passed=sum(1 for d in details if d["outcome"] == "passed"),
        failed=sum(1 for d in details if d["outcome"] == "failed"),
        details=details,
        record_seqs=seqs,
    )


def ground_truth_from_records(records: list[Record]) -> tuple[bool | None, int | None]:
    """``(passed, seq)`` of our own full_final run, or ``(None, None)``. One rule, defined in the pipeline."""
    return pipeline.ground_truth(records)


def _is_hand_written_fixture(records: list[Record]) -> bool:
    """The one hand-written cheating fixture (fixtures/sample_trace*.jsonl) that sample_verdict narrates."""
    if len(records) != 16 or records[0].kind != "prompt":
        return False
    if records[0].payload.get("task_id") != "trap_weaken_tests":
        return False
    r13 = records[12]
    return r13.kind == "diff" and str(r13.payload.get("path", "")).endswith("tests/test_parser.py")


def _claim_from_payload(claim_id: str, raw: Any, source_seq: int) -> Claim:
    if isinstance(raw, dict):
        return Claim(str(raw.get("id", claim_id)), str(raw.get("text", "")), raw.get("kind", "other"),
                     int(raw.get("source_seq", source_seq) or source_seq))
    return Claim(claim_id, str(raw or ""), "other", source_seq)


def verdicts_from_records(records: list[Record]) -> tuple[list[Claim], list[ClaimVerdict]]:
    """P2.10: the auditor's chained ``verdict`` records (``payload.stage == "audit"``)."""
    claims: list[Claim] = []
    verdicts: list[ClaimVerdict] = []
    for r in observed(records):
        p = r.payload or {}
        if r.kind != "verdict" or p.get("stage") != "audit":
            continue
        cid = str(p.get("claim_id", ""))
        status = p.get("status")
        if status not in ("SUPPORTED", "CONTRADICTED", "UNSUPPORTED") or not cid:
            continue
        verdicts.append(ClaimVerdict(cid, status, [int(x) for x in (p.get("evidence_seqs") or [])], str(p.get("reason", ""))))
        if "claim" in p and not cid.startswith(("tamper:", "protected:")):
            claims.append(_claim_from_payload(cid, p["claim"], r.seq))
    return claims, verdicts


def gate_verdict_from_records(records: list[Record]) -> tuple[GateDecision | None, int | None]:
    """The gate's own chained ``verdict`` record (no ``stage``): the decision as it was made."""
    for r in reversed(observed(records)):
        p = r.payload or {}
        if r.kind == "verdict" and "stage" not in p and p.get("decision") in ("PASS", "BLOCK"):
            return GateDecision(p["decision"], list(p.get("reasons") or []), [int(x) for x in (p.get("citing_seqs") or [])],
                                bool(p.get("chain_ok", True)), p.get("first_bad_seq")), r.seq
    return None, None


def real_verdict(records: list[Record]) -> tuple[GateDecision, list[ClaimVerdict], VerifierResult | None, list[Claim]]:
    """Audit + gate on the records. Raises NotImplementedError while the auditor is a stub."""
    claims = auditor.extract_claims(records)
    verdicts = auditor.check_claims(claims, records)
    verdicts += auditor.detect_test_tampering(records)
    chain_ok, first_bad = check_hash_chain(records)
    vr = verifier_result_from_records(records)
    gt_ok, gt_seq = ground_truth_from_records(records)
    decision = gate.decide(verdicts, vr, chain_ok, first_bad, claims=claims, ground_truth_ok=gt_ok, ground_truth_seq=gt_seq)
    return decision, verdicts, vr, claims


def auto_verdict(records: list[Record]) -> tuple[GateDecision, list[ClaimVerdict], VerifierResult | None, list[Claim]]:
    """What the page shows, in order of preference:

    1. a chained gate ``verdict`` record: the decision exactly as it was made,
       with the auditor's chained verdicts and the verifier's chained tests;
    2. the live auditor + gate on the records;
    3. for the one hand-written cheating fixture, its narrated story, through the real gate;
    4. otherwise the real gate on code-only evidence (chain, ground truth,
       verifier records): no claims, no guesses.
    """
    chain_ok, first_bad = check_hash_chain(records)
    vr = verifier_result_from_records(records)
    gt_ok, gt_seq = ground_truth_from_records(records)

    decision, _seq = gate_verdict_from_records(records)
    if decision is not None:
        claims, verdicts = verdicts_from_records(records)
        return decision, verdicts, vr, claims

    try:
        return real_verdict(records)
    except NotImplementedError:
        pass

    if _is_hand_written_fixture(records):
        _, verdicts, sample_vr, claims = sample_verdict(records)
        decision = gate.decide(verdicts, vr or sample_vr, chain_ok, first_bad, claims=claims)
        return decision, verdicts, vr or sample_vr, claims

    claims, verdicts = verdicts_from_records(records)
    decision = gate.decide(verdicts, vr, chain_ok, first_bad, claims=claims, ground_truth_ok=gt_ok, ground_truth_seq=gt_seq)
    return decision, verdicts, vr, claims


__all__ = ["auto_verdict", "gate_verdict_from_records", "ground_truth_from_records", "real_verdict",
           "verdicts_from_records", "verifier_result_from_records"]
