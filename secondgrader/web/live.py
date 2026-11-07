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

from secondgrader import auditor, gate
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
    """``(passed, seq)`` of our own full test run on the final tree, or ``(None, None)``.

    Only a ``test_run`` with ``ground_truth: true`` whose ``phase`` is
    ``full_final`` (or absent, for older traces) counts. The recorder's
    ``collect_base`` / ``collect_final`` runs are collection only and are ignored.
    """
    for r in reversed(observed(records)):
        p = r.payload or {}
        if r.kind != "test_run" or not p.get("ground_truth"):
            continue
        if p.get("phase", "full_final") != "full_final":
            continue
        return p.get("exit_code") == 0, r.seq
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
    """The real pipeline when the auditor exists, otherwise the sample story through the real gate."""
    try:
        return real_verdict(records)
    except NotImplementedError:
        pass
    _, verdicts, sample_vr, claims = sample_verdict(records)
    chain_ok, first_bad = check_hash_chain(records)
    vr = verifier_result_from_records(records) or sample_vr
    decision = gate.decide(verdicts, vr, chain_ok, first_bad, claims=claims)
    return decision, verdicts, vr, claims


__all__ = ["auto_verdict", "ground_truth_from_records", "real_verdict", "verifier_result_from_records"]
