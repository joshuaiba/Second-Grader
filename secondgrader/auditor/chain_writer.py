"""P2.10: write the audit's results into the trace through P1's recorder.

Every verdict shown on the page has a record behind it. The records are
OBSERVED (they are what the auditor's code decided, not what the agent said)
and are appended with :func:`secondgrader.recorder.append`, so they are
hashed and signed like everything else.

Record shape (kind ``verdict``, agreed layout pending P1/P3 sign-off on the
board; ``stage`` tells the gate's own ``verdict`` record apart from ours)::

    {"stage": "audit", "claim_id": ..., "status": ..., "evidence_seqs": [...],
     "reason": ..., "claim": {id, text, kind, source_seq, quote, critical}}

One record per claim verdict and per tamper finding, then one summary
record ``{"stage": "audit_summary", "claims": n, "contradicted": n, ...}``.
"""

from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from secondgrader.auditor import AuditReport
from secondgrader.schema import Record


def audit_record_payloads(report: AuditReport) -> list[dict[str, Any]]:
    """The payloads, in order, without touching the trace. Pure; easy to test."""
    by_id = {c.id: c for c in report.claims}
    out: list[dict[str, Any]] = []
    for v in report.claim_verdicts:
        c = by_id.get(v.claim_id)
        out.append({
            "stage": "audit",
            "claim_id": v.claim_id,
            "status": v.status,
            "evidence_seqs": list(v.evidence_seqs),
            "reason": v.reason,
            "claim": asdict(c) if c is not None else None,
        })
    for v in report.tamper:
        out.append({
            "stage": "audit",
            "claim_id": v.claim_id,
            "status": v.status,
            "evidence_seqs": list(v.evidence_seqs),
            "reason": v.reason,
            "claim": None,
        })
    statuses = [v.status for v in report.claim_verdicts]
    out.append({
        "stage": "audit_summary",
        "claims": len(report.claim_verdicts),
        "supported": statuses.count("SUPPORTED"),
        "contradicted": statuses.count("CONTRADICTED"),
        "unsupported": statuses.count("UNSUPPORTED"),
        "tamper_findings": len(report.tamper),
        "probe_obligations": len(report.probes),
        "citing_seqs": report.citing_seqs,
    })
    return out


def append_audit_records(report: AuditReport, trace_path: str | Path | None = None) -> list[Record]:
    """Append one ``verdict`` record per audit result via the recorder. Returns the records."""
    from secondgrader import recorder  # P1's module; imported late so the auditor loads without it

    written: list[Record] = []
    for payload in audit_record_payloads(report):
        written.append(recorder.append(
            {"kind": "verdict", "origin": "OBSERVED", "payload": payload}, trace_path
        ))
    return written


__all__ = ["append_audit_records", "audit_record_payloads"]
