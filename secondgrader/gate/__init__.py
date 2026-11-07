"""Gate (owner C): combine verdicts into PASS/BLOCK and roll back on BLOCK.

Rules (initial):
    - any CONTRADICTED claim verdict            -> BLOCK, cite its evidence_seqs
    - any tampering verdict                     -> BLOCK
    - verifier_result.failed > 0                -> BLOCK, cite record_seqs
    - chain_ok is False                         -> BLOCK, cite first_bad_seq
    - otherwise                                 -> PASS
"""

from __future__ import annotations

from pathlib import Path

from secondgrader.schema import ClaimVerdict, GateDecision, VerifierResult


def decide(
    verdicts: list[ClaimVerdict],
    verifier_result: VerifierResult | None,
    chain_ok: bool,
    first_bad_seq: int | None,
) -> GateDecision:
    """Combine auditor verdicts, verifier result and chain status into one decision.

    ``verifier_result`` may be ``None`` when the verifier was skipped (e.g. in
    ``secondgrader audit``); the gate then decides on verdicts and chain alone.
    """
    raise NotImplementedError("gate.decide: owner C")


def rollback(repo_path: str | Path, branch: str) -> None:
    """Undo the agent's work in the throwaway clone.

    Resets ``branch`` to its base commit and discards the working tree changes.
    Must be safe to call twice.
    """
    raise NotImplementedError("gate.rollback: owner C")


__all__ = ["decide", "rollback"]
