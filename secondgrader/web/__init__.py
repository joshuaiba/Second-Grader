"""Web (owner D): one verdict page. FastAPI + a single HTML template. No dashboard.

The page shows: the gate decision, each claim with its status and the cited
record(s), the verifier's tests, and the chain status. That is all.
"""

from __future__ import annotations

from secondgrader.schema import ClaimVerdict, GateDecision, VerifierResult


def render_verdict(
    decision: GateDecision,
    verdicts: list[ClaimVerdict],
    verifier_result: VerifierResult | None,
) -> str:
    """Return the verdict page as an HTML string."""
    raise NotImplementedError("web.render_verdict: owner D")


__all__ = ["render_verdict"]
