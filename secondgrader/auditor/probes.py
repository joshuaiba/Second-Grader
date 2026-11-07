"""P2.9: behavioural claims become probe obligations for P3's verifier.

Only the claim text and its source seq cross the line. P3 writes one test
per obligation in a fresh context; the agent's own tests and messages never
leak through here.
"""

from __future__ import annotations

from typing import Iterable

from secondgrader.auditor.types import ProbeObligation
from secondgrader.schema import Claim


def probe_obligations(claims: Iterable[Claim]) -> list[ProbeObligation]:
    """One obligation per ``behavior`` claim, de-duplicated on normalised text."""
    seen: set[str] = set()
    out: list[ProbeObligation] = []
    for c in claims:
        if c.kind != "behavior":
            continue
        key = " ".join(c.text.lower().split())
        if key in seen:
            continue
        seen.add(key)
        out.append(ProbeObligation(claim_id=c.id, text=c.text, source_seq=c.source_seq))
    return out


__all__ = ["probe_obligations"]
