"""Auditor-internal types that extend the shared contract without changing it.

``schema.py`` is frozen. SPEC §5 asks the auditor to hand P3 a few extra
fields (verbatim quote, critical flag, tamper findings, probe obligations).
They live here as dataclasses that *extend* or sit beside the schema types,
so every value we return is still a valid ``Claim`` / ``ClaimVerdict``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from secondgrader.schema import Claim

Severity = Literal["high", "medium", "low"]


@dataclass
class AuditClaim(Claim):
    """A :class:`~secondgrader.schema.Claim` plus the fields SPEC §5 wants.

    Attributes:
        quote: Verbatim substring of the source record's text. Code verifies
            it is really there; a claim whose quote cannot be found is dropped.
        critical: True for claims that gate the merge on their own
            ("all tests pass", "only changed X", "didn't touch tests").
        extractor: ``"regex"`` or ``"llm"``; which pass produced the claim.
        files: For ``files_changed`` claims, the paths the agent named.
    """

    quote: str = ""
    critical: bool = False
    extractor: str = "regex"
    files: list[str] = field(default_factory=list)


@dataclass
class TamperFinding:
    """SPEC §5 "Tamper finding" contract.

    Attributes:
        pattern_id: Stable id, e.g. ``"assert_weakened"``.
        severity: ``high`` / ``medium`` / ``low``.
        path: File the finding is about.
        line: 1-based line in the *final* file (or the diff hunk's new-line),
            ``None`` when the file was deleted.
        summary: One sentence, shown on the verdict page.
        snippet: Short diff excerpt that proves it.
        evidence_seqs: ``seq`` of the OBSERVED diff record(s) when the finding
            came from a trace; empty when it came from a base/final tree.
    """

    pattern_id: str
    severity: Severity
    path: str
    line: int | None
    summary: str
    snippet: str = ""
    evidence_seqs: list[int] = field(default_factory=list)


@dataclass
class ProbeObligation:
    """SPEC §5 "Probe obligation": a behavioural claim P3 must write a test for.

    Only the claim text and its source record cross to P3. Never the
    agent's tests, never the agent's reasoning.
    """

    claim_id: str
    text: str
    source_seq: int


__all__ = ["AuditClaim", "ProbeObligation", "Severity", "TamperFinding"]
