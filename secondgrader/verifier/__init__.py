"""Blinded verifier (owner C): Gemini writes its own tests from spec + diff + OBSERVED records.

The verifier must never see CLAIMED records or the agent's own tests. Pass it
``schema.observed(records)`` only. It writes tests into a fresh clone, runs
them, and appends ``verifier_test`` records to the trace via the recorder.
"""

from __future__ import annotations

from secondgrader.schema import Record, VerifierResult


def verify(spec: str, diff: str, observed: list[Record]) -> VerifierResult:
    """Generate and run independent tests.

    Args:
        spec: The task spec text (from ``tasks/<task>.yaml``).
        diff: The agent's full diff against the base commit.
        observed: OBSERVED records only. Passing a CLAIMED record is a bug.

    Uses gemini-4-argon (see AGENTS.md).
    """
    raise NotImplementedError("verifier.verify: owner C")


__all__ = ["verify"]
