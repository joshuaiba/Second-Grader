"""Blinded verifier (P3, Josh): Gemini writes its own tests from spec + diff + OBSERVED records.

The verifier must never see CLAIMED records or the agent's own tests. Pass it
``schema.observed(records)`` only. It writes tests into a fresh clone, runs
them, and appends ``verifier_test`` records to the trace via the recorder.

Submodules: ``client`` (cached, offline-capable Gemini client), ``safety``
(static check on generated tests), ``smoke`` (P3.1 end-to-end smoke test).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Callable

from secondgrader.schema import Record, VerifierResult

from . import blind
from .blind import BlindnessViolation

from .client import GeminiClient, MissingApiKey, OfflineCacheMiss, load_env
from .safety import check_test_source, is_safe


def verify(
    spec: str,
    diff: str,
    observed: list[Record],
    *,
    final_code_dir: str | Path | None = None,
    module_name: str = "parser",
    probes: list[str] | None = None,
    all_records: list[Record] | None = None,
    recorder_append: Callable[[dict[str, Any]], Any] | None = None,
    client: Any | None = None,
    timeout: int = 60,
    base_code_dir: str | Path | None = None,
) -> VerifierResult:
    """Generate and run independent tests (blind phase, then probe phase).

    Args:
        spec: The task spec text (from ``tasks/<task>.yaml``).
        diff: The agent's full diff against the base commit. Test-file hunks
            are stripped before the model sees it.
        observed: OBSERVED records only. A CLAIMED record raises ValueError
            before any model call.
        final_code_dir: The agent's final code (a throwaway clone). Tests run
            in a fresh copy with the agent's test files removed. Defaults to
            ``demo_repo/`` in this repo.
        module_name: The importable module under test.
        probes: Behavioural claims from the auditor (P2.9), as plain text.
            They go to a separate probe-phase call, never into the blind prompt.
        all_records: The full trace, if available, so the blindness check can
            look for leaked agent text.
        recorder_append: P1's ``recorder.append``; each test becomes a
            ``verifier_test`` OBSERVED record and its seq is returned.
        client: Anything with ``generate(prompt, system=)``. Defaults to a
            cached :class:`GeminiClient` (gemini-4-argon; honours SG_OFFLINE).
    """
    if client is None:
        client = GeminiClient()
    if final_code_dir is None:
        final_code_dir = Path(__file__).resolve().parents[2] / "demo_repo"
    return blind.verify(
        spec, diff, observed, client=client, final_code_dir=final_code_dir, module_name=module_name,
        probes=probes, all_records=all_records, recorder_append=recorder_append, timeout=timeout,
        base_code_dir=base_code_dir,
    )


__all__ = [
    "BlindnessViolation",
    "GeminiClient",
    "blind",
    "MissingApiKey",
    "OfflineCacheMiss",
    "check_test_source",
    "is_safe",
    "load_env",
    "verify",
]
