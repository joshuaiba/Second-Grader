"""Recorder (owner A): hook entry points, hash chain, Ed25519 signing, chain verification.

Hooks in ``scripts/hooks/`` call :func:`append` for every Muse Code event.
Everything here must be fast: a hook timeout lets the agent's action through.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from secondgrader.schema import Record


def append(record_fields: dict[str, Any], trace_path: str | Path | None = None) -> Record:
    """Append one record to the trace and return it, fully hashed and signed.

    Args:
        record_fields: ``kind``, ``origin``, ``payload`` and optionally ``ts``.
            ``seq``, ``prev_hash``, ``hash`` and ``sig`` are filled in here.
        trace_path: JSONL file to append to. Defaults to ``$SG_TRACE_PATH``.

    Returns:
        The :class:`~secondgrader.schema.Record` that was written.

    Raises:
        NotImplementedError: until owner A implements it.
    """
    raise NotImplementedError("recorder.append: owner A")


def verify_chain(path: str | Path) -> tuple[bool, int | None]:
    """Verify hashes, linkage **and signatures** of a trace file.

    Returns:
        ``(True, None)`` if intact, else ``(False, first_bad_seq)``.
        A bad signature counts as a broken chain at that seq.
    """
    raise NotImplementedError("recorder.verify_chain: owner A")


__all__ = ["append", "verify_chain"]
