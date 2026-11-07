"""Recorder (P1, Kevin): hook entry points, hash chain, Ed25519 signing, chain verification.

Public API (stable, others build against it):

- :func:`append` writes one record, numbered, tagged, chained and signed.
- :func:`verify_chain` returns ``(ok, first_bad_seq)``.
- :func:`verify_report` returns the full :class:`ChainReport` (reason, per-record statuses).
- :func:`start_run` writes the run-start seal (public key, task, base commit).

The trace path defaults to ``$SG_TRACE_PATH`` and the key to
``$SG_SIGNING_KEY_PATH`` (``keys/sg_ed25519.pem``). See ``chain.py`` for the
verification rules and ``writer.py`` for the single-writer guarantees.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from secondgrader.schema import Record

from .chain import ChainReport, read_seal, seal_path
from .chain import verify as verify_report
from .chain import verify_chain as _verify_chain
from .keys import key_path, load_or_create_key
from .writer import TraceWriter

_KEYS: dict[Path, Ed25519PrivateKey] = {}


def _trace_path(trace_path: str | Path | None) -> Path:
    p = trace_path or os.environ.get("SG_TRACE_PATH")
    if not p:
        raise ValueError("no trace path: pass trace_path or set SG_TRACE_PATH")
    return Path(p)


def _writer(trace_path: str | Path | None) -> TraceWriter:
    kp = key_path().resolve()
    if kp not in _KEYS:
        _KEYS[kp] = load_or_create_key(kp)
    return TraceWriter(_trace_path(trace_path), _KEYS[kp])


def append(record_fields: dict[str, Any], trace_path: str | Path | None = None) -> Record:
    """Append one record to the trace and return it, fully hashed and signed.

    Args:
        record_fields: ``kind`` and ``payload``. ``origin`` may be given but
            must match the kind (the recorder sets it). ``seq``, ``ts``,
            ``prev_hash``, ``hash`` and ``sig`` are always filled in here; a
            caller-supplied ``ts`` is ignored.
        trace_path: JSONL file to append to. Defaults to ``$SG_TRACE_PATH``.
    """
    return _writer(trace_path).append(record_fields["kind"], record_fields.get("payload", {}),
                                      origin=record_fields.get("origin"))


def start_run(run: dict[str, Any], trace_path: str | Path | None = None) -> None:
    """Write the signed run-start seal: ``run`` holds task id, base commit, mode, ..."""
    _writer(trace_path).start(run)


def verify_chain(path: str | Path, **kwargs: Any) -> tuple[bool, int | None]:
    """Verify hashes, linkage, **signatures** and the seal of a trace file.

    Returns:
        ``(True, None)`` if intact, else ``(False, first_bad_seq)``.
        A bad signature counts as a broken chain at that seq. Truncation
        reports the first missing seq. Traces that are entirely ``UNSIGNED``
        with no seal (hand-written fixtures) are checked on hashes only; use
        :func:`verify_report` and its ``signed`` flag to tell them apart.
        Pass ``require_signed=True`` (or set ``$SG_REQUIRE_SIGNED=1``) for real
        runs, and ``expect_run_id=...`` to stop a trace from another run being
        swapped in.
    """
    return _verify_chain(path, **kwargs)


__all__ = ["ChainReport", "TraceWriter", "append", "read_seal", "seal_path", "start_run",
           "verify_chain", "verify_report"]
