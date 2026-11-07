"""Chain verification and the signed seal.

A trace is ``trace.jsonl`` plus a sidecar ``trace.jsonl.seal.json``. The seal
is signed by the recorder and holds:

- ``pubkey``: the recorder's Ed25519 public key (hex)
- ``run``: run metadata written at start (task id, base commit, ...)
- ``count`` and ``head_hash``: how many records the recorder wrote, and the last hash

The recorder rewrites the seal after every append. Because of that,
deleting records from the end (truncation) is detected: the file then has
fewer records than the seal says. Re-hashing an edited record does not help a
forger either: every hash is signed, and only the recorder holds the key.

Rules :func:`verify` applies, per record in file order:

1. the line parses and is a valid Record              (reason ``parse``)
2. ``seq`` is the next number                         (``seq``: removed or reordered lines)
3. ``prev_hash`` is the previous record's hash        (``link``)
4. ``hash`` matches the record's content              (``hash``: edited record)
5. ``sig`` verifies against the public key            (``signature``)

Then the seal: its own signature (``seal``), and its count and head hash
against the file (``truncated`` / ``seal``).

Traces whose every record is ``UNSIGNED`` and that have no seal (the
hand-written fixtures) are checked on rules 1-4 only and reported with
``signed=False``. A trace that mixes signed and UNSIGNED records fails.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from secondgrader.schema import GENESIS_HASH, UNSIGNED, Record, canonical_json, record_hash

from .keys import verify_hex

SEAL_VERSION = 1


def seal_path(trace_path: str | Path) -> Path:
    p = Path(trace_path)
    return p.with_name(p.name + ".seal.json")


def seal_body(seal: dict[str, Any]) -> str:
    """Canonical JSON of the seal without its signature: the bytes that get signed."""
    return canonical_json({k: v for k, v in seal.items() if k != "sig"})


def read_seal(trace_path: str | Path) -> dict[str, Any] | None:
    p = seal_path(trace_path)
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


@dataclass
class ChainReport:
    """Full result of verifying a trace.

    Attributes:
        ok: True if every check passed.
        first_bad_seq: First record that can't be trusted. For truncation this
            is one past the last record in the file (the first missing one).
        reason: ``parse``, ``seq``, ``link``, ``hash``, ``signature``, ``key``,
            ``seal`` or ``truncated``. ``None`` when ok.
        detail: One human-readable sentence.
        count: Records in the file.
        head_hash: Hash of the last record in the file (or the genesis hash).
        signed: True if records carry real signatures.
        sealed: True if a valid seal was found.
        pubkey: The public key the signatures were checked against.
        run: Run metadata from the seal (task id, base commit, ...).
        statuses: One entry per record in the file: ``ok``, ``bad`` or
            ``untrusted`` (everything after the first bad record).
    """

    ok: bool
    first_bad_seq: int | None = None
    reason: str | None = None
    detail: str = ""
    count: int = 0
    head_hash: str = GENESIS_HASH
    signed: bool = False
    sealed: bool = False
    pubkey: str | None = None
    run: dict[str, Any] = field(default_factory=dict)
    statuses: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def verify(trace_path: str | Path, pubkey: str | None = None) -> ChainReport:
    """Verify a trace file and its seal. See the module docstring for the rules.

    Args:
        trace_path: The JSONL trace.
        pubkey: Expected public key (hex). Defaults to ``$SG_PUBKEY``, then the
            key in the seal. Pin it when you can: an attacker who rewrote the
            whole trace and the seal with their own key is caught only by a
            pinned key.
    """
    path = Path(trace_path)
    lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
    n = len(lines)
    seal = read_seal(path)
    pinned = pubkey or os.environ.get("SG_PUBKEY") or None
    key = pinned or (seal or {}).get("pubkey")

    report = ChainReport(ok=True, count=n, pubkey=key, run=(seal or {}).get("run", {}))

    def fail(seq: int, reason: str, detail: str) -> ChainReport:
        report.ok = False
        report.first_bad_seq = seq
        report.reason = reason
        report.detail = detail
        report.statuses = ["ok" if s < seq else "bad" if s == seq else "untrusted"
                           for s in range(1, n + 1)]
        return report

    # The seal must be authentic before we trust its key, count or head hash.
    if seal is not None:
        if pinned and seal.get("pubkey") != pinned:
            return fail(1, "key", "seal was made with a different key than the pinned one")
        if not verify_hex(seal.get("pubkey", ""), seal_body(seal), seal.get("sig", "")):
            return fail(n + 1, "seal", "seal signature is invalid, so the end of the log can't be trusted")
        report.sealed = True

    expected_prev = GENESIS_HASH
    expected_seq = 1
    saw_signed = saw_unsigned = False
    for idx, line in enumerate(lines, start=1):
        try:
            rec = Record.from_dict(json.loads(line))
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            return fail(idx, "parse", f"line {idx} is not a valid record: {exc}")
        if rec.seq != expected_seq:
            return fail(expected_seq, "seq",
                        f"expected seq {expected_seq} but found {rec.seq}: a record was removed or moved")
        if rec.prev_hash != expected_prev:
            return fail(rec.seq, "link", f"seq {rec.seq} does not point at the previous record's hash")
        if record_hash(rec) != rec.hash:
            return fail(rec.seq, "hash", f"seq {rec.seq} content does not match its hash: it was edited")
        if rec.sig == UNSIGNED:
            saw_unsigned = True
            if saw_signed or seal is not None:
                return fail(rec.seq, "signature", f"seq {rec.seq} is unsigned inside a signed trace")
        else:
            saw_signed = True
            if saw_unsigned:
                return fail(rec.seq, "signature", f"seq {rec.seq} is signed inside an unsigned trace")
            if not key:
                return fail(rec.seq, "signature", f"seq {rec.seq} is signed but there is no seal or public key")
            if not verify_hex(key, rec.hash, rec.sig):
                return fail(rec.seq, "signature", f"seq {rec.seq} signature does not verify")
        expected_prev = rec.hash
        expected_seq += 1

    report.head_hash = expected_prev
    report.signed = saw_signed
    report.statuses = ["ok"] * n

    if seal is None:
        if saw_signed:
            return fail(n + 1, "truncated", "the seal is missing, so records may have been cut from the end")
        return report

    count = seal.get("count")
    if count is None or n < count:
        return fail(n + 1, "truncated", f"the seal says {count} records but the file has {n}")
    if n > count:
        return fail(count + 1, "seal", f"records after seq {count} were added without the recorder")
    if seal.get("head_hash") != expected_prev:
        return fail(max(n, 1), "seal", "the last record's hash does not match the seal")
    return report


def verify_chain(trace_path: str | Path, pubkey: str | None = None) -> tuple[bool, int | None]:
    """``(True, None)`` if intact, else ``(False, first_bad_seq)``."""
    r = verify(trace_path, pubkey)
    return r.ok, r.first_bad_seq
