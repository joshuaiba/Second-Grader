"""The single writer: numbers, timestamps, tags, chains and signs records.

Every append takes an exclusive file lock, so concurrent writers (hooks,
the recorder service, the auditor and gate appending their results) can
never interleave or reuse a seq. The origin tag is set here from the record
kind, never by the caller: the agent can't label its own words as evidence.
"""

from __future__ import annotations

import fcntl
import json
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from secondgrader.schema import GENESIS_HASH, ORIGIN_FOR_KIND, Record, record_hash

from .chain import SEAL_VERSION, read_seal, seal_body, seal_path
from .keys import public_hex, sign_hex


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _last_line(path: Path) -> str | None:
    """Last non-empty line of a file, read from the end (cheap on long traces)."""
    if not path.exists() or path.stat().st_size == 0:
        return None
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        end = fh.tell()
        block, data = 4096, b""
        while end > 0:
            start = max(0, end - block)
            fh.seek(start)
            data = fh.read(end - start) + data
            end = start
            stripped = data.rstrip(b"\n")
            if b"\n" in stripped or end == 0:
                return stripped.rsplit(b"\n", 1)[-1].decode("utf-8") or None
    return None


class TraceWriter:
    """Appends signed records to one trace. Holds the private key in memory."""

    def __init__(self, trace_path: str | Path, key: Ed25519PrivateKey):
        self.path = Path(trace_path)
        self.key = key
        self.pubkey = public_hex(key)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock_path = self.path.with_name(self.path.name + ".lock")
        self._high_water = 0  # highest seq this writer has seen; the file may never go below it

    @contextmanager
    def _locked(self) -> Iterator[None]:
        with open(self._lock_path, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _write_seal(self, count: int, head_hash: str, run: dict[str, Any]) -> None:
        seal = {"version": SEAL_VERSION, "pubkey": self.pubkey, "run": run,
                "count": count, "head_hash": head_hash, "sealed_at": now_iso()}
        seal["sig"] = sign_hex(self.key, seal_body(seal))
        target = seal_path(self.path)
        tmp = target.with_name(target.name + ".tmp")
        tmp.write_text(json.dumps(seal, sort_keys=True, indent=1) + "\n", encoding="utf-8")
        os.replace(tmp, target)

    def _check(self) -> tuple[int, str, dict[str, Any]]:
        """Under the lock: ``(last seq, head hash, run meta)``, after checking file and seal agree.

        Refuses to write when the trace was cut, rolled back, replaced or
        written without the recorder. Appending would otherwise "repair" the
        damage, because the new seal would cover the shortened file.
        """
        seal = read_seal(self.path)
        if seal is not None and not isinstance(seal, dict):
            raise RuntimeError(f"{self.path}: seal is not a JSON object")
        last = _last_line(self.path)
        if last is None:
            seq, head = 0, GENESIS_HASH
        else:
            rec = json.loads(last)
            seq, head = rec["seq"], rec["hash"]
        if seal is None:
            if seq:
                raise RuntimeError(f"{self.path}: has records but no seal; refusing to append")
        else:
            if seal.get("pubkey") != self.pubkey:
                raise RuntimeError(f"{self.path}: sealed by a different key; refusing to append")
            if (seal.get("count"), seal.get("head_hash")) != (seq, head):
                raise RuntimeError(f"{self.path}: file has {seq} records but the seal says "
                                   f"{seal.get('count')}; refusing to append")
        if seq < self._high_water:
            raise RuntimeError(f"{self.path}: went back from seq {self._high_water} to {seq}; refusing to append")
        return seq, head, (seal or {}).get("run", {})

    def start(self, run: dict[str, Any]) -> None:
        """Write the run-start seal (public key, task, base commit, ...) before any record."""
        with self._locked():
            if self.path.exists() and self.path.stat().st_size > 0:
                raise RuntimeError(f"{self.path}: run already started")
            self.path.touch()
            self._write_seal(0, GENESIS_HASH, dict(run))

    def update_run(self, changes: dict[str, Any]) -> dict[str, Any]:
        """Merge ``changes`` into the signed run metadata (e.g. relabel a copy as REPLAY)."""
        with self._locked():
            seq, head, run = self._check()
            run = {**run, **changes}
            self._write_seal(seq, head, run)
            return run

    def append(self, kind: str, payload: dict[str, Any], origin: str | None = None) -> Record:
        """Append one record and re-seal. ``origin``, if given, must match the kind.

        The timestamp is always the recorder's clock; callers can't set it.
        """
        if kind not in ORIGIN_FOR_KIND:
            raise ValueError(f"unknown record kind {kind!r}")
        tag = ORIGIN_FOR_KIND[kind]
        if origin is not None and origin != tag:
            raise ValueError(f"kind {kind!r} is always {tag}, not {origin}")
        if not isinstance(payload, dict):
            raise ValueError("payload must be a dict")
        with self._locked():
            last_seq, prev, run = self._check()
            seq = last_seq + 1
            rec = Record(seq=seq, ts=now_iso(), kind=kind, origin=tag,  # type: ignore[arg-type]
                         payload=payload, prev_hash=prev, hash="", sig="")
            rec.hash = record_hash(rec)
            rec.sig = sign_hex(self.key, rec.hash)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(rec.to_json() + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._write_seal(seq, rec.hash, run)
            self._high_water = seq
            return rec
