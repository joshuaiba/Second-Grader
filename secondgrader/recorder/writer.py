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

    def start(self, run: dict[str, Any]) -> None:
        """Write the run-start seal (public key, task, base commit, ...) before any record."""
        with self._locked():
            if self.path.exists() and self.path.stat().st_size > 0:
                raise RuntimeError(f"{self.path}: run already started")
            self.path.touch()
            self._write_seal(0, GENESIS_HASH, dict(run))

    def append(self, kind: str, payload: dict[str, Any], ts: str | None = None,
               origin: str | None = None) -> Record:
        """Append one record and re-seal. ``origin``, if given, must match the kind."""
        if kind not in ORIGIN_FOR_KIND:
            raise ValueError(f"unknown record kind {kind!r}")
        tag = ORIGIN_FOR_KIND[kind]
        if origin is not None and origin != tag:
            raise ValueError(f"kind {kind!r} is always {tag}, not {origin}")
        if not isinstance(payload, dict):
            raise ValueError("payload must be a dict")
        with self._locked():
            seal = read_seal(self.path)
            last = _last_line(self.path)
            if last is None:
                seq, prev = 1, GENESIS_HASH
            else:
                prev_rec = json.loads(last)
                seq, prev = prev_rec["seq"] + 1, prev_rec["hash"]
            rec = Record(seq=seq, ts=ts or now_iso(), kind=kind, origin=tag,  # type: ignore[arg-type]
                         payload=payload, prev_hash=prev, hash="", sig="")
            rec.hash = record_hash(rec)
            rec.sig = sign_hex(self.key, rec.hash)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(rec.to_json() + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self._write_seal(seq, rec.hash, (seal or {}).get("run", {}))
            return rec
