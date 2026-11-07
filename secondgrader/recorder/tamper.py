"""Live tamper backend (P1.11): edit one field of record N, then re-verify.

Used by the "tamper with record N" button on the verdict page. The original
trace is never changed: the edit goes into a copy (with its seal), and the
copy is verified.

``rehash=True`` also recomputes the edited record's hash, to show that
re-hashing doesn't help a forger: the signature (over the old hash) and the
next record's link both still fail.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

from secondgrader.schema import canonical_json, record_hash

from .chain import ChainReport, seal_path, verify


def _set_path(obj: dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    for part in parts[:-1]:
        obj = obj[part]
    if parts[-1] not in obj:
        raise KeyError(f"no field {dotted!r} in record")
    obj[parts[-1]] = value


def tamper(trace_path: str | Path, seq: int, field: str, value: Any,
           out_path: str | Path | None = None, rehash: bool = False) -> tuple[Path, ChainReport]:
    """Copy the trace, set ``field`` (dotted, e.g. ``payload.exit_code``) of record ``seq``, verify.

    Returns:
        ``(path of the tampered copy, its ChainReport)``.
    """
    src = Path(trace_path)
    dst = Path(out_path) if out_path else src.with_name(f"{src.stem}.tampered-{seq}{src.suffix}")
    lines = [ln for ln in src.read_text(encoding="utf-8").splitlines() if ln.strip()]
    for i, line in enumerate(lines):
        rec = json.loads(line)
        if rec.get("seq") == seq:
            _set_path(rec, field, value)
            if rehash:
                rec["hash"] = record_hash(rec)
            lines[i] = canonical_json(rec)
            break
    else:
        raise KeyError(f"no record with seq {seq}")
    dst.write_text("\n".join(lines) + "\n", encoding="utf-8")
    if seal_path(src).exists():
        shutil.copyfile(seal_path(src), seal_path(dst))
    return dst, verify(dst)
