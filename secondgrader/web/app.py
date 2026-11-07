"""FastAPI app serving the single verdict page. Run: ``uvicorn secondgrader.web.app:app``.

Routes
------
- ``GET  /``            the verdict page for a trace (``?trace=<path>`` inside the repo,
                        ``?mode=LIVE|REPLAY``, ``?task=<id>``)
- ``GET  /api/tasks``   the task YAMLs in ``tasks/`` as ``[{"id", "title", "expected_gate"}]``
- ``POST /api/run``     start a run (not wired yet: HTTP 501)
- ``GET  /api/status``  stage progress for the inline poller
- ``POST /api/tamper``  tamper record N in a throwaway copy of the trace and re-render the page

Chain status
------------
When the trace path is known the page asks the recorder for the full
:class:`secondgrader.recorder.ChainReport` (hashes, links, signatures, seal)
and renders it; if the recorder is unavailable it falls back to
``schema.check_hash_chain`` (hashes only). The report is passed to
:func:`secondgrader.web.render_verdict` as a plain dict (``chain=``).

Hook points for the lead
------------------------
The default verdict provider is :func:`secondgrader.web.live.auto_verdict`:
the auditor plus the real gate, with the sample story as a fallback while
the auditor is a stub. The default tamper provider is :func:`tamper_default`:
P1's ``recorder.tamper`` on a temp copy, falling back to the in-memory tamper.
Plug in your own with::

    from secondgrader.web import app as web_app
    web_app.set_verdict_provider(lambda records: (decision, verdicts, verifier_result, claims))
    web_app.set_tamper_provider(lambda records, seq, *, trace_path: tampered_copy)  # or (copy, ChainReport)
    web_app.set_run_provider(lambda task_id, mode: {...})
    web_app.set_status_provider(lambda: {"stage": ..., "stages": [...]})
"""

from __future__ import annotations

import copy
import inspect
import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs

import yaml
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse

from secondgrader import web
from secondgrader.schema import (
    Claim,
    ClaimVerdict,
    GateDecision,
    Record,
    VerifierResult,
    check_hash_chain,
    load_trace,
    record_hash,
)
from secondgrader.web.live import auto_verdict

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "fixtures"
TASKS_DIR = REPO_ROOT / "tasks"
DEFAULT_TRACE = "fixtures/sample_trace.jsonl"

from secondgrader.gate.pipeline import STAGES as _PIPELINE_STAGES

STAGES: list[str] = list(_PIPELINE_STAGES)  # one definition, in the pipeline

VerdictProvider = Callable[
    [list[Record]],
    tuple[GateDecision, list[ClaimVerdict], VerifierResult | None, list[Claim]],
]
# ``fn(records, seq, *, trace_path) -> tampered records`` or ``(tampered records, ChainReport | dict)``.
TamperProvider = Callable[..., "list[Record] | tuple[list[Record], Any]"]
RunProvider = Callable[[str, str], dict[str, Any]]
StatusProvider = Callable[[], dict[str, Any]]

CHAIN_KEYS: tuple[str, ...] = (
    "ok", "first_bad_seq", "reason", "detail", "count", "head_hash",
    "signed", "sealed", "pubkey", "run", "statuses",
)

app = FastAPI(title="Second Grader", docs_url=None, redoc_url=None)


# --------------------------------------------------------------------------- #
# Chain report (code decides; the recorder is the authority when present)
# --------------------------------------------------------------------------- #

def chain_dict(report: Any) -> dict[str, Any]:
    """Flatten a recorder ``ChainReport`` (or a dict) into the plain dict the page renders."""
    if isinstance(report, dict):
        src = report
    elif hasattr(report, "to_dict"):
        src = report.to_dict()
    else:
        src = {k: getattr(report, k, None) for k in CHAIN_KEYS}
    out: dict[str, Any] = {k: src.get(k) for k in CHAIN_KEYS}
    out["ok"] = bool(out["ok"])
    out["run"] = dict(out["run"]) if isinstance(out.get("run"), dict) else {}
    out["statuses"] = list(out["statuses"]) if out.get("statuses") else None
    return out


def chain_from_records(records: list[Record]) -> dict[str, Any]:
    """Hashes-only chain status (``schema.check_hash_chain``) in the same dict shape."""
    ok, first_bad = check_hash_chain(records)
    return chain_dict(
        {
            "ok": ok,
            "first_bad_seq": first_bad,
            "reason": None if ok else "hash",
            "detail": "" if ok else f"seq {first_bad} content does not match its hash or prev_hash",
            "count": len(records),
            "head_hash": records[-1].hash if records else None,
            "signed": any(r.sig != "UNSIGNED" for r in records),
            "sealed": False,
            "pubkey": None,
            "run": {},
            "statuses": None,
        }
    )


def chain_report(trace_path: Path, records: list[Record]) -> dict[str, Any]:
    """The recorder's full report for ``trace_path``; hashes-only fallback if the recorder can't run."""
    try:
        from secondgrader import recorder

        report = recorder.verify_report(trace_path)
    except Exception:  # noqa: BLE001 - missing recorder, old API, unreadable file: fall back
        return chain_from_records(records)
    return chain_dict(report)


# --------------------------------------------------------------------------- #
# Providers (swappable by the lead)
# --------------------------------------------------------------------------- #

def _tamper_field(rec: Record) -> tuple[str, Any]:
    """Pick an existing payload field of ``rec`` to change and the value to set it to."""
    for key, value in (rec.payload or {}).items():
        if isinstance(value, str):
            return key, value + "!"
    for key, value in (rec.payload or {}).items():
        if isinstance(value, bool):
            return key, not value
        if isinstance(value, int):
            return key, value + 1
    raise KeyError(f"record {rec.seq} has no payload field that can be tampered")


def tamper_in_memory(records: list[Record], seq: int, *, trace_path: Path | None = None) -> list[Record]:
    """Return a deep copy of ``records`` with one byte of record ``seq``'s payload changed.

    The record's own ``hash`` is left as it was, so ``check_hash_chain`` flags
    ``seq`` as the first bad record and the strip turns red from there. The
    original list and the file on disk are untouched. ``trace_path`` is unused.
    """
    copied = copy.deepcopy(records)
    for rec in copied:
        if rec.seq == seq:
            payload = rec.payload
            for key, value in payload.items():
                if isinstance(value, str):
                    payload[key] = value + "!"
                    break
            else:
                payload["_tampered"] = True
            return copied
    raise KeyError(f"no record with seq {seq}")


def tamper_via_recorder(records: list[Record], seq: int, *, trace_path: Path) -> tuple[list[Record], Any]:
    """Tamper record ``seq`` with P1's ``recorder.tamper`` on a copy in a temp dir, re-verify, clean up.

    Returns ``(records of the tampered copy, ChainReport of that copy)``. The
    copy (and its seal, if any) lives in a fresh temp directory that is
    removed before returning, so nothing lands next to the real trace.
    """
    from secondgrader.recorder import tamper as recorder_tamper

    target = next((r for r in records if r.seq == seq), None)
    if target is None:
        raise KeyError(f"no record with seq {seq}")
    field, value = _tamper_field(target)
    tmpdir = Path(tempfile.mkdtemp(prefix="sg-tamper-"))
    try:
        out_path = tmpdir / Path(trace_path).name
        copy_path, report = recorder_tamper.tamper(trace_path, seq, f"payload.{field}", value, out_path=out_path)
        tampered = load_trace(copy_path)
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return tampered, report


def tamper_default(records: list[Record], seq: int, *, trace_path: Path) -> list[Record] | tuple[list[Record], Any]:
    """Default provider: the recorder's tamper backend, or the in-memory tamper if that raises."""
    try:
        return tamper_via_recorder(records, seq, trace_path=trace_path)
    except Exception:  # noqa: BLE001 - recorder missing or refused: the demo still works in memory
        return tamper_in_memory(records, seq)


def _call_tamper(fn: Callable[..., Any], records: list[Record], seq: int, trace_path: Path) -> Any:
    """Call a tamper provider; legacy ``fn(records, seq)`` providers still work."""
    try:
        params = inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return fn(records, seq, trace_path=trace_path)
    accepts = "trace_path" in params or any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values())
    return fn(records, seq, trace_path=trace_path) if accepts else fn(records, seq)


def _run_not_wired(task_id: str, mode: str) -> dict[str, Any]:
    return {
        "status": "not wired",
        "message": f"pipeline for task {task_id!r} ({mode}) is not connected yet",
        "task": task_id,
        "mode": mode,
        "http_status": 501,
    }


def _status_static() -> dict[str, Any]:
    return {"stage": "done", "stages": list(STAGES)}


providers: dict[str, Callable[..., Any]] = {
    "verdict": auto_verdict,
    "tamper": tamper_default,
    "run": None,     # filled below from web.runs (kept lazy so a broken runner never breaks import)
    "status": None,
}


def set_verdict_provider(fn: VerdictProvider) -> None:
    """``fn(records) -> (GateDecision, [ClaimVerdict], VerifierResult | None, [Claim])``."""
    providers["verdict"] = fn


def set_tamper_provider(fn: TamperProvider) -> None:
    """``fn(records, seq, *, trace_path) -> tampered records | (tampered records, ChainReport | dict)``.

    Must never modify the trace on disk or the ``records`` list it was given.
    Without a report the page falls back to a hashes-only chain check of the
    returned records. A legacy ``fn(records, seq)`` is still accepted.
    """
    providers["tamper"] = fn


def set_run_provider(fn: RunProvider) -> None:
    """``fn(task_id, mode) -> dict``; include ``"http_status"`` to override 200, ``"redirect"`` to send the browser on."""
    providers["run"] = fn


def set_status_provider(fn: StatusProvider) -> None:
    """``fn() -> {"stage": str, "stages": [str, ...]}``."""
    providers["status"] = fn


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def default_trace_path() -> Path:
    env = os.environ.get("SG_TRACE_PATH")
    return Path(env) if env else REPO_ROOT / DEFAULT_TRACE


def resolve_trace(trace: str | None) -> Path:
    """Resolve ``?trace=`` to a file inside the repo root; reject anything else (400)."""
    if not trace:
        path = default_trace_path()
        if not path.is_file():
            raise HTTPException(404, f"trace not found: {path}")
        return path
    if "\x00" in trace:
        raise HTTPException(400, "invalid trace path")
    candidate = Path(trace)
    if not candidate.is_absolute():
        candidate = REPO_ROOT / candidate
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise HTTPException(400, f"invalid trace path: {exc}") from exc
    root = REPO_ROOT.resolve()
    if not resolved.is_relative_to(root):
        raise HTTPException(400, "trace path must be inside the repository")
    if resolved.suffix != ".jsonl":
        raise HTTPException(400, "trace must be a .jsonl file")
    if not resolved.is_file():
        raise HTTPException(404, f"trace not found: {trace}")
    return resolved


def _display_name(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT.resolve()))
    except ValueError:
        return path.name


def _load(path: Path) -> list[Record]:
    try:
        return load_trace(path)
    except ValueError as exc:
        raise HTTPException(422, f"bad trace: {exc}") from exc


def _scalar_fields(text: str, keys: tuple[str, ...]) -> dict[str, str]:
    """Best-effort ``key: value`` extraction for top-level scalars of a broken YAML file."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line[0] in " \t#":
            continue
        key, sep, value = line.partition(":")
        if sep and key.strip() in keys:
            out[key.strip()] = value.strip().strip("'\"")
    return out


def list_tasks() -> list[dict[str, Any]]:
    """``[{"id", "title", "expected_gate"}]`` for every YAML in ``tasks/``, sorted by id."""
    tasks: list[dict[str, Any]] = []
    if not TASKS_DIR.is_dir():
        return tasks
    for path in sorted(TASKS_DIR.glob("*.y*ml")):
        text = path.read_text(encoding="utf-8")
        try:
            data = yaml.safe_load(text) or {}
        except yaml.YAMLError:
            # Tolerate a malformed file (e.g. an unquoted "a: b" inside a title):
            # pull the three top-level scalars we need line by line.
            data = _scalar_fields(text, ("id", "title", "expected_gate"))
        if not isinstance(data, dict):
            continue
        tasks.append(
            {
                "id": str(data.get("id") or path.stem),
                "title": str(data.get("title") or ""),
                "expected_gate": str(data.get("expected_gate") or ""),
            }
        )
    tasks.sort(key=lambda t: t["id"])
    return tasks


def _normalise_mode(mode: str | None) -> str:
    mode = (mode or "REPLAY").upper()
    return mode if mode in web.MODES else "REPLAY"


def _render(
    records: list[Record],
    *,
    trace_path: Path,
    mode: str,
    task_id: str,
    flash: str = "",
    chain: dict[str, Any] | None = None,
) -> str:
    decision, verdicts, verifier_result, claims = providers["verdict"](records)
    # Chain status always comes from code, never from the provider alone: the
    # recorder's full report when we have it, hashes-only otherwise.
    if chain is None:
        chain = chain_report(trace_path, records)
    chain_ok, first_bad = chain["ok"], chain["first_bad_seq"]
    if decision.chain_ok != chain_ok or decision.first_bad_seq != first_bad:
        decision = copy.copy(decision)
        decision.chain_ok = chain_ok
        decision.first_bad_seq = first_bad
        if not chain_ok:
            why = f": {chain['detail']}" if chain.get("detail") else ": the trace cannot be trusted."
            decision.decision = "BLOCK"
            decision.reasons = [f"Hash chain broken at seq {first_bad}{why}"] + list(decision.reasons)
            if first_bad is not None and first_bad not in decision.citing_seqs:
                decision.citing_seqs = [first_bad] + list(decision.citing_seqs)  # every BLOCK cites its record
    run = chain.get("run") or {}
    # Never present a replay as live. LIVE needs both the request and the signed seal to say so
    # (the run that just finished redirects here with mode=LIVE); a REPLAY seal always wins; a
    # recorded file opened later is a REPLAY whatever its seal says.
    seal_mode = str(run.get("mode") or "").upper()
    mode = "LIVE" if (mode == "LIVE" and seal_mode == "LIVE") else "REPLAY"
    tasks = list_tasks()
    task_title = ""
    if not task_id and run.get("task_id"):
        task_id = str(run["task_id"])
    if not task_id and records and records[0].kind == "prompt":
        task_id = str(records[0].payload.get("task_id", ""))
    for t in tasks:
        if t["id"] == task_id:
            task_title = t["title"]
    return web.render_verdict(
        decision,
        verdicts,
        verifier_result,
        records,
        task_title=task_title,
        mode=mode,
        claims=claims,
        tasks=tasks,
        selected_task=task_id,
        trace_name=_display_name(trace_path),
        flash=flash,
        chain=chain,
    )


async def _form_or_json(request: Request) -> dict[str, str]:
    """Read a urlencoded form or a JSON body without needing python-multipart."""
    body = await request.body()
    ctype = request.headers.get("content-type", "")
    if "json" in ctype:
        try:
            data = json.loads(body or b"{}")
        except json.JSONDecodeError as exc:
            raise HTTPException(400, f"bad JSON: {exc}") from exc
        if not isinstance(data, dict):
            raise HTTPException(400, "JSON body must be an object")
        return {str(k): str(v) for k, v in data.items()}
    parsed = parse_qs(body.decode("utf-8", errors="replace"), keep_blank_values=True)
    return {k: v[-1] for k, v in parsed.items()}


# --------------------------------------------------------------------------- #
# Routes
# --------------------------------------------------------------------------- #

@app.get("/", response_class=HTMLResponse)
def verdict_page(trace: str | None = None, mode: str | None = None, task: str = "") -> str:
    """The one page: verdict for ``trace`` (default ``SG_TRACE_PATH`` or the sample fixture)."""
    path = resolve_trace(trace)
    records = _load(path)
    return _render(records, trace_path=path, mode=_normalise_mode(mode), task_id=task)


@app.get("/api/tasks")
def api_tasks() -> list[dict[str, Any]]:
    return list_tasks()


@app.post("/api/run")
async def api_run(request: Request) -> JSONResponse:
    data = await _form_or_json(request)
    task_id = data.get("task", "")
    mode = _normalise_mode(data.get("mode"))
    fn = providers["run"]
    trace = data.get("trace") or None
    if trace:
        try:
            result = dict(fn(task_id, mode, trace=trace))
        except TypeError as exc:
            if "trace" not in str(exc):
                raise  # a real TypeError inside the provider, not a legacy signature
            result = dict(fn(task_id, mode))  # a provider that only takes (task_id, mode)
    else:
        result = dict(fn(task_id, mode))
    status = int(result.pop("http_status", 200))
    return JSONResponse(result, status_code=status)


@app.get("/api/status")
def api_status() -> dict[str, Any]:
    return providers["status"]()


def _install_default_run_providers() -> None:
    try:
        from secondgrader.web.runs import manager
    except Exception:  # pragma: no cover - only if the pipeline cannot import
        providers["run"] = _run_not_wired
        providers["status"] = _status_static
        return
    providers["run"] = manager.start
    providers["status"] = manager.status


_install_default_run_providers()


@app.post("/api/tamper", response_class=HTMLResponse)
async def api_tamper(request: Request) -> str:
    """Tamper record N in a throwaway copy, re-verify the chain and re-render. Never touches the trace."""
    data = await _form_or_json(request)
    try:
        seq = int(data.get("seq", ""))
    except ValueError:
        raise HTTPException(400, "seq must be an integer")
    path = resolve_trace(data.get("trace") or None)
    records = _load(path)
    if not any(r.seq == seq for r in records):
        raise HTTPException(400, f"no record with seq {seq} (trace has {len(records)} records)")
    original_hashes = [(r.seq, r.hash) for r in records]
    result = _call_tamper(providers["tamper"], records, seq, path)
    # Sanity: the provider must not have mutated the loaded list.
    assert [(r.seq, r.hash) for r in records] == original_hashes, "tamper provider mutated its input"
    if isinstance(result, tuple):
        tampered, report = result
        chain = chain_dict(report) if report is not None else chain_from_records(tampered)
    else:
        tampered = result
        chain = chain_from_records(tampered)
    chain_ok, first_bad = chain["ok"], chain["first_bad_seq"]
    changed = next((r for r in tampered if r.seq == seq), None)
    flash = (
        f"Tampered with record {seq} in a throwaway copy (payload changed, stored hash kept; recomputed hash now "
        f"{record_hash(changed)[:12] if changed else '?'}...). Chain check: "
        + ("still intact (unexpected)" if chain_ok else f"BROKEN from seq {first_bad}")
        + (f" ({chain['reason']}: {chain['detail']})" if not chain_ok and chain.get("detail") else "")
        + ". The trace file on disk was not modified."
    )
    return _render(
        tampered,
        trace_path=path,
        mode=_normalise_mode(data.get("mode")),
        task_id=data.get("task", ""),
        flash=flash,
        chain=chain,
    )


__all__ = [
    "CHAIN_KEYS",
    "app",
    "chain_dict",
    "chain_from_records",
    "chain_report",
    "list_tasks",
    "providers",
    "resolve_trace",
    "set_run_provider",
    "set_status_provider",
    "set_tamper_provider",
    "set_verdict_provider",
    "tamper_default",
    "tamper_in_memory",
    "tamper_via_recorder",
]
