"""FastAPI app serving the single verdict page. Run: ``uvicorn secondgrader.web.app:app``.

Routes
------
- ``GET  /``            the verdict page for a trace (``?trace=<path>`` inside the repo,
                        ``?mode=LIVE|REPLAY``, ``?task=<id>``)
- ``GET  /api/tasks``   the task YAMLs in ``tasks/`` as ``[{"id", "title", "expected_gate"}]``
- ``POST /api/run``     start a run (not wired yet: HTTP 501)
- ``GET  /api/status``  stage progress for the inline poller
- ``POST /api/tamper``  tamper record N in memory and re-render the page

Hook points for the lead
------------------------
This module never imports ``secondgrader.gate`` or ``secondgrader.auditor``
at import time. The default provider is :func:`secondgrader.web.live.auto_verdict`; the sample story
produces the verdict. Plug in the real thing with::

    from secondgrader.web import app as web_app
    web_app.set_verdict_provider(lambda records: (decision, verdicts, verifier_result, claims))
    web_app.set_tamper_provider(lambda records, seq: tampered_copy)
    web_app.set_run_provider(lambda task_id, mode: {...})
    web_app.set_status_provider(lambda: {"stage": ..., "stages": [...]})
"""

from __future__ import annotations

import copy
import json
import os
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

STAGES: list[str] = ["record", "audit", "verify", "gate", "done"]

VerdictProvider = Callable[
    [list[Record]],
    tuple[GateDecision, list[ClaimVerdict], VerifierResult | None, list[Claim]],
]
TamperProvider = Callable[[list[Record], int], list[Record]]
RunProvider = Callable[[str, str], dict[str, Any]]
StatusProvider = Callable[[], dict[str, Any]]

app = FastAPI(title="Second Grader", docs_url=None, redoc_url=None)


# --------------------------------------------------------------------------- #
# Providers (swappable by the lead)
# --------------------------------------------------------------------------- #

def tamper_in_memory(records: list[Record], seq: int) -> list[Record]:
    """Return a deep copy of ``records`` with one byte of record ``seq``'s payload changed.

    The record's own ``hash`` is left as it was, so ``check_hash_chain`` flags
    ``seq`` as the first bad record and the strip turns red from there. The
    original list and the file on disk are untouched.
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
    "tamper": tamper_in_memory,
    "run": _run_not_wired,
    "status": _status_static,
}


def set_verdict_provider(fn: VerdictProvider) -> None:
    """``fn(records) -> (GateDecision, [ClaimVerdict], VerifierResult | None, [Claim])``."""
    providers["verdict"] = fn


def set_tamper_provider(fn: TamperProvider) -> None:
    """``fn(records, seq) -> tampered copy of records`` (never writes the trace on disk)."""
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


def _render(records: list[Record], *, trace_path: Path, mode: str, task_id: str, flash: str = "") -> str:
    decision, verdicts, verifier_result, claims = providers["verdict"](records)
    # Chain status always comes from code, never from the provider alone.
    chain_ok, first_bad = check_hash_chain(records)
    if decision.chain_ok != chain_ok or decision.first_bad_seq != first_bad:
        decision = copy.copy(decision)
        decision.chain_ok = chain_ok
        decision.first_bad_seq = first_bad
        if not chain_ok:
            decision.decision = "BLOCK"
            decision.reasons = [f"Hash chain broken at seq {first_bad}: the trace cannot be trusted."] + list(
                decision.reasons
            )
    tasks = list_tasks()
    task_title = ""
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
    result = dict(providers["run"](task_id, mode))
    status = int(result.pop("http_status", 200))
    return JSONResponse(result, status_code=status)


@app.get("/api/status")
def api_status() -> dict[str, Any]:
    return providers["status"]()


@app.post("/api/tamper", response_class=HTMLResponse)
async def api_tamper(request: Request) -> str:
    """Tamper record N in memory, re-check the chain and re-render. Never writes to disk."""
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
    tampered = providers["tamper"](records, seq)
    # Sanity: the provider must not have mutated the loaded list.
    assert [(r.seq, r.hash) for r in records] == original_hashes, "tamper provider mutated its input"
    chain_ok, first_bad = check_hash_chain(tampered)
    changed = next((r for r in tampered if r.seq == seq), None)
    flash = (
        f"Tampered with record {seq} in memory (payload changed, stored hash kept; recomputed hash now "
        f"{record_hash(changed)[:12] if changed else '?'}...). Chain check: "
        + ("still intact (unexpected)" if chain_ok else f"BROKEN from seq {first_bad}")
        + ". The trace file on disk was not modified."
    )
    return _render(
        tampered,
        trace_path=path,
        mode=_normalise_mode(data.get("mode")),
        task_id=data.get("task", ""),
        flash=flash,
    )


__all__ = [
    "app",
    "list_tasks",
    "providers",
    "resolve_trace",
    "set_run_provider",
    "set_status_provider",
    "set_tamper_provider",
    "set_verdict_provider",
    "tamper_in_memory",
]
