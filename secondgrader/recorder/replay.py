"""Replays (P1.10): save a run, re-run it later, always labelled REPLAY.

A saved replay is the agent stage of a real run: the signed trace snapshot
(``agent_trace.jsonl`` + seal), the clone (as ``work.bundle``), and the base and final code. It
lives in ``replays/<task_id>/`` and is committed, so the demo works without
the network.

Replaying copies it into a fresh run directory with ``mode: "REPLAY"``, the
original ``recorded_at`` and a new ``replayed_at``, then runs the ground
truth live. Stages after that (audit, verify, gate) also run live.

Why a replay can't be faked: the trace is signed by the recorder's key and
the seal's ``run`` metadata (task, base commit, recording time) is signed
too. The replay is verified before it is used; an edited replay fails.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from .chain import seal_path, verify
from .keys import load_or_create_key, public_hex
from .runner import ROOT, RunResult, ensure_upstream, run_ground_truth
from .writer import TraceWriter

REPLAYS = ROOT / "replays"


def save_replay(run_dir: str | Path, dest: str | Path | None = None) -> Path:
    """Copy a finished live run's agent stage into ``replays/<task_id>/``."""
    src = Path(run_dir)
    result = RunResult.load(src)
    if result.mode != "LIVE":
        raise ValueError("only live runs can be saved as replays")
    snap = src / "agent_trace.jsonl"
    report = verify(snap)
    if not report.ok:
        raise ValueError(f"refusing to save a broken trace: {report.detail}")
    out = Path(dest) if dest else REPLAYS / result.task_id
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    shutil.copyfile(snap, out / "agent_trace.jsonl")
    shutil.copyfile(seal_path(snap), seal_path(out / "agent_trace.jsonl"))
    subprocess.run(["git", "-C", str(src / "work"), "bundle", "create", str(out / "work.bundle"), "--all"],
                   check=True, capture_output=True, timeout=60)
    for sub in ("base", "final"):
        shutil.copytree(src / sub, out / sub, symlinks=True)
    for name in ("agent_stdout.jsonl", "agent_stderr.txt"):
        if (src / name).exists():
            shutil.copyfile(src / name, out / name)
    meta = {k: getattr(result, k) for k in ("run_id", "task_id", "recorded_at", "branch", "base_commit",
                                             "base_tree", "final_tree", "final_commit", "agent_exit",
                                             "timed_out", "upstream")}
    (out / "replay.json").write_text(json.dumps(meta, indent=1) + "\n")
    return out


def replay(task_or_path: str | Path, *, traces: Path | None = None, ground_truth: bool = True) -> RunResult:
    """Start a REPLAY run from ``replays/<task_id>`` (or a replay directory path)."""
    src = Path(task_or_path)
    if not src.exists():
        src = REPLAYS / str(task_or_path)
    meta = json.loads((src / "replay.json").read_text())
    snap = src / "agent_trace.jsonl"
    report = verify(snap)
    if not report.ok:
        raise ValueError(f"replay {src} fails verification at seq {report.first_bad_seq}: {report.detail}")
    key = load_or_create_key()
    if public_hex(key) != report.pubkey:
        raise ValueError("this replay was signed by a different recorder key than keys/; "
                         "record it on this machine or copy that key")

    traces = traces or ROOT / "traces"
    run_id = f"{meta['task_id']}-replay-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid() % 1000:03d}"
    run_dir = traces / run_id
    run_dir.mkdir(parents=True)
    for sub in ("base", "final"):
        shutil.copytree(src / sub, run_dir / sub, symlinks=True)
    work = run_dir / "work"
    subprocess.run(["git", "clone", "-q", "--no-checkout", str(src / "work.bundle"), str(work)],
                   check=True, capture_output=True, timeout=60)
    subprocess.run(["git", "-C", str(work), "checkout", "-q", "-B", meta["branch"], meta["final_commit"]],
                   check=True, capture_output=True, timeout=60)
    trace = run_dir / "trace.jsonl"
    shutil.copyfile(snap, trace)
    shutil.copyfile(seal_path(snap), seal_path(trace))
    replayed_at = datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    writer = TraceWriter(trace, key)
    # The REPLAY label goes into the signed seal, not just run.json, so it can't be dropped.
    writer.update_run({"mode": "REPLAY", "run_id": run_id, "recorded_run_id": meta["run_id"],
                       "replayed_at": replayed_at})
    shutil.copyfile(trace, run_dir / "agent_trace.jsonl")
    shutil.copyfile(seal_path(trace), seal_path(run_dir / "agent_trace.jsonl"))

    result = RunResult(run_id=run_id, task_id=meta["task_id"], mode="REPLAY", run_dir=str(run_dir),
                       trace_path=str(trace), work_dir=str(run_dir / "work"), branch=meta["branch"],
                       base_commit=meta["base_commit"], base_tree=meta["base_tree"],
                       final_tree=meta["final_tree"], final_commit=meta["final_commit"],
                       recorded_at=meta["recorded_at"], agent_exit=meta["agent_exit"],
                       timed_out=meta["timed_out"], replayed_at=replayed_at,
                       upstream=meta.get("upstream") if Path(meta.get("upstream") or "/nonexistent").exists()
                       else str(ensure_upstream(traces=traces)))
    if ground_truth:
        result.ground_truth_seqs = run_ground_truth(result, writer)
    result.save()
    return result


def export_played(result: RunResult, dest: str | Path) -> Path:
    """Copy a played-back run to ``dest/<task_id>/`` for the S3 check on another machine.

    Writes the full trace (agent stage + ground truth, signed and sealed) as
    ``agent_trace.jsonl`` next to ``base/`` and ``final/``: the layout
    ``python -m secondgrader.auditor.replay_check --all <dest>`` reads.
    """
    out = Path(dest) / result.task_id
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    run_dir = Path(result.run_dir)
    shutil.copyfile(result.trace_path, out / "agent_trace.jsonl")
    shutil.copyfile(seal_path(Path(result.trace_path)), seal_path(out / "agent_trace.jsonl"))
    for sub in ("base", "final"):
        shutil.copytree(run_dir / sub, out / sub, symlinks=True)
    return out

