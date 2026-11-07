"""Run a task from the page (P3.9 "Run" button): one run at a time, in a thread.

The page POSTs ``/api/run`` and then polls ``/api/status`` every second. When
the pipeline finishes, the status carries a ``redirect`` to the verdict page
for the run's own trace. Nothing here decides anything: it only drives
:mod:`secondgrader.gate.pipeline` and reports its stage.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

from secondgrader.gate import pipeline

REPO_ROOT = Path(__file__).resolve().parents[2]


class RunManager:
    def __init__(self, *, traces: Path | None = None) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.traces = traces or REPO_ROOT / "traces"
        self.state: dict[str, Any] = {"stage": "idle", "stages": list(pipeline.STAGES), "detail": "",
                                      "task": "", "mode": "", "trace": None, "redirect": None, "error": None}

    # -- status -------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        with self._lock:
            return dict(self.state)

    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def wait(self, timeout: float = 60) -> None:
        t = self._thread
        if t is not None:
            t.join(timeout)

    def _set(self, **changes: Any) -> None:
        with self._lock:
            self.state.update(changes)

    # -- start --------------------------------------------------------------
    def start(self, task_id: str, mode: str, trace: str | None = None) -> dict[str, Any]:
        """Start a run. Returns the JSON for ``/api/run`` (``http_status`` set on refusal)."""
        if self.running():
            return {"status": "busy", "message": f"a run of {self.state['task']} is still going", "http_status": 409}
        try:
            task = pipeline.load_task(task_id)
        except FileNotFoundError:
            return {"status": "unknown task", "message": f"no tasks/{task_id}.yaml", "http_status": 404}
        mode = "LIVE" if str(mode).upper() == "LIVE" else "REPLAY"
        trace_path: Path | None = None
        if trace:
            candidate = Path(trace)
            if not candidate.is_absolute():
                candidate = REPO_ROOT / candidate
            if not candidate.resolve().is_relative_to(REPO_ROOT.resolve()) or not candidate.is_file():
                return {"status": "bad trace", "message": "trace must be an existing file inside the repository", "http_status": 400}
            trace_path = candidate
            mode = "REPLAY"  # judging an existing trace is never live

        self._set(stage="record", detail="starting", task=task_id, mode=mode, trace=None, redirect=None, error=None,
                  started_at=time.time())
        self._thread = threading.Thread(target=self._work, args=(task, mode, trace_path), daemon=True, name="sg-run")
        self._thread.start()
        return {"status": "started", "task": task_id, "mode": mode}

    # -- worker -------------------------------------------------------------
    def _work(self, task: dict[str, Any], mode: str, trace_path: Path | None) -> None:
        def on_stage(stage: str, detail: str) -> None:
            self._set(stage=stage, detail=detail)

        task_id = str(task.get("id", ""))
        try:
            if trace_path is not None:
                target = pipeline.copy_trace_for_results(task_id, trace_path, self.traces)
                res = pipeline.run_trace(task, target, on_stage=on_stage, mode="REPLAY")  # final code rebuilt from diffs
            elif mode == "LIVE":
                res = pipeline.run_live(task_id, on_stage=on_stage, traces=self.traces)
            else:
                res = pipeline.run_replay(task_id, on_stage=on_stage, traces=self.traces)
        except Exception as exc:  # the page must show the failure, never hang on "verify"
            self._set(stage="error", detail=f"{type(exc).__name__}: {exc}", error=str(exc))
            return
        rel = Path(res.trace_path).resolve()
        try:
            rel_str = rel.relative_to(REPO_ROOT.resolve()).as_posix()
        except ValueError:
            rel_str = str(rel)
        redirect = f"/?trace={rel_str}&mode={res.mode}&task={task_id}"
        self._set(stage="done", detail=res.decision.decision, trace=rel_str, redirect=redirect,
                  decision=res.decision.decision, warnings=list(res.warnings))


manager = RunManager()

__all__ = ["RunManager", "manager"]
