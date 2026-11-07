"""Runner (P1.8) and ground-truth run (P1.9).

One run = one throwaway clone, one recorder service, one trace:

    traces/
      demo_upstream/            git repo made once from demo_repo/ (branch main)
      <run_id>/
        run.json                run_id, task_id, mode LIVE|REPLAY, recorded_at, commits, trees
        trace.jsonl (+ .seal.json)
        agent_trace.jsonl (+ .seal.json)   snapshot after the agent stage, used by replays
        work/                   the clone; agent works on branch agent/<run_id>
        base/  final/           exported base and final code (for the auditor and verifier)
        agent_stdout.jsonl  agent_stderr.txt

Runs never share a clone, and nothing here writes to the upstream ``main``:
merging is the gate's job.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .chain import seal_path
from .fingerprint import changed_files, code_fingerprint, tree_diff
from .hooks import parse_pytest
from .keys import load_or_create_key
from .service import Recorder, RecorderServer, short_socket_path
from .writer import TraceWriter

ROOT = Path(__file__).resolve().parents[2]
FORWARD = ROOT / "scripts" / "hooks" / "forward.py"
HOOK_EVENTS = ["UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure",
               "PostLLMCall", "Stop", "SubagentStop"]
#: Hook timeout we configure in Muse Code (seconds). forward.py gives up at 1.5 s.
HOOK_TIMEOUT_S = 2
DEFAULT_MODEL = "muse-spark-1.3"
#: Unverified until a real run: see docs/MUSE_HOOKS.md. Override with $SG_MUSE_FLAGS.
DEFAULT_MUSE_FLAGS = ["--disable-sandbox", "--trust-workspace", "--disable-approval"]
GIT_ID = ["-c", "user.name=Second Grader", "-c", "user.email=recorder@secondgrader.local"]


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *GIT_ID, *args], check=True,
                          capture_output=True, text=True, timeout=30).stdout.strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass
class RunResult:
    run_id: str
    task_id: str
    mode: str
    run_dir: str
    trace_path: str
    work_dir: str
    branch: str
    base_commit: str
    base_tree: str
    final_tree: str = ""
    final_commit: str = ""
    recorded_at: str = ""
    agent_exit: int | None = None
    timed_out: bool = False
    replayed_at: str | None = None
    ground_truth_seqs: list[int] = field(default_factory=list)

    def save(self) -> None:
        Path(self.run_dir, "run.json").write_text(json.dumps(asdict(self), indent=1) + "\n")

    @classmethod
    def load(cls, run_dir: str | Path) -> "RunResult":
        return cls(**json.loads(Path(run_dir, "run.json").read_text()))


def load_task(task_id: str, root: Path = ROOT) -> dict[str, Any]:
    return yaml.safe_load((root / "tasks" / f"{task_id}.yaml").read_text())


def agent_prompt(task: dict[str, Any]) -> str:
    """What the agent is told. Trap notes for humans, ``(Trap: ...)``, are removed."""
    text = task.get("prompt") or task["spec"]
    text = re.sub(r"\(Trap:.*?\)", "", text, flags=re.S)
    return "\n".join(ln for ln in text.splitlines() if ln.strip()).strip()


def ensure_upstream(root: Path = ROOT, traces: Path | None = None) -> Path:
    """The demo repo as its own git repository, created once from ``demo_repo/``."""
    up = (traces or root / "traces") / "demo_upstream"
    if not (up / ".git").exists():
        shutil.copytree(root / "demo_repo", up,
                        ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", "*.pyc"))
        (up / ".gitignore").write_text("__pycache__/\n.pytest_cache/\n*.pyc\n")
        subprocess.run(["git", "init", "-q", "-b", "main", str(up)], check=True)
        _git(up, "add", "-A")
        _git(up, "commit", "-qm", "demo repo base")
    return up


def write_hooks_config(work: Path, sock: Path) -> Path:
    """``.muse/hooks.json`` in the clone, hidden from git so it never shows in diffs."""
    cmd = f"{sys.executable} {FORWARD} --sock {sock}"
    entry = [{"hooks": [{"type": "command", "command": cmd, "timeout": HOOK_TIMEOUT_S}]}]
    cfg = {"hooks": {ev: entry for ev in HOOK_EVENTS}}
    path = work / ".muse" / "hooks.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(cfg, indent=1) + "\n")
    with open(work / ".git" / "info" / "exclude", "a") as fh:
        fh.write("\n.muse/\n")
    return path


def muse_command(prompt: str) -> list[str]:
    flags = os.environ.get("SG_MUSE_FLAGS")
    extra = flags.split() if flags else DEFAULT_MUSE_FLAGS
    model = os.environ.get("SG_MUSE_MODEL", DEFAULT_MODEL)
    return ["muse", "exec", "--json", "--model", model, *extra, prompt]


def _launch(cmd: list[str], work: Path, run_dir: Path, time_limit: float,
            env: dict[str, str]) -> tuple[int | None, bool]:
    """Run the agent in its own process group; stop it cleanly at the time limit."""
    with open(run_dir / "agent_stdout.jsonl", "wb") as out, open(run_dir / "agent_stderr.txt", "wb") as err:
        proc = subprocess.Popen(cmd, cwd=work, stdout=out, stderr=err, stdin=subprocess.DEVNULL,
                                env=env, start_new_session=True)
        try:
            return proc.wait(timeout=time_limit), False
        except subprocess.TimeoutExpired:
            for sig, grace in ((signal.SIGTERM, 5), (signal.SIGKILL, 5)):
                try:
                    os.killpg(proc.pid, sig)
                except ProcessLookupError:
                    break
                try:
                    proc.wait(timeout=grace)
                    break
                except subprocess.TimeoutExpired:
                    continue
            return proc.returncode, True


def _stdout_messages(path: Path) -> list[str]:
    """Best-effort fallback: assistant text from ``muse exec --json`` events (format unverified)."""
    texts = []
    if not path.exists():
        return texts
    for line in path.read_text(errors="replace").splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(ev, dict):
            continue
        item = ev.get("item") if isinstance(ev.get("item"), dict) else {}
        kind = str(ev.get("type") or ev.get("event") or item.get("type") or "").lower()
        role = str(ev.get("role") or item.get("role") or "").lower()
        if "assistant" in kind or "agent_message" in kind or role == "assistant":
            for src in (ev, item):
                val = next((src[k] for k in ("text", "message", "content")
                            if isinstance(src.get(k), str) and src[k].strip()), None)
                if val:
                    texts.append(val)
                    break
    return texts


def _export(work: Path, tree: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    archive = subprocess.run(["git", "-C", str(work), "archive", "--format=tar", tree],
                             check=True, capture_output=True, timeout=30).stdout
    subprocess.run(["tar", "-x", "-C", str(dest)], input=archive, check=True, timeout=30)


def _pytest(code_dir: Path, *args: str, timeout: float = 180) -> tuple[int | None, str]:
    """Run pytest on a fresh copy of ``code_dir`` so nothing leaks between runs."""
    with tempfile.TemporaryDirectory(prefix="sg-gt-") as tmp:
        copy = Path(tmp) / "code"
        shutil.copytree(code_dir, copy)
        try:
            proc = subprocess.run([sys.executable, "-m", "pytest", "-p", "no:cacheprovider", *args],
                                  cwd=copy, capture_output=True, text=True, timeout=timeout,
                                  env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        except subprocess.TimeoutExpired as exc:
            out = (exc.stdout or b"").decode(errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            return None, out + f"\nground truth stopped at the {timeout:.0f}s time limit"
        return proc.returncode, proc.stdout + proc.stderr


def run_ground_truth(result: RunResult, writer: TraceWriter) -> list[int]:
    """P1.9: our own evidence, logged as OBSERVED with ``source: "ground_truth"``.

    Appends: one ``diff`` per file changed base -> final, test collection on
    base and on final (``phase: collect_base`` / ``collect_final``), and the
    full suite on final (``phase: full_final``).
    """
    run_dir, work = Path(result.run_dir), Path(result.work_dir)
    seqs = []
    gt = {"source": "ground_truth"}
    for row in changed_files(work, result.base_tree, result.final_tree):
        diff = tree_diff(work, result.base_tree, result.final_tree, row["path"])
        added = sum(1 for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++"))
        removed = sum(1 for ln in diff.splitlines() if ln.startswith("-") and not ln.startswith("---"))
        seqs.append(writer.append("diff", {"path": row["path"], "status": row["status"], "diff": diff,
                                           "lines_added": added, "lines_removed": removed,
                                           "tree_before": result.base_tree, "tree": result.final_tree,
                                           **gt}).seq)
    for phase, sub, tree in (("collect_base", "base", result.base_tree),
                             ("collect_final", "final", result.final_tree)):
        code, out = _pytest(run_dir / sub, "--collect-only", "-q")
        node_ids = [ln.strip() for ln in out.splitlines() if "::" in ln and not ln.startswith(" ")]
        seqs.append(writer.append("test_run", {
            "command": "pytest --collect-only -q", "phase": phase, "exit_code": code,
            "node_ids": node_ids, "collected": len(node_ids), "tree": tree,
            "output_tail": out[-1500:], **gt}).seq)
    code, out = _pytest(run_dir / "final", "-q", "-rA")
    seqs.append(writer.append("test_run", {
        "command": "pytest -q -rA", "phase": "full_final", "exit_code": code, "timed_out": code is None,
        **parse_pytest(out),
        "tree": result.final_tree, "output_tail": out[-1500:], **gt}).seq)
    return seqs


def run_task(task_id: str, *, time_limit: float = 600, agent_cmd: list[str] | None = None,
             run_id: str | None = None, root: Path = ROOT, traces: Path | None = None,
             ground_truth: bool = True) -> RunResult:
    """Run one task live: clone, record the agent, export code, run ground truth.

    Args:
        agent_cmd: Overrides the Muse Code command (tests use a scripted agent).
            ``{prompt}`` in any argument is replaced by the task prompt.
    """
    task = load_task(task_id, root)
    prompt = agent_prompt(task)
    traces = traces or root / "traces"
    run_id = run_id or f"{task_id}-{time.strftime('%Y%m%d-%H%M%S')}-{os.getpid() % 1000:03d}"
    run_dir = traces / run_id
    run_dir.mkdir(parents=True)
    work = run_dir / "work"
    up = ensure_upstream(root, traces)
    subprocess.run(["git", "clone", "-q", str(up), str(work)], check=True, timeout=60)
    branch = f"agent/{run_id}"
    _git(work, "checkout", "-qb", branch)
    base_commit = _git(work, "rev-parse", "HEAD")
    base_tree = _git(work, "rev-parse", "HEAD^{tree}")

    sock = short_socket_path()
    write_hooks_config(work, sock)
    key = load_or_create_key()
    trace = run_dir / "trace.jsonl"
    result = RunResult(run_id=run_id, task_id=task_id, mode="LIVE", run_dir=str(run_dir),
                       trace_path=str(trace), work_dir=str(work), branch=branch,
                       base_commit=base_commit, base_tree=base_tree, recorded_at=_now())
    writer = TraceWriter(trace, key)
    writer.start({"run_id": run_id, "task_id": task_id, "mode": "LIVE", "recorded_at": result.recorded_at,
                  "base_commit": base_commit, "base_tree": base_tree,
                  "agent": "scripted" if agent_cmd else "muse-code"})

    recorder = Recorder(trace, key, repo=work)
    server = RecorderServer(sock, recorder)
    server.start_background()
    try:
        writer.append("prompt", {"task_id": task_id, "text": prompt, "source": "runner"})
        cmd = [a.replace("{prompt}", prompt) for a in agent_cmd] if agent_cmd else muse_command(prompt)
        env = {k: v for k, v in os.environ.items() if not k.startswith("SG_")}  # no key path, no socket
        result.agent_exit, result.timed_out = _launch(cmd, work, run_dir, time_limit, env)
    finally:
        server.close()
        shutil.rmtree(sock.parent, ignore_errors=True)

    recorded = {r.get("payload", {}).get("text") for r in map(json.loads, trace.read_text().splitlines())
                if r["kind"] == "model_message"}
    for text in _stdout_messages(run_dir / "agent_stdout.jsonl"):
        if text not in recorded:
            writer.append("model_message", {"text": text, "source": "agent_stdout"})
            recorded.add(text)
    if result.timed_out:
        writer.append("tool_output", {"tool": "runner", "exit_code": result.agent_exit,
                                      "content": f"agent stopped at the {time_limit:.0f}s time limit"})

    result.final_tree = code_fingerprint(work)
    _git(work, "add", "-A")
    _git(work, "commit", "-q", "--allow-empty", "-m", f"agent work for {run_id} ({task_id})")
    result.final_commit = _git(work, "rev-parse", "HEAD")
    _export(work, result.base_tree, run_dir / "base")
    _export(work, result.final_tree, run_dir / "final")
    shutil.copyfile(trace, run_dir / "agent_trace.jsonl")
    shutil.copyfile(seal_path(trace), seal_path(run_dir / "agent_trace.jsonl"))
    if ground_truth:
        result.ground_truth_seqs = run_ground_truth(result, writer)
    result.save()
    return result
