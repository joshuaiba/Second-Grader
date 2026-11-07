"""One run, five stages (P3): record -> ground truth -> audit -> verify -> gate.

This module strings the owners' pieces together and is what the CLI and the
verdict page call. Three entry points, all returning a :class:`PipelineResult`:

- :func:`run_live`   P1's runner records a real Muse Code run, then the rest.
- :func:`run_replay` P1 re-plays a saved run (labelled REPLAY in its seal).
- :func:`run_trace`  the rest of the pipeline on any trace file (fixtures).

Where another owner's piece is still a stub, the pipeline degrades with a
warning instead of crashing, and it never invents a verdict: no auditor means
no claim verdicts; no verifier means "verifier: skipped". Code decides.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable

from secondgrader import auditor, gate, recorder, schema, verifier
from secondgrader.schema import Claim, ClaimVerdict, GateDecision, Record, VerifierResult, load_trace

ROOT = Path(__file__).resolve().parents[2]

STAGES: tuple[str, ...] = ("record", "ground_truth", "audit", "verify", "gate", "done")

StageCallback = Callable[[str, str], None]
WarnCallback = Callable[[str], None]


@dataclass
class PipelineResult:
    task_id: str
    mode: str                      # LIVE or REPLAY, from the signed seal when there is one
    trace_path: str
    decision: GateDecision
    claims: list[Claim] = field(default_factory=list)
    verdicts: list[ClaimVerdict] = field(default_factory=list)
    verifier_result: VerifierResult | None = None
    chain_ok: bool = True
    first_bad_seq: int | None = None
    chain_report: Any | None = None       # recorder.ChainReport when available
    git_outcome: str | None = None        # "merged into main" / "quarantined at refs/..." / None
    verdict_seq: int | None = None        # seq of the gate's verdict record, when chained
    records: list[Record] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    run: dict[str, Any] = field(default_factory=dict)   # P1 RunResult fields when we ran it

    def to_dict(self) -> dict[str, Any]:
        d = {
            "task_id": self.task_id, "mode": self.mode, "trace_path": self.trace_path,
            "decision": asdict(self.decision), "claims": [asdict(c) for c in self.claims],
            "verdicts": [asdict(v) for v in self.verdicts],
            "verifier_result": asdict(self.verifier_result) if self.verifier_result else None,
            "chain_ok": self.chain_ok, "first_bad_seq": self.first_bad_seq,
            "git_outcome": self.git_outcome, "verdict_seq": self.verdict_seq,
            "warnings": list(self.warnings), "run": dict(self.run),
        }
        r = self.chain_report
        if r is not None:
            d["chain_report"] = {k: getattr(r, k, None) for k in ("ok", "first_bad_seq", "reason", "detail", "count",
                                                                  "head_hash", "signed", "sealed", "pubkey", "run")}
        return d


# --------------------------------------------------------------------------- #
# Pieces (each tolerant of a still-missing owner module)
# --------------------------------------------------------------------------- #

def chain_status(trace: str | Path) -> tuple[bool, int | None, Any | None]:
    """``(ok, first_bad_seq, report)`` from P1's verify_report (hashes, links, signatures, seal).

    Signing is not required by default so the hand-written UNSIGNED fixtures
    still verify; set SG_REQUIRE_SIGNED=1 (or pin SG_PUBKEY) for real runs.
    """
    report_fn = getattr(recorder, "verify_report", None)
    if report_fn is not None:
        report = report_fn(trace)
        return bool(report.ok), report.first_bad_seq, report
    try:
        ok, bad = recorder.verify_chain(trace)
    except NotImplementedError:
        ok, bad = schema.check_hash_chain(load_trace(trace))
    return ok, bad, None


def audit_records(records: list[Record], task: dict[str, Any] | None = None, *,
                  base_code: Path | None = None, final_code: Path | None = None,
                  warn: WarnCallback | None = None) -> tuple[list[Claim], list[ClaimVerdict], list[str]]:
    """P2's auditor: ``(claims, verdicts, probe obligations)``.

    Prefers ``auditor.audit(...)`` (claims, tamper findings, probes) when P2
    ships it, else the three basic functions. Until either lands: nothing.
    """
    def _warn(msg: str) -> None:
        if warn:
            warn(msg)

    audit = getattr(auditor, "audit", None)
    if audit is not None:
        try:
            kwargs: dict[str, Any] = {"task": task}
            if base_code is not None:
                kwargs["base_dir"] = base_code
            if final_code is not None:
                kwargs["final_dir"] = final_code
            report = audit(records, **kwargs)
            probes = [str(getattr(p, "text", p)) for p in (getattr(report, "probes", None) or [])]
            return list(getattr(report, "claims", [])), list(getattr(report, "verdicts", [])), probes
        except NotImplementedError as exc:
            _warn(f"auditor.audit not implemented ({exc}); trying the basic functions")
        except TypeError as exc:
            if "argument" not in str(exc):
                raise  # a real TypeError inside the auditor, not a signature mismatch
            _warn(f"auditor.audit signature mismatch ({exc}); trying the basic functions")
    try:
        claims = auditor.extract_claims(records)
        verdicts = auditor.check_claims(claims, records)
        verdicts += auditor.detect_test_tampering(records)
    except NotImplementedError as exc:
        _warn(f"auditor not implemented ({exc}); no claim verdicts")
        return [], [], []
    return claims, verdicts, []


def task_spec(task: dict[str, Any]) -> str:
    """The text the verifier gets: ``spec``, or P2's ``prompt`` plus ``acceptance`` sentences."""
    spec = str(task.get("spec") or "").strip()
    if spec:
        return spec
    parts = [str(task.get("prompt") or "").strip()]
    acceptance = task.get("acceptance") or []
    if isinstance(acceptance, str):
        acceptance = [acceptance]
    parts += [str(a).strip() for a in acceptance]
    return "\n".join(x for x in parts if x)


def full_diff(records: list[Record]) -> str:
    """The agent's own diff records (not the ground-truth base->final diff, which duplicates them)."""
    agent = [r for r in schema.observed(records) if r.kind == "diff" and not (r.payload or {}).get("ground_truth")]
    if not agent:
        agent = [r for r in schema.observed(records) if r.kind == "diff"]
    return _join_diffs(str(r.payload.get("diff", "")) for r in agent)


def _join_diffs(chunks: Any) -> str:
    """Concatenate per-file diffs so every file header starts on its own line."""
    out = []
    for c in chunks:
        if not c:
            continue
        out.append(c if c.endswith("\n") else c + "\n")
    return "".join(out)


def final_diff(records: list[Record]) -> str:
    """The base -> final diff: P1's ground-truth diff records when present, else the agent's diffs in order."""
    gt = [r for r in schema.observed(records) if r.kind == "diff" and (r.payload or {}).get("ground_truth")]
    if gt:
        return _join_diffs(str(r.payload.get("diff", "")) for r in gt)
    return full_diff(records)


def materialize_final_code(records: list[Record], base_code: Path, dest: Path) -> tuple[bool, str]:
    """Rebuild the agent's final tree: copy ``base_code`` to ``dest`` and apply the recorded diffs.

    Returns ``(ok, message)``. On failure ``dest`` is left as a copy of the
    base and the caller must not judge it as if it were the final code.
    """
    import shutil
    import subprocess

    shutil.copytree(base_code, dest, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache", "*.pyc"))
    diff = final_diff(records)
    if not diff.strip():
        return True, "no diff records: final code equals base"
    patch = dest / ".sg_final.patch"
    patch.write_text(diff, encoding="utf-8")
    try:
        proc = subprocess.run(["git", "apply", "--whitespace=nowarn", "--unsafe-paths", str(patch)],
                              cwd=dest, capture_output=True, text=True, timeout=60)
    finally:
        patch.unlink(missing_ok=True)
    if proc.returncode != 0:
        return False, f"could not rebuild the final code from the recorded diffs: {proc.stderr.strip()[:300]}"
    return True, "final code rebuilt from the recorded diffs"


def ground_truth(records: list[Record]) -> tuple[bool | None, int | None]:
    """P1's ground-truth full run: ``test_run`` with ``ground_truth: true`` and phase ``full_final``."""
    for r in reversed(schema.observed(records)):
        p = r.payload or {}
        if r.kind == "test_run" and p.get("ground_truth") and p.get("phase", "full_final") == "full_final":
            return p.get("exit_code") == 0, r.seq
    return None, None


def run_verifier(task: dict[str, Any], records: list[Record], *, offline: bool | None, final_code: Path,
                 append: Any | None, probes: list[str] | None = None, base_code: Path | None = None,
                 warn: WarnCallback | None = None) -> VerifierResult | None:
    try:
        client = verifier.GeminiClient(offline=offline)
        return verifier.verify(
            task_spec(task), full_diff(records), schema.observed(records),
            final_code_dir=final_code, all_records=records, recorder_append=append, client=client,
            probes=probes or None, base_code_dir=base_code,
        )
    except (verifier.MissingApiKey, verifier.OfflineCacheMiss) as exc:
        if warn:
            warn(f"verifier skipped: {exc}")
        return None
    except verifier.BlindnessViolation as exc:
        if warn:
            warn(f"VERIFIER SKIPPED, BLINDNESS VIOLATION (bug in the verifier input builder, not the agent): {exc}")
        return None
    except Exception as exc:  # API errors, SDK import errors, subprocess failures: never abort after the agent ran
        if warn:
            warn(f"verifier skipped after an error: {type(exc).__name__}: {exc}")
        return None


class ChainAppender:
    """``recorder.append`` bound to one trace; goes quiet after the first refusal.

    The recorder refuses to append to an unsealed trace (hand-written fixtures)
    or one sealed by another key. That is correct, and it must not stop the
    audit: results are then only shown, not chained, and we say so once.
    """

    def __init__(self, trace: Path, warn: WarnCallback | None = None) -> None:
        self.trace = trace
        self.warn = warn
        self.disabled = False
        self.written: list[int] = []

    def __call__(self, fields: dict[str, Any]) -> Any | None:
        if self.disabled:
            return None
        try:
            rec = recorder.append(fields, self.trace)
        except (NotImplementedError, RuntimeError) as exc:
            self.disabled = True
            if self.warn:
                self.warn(f"results not written to the chain: {exc}")
            return None
        self.written.append(rec.seq)
        return rec


def copy_trace_for_results(task_id: str, trace: Path, out_dir: Path) -> Path:
    """Copy a trace (and its seal, if any) under ``out_dir`` so results can be chained onto it."""
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"replay-{task_id}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.jsonl"
    out.write_bytes(trace.read_bytes())
    seal_path = getattr(recorder, "seal_path", None)
    if seal_path is not None:
        src_seal = Path(seal_path(trace))
        if src_seal.exists():
            Path(seal_path(out)).write_bytes(src_seal.read_bytes())
    return out


def load_task(name: str) -> dict[str, Any]:
    import yaml

    path = Path(name) if name.endswith((".yaml", ".yml")) else ROOT / "tasks" / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(path)
    with open(path, encoding="utf-8") as fh:
        task = yaml.safe_load(fh) or {}
    task.setdefault("id", path.stem)
    return task


# --------------------------------------------------------------------------- #
# The pipeline from "trace exists" onwards
# --------------------------------------------------------------------------- #

def run_trace(
    task: dict[str, Any],
    trace_path: str | Path,
    *,
    final_code: str | Path | None = None,
    base_code: str | Path | None = None,
    work_dir: str | Path | None = None,
    branch: str | None = None,
    offline: bool | None = None,
    no_verify: bool = False,
    chain_results: bool = True,
    on_stage: StageCallback | None = None,
    mode: str = "REPLAY",
) -> PipelineResult:
    """Audit, verify and gate an existing trace, chaining results onto it.

    Args:
        trace_path: The trace to judge. Results are appended to **this file**
            (callers who want the original untouched copy it first, see
            :func:`copy_trace_for_results`).
        final_code / base_code: The agent's final code and the code before it.
            When ``final_code`` is None it is rebuilt by applying the recorded
            diffs to a copy of ``base_code`` (default: the task's repo in this
            checkout); if that fails the verifier is skipped rather than
            judging code the agent never produced.
        work_dir / branch: The throwaway git clone and the agent branch. When
            given, the gate acts in git (merge or quarantine).
        mode: ``"LIVE"`` only when the caller just ran the agent (run_live);
            anything judged from a recorded file is ``"REPLAY"``, and a REPLAY
            seal wins over any caller.
    """
    warnings: list[str] = []

    def warn(msg: str) -> None:
        warnings.append(msg)

    def stage(name: str, detail: str = "") -> None:
        if on_stage:
            on_stage(name, detail)

    import tempfile

    trace = Path(trace_path)
    base = Path(base_code) if base_code else None
    records = load_trace(trace)
    tmp_final: tempfile.TemporaryDirectory[str] | None = None
    final: Path | None = Path(final_code) if final_code else None
    if final is None:
        src = base or (ROOT / str(task.get("repo", "demo_repo")))
        tmp_final = tempfile.TemporaryDirectory(prefix="sg-final-")
        final = Path(tmp_final.name) / "final"
        ok, msg = materialize_final_code(records, src, final)
        if not ok:
            warn(msg + "; verifier skipped")
            no_verify = True
        if base is None:
            base = src

    stage("ground_truth", "reading the recorder's own test run")
    chain_ok, first_bad, report = chain_status(trace)
    # Never present a replay as live: a REPLAY seal always wins, and a LIVE seal only confirms a
    # caller that is itself live (run_live). Re-auditing a recorded file is a REPLAY whatever its seal says.
    seal_mode = str(((getattr(report, "run", None) or {}).get("mode") or "")).upper()
    if seal_mode == "REPLAY" or mode != "LIVE":
        mode = "REPLAY"
    gt_ok, gt_seq = ground_truth(records)

    stage("audit", "extracting and checking claims")
    claims, verdicts, probes = audit_records(records, task, base_code=base, final_code=final, warn=warn)

    append = ChainAppender(trace, warn) if chain_results else None
    stage("verify", "independent model writes tests" if not no_verify else "skipped")
    vr = None if no_verify else run_verifier(task, records, offline=offline, final_code=final, append=append,
                                             probes=probes, base_code=base, warn=warn)

    stage("gate", "deciding")
    decision = gate.decide(verdicts, vr, chain_ok, first_bad, claims=claims,
                           ground_truth_ok=gt_ok, ground_truth_seq=gt_seq)

    verdict_seq = None
    if append is not None:
        rec = append({"kind": "verdict", "origin": "OBSERVED", "payload": asdict(decision)})
        if rec is not None:
            verdict_seq = rec.seq
            chain_ok2, first_bad2, report = chain_status(trace)  # head hash now covers the verdict
            if chain_ok and not chain_ok2:
                warn(f"chain broke while appending results (seq {first_bad2}); check the recorder key")
                chain_ok, first_bad = chain_ok2, first_bad2

    git_outcome = None
    if work_dir and branch:
        head = str(getattr(report, "head_hash", "") or "") or None
        try:
            ref = gate.apply(work_dir, branch, decision, chain_head=head)
            git_outcome = f"merged into {ref}" if decision.decision == "PASS" else f"quarantined at {ref}"
        except Exception as exc:  # git failure must not hide the verdict
            warn(f"git action failed: {exc}")
            git_outcome = "git action failed"

    if tmp_final is not None:
        tmp_final.cleanup()
    stage("done", decision.decision)
    return PipelineResult(
        task_id=str(task.get("id", "")), mode=mode, trace_path=str(trace), decision=decision,
        claims=claims, verdicts=verdicts, verifier_result=vr, chain_ok=chain_ok, first_bad_seq=first_bad,
        chain_report=report, git_outcome=git_outcome, verdict_seq=verdict_seq,
        records=load_trace(trace), warnings=warnings,
    )


def _from_run_result(res: Any, task: dict[str, Any], *, offline: bool | None, no_verify: bool,
                     on_stage: StageCallback | None) -> PipelineResult:
    run_dir = Path(res.run_dir)
    out = run_trace(
        task, res.trace_path, final_code=run_dir / "final", base_code=run_dir / "base",
        work_dir=res.work_dir, branch=res.branch, offline=offline, no_verify=no_verify,
        on_stage=on_stage, mode=res.mode,
    )
    out.run = asdict(res) if hasattr(res, "__dataclass_fields__") else dict(getattr(res, "__dict__", {}))
    return out


def run_live(task_id: str, *, time_limit: float = 600, offline: bool | None = None, no_verify: bool = False,
             on_stage: StageCallback | None = None, agent_cmd: list[str] | None = None,
             traces: Path | None = None) -> PipelineResult:
    """P1 records a real run (Muse Code, or a scripted agent in tests), then the rest."""
    from secondgrader.recorder import runner  # P1's module; import here so a stub never breaks import

    task = load_task(task_id)
    if on_stage:
        on_stage("record", f"running the agent on {task_id} (limit {time_limit:.0f}s)")
    kwargs: dict[str, Any] = {"time_limit": time_limit}
    if agent_cmd is not None:
        kwargs["agent_cmd"] = agent_cmd
    if traces is not None:
        kwargs["traces"] = traces
    res = runner.run_task(task_id, **kwargs)
    return _from_run_result(res, task, offline=offline, no_verify=no_verify, on_stage=on_stage)


def run_replay(task_id: str, *, offline: bool | None = None, no_verify: bool = False,
               on_stage: StageCallback | None = None, traces: Path | None = None) -> PipelineResult:
    """P1 re-plays a saved run of ``task_id`` (labelled REPLAY in its signed seal), then the rest."""
    from secondgrader.recorder import replay as replay_mod

    task = load_task(task_id)
    if on_stage:
        on_stage("record", f"replaying the recorded run of {task_id}")
    kwargs: dict[str, Any] = {}
    if traces is not None:
        kwargs["traces"] = traces
    res = replay_mod.replay(task_id, **kwargs)
    return _from_run_result(res, task, offline=offline, no_verify=no_verify, on_stage=on_stage)


__all__ = [
    "STAGES", "ChainAppender", "PipelineResult", "audit_records", "chain_status", "copy_trace_for_results",
    "final_diff", "full_diff", "ground_truth", "load_task", "materialize_final_code", "run_live", "run_replay",
    "run_trace", "run_verifier", "task_spec",
]
