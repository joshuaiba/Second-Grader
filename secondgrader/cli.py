"""Command-line entry point (P3, Josh).

    secondgrader run <task>                       run Muse Code on tasks/<task>.yaml, record, audit, verify, gate
    secondgrader run <task> --replay trace.jsonl  re-audit a recorded trace, labelled REPLAY, same pipeline
    secondgrader audit <trace.jsonl>              extract + check claims on an existing trace, print verdicts
    secondgrader verify-chain <trace.jsonl>       verify hashes and signatures

Code decides every verdict here. The only LLM call is inside the verifier,
and it only writes tests.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any

import yaml

from secondgrader import auditor, gate, recorder, schema, verifier
from secondgrader.schema import Claim, ClaimVerdict, GateDecision, Record, VerifierResult, load_trace

ROOT = Path(__file__).resolve().parents[1]


def _not_implemented(exc: NotImplementedError) -> int:
    print(f"not implemented yet: {exc}", file=sys.stderr)
    return 2


def _warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


def load_task(name: str) -> dict[str, Any]:
    path = Path(name) if name.endswith((".yaml", ".yml")) else ROOT / "tasks" / f"{name}.yaml"
    if not path.exists():
        raise FileNotFoundError(path)
    with open(path, encoding="utf-8") as fh:
        task = yaml.safe_load(fh) or {}
    task.setdefault("id", path.stem)
    return task


def chain_status(trace: str | Path) -> tuple[bool, int | None, Any | None]:
    """``(ok, first_bad_seq, report)`` from P1's verify_report (hashes, links, signatures, seal).

    The report is None when only the basic check is available. Signing is not
    required by default so the hand-written UNSIGNED fixtures still verify;
    set SG_REQUIRE_SIGNED=1 (or pin SG_PUBKEY) for real runs.
    """
    report_fn = getattr(recorder, "verify_report", None)
    if report_fn is not None:
        report = report_fn(trace)
        return bool(report.ok), report.first_bad_seq, report
    try:
        ok, bad = recorder.verify_chain(trace)
    except NotImplementedError:
        _warn("recorder.verify_chain not implemented; checking hashes only")
        ok, bad = schema.check_hash_chain(load_trace(trace))
    return ok, bad, None


def audit_records(records: list[Record], task: dict[str, Any] | None = None,
                  final_code: Path | None = None) -> tuple[list[Claim], list[ClaimVerdict], list[str]]:
    """P2's auditor: ``(claims, verdicts, probe obligations)``.

    Prefers ``auditor.audit(...)`` (full report with tamper findings and probes)
    when P2 ships it, else the three basic functions. Until either lands: no
    claims, no verdicts, no probes. Never a verdict from guesswork.
    """
    audit = getattr(auditor, "audit", None)
    if audit is not None:
        try:
            report = audit(records, task=task, final_dir=final_code)
            probes = [getattr(p, "text", p) for p in (getattr(report, "probes", None) or [])]
            return list(getattr(report, "claims", [])), list(getattr(report, "verdicts", [])), [str(p) for p in probes]
        except NotImplementedError as exc:
            _warn(f"auditor.audit not implemented ({exc}); trying the basic functions")
        except TypeError as exc:
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
    return "".join(str(r.payload.get("diff", "")) for r in schema.observed(records) if r.kind == "diff")


def ground_truth(records: list[Record]) -> tuple[bool | None, int | None]:
    """P1's ground-truth full run: a ``test_run`` with ``ground_truth: true`` and phase ``full_final``.

    The ``collect_base`` / ``collect_final`` records are collection only and
    never decide anything. None if no full run was recorded.
    """
    for r in reversed(schema.observed(records)):
        p = r.payload or {}
        if r.kind == "test_run" and p.get("ground_truth") and p.get("phase", "full_final") == "full_final":
            return p.get("exit_code") == 0, r.seq
    return None, None


def run_verifier(task: dict[str, Any], records: list[Record], *, offline: bool, final_code: Path,
                 append: Any | None, probes: list[str] | None = None) -> VerifierResult | None:
    try:
        client = verifier.GeminiClient(offline=offline)
        return verifier.verify(
            task_spec(task), full_diff(records), schema.observed(records),
            final_code_dir=final_code, all_records=records, recorder_append=append, client=client,
            probes=probes or None,
        )
    except (verifier.MissingApiKey, verifier.OfflineCacheMiss) as exc:
        _warn(f"verifier skipped: {exc}")
        return None


def print_report(mode: str, task: dict[str, Any], chain_ok: bool, first_bad: int | None,
                 verdicts: list[ClaimVerdict], vr: VerifierResult | None, decision: GateDecision,
                 report: Any | None = None) -> None:
    label = "LIVE" if mode == "LIVE" else "REPLAY"
    print(f"[{label}] task {task.get('id')}: {task.get('title', '')}")
    if report is not None:
        signed = "signed+sealed" if getattr(report, "signed", False) and getattr(report, "sealed", False) else "UNSIGNED"
        head = str(getattr(report, "head_hash", "") or "")[:12]
        where = "OK" if chain_ok else f"BROKEN at seq {first_bad} ({getattr(report, 'reason', '')}: {getattr(report, 'detail', '')})"
        print(f"chain: {where} [{signed}, {getattr(report, 'count', len(verdicts))} records, head {head}]")
    else:
        print(f"chain: {'OK' if chain_ok else f'BROKEN at seq {first_bad}'}")
    for v in verdicts:
        print(f"{v.status:<13} {v.claim_id:<28} seqs={v.evidence_seqs} {v.reason}")
    if vr is None:
        print("verifier: skipped")
    else:
        errored = len(vr.details) - vr.passed - vr.failed
        print(f"verifier: {vr.passed} passed, {vr.failed} failed, {errored} errored (seqs={vr.record_seqs})")
        if vr.passed + vr.failed == 0:
            print("verifier: NO COUNTABLE TESTS (generation rejected or every test errored); this does not block, but nothing was independently verified")
        for d in vr.details:
            print(f"  {d.get('outcome', '?'):<7} {d.get('name')}  {d.get('spec_sentence', '')}")
    stamp = "MERGED" if decision.decision == "PASS" else "BLOCKED"
    print(f"\n{decision.decision} ({stamp})")
    for r in decision.reasons:
        print(f"  - {r}")
    if decision.citing_seqs:
        print(f"  cited records: {decision.citing_seqs}")
    expected = task.get("expected_gate")
    if expected:
        print(f"expected for demo: {expected} -> {'as expected' if expected == decision.decision else 'MISMATCH'}")


def replay(task: dict[str, Any], trace: Path, *, offline: bool, no_verify: bool, final_code: Path,
           out_dir: Path | None) -> int:
    """The whole pipeline on an existing trace: chain -> audit -> verify -> gate."""
    records = load_trace(trace)
    chain_ok, first_bad, report = chain_status(trace)
    seal_mode = str((getattr(report, "run", None) or {}).get("mode", "")).upper() if report is not None else ""
    claims, verdicts, probes = audit_records(records, task, final_code)

    append = None
    if not no_verify and out_dir is not None:
        out_dir.mkdir(parents=True, exist_ok=True)
        out = out_dir / f"replay-{task.get('id')}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}.jsonl"
        out.write_bytes(Path(trace).read_bytes())
        try:
            recorder.append({"kind": "verifier_test", "origin": "OBSERVED", "payload": {"probe": True}}, out)
            out.write_bytes(Path(trace).read_bytes())  # probe worked; start clean
            append = lambda fields: recorder.append(fields, out)  # noqa: E731
            print(f"verifier records -> {out}")
        except NotImplementedError:
            _warn("recorder.append not implemented; verifier results are not written to the chain")
            out.unlink(missing_ok=True)

    vr = None if no_verify else run_verifier(task, records, offline=offline, final_code=final_code, append=append, probes=probes)
    gt_ok, gt_seq = ground_truth(records)
    decision = gate.decide(verdicts, vr, chain_ok, first_bad, claims=claims, ground_truth_ok=gt_ok, ground_truth_seq=gt_seq)
    # A trace is only ever shown as LIVE if its signed seal says so, and the CLI replay path is always REPLAY.
    print_report("REPLAY", task, chain_ok, first_bad, verdicts, vr, decision, report)
    if seal_mode and seal_mode != "REPLAY":
        print(f"note: the seal recorded this run as {seal_mode}; it is being re-audited now, so it is shown as REPLAY")
    return 0 if decision.decision == "PASS" else 1


def cmd_run(args: argparse.Namespace) -> int:
    try:
        task = load_task(args.task)
    except FileNotFoundError as exc:
        print(f"no such task: {exc}", file=sys.stderr)
        return 1
    final_code = Path(args.final_code) if args.final_code else ROOT / task.get("repo", "demo_repo")
    out_dir = None if args.no_write else Path(args.out_dir)

    try:
        if args.replay:
            return replay(task, Path(args.replay), offline=args.offline, no_verify=args.no_verify,
                          final_code=final_code, out_dir=out_dir)
    except verifier.BlindnessViolation as exc:
        print(f"error: refusing to call the verifier, its input is not blind: {exc}", file=sys.stderr)
        return 2

    run_task = getattr(recorder, "run_task", None)
    if run_task is None:
        print("secondgrader run: live mode needs P1's recorder.run_task (clone, launch Muse Code, record). "
              "Use --replay <trace.jsonl> meanwhile.", file=sys.stderr)
        return 2
    try:
        trace = Path(run_task(task))  # P1 returns the trace path of the finished run
    except NotImplementedError as exc:
        return _not_implemented(exc)
    return replay(task, trace, offline=args.offline, no_verify=args.no_verify, final_code=final_code, out_dir=out_dir)


def cmd_audit(args: argparse.Namespace) -> int:
    records = load_trace(args.trace)
    try:
        chain_ok, first_bad, _report = chain_status(args.trace)
        claims = auditor.extract_claims(records)
        verdicts = auditor.check_claims(claims, records)
        verdicts += auditor.detect_test_tampering(records)
    except NotImplementedError as exc:
        return _not_implemented(exc)
    decision = gate.decide(verdicts, None, chain_ok, first_bad, claims=claims)
    for v in verdicts:
        print(f"{v.status:<13} {v.claim_id:<12} seqs={v.evidence_seqs} {v.reason}")
    print(f"\n{decision.decision}: {'; '.join(decision.reasons) or 'no findings'}")
    return 0 if decision.decision == "PASS" else 1


def cmd_verify_chain(args: argparse.Namespace) -> int:
    try:
        ok, first_bad = recorder.verify_chain(args.trace)
    except NotImplementedError as exc:
        return _not_implemented(exc)
    if ok:
        print("chain OK")
        return 0
    print(f"chain BROKEN at seq {first_bad}")
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="secondgrader", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="run a task end to end (live), or re-audit a trace with --replay")
    run.add_argument("task", help="name of a file in tasks/ without .yaml, or a path to a task yaml")
    run.add_argument("--replay", metavar="TRACE", help="re-run the pipeline on this recorded trace (labelled REPLAY)")
    run.add_argument("--offline", action="store_true", help="verifier uses its cache only; no network")
    run.add_argument("--no-verify", action="store_true", help="skip the blinded verifier")
    run.add_argument("--final-code", metavar="DIR", help="the agent's final code (default: the task's repo in this checkout)")
    run.add_argument("--out-dir", default=str(ROOT / "traces"), help="where replay traces with verifier records go")
    run.add_argument("--no-write", action="store_true", help="do not write verifier records to a trace copy")
    run.set_defaults(func=cmd_run)

    audit = sub.add_parser("audit", help="audit an existing trace")
    audit.add_argument("trace", help="path to trace.jsonl")
    audit.set_defaults(func=cmd_audit)

    vc = sub.add_parser("verify-chain", help="verify a trace's hash chain and signatures")
    vc.add_argument("trace", help="path to trace.jsonl")
    vc.set_defaults(func=cmd_verify_chain)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
