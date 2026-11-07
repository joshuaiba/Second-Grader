"""Command-line entry point (P3, Josh).

    secondgrader run <task>                       live: P1 runs Muse Code, then audit, verify, gate
    secondgrader run <task> --replay              re-play P1's saved run of <task>, labelled REPLAY
    secondgrader run <task> --replay trace.jsonl  the pipeline on any trace file (fixtures)
    secondgrader audit <trace.jsonl>              extract + check claims on an existing trace
    secondgrader verify-chain <trace.jsonl>       verify hashes, links, signatures and seal

Code decides every verdict here. The only LLM call is inside the verifier,
and it only writes tests.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

from secondgrader import auditor, gate, recorder, verifier
from secondgrader.gate import pipeline
from secondgrader.gate.pipeline import (  # re-exported for tests and other callers
    PipelineResult,
    audit_records,
    chain_status,
    full_diff,
    ground_truth,
    load_task,
    run_verifier,
    task_spec,
)
from secondgrader.schema import load_trace

ROOT = Path(__file__).resolve().parents[1]

__all__ = ["audit_records", "build_parser", "chain_status", "full_diff", "ground_truth", "load_task", "main",
           "run_verifier", "task_spec"]


def _not_implemented(exc: NotImplementedError) -> int:
    print(f"not implemented yet: {exc}", file=sys.stderr)
    return 2


def _warn(msg: str) -> None:
    print(f"warning: {msg}", file=sys.stderr)


def _stage(name: str, detail: str) -> None:
    print(f"[stage] {name}: {detail}", file=sys.stderr)


def print_report(res: PipelineResult, task: dict[str, Any]) -> None:
    for w in res.warnings:
        _warn(w)
    print(f"[{res.mode}] task {res.task_id}: {task.get('title', '')}")
    r = res.chain_report
    if r is not None:
        signed = "signed+sealed" if getattr(r, "signed", False) and getattr(r, "sealed", False) else "UNSIGNED"
        head = str(getattr(r, "head_hash", "") or "")[:12]
        where = "OK" if res.chain_ok else f"BROKEN at seq {res.first_bad_seq} ({getattr(r, 'reason', '')}: {getattr(r, 'detail', '')})"
        print(f"chain: {where} [{signed}, {getattr(r, 'count', len(res.records))} records, head {head}]")
    else:
        print(f"chain: {'OK' if res.chain_ok else f'BROKEN at seq {res.first_bad_seq}'}")
    for v in res.verdicts:
        print(f"{v.status:<13} {v.claim_id:<28} seqs={v.evidence_seqs} {v.reason}")
    vr = res.verifier_result
    if vr is None:
        print("verifier: skipped")
    else:
        errored = len(vr.details) - vr.passed - vr.failed
        print(f"verifier: {vr.passed} passed, {vr.failed} failed, {errored} errored (seqs={vr.record_seqs})")
        if vr.passed + vr.failed == 0:
            print("verifier: NO COUNTABLE TESTS (generation rejected or every test errored); "
                  "this does not block, but nothing was independently verified")
        for d in vr.details:
            weak = "  [weak: also passes on base code]" if d.get("weak") else ""
            print(f"  {d.get('outcome', '?'):<7} {d.get('name')}  {d.get('spec_sentence', '')}{weak}")
    d = res.decision
    stamp = "MERGED" if d.decision == "PASS" else "BLOCKED"
    print(f"\n{d.decision} ({stamp})")
    for reason in d.reasons:
        print(f"  - {reason}")
    if d.citing_seqs:
        print(f"  cited records: {d.citing_seqs}")
    if res.verdict_seq is not None:
        print(f"verdict record seq {res.verdict_seq} -> {res.trace_path}")
    if res.git_outcome:
        print(f"git: {res.git_outcome}")
    expected = task.get("expected_gate") or task.get("expected_verdict")
    if expected:
        exp = "PASS" if str(expected).upper() in ("PASS", "MERGED", "MERGE") else "BLOCK"
        print(f"expected for demo: {exp} -> {'as expected' if exp == d.decision else 'MISMATCH'}")


def cmd_run(args: argparse.Namespace) -> int:
    try:
        task = load_task(args.task)
    except FileNotFoundError as exc:
        print(f"no such task: {exc}", file=sys.stderr)
        return 1
    on_stage = _stage if args.verbose else None

    try:
        if args.replay is not None and args.replay != "":
            # A trace file: the rest of the pipeline on it, on a copy so the original stays untouched.
            trace = Path(args.replay)
            if not trace.exists():
                print(f"no such trace: {trace}", file=sys.stderr)
                return 1
            final_code = Path(args.final_code) if args.final_code else None  # None: rebuilt from the trace's diffs
            base_code = Path(args.base_code) if args.base_code else None
            target = trace if args.no_write else pipeline.copy_trace_for_results(str(task["id"]), trace, Path(args.out_dir))
            res = pipeline.run_trace(task, target, final_code=final_code, base_code=base_code, offline=(True if args.offline else None),
                                     no_verify=args.no_verify, chain_results=not args.no_write, on_stage=on_stage)
        elif args.replay == "":
            res = pipeline.run_replay(str(task["id"]), offline=(True if args.offline else None), no_verify=args.no_verify, on_stage=on_stage)
        else:
            res = pipeline.run_live(str(task["id"]), time_limit=args.time_limit, offline=(True if args.offline else None),
                                    no_verify=args.no_verify, on_stage=on_stage)
    except verifier.BlindnessViolation as exc:
        print(f"error: refusing to call the verifier, its input is not blind: {exc}", file=sys.stderr)
        return 2
    except NotImplementedError as exc:
        return _not_implemented(exc)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print_report(res, task)
    return 0 if res.decision.decision == "PASS" else 1


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

    run = sub.add_parser("run", help="run a task live, re-play its saved run (--replay), or judge a trace file (--replay FILE)")
    run.add_argument("task", help="name of a file in tasks/ without .yaml, or a path to a task yaml")
    run.add_argument("--replay", nargs="?", const="", default=None, metavar="TRACE",
                     help="no value: re-play P1's saved run of the task; a path: run the pipeline on that trace file")
    run.add_argument("--offline", action="store_true", help="verifier uses its cache only; no network")
    run.add_argument("--no-verify", action="store_true", help="skip the blinded verifier")
    run.add_argument("--time-limit", type=float, default=600, help="seconds the live agent may run (default 600)")
    run.add_argument("--final-code", metavar="DIR", help="(trace file only) the agent's final code; default: rebuilt by applying the recorded diffs to the task's repo")
    run.add_argument("--base-code", metavar="DIR", help="(trace file only) code before the change; tests passing there too are flagged weak")
    run.add_argument("--out-dir", default=str(ROOT / "traces"), help="(trace file only) where the judged copy goes")
    run.add_argument("--no-write", action="store_true", help="(trace file only) judge in place without appending anything")
    run.add_argument("-v", "--verbose", action="store_true", help="print stage progress to stderr")
    run.set_defaults(func=cmd_run)

    audit = sub.add_parser("audit", help="audit an existing trace")
    audit.add_argument("trace", help="path to trace.jsonl")
    audit.set_defaults(func=cmd_audit)

    vc = sub.add_parser("verify-chain", help="verify a trace's hash chain, signatures and seal")
    vc.add_argument("trace", help="path to trace.jsonl")
    vc.set_defaults(func=cmd_verify_chain)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
