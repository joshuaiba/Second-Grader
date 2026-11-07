"""Command-line entry point.

    secondgrader run <task>                 run Muse Code on tasks/<task>.yaml, record, audit, verify, gate
    secondgrader audit <trace.jsonl>        extract + check claims on an existing trace, print verdicts
    secondgrader verify-chain <trace.jsonl> verify hashes and signatures
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secondgrader import auditor, gate, recorder
from secondgrader.schema import load_trace


def _not_implemented(exc: NotImplementedError) -> int:
    print(f"not implemented yet: {exc}", file=sys.stderr)
    return 2


def cmd_run(args: argparse.Namespace) -> int:
    task_path = Path("tasks") / f"{args.task}.yaml"
    if not task_path.exists():
        print(f"no such task: {task_path}", file=sys.stderr)
        return 1
    # Owner D wires this up once recorder/auditor/verifier/gate land:
    #   clone demo_repo -> run Muse Code with hooks -> audit -> verify -> gate -> web
    print("secondgrader run: pipeline not wired yet", file=sys.stderr)
    return 2


def cmd_audit(args: argparse.Namespace) -> int:
    records = load_trace(args.trace)
    try:
        chain_ok, first_bad = recorder.verify_chain(args.trace)
        claims = auditor.extract_claims(records)
        verdicts = auditor.check_claims(claims, records)
        verdicts += auditor.detect_test_tampering(records)
        decision = gate.decide(verdicts, None, chain_ok, first_bad)
    except NotImplementedError as exc:
        return _not_implemented(exc)
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

    run = sub.add_parser("run", help="run a task end to end")
    run.add_argument("task", help="name of a file in tasks/ without .yaml")
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
