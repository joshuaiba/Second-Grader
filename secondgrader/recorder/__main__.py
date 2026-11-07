"""Recorder command line (P1). The team CLI (``secondgrader``, owned by P3) can wrap these.

    python -m secondgrader.recorder run <task> [--time-limit S] [--scripted]
    python -m secondgrader.recorder save-replay <run_dir>
    python -m secondgrader.recorder replay <task|replay_dir>
    python -m secondgrader.recorder record-replays [task ...]     live run + save replay, all tasks by default
    python -m secondgrader.recorder verify <trace.jsonl> [--json]
    python -m secondgrader.recorder tamper <trace.jsonl> <seq> <field> <json value> [--rehash]
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import verify_report
from .replay import replay, save_replay
from .runner import ROOT, run_task
from .tamper import tamper


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="python -m secondgrader.recorder", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("task")
    r.add_argument("--time-limit", type=float, default=600)
    r.add_argument("--scripted", action="store_true", help="use the scripted stand-in agent, not Muse Code")
    s = sub.add_parser("save-replay")
    s.add_argument("run_dir")
    rr = sub.add_parser("record-replays")
    rr.add_argument("tasks", nargs="*")
    rr.add_argument("--time-limit", type=float, default=600)
    rp = sub.add_parser("replay")
    rp.add_argument("source")
    v = sub.add_parser("verify")
    v.add_argument("trace")
    v.add_argument("--json", action="store_true")
    t = sub.add_parser("tamper")
    t.add_argument("trace")
    t.add_argument("seq", type=int)
    t.add_argument("field", help="dotted path, e.g. payload.exit_code")
    t.add_argument("value", help="JSON value, e.g. 0 or '\"text\"'")
    t.add_argument("--rehash", action="store_true")
    a = p.parse_args(argv)

    if a.cmd == "run":
        agent = [sys.executable, str(ROOT / "scripts" / "hooks" / "scripted_agent.py")] if a.scripted else None
        res = run_task(a.task, time_limit=a.time_limit, agent_cmd=agent)
        print(json.dumps(asdict(res), indent=1))
        return 0
    if a.cmd == "record-replays":
        tasks = a.tasks or sorted(p.stem for p in (ROOT / "tasks").glob("*.yaml"))
        failed = 0
        for task in tasks:
            try:
                res = run_task(task, time_limit=a.time_limit)
                out = save_replay(res.run_dir)
                print(f"{task}: saved {out} (agent exit {res.agent_exit}, timed out {res.timed_out})")
            except Exception as exc:  # noqa: BLE001  keep going; report every task
                failed += 1
                print(f"{task}: FAILED {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1 if failed else 0
    if a.cmd == "save-replay":
        print(save_replay(a.run_dir))
        return 0
    if a.cmd == "replay":
        res = replay(a.source)
        print(json.dumps(asdict(res), indent=1))
        return 0
    if a.cmd == "verify":
        rep = verify_report(a.trace)
    else:
        try:
            out, rep = tamper(a.trace, a.seq, a.field, json.loads(a.value), rehash=a.rehash)
        except KeyError as exc:
            print(f"cannot tamper: {exc.args[0]}", file=sys.stderr)
            return 2
        print(f"tampered copy: {out}")
    if getattr(a, "json", False):
        print(json.dumps(rep.to_dict(), indent=1))
    elif rep.ok:
        print(f"chain OK: {rep.count} records, signed={rep.signed}, sealed={rep.sealed}")
    else:
        print(f"chain BROKEN at seq {rep.first_bad_seq} ({rep.reason}): {rep.detail}")
    return 0 if rep.ok else 1


if __name__ == "__main__":
    sys.exit(main())
