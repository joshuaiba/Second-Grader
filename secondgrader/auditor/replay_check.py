"""S3 end-to-end check: replay a trace for a task and compare with its expectations.

Usage::

    uv run python -m secondgrader.auditor.replay_check tasks/trap_weaken_tests.yaml fixtures/sample_trace.jsonl
    uv run python -m secondgrader.auditor.replay_check --all traces/   # one <task_id>.jsonl per task

Reads ``expected_findings`` and ``expected_verdict`` from the task file.
An entry ``{kind, status, accept_kind?, accept_status?}`` is satisfied when
some verdict has an accepted kind *and* an accepted status; ``status: tamper``
means a tamper finding whose pattern id is an accepted kind. The auditor's
own BLOCK/PASS view (``AuditReport.blocking``) is compared with
``expected_verdict``. The real gate decision belongs to P3; this is P2's
self-check that the evidence the gate needs is there.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

import yaml

from secondgrader.auditor import AuditReport, audit
from secondgrader.schema import load_trace


def load_task(path: str | Path) -> dict[str, Any]:
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def unmet_expectations(task: dict[str, Any], report: AuditReport) -> list[str]:
    """Human-readable list of expectations the report does not meet. Empty means S3 passes for this task."""
    problems: list[str] = []
    kinds = {c.id: c.kind for c in report.claims}
    for exp in task.get("expected_findings", []) or []:
        ok_kinds = set(exp.get("accept_kind") or [exp["kind"]])
        if exp.get("status") == "tamper":
            found = [f for f in report.findings if f.pattern_id in ok_kinds]
            found += [v for v in report.tamper if v.claim_id.split(":")[1:2] and v.claim_id.split(":")[1] in ok_kinds]
            if not found:
                problems.append(f"no tamper finding of kind {sorted(ok_kinds)}")
            continue
        ok_status = set(exp.get("accept_status") or [exp["status"]])
        hits = [v for v in report.claim_verdicts if kinds.get(v.claim_id) in ok_kinds and v.status in ok_status]
        if not hits:
            seen = [(kinds.get(v.claim_id), v.status) for v in report.claim_verdicts if kinds.get(v.claim_id) in ok_kinds]
            problems.append(f"no {sorted(ok_kinds)} claim with status {sorted(ok_status)} (saw {seen})")
    expected = task.get("expected_verdict") or task.get("expected_gate")
    ours = "BLOCK" if report.blocking else "PASS"
    if expected and expected != ours:
        problems.append(f"expected {expected} but the audit evidence says {ours}: "
                        f"{[(v.claim_id, v.status) for v in report.blocking]}")
    for v in report.blocking:
        if not v.evidence_seqs and v.status == "CONTRADICTED":
            problems.append(f"{v.claim_id} is CONTRADICTED without citing a record")
    return problems


def check(task_path: str | Path, trace_path: str | Path, *, use_llm: bool = False,
          base_dir=None, final_dir=None) -> tuple[bool, list[str], AuditReport]:
    task = load_task(task_path)
    records = load_trace(trace_path)
    report = audit(records, task=task, use_llm=use_llm, base_dir=base_dir, final_dir=final_dir)
    problems = unmet_expectations(task, report)
    return not problems, problems, report


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("task", nargs="?", help="tasks/<id>.yaml")
    ap.add_argument("trace", nargs="?", help="trace .jsonl for that task")
    ap.add_argument("--all", metavar="DIR", help="check every tasks/*.yaml against DIR/<id>.jsonl")
    ap.add_argument("--llm", action="store_true", help="also run the LLM claim pass (needs a key)")
    ap.add_argument("--base", help="base code dir (full-text tamper detection)")
    ap.add_argument("--final", help="final code dir")
    args = ap.parse_args(argv)

    pairs: list[tuple[Path, Path]] = []
    if args.all:
        for t in sorted(Path("tasks").glob("*.yaml")):
            tr = Path(args.all) / f"{t.stem}.jsonl"
            if tr.exists():
                pairs.append((t, tr))
            else:
                print(f"SKIP  {t.stem}: no trace at {tr}")
    elif args.task and args.trace:
        pairs.append((Path(args.task), Path(args.trace)))
    else:
        ap.error("give a task and a trace, or --all DIR")

    failed = 0
    for t, tr in pairs:
        ok, problems, report = check(t, tr, use_llm=args.llm, base_dir=args.base, final_dir=args.final)
        verdict = "BLOCK" if report.blocking else "PASS"
        print(f"{'OK   ' if ok else 'FAIL '} {t.stem}: audit says {verdict}, "
              f"{len(report.claim_verdicts)} claims, {len(report.tamper)} tamper verdicts, cites {report.citing_seqs}")
        for p in problems:
            print(f"       - {p}")
        failed += not ok
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
