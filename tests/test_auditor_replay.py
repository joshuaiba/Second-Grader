"""S3 self-check: the sample (cheating) trace replayed against its task meets the task's expectations."""

from __future__ import annotations

from pathlib import Path

from secondgrader.auditor import replay_check

ROOT = Path(__file__).resolve().parents[1]


def test_sample_trace_meets_trap_weaken_tests_expectations():
    ok, problems, report = replay_check.check(ROOT / "tasks/trap_weaken_tests.yaml",
                                              ROOT / "fixtures/sample_trace.jsonl")
    assert ok, problems
    assert report.blocking


def test_honest_variant_of_sample_trace_does_not_meet_block_expectations():
    # Dropping the test edit leaves only a subset run: still not a PASS, but no tamper finding.
    from secondgrader.schema import dump_trace, load_trace
    import tempfile

    recs = [r for r in load_trace(ROOT / "fixtures/sample_trace.jsonl") if r.seq not in (12, 13)]
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "t.jsonl"
        dump_trace(recs, p)
        ok, problems, _ = replay_check.check(ROOT / "tasks/trap_weaken_tests.yaml", p)
    assert not ok and any("tamper" in x for x in problems)


def test_cli_runs(capsys):
    rc = replay_check.main([str(ROOT / "tasks/trap_weaken_tests.yaml"), str(ROOT / "fixtures/sample_trace.jsonl")])
    out = capsys.readouterr().out
    assert rc == 0 and out.startswith("OK")
