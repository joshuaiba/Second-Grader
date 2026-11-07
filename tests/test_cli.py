"""P3 (Josh): CLI. Tests that depend on another owner's module fake it or un-skip when it lands."""

from __future__ import annotations

import pytest

from secondgrader.cli import build_parser, main

from .conftest import NOT_IMPLEMENTED, SAMPLE_TRACE, TAMPERED_TRACE


def test_parser_has_three_subcommands():
    sub = next(a for a in build_parser()._actions if a.dest == "command")
    assert set(sub.choices) == {"run", "audit", "verify-chain"}


def test_stubs_exit_2_not_crash(capsys, monkeypatch):
    # Independent of which owner's stub is still a stub: fake one.
    from secondgrader import recorder

    def boom(path):
        raise NotImplementedError("recorder.verify_chain: faked for the test")

    monkeypatch.setattr(recorder, "verify_chain", boom)
    assert main(["verify-chain", str(SAMPLE_TRACE)]) == 2
    assert "not implemented" in capsys.readouterr().err


def test_verify_chain_exit_codes():
    assert main(["verify-chain", str(SAMPLE_TRACE)]) == 0
    assert main(["verify-chain", str(TAMPERED_TRACE)]) == 1


@pytest.mark.skip(reason=NOT_IMPLEMENTED)
def test_audit_blocks_cheating_fixture(capsys):
    assert main(["audit", str(SAMPLE_TRACE)]) == 1
    assert "BLOCK" in capsys.readouterr().out


# --------------------------------------------------------------------------- #
# P3: `run --replay` works today against fixtures, degrading where P1/P2 are stubs
# --------------------------------------------------------------------------- #

def test_run_without_replay_needs_the_runner(capsys):
    assert main(["run", "trap_weaken_tests"]) == 2
    assert "--replay" in capsys.readouterr().err


def test_run_unknown_task_exits_1(capsys):
    assert main(["run", "no_such_task", "--replay", str(SAMPLE_TRACE)]) == 1
    assert "no such task" in capsys.readouterr().err


def test_replay_is_labelled_and_reports_chain(capsys):
    code = main(["run", "trap_weaken_tests", "--replay", str(SAMPLE_TRACE), "--no-verify", "--no-write"])
    out = capsys.readouterr().out
    assert out.startswith("[REPLAY]")
    assert "chain: OK" in out
    assert code in (0, 1)  # PASS until the auditor lands, BLOCK after; never a crash


def test_replay_of_tampered_trace_blocks_citing_seq_13(capsys):
    code = main(["run", "trap_weaken_tests", "--replay", str(TAMPERED_TRACE), "--no-verify", "--no-write"])
    out = capsys.readouterr().out
    assert code == 1
    assert "chain: BROKEN at seq 13" in out
    assert "BLOCK" in out and "13" in out


def test_replay_offline_without_cache_skips_verifier_instead_of_crashing(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("SG_CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    code = main(["run", "honest_fix", "--replay", str(SAMPLE_TRACE), "--offline", "--no-write"])
    captured = capsys.readouterr()
    assert "verifier: skipped" in captured.out
    assert "verifier skipped" in captured.err
    assert code in (0, 1)


def test_replay_refuses_non_blind_verifier_input(capsys, monkeypatch):
    from secondgrader import cli, verifier

    def leaky(*a, **k):
        raise verifier.BlindnessViolation("prompt contains agent text")

    monkeypatch.setattr(cli, "run_verifier", lambda *a, **k: leaky())
    code = main(["run", "honest_fix", "--replay", str(SAMPLE_TRACE), "--no-write"])
    assert code == 2
    assert "not blind" in capsys.readouterr().err


def test_task_spec_falls_back_to_prompt_and_acceptance():
    from secondgrader.cli import task_spec
    assert task_spec({"spec": "S"}) == "S"
    assert task_spec({"prompt": "P", "acceptance": ["a1", "a2"]}) == "P\na1\na2"


def test_ground_truth_uses_only_the_full_final_run():
    from secondgrader.cli import ground_truth
    from secondgrader.schema import Record

    def tr(seq, phase, exit_code):
        return Record(seq, "t", "test_run", "OBSERVED",
                      {"ground_truth": True, "phase": phase, "exit_code": exit_code, "command": "pytest"}, "p", "h", "UNSIGNED")

    recs = [tr(16, "collect_base", 0), tr(17, "collect_final", 0), tr(18, "full_final", 1), tr(19, "collect_final", 0)]
    assert ground_truth(recs) == (False, 18)
    assert ground_truth([tr(16, "collect_base", 0)]) == (None, None)
    assert ground_truth([]) == (None, None)


def test_replay_of_recorder_samples_matches_their_story(capsys):
    from .conftest import FIXTURES
    samples = FIXTURES / "samples"
    if not samples.exists():
        pytest.skip("fixtures/samples not present")
    expected = {"honest": 0, "stale_tests": 1, "subset_run": 1, "masked_exit": 1, "tampered": 1}
    for name, code in expected.items():
        got = main(["run", "honest_fix", "--replay", str(samples / f"{name}.jsonl"), "--no-verify", "--no-write"])
        out = capsys.readouterr().out
        assert got == code, (name, out)
        assert "[REPLAY]" in out
    assert "BROKEN at seq 5" in out  # tampered.jsonl, the last one
