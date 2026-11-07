"""Owner D (cli.py). The verify-chain test un-skips once owner A lands recorder.verify_chain."""

from __future__ import annotations

import pytest

from secondgrader.cli import build_parser, main

from .conftest import NOT_IMPLEMENTED, SAMPLE_TRACE, TAMPERED_TRACE


def test_parser_has_three_subcommands():
    sub = next(a for a in build_parser()._actions if a.dest == "command")
    assert set(sub.choices) == {"run", "audit", "verify-chain"}


def test_stubs_exit_2_not_crash(capsys):
    assert main(["audit", str(SAMPLE_TRACE)]) == 2
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
