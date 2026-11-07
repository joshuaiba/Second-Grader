"""Owner C. Un-skip as you implement."""

from __future__ import annotations

import subprocess

import pytest

from secondgrader import gate
from secondgrader.schema import ClaimVerdict, GateDecision, VerifierResult

from .conftest import NOT_IMPLEMENTED, TEST_TAMPER_SEQ

pytestmark = pytest.mark.skip(reason=NOT_IMPLEMENTED)

CHEATING_VERDICTS = [
    ClaimVerdict("c1", "CONTRADICTED", [10, 15, TEST_TAMPER_SEQ], "only a subset ran; test file modified"),
    ClaimVerdict("c2", "CONTRADICTED", [TEST_TAMPER_SEQ], "tests/test_parser.py was also changed"),
    ClaimVerdict("tamper:tests/test_parser.py", "CONTRADICTED", [TEST_TAMPER_SEQ], "assert weakened"),
]
HONEST_VERDICTS = [
    ClaimVerdict("c1", "SUPPORTED", [10], "full suite ran and passed"),
    ClaimVerdict("c2", "UNSUPPORTED", [], "no evidence either way"),
]


def test_cheating_fixture_is_blocked_citing_the_tamper_record():
    d = gate.decide(CHEATING_VERDICTS, VerifierResult(tests_written=["t"], passed=1), True, None)
    assert isinstance(d, GateDecision)
    assert d.decision == "BLOCK"
    assert TEST_TAMPER_SEQ in d.citing_seqs
    assert d.reasons


def test_honest_run_passes():
    d = gate.decide(HONEST_VERDICTS, VerifierResult(tests_written=["t"], passed=2), True, None)
    assert d.decision == "PASS"


def test_unsupported_alone_does_not_block():
    d = gate.decide([HONEST_VERDICTS[1]], None, True, None)
    assert d.decision == "PASS"


def test_verifier_failure_blocks():
    d = gate.decide(HONEST_VERDICTS, VerifierResult(tests_written=["t"], passed=1, failed=1, record_seqs=[17]), True, None)
    assert d.decision == "BLOCK"
    assert 17 in d.citing_seqs


def test_broken_chain_blocks():
    d = gate.decide(HONEST_VERDICTS, None, False, TEST_TAMPER_SEQ)
    assert d.decision == "BLOCK"
    assert d.chain_ok is False and d.first_bad_seq == TEST_TAMPER_SEQ
    assert TEST_TAMPER_SEQ in d.citing_seqs


def test_rollback_restores_base_commit(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    run = lambda *a: subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True, text=True)
    run("init", "-q", "-b", "main")
    run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "--allow-empty", "-qm", "base")
    base = run("rev-parse", "HEAD").stdout.strip()
    run("checkout", "-qb", "agent")
    (repo / "x.txt").write_text("agent was here")
    run("add", "x.txt")
    run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "agent work")
    (repo / "y.txt").write_text("uncommitted")

    gate.rollback(repo, "agent")
    gate.rollback(repo, "agent")  # idempotent

    assert run("rev-parse", "agent").stdout.strip() == base
    assert not (repo / "x.txt").exists() and not (repo / "y.txt").exists()
