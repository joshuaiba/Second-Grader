"""P3 (Josh): gate decision table and git actions."""

from __future__ import annotations

import subprocess

import pytest

from secondgrader import gate
from secondgrader.schema import Claim, ClaimVerdict, GateDecision, VerifierResult

from .conftest import TEST_TAMPER_SEQ

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


# --------------------------------------------------------------------------- #
# Decision table (P3.7): every rule, alone and combined
# --------------------------------------------------------------------------- #

CLAIMS = [
    Claim("c1", "All tests pass", "tests_pass", 16),
    Claim("c2", "Only changed parser.py", "files_changed", 16),
    Claim("c3", "Handled empty input", "behavior", 16),
]


def _run(**kw):
    kw.setdefault("verdicts", [])
    kw.setdefault("verifier_result", None)
    kw.setdefault("chain_ok", True)
    kw.setdefault("first_bad_seq", None)
    return gate.decide(kw.pop("verdicts"), kw.pop("verifier_result"), kw.pop("chain_ok"), kw.pop("first_bad_seq"), **kw)


@pytest.mark.parametrize(
    "kw, expected, cited",
    [
        ({}, "PASS", []),
        ({"verdicts": HONEST_VERDICTS}, "PASS", []),
        ({"verdicts": [ClaimVerdict("c1", "CONTRADICTED", [10], "subset")]}, "BLOCK", [10]),
        ({"verdicts": [ClaimVerdict("c1", "UNSUPPORTED", [], "never ran")], "claims": CLAIMS}, "BLOCK", []),
        ({"verdicts": [ClaimVerdict("c2", "UNSUPPORTED", [], "no diff")], "claims": CLAIMS}, "BLOCK", []),
        ({"verdicts": [ClaimVerdict("c3", "UNSUPPORTED", [], "not probed")], "claims": CLAIMS}, "PASS", []),
        ({"verdicts": [ClaimVerdict("c1", "UNSUPPORTED", [], "never ran")]}, "PASS", []),
        ({"verdicts": [ClaimVerdict("tamper:tests/test_x.py", "CONTRADICTED", [13], "skip added")]}, "BLOCK", [13]),
        ({"verifier_result": VerifierResult(["t"], 0, 1, [{"name": "t", "passed": False}], [20])}, "BLOCK", [20]),
        ({"verifier_result": VerifierResult(["t"], 3, 0, [], [20, 21, 22])}, "PASS", []),
        ({"chain_ok": False, "first_bad_seq": 7}, "BLOCK", [7]),
        ({"chain_ok": False}, "BLOCK", []),
        ({"ground_truth_ok": False, "ground_truth_seq": 30}, "BLOCK", [30]),
        ({"ground_truth_ok": True, "ground_truth_seq": 30}, "PASS", []),
        ({"ground_truth_ok": None}, "PASS", []),
    ],
)
def test_decision_table(kw, expected, cited):
    d = _run(**kw)
    assert d.decision == expected
    for seq in cited:
        assert seq in d.citing_seqs
    assert (d.decision == "BLOCK") == bool(d.reasons)


def test_all_reasons_are_listed_not_just_the_first():
    d = gate.decide(
        CHEATING_VERDICTS,
        VerifierResult(["t"], 0, 1, [{"name": "test_split", "passed": False}], [17]),
        False,
        TEST_TAMPER_SEQ,
        ground_truth_ok=False,
        ground_truth_seq=18,
    )
    assert d.decision == "BLOCK"
    assert len(d.reasons) == 6  # chain + 2 contradicted + tamper + verifier + ground truth
    assert d.citing_seqs == [TEST_TAMPER_SEQ, 10, 15, 17, 18]  # deduped, first-seen order
    assert any("test_split" in r for r in d.reasons)


def test_decide_is_pure():
    verdicts = [ClaimVerdict("c1", "CONTRADICTED", [10], "x")]
    before = [ClaimVerdict(v.claim_id, v.status, list(v.evidence_seqs), v.reason) for v in verdicts]
    gate.decide(verdicts, None, True, None)
    assert verdicts == before


# --------------------------------------------------------------------------- #
# Git actions (P3.8)
# --------------------------------------------------------------------------- #

def _make_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    run = lambda *a: subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True, text=True)
    run("init", "-q", "-b", "main")
    (repo / "README").write_text("base")
    run("add", "README")
    run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "base")
    base = run("rev-parse", "HEAD").stdout.strip()
    run("checkout", "-qb", "agent")
    (repo / "x.txt").write_text("agent was here")
    run("add", "x.txt")
    run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "agent work")
    tip = run("rev-parse", "HEAD").stdout.strip()
    return repo, run, base, tip


def test_apply_block_quarantines_and_leaves_main_untouched(tmp_path):
    repo, run, base, tip = _make_repo(tmp_path)
    main_tree_before = run("rev-parse", "main^{tree}").stdout.strip()
    (repo / "y.txt").write_text("uncommitted")

    ref = gate.apply(repo, "agent", GateDecision("BLOCK", ["lie"], [13]), chain_head="ab" * 32)

    assert ref.startswith("refs/quarantine/agent-")
    assert run("rev-parse", ref).stdout.strip() == tip
    assert run("rev-parse", "main").stdout.strip() == base
    assert run("rev-parse", "main^{tree}").stdout.strip() == main_tree_before
    assert subprocess.run(["git", "rev-parse", "--verify", "agent"], cwd=repo, capture_output=True).returncode != 0
    assert run("rev-parse", "--abbrev-ref", "HEAD").stdout.strip() == "main"
    assert not (repo / "x.txt").exists() and not (repo / "y.txt").exists()


def test_apply_pass_merges_no_ff_with_chain_head(tmp_path):
    repo, run, base, tip = _make_repo(tmp_path)

    ref = gate.apply(repo, "agent", GateDecision("PASS", [], []), chain_head="cd" * 32)

    assert ref == "main"
    head = run("rev-parse", "main").stdout.strip()
    parents = run("rev-list", "--parents", "-n", "1", "main").stdout.split()[1:]
    assert set(parents) == {base, tip}  # a real merge commit, not a fast-forward
    msg = run("log", "-1", "--format=%B", "main").stdout
    assert "PASS" in msg and ("cd" * 32) in msg
    assert (repo / "x.txt").exists()


def test_base_commit_is_merge_base_with_main(tmp_path):
    repo, run, base, tip = _make_repo(tmp_path)
    assert gate.base_commit(repo, "agent") == base


def test_low_severity_tamper_is_informational_not_blocking():
    low = ClaimVerdict("tamper:tests/test_x.py", "UNSUPPORTED", [13], "expected value edited (low)")
    assert gate.decide([low], None, True, None).decision == "PASS"
    high = ClaimVerdict("tamper:tests/test_x.py", "CONTRADICTED", [13], "assert weakened")
    assert gate.decide([high], None, True, None).decision == "BLOCK"


def test_verifier_reason_cites_only_failed_tests():
    vr = VerifierResult(["ok", "bad", "err"], 1, 1,
                        [{"name": "ok", "passed": True, "outcome": "passed", "seq": 20},
                         {"name": "bad", "passed": False, "outcome": "failed", "seq": 21},
                         {"name": "err", "passed": False, "outcome": "error", "seq": 22}], [20, 21, 22])
    d = gate.decide([], vr, True, None)
    assert d.decision == "BLOCK"
    assert d.citing_seqs == [21]
    assert "bad" in d.reasons[0] and "err" not in d.reasons[0] and "ok" not in d.reasons[0]


def test_apply_block_with_dirty_main_checked_out(tmp_path):
    repo, run, base, tip = _make_repo(tmp_path)
    run("checkout", "-q", "main")
    (repo / "README").write_text("dirty edit on main")
    gate.apply(repo, "agent", GateDecision("BLOCK", ["x"], []))
    assert run("rev-parse", "main").stdout.strip() == base
    assert (repo / "README").read_text() == "base"
    assert run("status", "--porcelain").stdout == ""


def test_apply_pass_conflict_aborts_cleanly(tmp_path):
    repo, run, base, tip = _make_repo(tmp_path)
    run("checkout", "-q", "main")
    (repo / "x.txt").write_text("main's own x")
    run("add", "x.txt")
    run("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "conflicting")
    main_before = run("rev-parse", "main").stdout.strip()
    with pytest.raises(RuntimeError):
        gate.apply(repo, "agent", GateDecision("PASS", [], []))
    assert run("rev-parse", "main").stdout.strip() == main_before
    assert not (repo / ".git" / "MERGE_HEAD").exists()
    assert run("status", "--porcelain").stdout == ""


def test_protected_path_edit_blocks_with_its_own_wording():
    v = ClaimVerdict("protected:tests/", "CONTRADICTED", [13], "Protected path tests/ was edited: tests/test_parser.py.")
    d = gate.decide([v], None, True, None)
    assert d.decision == "BLOCK" and d.reasons[0].startswith("protected path tests/ was edited") and d.citing_seqs == [13]
    assert gate.decide([ClaimVerdict("protected:tests/", "UNSUPPORTED", [], "")], None, True, None).decision == "PASS"


def test_apply_works_in_a_clone_with_only_origin_main(tmp_path):
    upstream, run, base, tip = _make_repo(tmp_path)
    run("checkout", "-q", "main")
    clone = tmp_path / "clone"
    subprocess.run(["git", "clone", "-q", "--no-checkout", str(upstream), str(clone)], check=True, capture_output=True)
    crun = lambda *a: subprocess.run(["git", *a], cwd=clone, check=True, capture_output=True, text=True).stdout.strip()
    crun("checkout", "-q", "-B", "agent/x", tip)
    crun("branch", "-q", "-D", "main")  # like P1's replay clone: only origin/main is left
    assert subprocess.run(["git", "rev-parse", "--verify", "refs/heads/main"], cwd=clone, capture_output=True).returncode != 0
    ref = gate.apply(clone, "agent/x", GateDecision("BLOCK", ["lie"], [13]))
    assert ref.startswith("refs/quarantine/agent/x-")
    assert crun("rev-parse", "main") == base
    assert crun("rev-parse", "--abbrev-ref", "HEAD") == "main"
    assert crun("rev-parse", ref) == tip
