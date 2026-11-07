"""Gate (P3, Josh): combine every verdict into PASS or BLOCK, then act on git.

:func:`decide` is a pure function. It blocks when any of these is true, and it
lists **every** reason that applies, each with the record seqs that prove it:

    - the hash chain is invalid                      -> cite first_bad_seq
    - any claim verdict is CONTRADICTED              -> cite its evidence_seqs
    - a critical claim is UNSUPPORTED                -> cite its evidence_seqs
      (critical = kind ``tests_pass`` or ``files_changed``; known only when the
      caller passes the ``claims``; an UNSUPPORTED verdict with no claim
      context never blocks on its own)
    - any tamper finding (claim_id ``tamper:<pattern>``) with status CONTRADICTED;
      an UNSUPPORTED tamper verdict is informational (low severity) and is
      shown but never blocks
    - any verifier assertion failure                 -> cite its record_seqs
    - our own ground-truth test run failed           -> cite its record seq

No LLM is involved anywhere in here. Code decides.

:func:`rollback` and :func:`apply` are the git side (P3.8): on PASS merge the
agent branch into main with ``--no-ff`` and the verdict in the message; on
BLOCK quarantine the branch under ``refs/quarantine/`` and leave main
byte-identical.
"""

from __future__ import annotations

import subprocess
import time
from pathlib import Path

from secondgrader.schema import Claim, ClaimVerdict, GateDecision, VerifierResult

#: Claim kinds whose UNSUPPORTED status blocks the merge (SPEC §2 "Critical claim").
CRITICAL_KINDS: frozenset[str] = frozenset({"tests_pass", "files_changed"})

#: Prefix the auditor uses for tamper findings' ``claim_id``.
TAMPER_PREFIX = "tamper:"
#: Prefix the auditor uses for edits to a task's protected paths.
PROTECTED_PREFIX = "protected:"


def _dedupe(seqs: list[int]) -> list[int]:
    seen: set[int] = set()
    out: list[int] = []
    for s in seqs:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _with_reason(prefix: str, reason: str) -> str:
    return f"{prefix}: {reason}" if reason else prefix


def decide(
    verdicts: list[ClaimVerdict],
    verifier_result: VerifierResult | None,
    chain_ok: bool,
    first_bad_seq: int | None,
    *,
    claims: list[Claim] | None = None,
    ground_truth_ok: bool | None = None,
    ground_truth_seq: int | None = None,
) -> GateDecision:
    """Combine auditor verdicts, verifier result, chain status and ground truth.

    Args:
        verdicts: The auditor's claim verdicts and tamper findings.
        verifier_result: The blinded verifier's result, or ``None`` if skipped
            (e.g. ``secondgrader audit``). Only assertion failures count;
            the verifier never reports its own errors as failures.
        chain_ok: Result of the recorder's chain verification.
        first_bad_seq: First record that broke the chain, if any.
        claims: The extracted claims. When given, an UNSUPPORTED verdict on a
            critical claim blocks. When omitted, UNSUPPORTED never blocks.
        ground_truth_ok: Outcome of our own full test run on the final code.
            ``None`` means it was not run (replay of an old trace, audit only).
        ground_truth_seq: The ``test_run`` record seq of that ground-truth run.
    """
    reasons: list[str] = []
    citing: list[int] = []
    kinds = {c.id: c.kind for c in (claims or [])}

    if not chain_ok:
        where = f" at seq {first_bad_seq}" if first_bad_seq is not None else ""
        reasons.append(f"trace integrity check failed{where}: records cannot be trusted")
        if first_bad_seq is not None:
            citing.append(first_bad_seq)

    for v in verdicts:
        if v.claim_id.startswith(TAMPER_PREFIX):
            if v.status != "CONTRADICTED":
                continue  # low-severity finding: shown on the page, does not block
            target = v.claim_id[len(TAMPER_PREFIX):]
            reasons.append(_with_reason(f"test tampering detected in {target}", v.reason))
            citing.extend(v.evidence_seqs)
        elif v.claim_id.startswith(PROTECTED_PREFIX):
            if v.status != "CONTRADICTED":
                continue
            reasons.append(_with_reason(f"protected path {v.claim_id[len(PROTECTED_PREFIX):]} was edited", v.reason))
            citing.extend(v.evidence_seqs)
        elif v.status == "CONTRADICTED":
            reasons.append(_with_reason(f"claim {v.claim_id} is contradicted by the record", v.reason))
            citing.extend(v.evidence_seqs)
        elif v.status == "UNSUPPORTED" and kinds.get(v.claim_id) in CRITICAL_KINDS:
            reasons.append(_with_reason(f"critical claim {v.claim_id} has no supporting evidence", v.reason))
            citing.extend(v.evidence_seqs)

    if verifier_result is not None and verifier_result.failed > 0:
        failed = [d for d in verifier_result.details
                  if d.get("outcome", "failed" if d.get("passed") is False else "passed") == "failed"]
        names = ", ".join(str(d.get("name", "?")) for d in failed) or f"{verifier_result.failed} test(s)"
        reasons.append(f"independent verifier test(s) failed: {names}")
        failed_seqs = [d["seq"] for d in failed if isinstance(d.get("seq"), int)]
        citing.extend(failed_seqs or verifier_result.record_seqs)

    if ground_truth_ok is False:
        where = f" (seq {ground_truth_seq})" if ground_truth_seq is not None else ""
        reasons.append(f"ground-truth test run on the final code failed{where}")
        if ground_truth_seq is not None:
            citing.append(ground_truth_seq)

    return GateDecision(
        decision="BLOCK" if reasons else "PASS",
        reasons=reasons,
        citing_seqs=_dedupe(citing),
        chain_ok=chain_ok,
        first_bad_seq=first_bad_seq,
    )


# --------------------------------------------------------------------------- #
# Git side (P3.8)
# --------------------------------------------------------------------------- #

def _git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-c", "user.email=gate@secondgrader", "-c", "user.name=Second Grader gate", *args],
        cwd=repo, check=check, capture_output=True, text=True,
    )


def _main_branch(repo: Path) -> str:
    for name in ("main", "master"):
        if _git(repo, "show-ref", "--verify", "--quiet", f"refs/heads/{name}", check=False).returncode == 0:
            return name
    raise RuntimeError(f"no main/master branch in {repo}")


def base_commit(repo_path: str | Path, branch: str, base_branch: str | None = None) -> str:
    """The commit the agent started from: the merge base of ``branch`` and main."""
    repo = Path(repo_path)
    base_branch = base_branch or _main_branch(repo)
    return _git(repo, "merge-base", base_branch, branch).stdout.strip()


def rollback(repo_path: str | Path, branch: str) -> None:
    """Undo the agent's work in the throwaway clone.

    Resets ``branch`` to its base commit (merge base with main) and discards
    every working-tree change, tracked or untracked. Safe to call twice.
    """
    repo = Path(repo_path)
    base = base_commit(repo, branch)
    _git(repo, "checkout", "-q", "-f", branch)
    _git(repo, "reset", "-q", "--hard", base)
    _git(repo, "clean", "-fdq")


def apply(
    repo_path: str | Path,
    branch: str,
    decision: GateDecision,
    chain_head: str | None = None,
    base_branch: str | None = None,
) -> str:
    """Act on a decision in git. Returns the ref that now holds the agent's work.

    PASS:  ``git merge --no-ff`` into main, with the verdict and chain head
           hash in the commit message. Returns the main branch name.
    BLOCK: move the agent branch tip to ``refs/quarantine/<branch>-<time>``,
           delete the agent branch, and leave main byte-identical.
           Returns the quarantine ref.
    """
    repo = Path(repo_path)
    base_branch = base_branch or _main_branch(repo)
    tip = _git(repo, "rev-parse", branch).stdout.strip()

    if decision.decision == "PASS":
        msg = [f"Merge {branch}: PASS (Second Grader)", ""]
        if chain_head:
            msg.append(f"Chain-Head: {chain_head}")
        if decision.citing_seqs:
            msg.append(f"Cited-Seqs: {', '.join(map(str, decision.citing_seqs))}")
        _git(repo, "checkout", "-q", "-f", base_branch)
        _git(repo, "reset", "-q", "--hard")
        try:
            _git(repo, "merge", "--no-ff", "-q", "-m", "\n".join(msg), branch)
        except subprocess.CalledProcessError as exc:
            _git(repo, "merge", "--abort", check=False)
            _git(repo, "reset", "-q", "--hard", check=False)
            raise RuntimeError(f"merge of {branch} into {base_branch} failed and was aborted: {exc.stderr.strip()}") from exc
        return base_branch

    quarantine = f"refs/quarantine/{branch}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}"
    _git(repo, "update-ref", quarantine, tip)
    _git(repo, "checkout", "-q", "-f", base_branch)
    _git(repo, "reset", "-q", "--hard")  # main's working tree matches main's tree exactly
    _git(repo, "clean", "-fdq")
    _git(repo, "branch", "-D", "-q", branch)
    return quarantine


__all__ = ["CRITICAL_KINDS", "PROTECTED_PREFIX", "TAMPER_PREFIX", "apply", "base_commit", "decide", "rollback"]
