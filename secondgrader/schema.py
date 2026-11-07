"""THE SHARED CONTRACT for Second Grader.

Every module speaks in these types. Do not change this file without the
whole team agreeing (propose changes in team chat first).

Vocabulary
----------
OBSERVED  a record produced by a hook from something that really happened:
          a tool call, a tool's output, a diff, a test run.
CLAIMED   a record of something the model *said*: a prompt or model message.
          Claims are never evidence; they are what gets checked.

Hash chain
----------
Each trace is a JSONL file of :class:`Record` objects. ``record.hash`` is the
SHA-256 of the canonical JSON of the record *without* ``hash`` and ``sig``.
``record.prev_hash`` is the ``hash`` of the previous record; the first record
points at :data:`GENESIS_HASH`. ``sig`` is an Ed25519 signature over ``hash``
(or the literal string ``"UNSIGNED"`` in hand-written fixtures).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable, Literal, get_args

# --------------------------------------------------------------------------- #
# Literals
# --------------------------------------------------------------------------- #

RecordKind = Literal[
    "prompt",
    "model_message",
    "tool_call",
    "tool_output",
    "diff",
    "test_run",
    "verifier_test",
    "verdict",
]
Origin = Literal["OBSERVED", "CLAIMED"]
ClaimKind = Literal["tests_pass", "files_changed", "behavior", "other"]
ClaimStatus = Literal["SUPPORTED", "CONTRADICTED", "UNSUPPORTED"]
Decision = Literal["PASS", "BLOCK"]

RECORD_KINDS: tuple[str, ...] = get_args(RecordKind)
ORIGINS: tuple[str, ...] = get_args(Origin)
CLAIM_KINDS: tuple[str, ...] = get_args(ClaimKind)
CLAIM_STATUSES: tuple[str, ...] = get_args(ClaimStatus)
DECISIONS: tuple[str, ...] = get_args(Decision)

#: ``prev_hash`` of the first record in every trace.
GENESIS_HASH: str = "0" * 64

#: ``sig`` value used by hand-written fixtures before the recorder signs for real.
UNSIGNED: str = "UNSIGNED"

#: Which origin each record kind must carry. Model statements are CLAIMED;
#: everything a hook observes is OBSERVED.
ORIGIN_FOR_KIND: dict[str, str] = {
    "prompt": "CLAIMED",
    "model_message": "CLAIMED",
    "tool_call": "OBSERVED",
    "tool_output": "OBSERVED",
    "diff": "OBSERVED",
    "test_run": "OBSERVED",
    "verifier_test": "OBSERVED",
    "verdict": "OBSERVED",
}


# --------------------------------------------------------------------------- #
# Canonical hashing
# --------------------------------------------------------------------------- #

def canonical_json(obj: Any) -> str:
    """Serialise ``obj`` deterministically: sorted keys, no whitespace, UTF-8 kept."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def record_hash(record_without_hash_and_sig: "Record | dict[str, Any]") -> str:
    """SHA-256 hex digest of the canonical JSON of a record minus ``hash`` and ``sig``.

    Accepts either a :class:`Record` or a plain dict. If ``hash``/``sig`` keys
    are present they are ignored, so you can pass a complete record to
    recompute and compare.
    """
    if isinstance(record_without_hash_and_sig, Record):
        data = record_without_hash_and_sig.to_dict()
    else:
        data = dict(record_without_hash_and_sig)
    data.pop("hash", None)
    data.pop("sig", None)
    return hashlib.sha256(canonical_json(data).encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- #
# Records
# --------------------------------------------------------------------------- #

@dataclass
class Record:
    """One line of a trace. See module docstring for the chain rules.

    Attributes:
        seq: 1-based position in the trace. Contiguous, no gaps.
        ts: ISO-8601 timestamp with timezone, e.g. ``2026-11-07T18:00:00Z``.
        kind: What happened (see :data:`RecordKind`).
        origin: ``OBSERVED`` for hook-captured facts, ``CLAIMED`` for model text.
        payload: Kind-specific content. Conventions used by the fixtures:
            - prompt:        ``{"task_id", "text"}``
            - model_message: ``{"text"}``
            - tool_call:     ``{"tool", "args"}``
            - tool_output:   ``{"tool", "exit_code"?, "content"|"content_sha256", ...}``
            - diff:          ``{"path", "diff", "lines_added", "lines_removed"}``
            - test_run:      ``{"command", "exit_code", "passed", "failed",
                               "selected", "collected", "output_tail"}``
            - verifier_test: ``{"name", "source", "passed", "output"}``
            - verdict:       a serialised :class:`GateDecision`
        prev_hash: ``hash`` of the previous record, or :data:`GENESIS_HASH`.
        hash: :func:`record_hash` of this record.
        sig: Ed25519 signature (hex) over ``hash``, or :data:`UNSIGNED`.
    """

    seq: int
    ts: str
    kind: RecordKind
    origin: Origin
    payload: dict[str, Any]
    prev_hash: str
    hash: str
    sig: str

    def to_dict(self) -> dict[str, Any]:
        """Plain-dict form, in canonical field order."""
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Record":
        """Build a Record from a parsed JSONL line. Unknown keys are rejected."""
        allowed = {"seq", "ts", "kind", "origin", "payload", "prev_hash", "hash", "sig"}
        extra = set(data) - allowed
        if extra:
            raise ValueError(f"unknown record fields: {sorted(extra)}")
        rec = cls(**data)
        rec.validate_fields()
        return rec

    def validate_fields(self) -> None:
        """Check literal values and origin/kind consistency. Does not check hashes."""
        if self.kind not in RECORD_KINDS:
            raise ValueError(f"seq {self.seq}: unknown kind {self.kind!r}")
        if self.origin not in ORIGINS:
            raise ValueError(f"seq {self.seq}: unknown origin {self.origin!r}")
        if ORIGIN_FOR_KIND[self.kind] != self.origin:
            raise ValueError(
                f"seq {self.seq}: kind {self.kind!r} must have origin "
                f"{ORIGIN_FOR_KIND[self.kind]!r}, got {self.origin!r}"
            )
        if not isinstance(self.payload, dict):
            raise ValueError(f"seq {self.seq}: payload must be a dict")

    def to_json(self) -> str:
        """One canonical JSONL line (no trailing newline)."""
        return canonical_json(self.to_dict())


def check_hash_chain(records: Iterable[Record]) -> tuple[bool, int | None]:
    """Verify seq continuity, ``prev_hash`` linkage and every ``hash``.

    This is the *pure* chain check that any module may use on in-memory
    records. It does **not** verify signatures; that is
    :func:`secondgrader.recorder.verify_chain`'s job.

    Returns:
        ``(True, None)`` if the chain is intact, else ``(False, seq)`` where
        ``seq`` is the first record that breaks the chain.
    """
    expected_prev = GENESIS_HASH
    expected_seq = 1
    for rec in records:
        if rec.seq != expected_seq:
            return False, rec.seq
        if rec.prev_hash != expected_prev:
            return False, rec.seq
        if record_hash(rec) != rec.hash:
            return False, rec.seq
        expected_prev = rec.hash
        expected_seq += 1
    return True, None


def load_trace(path: str | Path) -> list[Record]:
    """Read a JSONL trace into Records. Blank lines are skipped. No chain check."""
    records: list[Record] = []
    with open(path, encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(Record.from_dict(json.loads(line)))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise ValueError(f"{path}:{line_no}: bad record: {exc}") from exc
    return records


def dump_trace(records: Iterable[Record], path: str | Path) -> None:
    """Write Records as canonical JSONL (one record per line)."""
    with open(path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(rec.to_json() + "\n")


def observed(records: Iterable[Record]) -> list[Record]:
    """Only the OBSERVED records. The verifier must see nothing else."""
    return [r for r in records if r.origin == "OBSERVED"]


def claimed(records: Iterable[Record]) -> list[Record]:
    """Only the CLAIMED records. The auditor extracts claims from these."""
    return [r for r in records if r.origin == "CLAIMED"]


# --------------------------------------------------------------------------- #
# Auditor types
# --------------------------------------------------------------------------- #

@dataclass
class Claim:
    """A checkable statement the agent made.

    Attributes:
        id: Stable identifier, e.g. ``"c1"``. Unique within a trace.
        text: The claim as extracted, close to the agent's words.
        kind: Which checker applies (see :data:`ClaimKind`).
        source_seq: ``seq`` of the CLAIMED record the claim came from.
    """

    id: str
    text: str
    kind: ClaimKind
    source_seq: int


@dataclass
class ClaimVerdict:
    """The auditor's finding for one claim.

    Attributes:
        claim_id: The :attr:`Claim.id` this verdict is about.
        status: SUPPORTED if observed records back it, CONTRADICTED if they
            refute it, UNSUPPORTED if nothing observed speaks to it.
        evidence_seqs: ``seq`` values of the OBSERVED records cited.
        reason: One or two human-readable sentences. Shown on the verdict page.
    """

    claim_id: str
    status: ClaimStatus
    evidence_seqs: list[int] = field(default_factory=list)
    reason: str = ""


# --------------------------------------------------------------------------- #
# Verifier types
# --------------------------------------------------------------------------- #

@dataclass
class VerifierResult:
    """Outcome of the blinded verifier's independently written tests.

    Attributes:
        tests_written: Names (or paths) of the tests the verifier authored.
        passed: Number of verifier tests that passed.
        failed: Number of verifier tests that failed.
        details: One dict per test: ``{"name", "passed", "output"}`` at least.
        record_seqs: ``seq`` values of the ``verifier_test`` records appended
            to the trace for these tests.
    """

    tests_written: list[str] = field(default_factory=list)
    passed: int = 0
    failed: int = 0
    details: list[dict[str, Any]] = field(default_factory=list)
    record_seqs: list[int] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Gate types
# --------------------------------------------------------------------------- #

@dataclass
class GateDecision:
    """Final merge decision.

    Attributes:
        decision: ``PASS`` or ``BLOCK``.
        reasons: Human-readable reasons, one per blocking finding.
        citing_seqs: ``seq`` values of the records that justify the decision.
            For a BLOCK these are the records that contradict the claims.
        chain_ok: Whether the trace's hash chain (and signatures) verified.
        first_bad_seq: First record that broke the chain, or ``None``.
    """

    decision: Decision
    reasons: list[str] = field(default_factory=list)
    citing_seqs: list[int] = field(default_factory=list)
    chain_ok: bool = True
    first_bad_seq: int | None = None


__all__ = [
    "CLAIM_KINDS",
    "CLAIM_STATUSES",
    "Claim",
    "ClaimKind",
    "ClaimStatus",
    "ClaimVerdict",
    "DECISIONS",
    "Decision",
    "GENESIS_HASH",
    "GateDecision",
    "ORIGINS",
    "ORIGIN_FOR_KIND",
    "Origin",
    "RECORD_KINDS",
    "Record",
    "RecordKind",
    "UNSIGNED",
    "VerifierResult",
    "canonical_json",
    "check_hash_chain",
    "claimed",
    "dump_trace",
    "load_trace",
    "observed",
    "record_hash",
]
