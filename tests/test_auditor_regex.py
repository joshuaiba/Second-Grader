"""Tests for the deterministic regex claim pre-pass (auditor P2.4)."""

from __future__ import annotations

import logging

import pytest

from secondgrader.auditor.regex_claims import (
    ALL_PATTERNS,
    CRITICAL_PATTERNS,
    FAMILIES,
    extract_regex_claims,
    family_of,
)
from secondgrader.auditor.types import AuditClaim
from secondgrader.schema import GENESIS_HASH, UNSIGNED, Claim, Record, load_trace, record_hash

from .conftest import FINAL_CLAIM_SEQ, SAMPLE_TRACE


def _record(text: str, seq: int = 1, kind: str = "model_message") -> Record:
    origin = "CLAIMED" if kind in ("prompt", "model_message") else "OBSERVED"
    payload = {"text": text} if kind != "prompt" else {"task_id": "t", "text": text}
    base = {
        "seq": seq,
        "ts": "2026-11-07T18:00:00Z",
        "kind": kind,
        "origin": origin,
        "payload": payload,
        "prev_hash": GENESIS_HASH,
    }
    return Record(**base, hash=record_hash(base), sig=UNSIGNED)


# (sentence, expected list of (kind, critical, text prefix, files)); [] means no claim.
TABLE: list[tuple[str, list[tuple[str, bool, str, list[str]]]]] = [
    # --- tests_pass: positives --------------------------------------------
    ("All tests pass.", [("tests_pass", True, "all tests pass", [])]),
    ("All tests are passing now.", [("tests_pass", True, "all tests are passing", [])]),
    ("Tests pass.", [("tests_pass", True, "tests pass", [])]),
    ("The tests are passing.", [("tests_pass", True, "the tests are passing", [])]),
    ("The full test suite passes.", [("tests_pass", True, "the full test suite passes", [])]),
    ("The entire suite is green.", [("tests_pass", True, "the entire suite is green", [])]),
    ("12 tests passed.", [("tests_pass", False, "12 tests passed", [])]),  # a count: true of a subset too
    ("3/3 tests pass.", [("tests_pass", False, "3/3 tests pass", [])]),
    ("All 12 tests passed.", [("tests_pass", True, "all 12 tests passed", [])]),
    ("Everything's green now.", [("tests_pass", True, "everythings green", [])]),
    ("After making the fix, all tests pass.", [("tests_pass", True, "all tests pass", [])]),
    ("Everything passes.", [("tests_pass", True, "everything passes", [])]),
    ("All green!", [("tests_pass", True, "all green", [])]),
    ("The test suite is green.", [("tests_pass", True, "the test suite is green", [])]),
    ("CI is green.", [("tests_pass", True, "ci is green", [])]),
    ("**All tests pass** after the change.", [("tests_pass", True, "all tests pass", [])]),
    ("Fixed the failing test; all tests pass now.", [("tests_pass", True, "all tests pass", [])]),
    ("No failures.", [("tests_pass", True, "no failures", [])]),
    # --- tests_pass: negatives (must produce NO claim) ----------------------
    ("Tests do not pass.", []),
    ("Tests fail.", []),
    ("Not all tests pass.", []),
    ("All tests should pass once you install the deps.", []),
    ("All tests will pass after you rebuild.", []),
    ("All tests pass once the migration is applied.", []),
    ("Do all tests pass?", []),
    ("Let me check if all tests pass.", []),
    ("2 tests passed, 1 failed.", []),
    ("All tests pass except test_foo.", []),
    # --- tests_ran ----------------------------------------------------------
    ("I ran the full test suite.", [("tests_pass", False, "ran tests (full suite)", [])]),
    ("I ran pytest.", [("tests_pass", False, "ran tests", [])]),
    ("Ran all tests.", [("tests_pass", False, "ran tests (full suite)", [])]),
    ("I executed the tests.", [("tests_pass", False, "ran tests", [])]),
    ("I did not run the tests.", []),
    ("I ran the tests and they all pass.",
     [("tests_pass", False, "ran tests", []), ("tests_pass", True, "they all pass", [])]),
    ("I ran `pytest` and all 8 tests pass.",
     [("tests_pass", False, "ran tests", []), ("tests_pass", True, "all 8 tests pass", [])]),
    # --- files_only ---------------------------------------------------------
    ("Only changed parser.py.", [("files_changed", True, "only changed parser.py", ["parser.py"])]),
    ("I only changed parser.py.", [("files_changed", True, "only changed parser.py", ["parser.py"])]),
    ("Only modified `parser.py` and `utils.py`.",
     [("files_changed", True, "only changed parser.py, utils.py", ["parser.py", "utils.py"])]),
    ("Only changed **parser.py**.", [("files_changed", True, "only changed parser.py", ["parser.py"])]),
    ("I only touched src/foo/bar.py.",
     [("files_changed", True, "only changed src/foo/bar.py", ["src/foo/bar.py"])]),
    ("The only change is in parser.py.", [("files_changed", True, "only changed parser.py", ["parser.py"])]),
    ("The only changes are to parser.py and tests/test_parser.py.",
     [("files_changed", True, "only changed parser.py, tests/test_parser.py",
       ["parser.py", "tests/test_parser.py"])]),
    ("The only file I modified was parser.py.",
     [("files_changed", True, "only changed parser.py", ["parser.py"])]),
    ("Changes are limited to parser.py.", [("files_changed", True, "only changed parser.py", ["parser.py"])]),
    ("parser.py was the only file I changed.",
     [("files_changed", True, "only changed parser.py", ["parser.py"])]),
    # --- files_changed (plain, not critical) --------------------------------
    ("I changed parser.py and utils.py.",
     [("files_changed", False, "changed parser.py, utils.py", ["parser.py", "utils.py"])]),
    # --- files_untouched ----------------------------------------------------
    ("I didn't touch the tests.", [("files_changed", True, "did not change tests/", ["tests/"])]),
    ("I did not modify any test files.", [("files_changed", True, "did not change tests/", ["tests/"])]),
    ("I never touched tests/test_parser.py.",
     [("files_changed", True, "did not change tests/test_parser.py", ["tests/test_parser.py"])]),
    ("I haven't changed the tests.", [("files_changed", True, "did not change tests/", ["tests/"])]),
    ("No changes to parser.py.", [("files_changed", True, "did not change parser.py", ["parser.py"])]),
    ("No changes were made to the test files.",
     [("files_changed", True, "did not change tests/", ["tests/"])]),
    ("I left the tests untouched.", [("files_changed", True, "did not change tests/", ["tests/"])]),
    ("tests/test_parser.py is unchanged.",
     [("files_changed", True, "did not change tests/test_parser.py", ["tests/test_parser.py"])]),
    ("Fixed it without touching the tests.", [("files_changed", True, "did not change tests/", ["tests/"])]),
    ("As you asked, I didn't touch the tests.", [("files_changed", True, "did not change tests/", ["tests/"])]),
    # --- files: negatives ---------------------------------------------------
    ("You asked me to never touch the tests.", []),
    ("The API is unchanged.", []),
    ("I'll only change parser.py.", []),
    # --- mixed --------------------------------------------------------------
    ("Fixed the bug. All tests pass. Only changed parser.py.",
     [("tests_pass", True, "all tests pass", []),
      ("files_changed", True, "only changed parser.py", ["parser.py"])]),
]


@pytest.mark.parametrize("sentence,expected", TABLE, ids=[row[0] for row in TABLE])
def test_table(sentence: str, expected: list[tuple[str, bool, str, list[str]]]) -> None:
    claims = extract_regex_claims([_record(sentence, seq=7)])
    got = [(c.kind, c.critical, c.text, c.files) for c in claims]
    assert len(got) == len(expected), f"{sentence!r}: got {got}, expected {expected}"
    for (kind, critical, prefix, files), claim in zip(expected, claims):
        assert claim.kind == kind, (sentence, claim)
        assert claim.critical is critical, (sentence, claim)
        assert claim.text.startswith(prefix), (sentence, claim.text, prefix)
        assert claim.files == files, (sentence, claim)
        assert claim.source_seq == 7
        assert claim.extractor == "regex"
        assert claim.quote and claim.quote in sentence, (sentence, claim.quote)
        assert isinstance(claim, AuditClaim) and isinstance(claim, Claim)


def test_table_has_enough_rows() -> None:
    assert len(TABLE) >= 25
    assert sum(1 for _, exp in TABLE if not exp) >= 5, "need negative rows"


def test_sample_trace_seq_16() -> None:
    records = load_trace(SAMPLE_TRACE)
    claims = extract_regex_claims(records)

    from_final = [c for c in claims if c.source_seq == FINAL_CLAIM_SEQ]
    assert len(from_final) == 2
    tests_claim, files_claim = from_final
    assert tests_claim.kind == "tests_pass" and tests_claim.critical
    assert "all tests pass" in tests_claim.text
    assert files_claim.kind == "files_changed" and files_claim.critical
    assert "only changed parser.py" in files_claim.text
    assert files_claim.files == ["parser.py"]

    final_text = next(r for r in records if r.seq == FINAL_CLAIM_SEQ).payload["text"]
    for c in from_final:
        assert c.quote in final_text

    # Nothing from prompts or OBSERVED records; every claim comes from a model_message.
    by_seq = {r.seq: r for r in records}
    for c in claims:
        src = by_seq[c.source_seq]
        assert src.origin == "CLAIMED" and src.kind == "model_message", c
    prompt_seqs = {r.seq for r in records if r.kind == "prompt"}
    assert not any(c.source_seq in prompt_seqs for c in claims)
    # The prompt itself mentions "the whole suite passes"; it must not become a claim.
    assert all(c.source_seq != 1 for c in claims)


def test_ids_are_stable_and_unique() -> None:
    records = load_trace(SAMPLE_TRACE) + [
        _record("All tests pass. I only changed a.py. All tests pass again.", seq=99),
    ]
    first = extract_regex_claims(records)
    second = extract_regex_claims(records)
    assert [c.id for c in first] == [c.id for c in second]
    assert len({c.id for c in first}) == len(first)
    for c in first:
        assert c.id == f"r{c.source_seq}-{c.id.split('-')[1]}"
        assert c.id.startswith(f"r{c.source_seq}-")
    ids_99 = [c.id for c in first if c.source_seq == 99]
    assert ids_99 == ["r99-1", "r99-2"], ids_99  # second "all tests pass" is deduped


def test_dedupe_keeps_first_occurrence() -> None:
    claims = extract_regex_claims([_record("All tests pass! Yes, all tests pass.", seq=3)])
    assert len(claims) == 1
    assert claims[0].quote == "All tests pass"
    assert claims[0].id == "r3-1"


def test_prompt_and_observed_records_are_ignored() -> None:
    prompt = _record("All tests pass. Only changed parser.py.", seq=1, kind="prompt")
    base = {
        "seq": 2, "ts": "2026-11-07T18:00:00Z", "kind": "tool_output", "origin": "OBSERVED",
        "payload": {"tool": "bash", "content": "All tests pass. Only changed parser.py."},
        "prev_hash": GENESIS_HASH,
    }
    observed = Record(**base, hash=record_hash(base), sig=UNSIGNED)
    assert extract_regex_claims([prompt, observed]) == []


def test_missing_or_non_string_text_is_skipped() -> None:
    base = {
        "seq": 1, "ts": "2026-11-07T18:00:00Z", "kind": "model_message", "origin": "CLAIMED",
        "payload": {"text": ["not", "a", "string"]}, "prev_hash": GENESIS_HASH,
    }
    weird = Record(**base, hash=record_hash(base), sig=UNSIGNED)
    base2 = dict(base, seq=2, payload={})
    empty = Record(**base2, hash=record_hash(base2), sig=UNSIGNED)
    assert extract_regex_claims([weird, empty]) == []


def test_quote_not_found_is_dropped_and_logged(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture) -> None:
    from secondgrader.auditor import regex_claims as rc

    real_scan = rc._scan

    def fake_scan(text: str):
        hits = real_scan(text)
        return [rc._Hit(h.start, h.end, h.pattern, "FABRICATED", h.files, h.scope_full) for h in hits]

    monkeypatch.setattr(rc, "_scan", fake_scan)
    with caplog.at_level(logging.WARNING, logger="secondgrader.auditor"):
        claims = extract_regex_claims([_record("All tests pass.", seq=5)])
    assert claims == []
    assert any("quote not found verbatim" in r.getMessage() for r in caplog.records)


def test_family_of_round_trips() -> None:
    text = (
        "All tests pass. I ran the full test suite. Only changed a.py. "
        "I didn't touch the tests. I changed b.py and c.py."
    )
    claims = extract_regex_claims([_record(text)])
    fams = [family_of(c) for c in claims]
    assert fams == ["tests_pass", "tests_ran", "files_only", "files_untouched", "files_changed"]
    assert set(fams) == set(FAMILIES)
    # Works on a plain Claim too (checkers need not depend on AuditClaim).
    plain = Claim(id="x", text="ran tests (full suite)", kind="tests_pass", source_seq=1)
    assert family_of(plain) == "tests_ran"
    assert family_of(Claim(id="y", text="whatever", kind="behavior", source_seq=1)) == "other"


def test_pattern_tables_are_inspectable() -> None:
    assert CRITICAL_PATTERNS and all(p.critical for p in CRITICAL_PATTERNS)
    assert set(CRITICAL_PATTERNS) <= set(ALL_PATTERNS)
    assert {p.family for p in ALL_PATTERNS} == set(FAMILIES)
    assert all(p.kind in ("tests_pass", "files_changed") for p in ALL_PATTERNS)
