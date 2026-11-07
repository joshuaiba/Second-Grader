"""P2.5: LLM claim extraction with verbatim quotes. No network: a FakeLLM
returns canned JSON and the real providers are never constructed."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from secondgrader.auditor import llm_claims
from secondgrader.auditor.llm_claims import (
    CachedLLM,
    claims_from_response,
    extract_llm_claims,
    locate_quote,
    parse_claims_json,
)
from secondgrader.auditor.types import AuditClaim
from secondgrader.schema import GENESIS_HASH, UNSIGNED, Record

from .conftest import FINAL_CLAIM_SEQ


class FakeLLM:
    """Records every prompt; answers from a dict keyed by a substring of the
    prompt, or with a single canned reply."""

    def __init__(self, reply: str | dict[str, str] = "[]") -> None:
        self.reply = reply
        self.prompts: list[str] = []

    def complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if isinstance(self.reply, dict):
            for needle, answer in self.reply.items():
                if needle in prompt:
                    return answer
            return "[]"
        return self.reply


def _msg(seq: int, text: str) -> Record:
    return Record(
        seq=seq, ts="2026-11-07T18:00:00Z", kind="model_message", origin="CLAIMED",
        payload={"text": text}, prev_hash=GENESIS_HASH, hash="x" * 64, sig=UNSIGNED,
    )


def _tool_output(seq: int, content: str) -> Record:
    return Record(
        seq=seq, ts="2026-11-07T18:00:00Z", kind="tool_output", origin="OBSERVED",
        payload={"tool": "bash", "content": content}, prev_hash=GENESIS_HASH,
        hash="y" * 64, sig=UNSIGNED,
    )


MSG = "Fixed the bug. Added validation for negative numbers in parser.py. Empty input now returns {}."


def _reply(*rows: dict) -> str:
    return json.dumps(list(rows))


# (1) valid claims come back with seq / kind / quote / extractor "llm"
def test_valid_claims_returned_with_metadata():
    fake = FakeLLM(_reply(
        {"text": "Empty input returns {}", "kind": "behavior",
         "quote": "Empty input now returns {}.", "files": []},
        {"text": "Added validation for negative numbers", "kind": "behavior",
         "quote": "Added validation for negative numbers in parser.py", "files": ["parser.py"]},
        {"text": "Bug fixed", "kind": "not-a-kind", "quote": "Fixed the bug", "files": []},
    ))
    claims = extract_llm_claims([_msg(7, MSG)], client=fake)

    assert len(claims) == 3
    assert all(isinstance(c, AuditClaim) for c in claims)
    assert all(c.source_seq == 7 for c in claims)
    assert all(c.extractor == "llm" and c.critical is False for c in claims)
    # Deterministic order by quote position; ids l<seq>-<n>.
    assert [c.id for c in claims] == ["l7-1", "l7-2", "l7-3"]
    assert [c.quote for c in claims] == [
        "Fixed the bug",
        "Added validation for negative numbers in parser.py",
        "Empty input now returns {}.",
    ]
    assert claims[0].kind == "other"  # invalid kind coerced
    assert claims[1].kind == "behavior"
    assert claims[1].files == ["parser.py"]
    assert claims[1].text == "Added validation for negative numbers"
    # Same input twice -> same ids.
    assert [c.id for c in extract_llm_claims([_msg(7, MSG)], client=fake)] == ["l7-1", "l7-2", "l7-3"]


# (2) a quote not in the text is dropped and logged
def test_unfound_quote_is_dropped_and_logged(caplog):
    fake = FakeLLM(_reply(
        {"text": "All tests pass", "kind": "tests_pass", "quote": "All tests pass", "files": []},
        {"text": "Bug fixed", "kind": "other", "quote": "Fixed the bug", "files": []},
    ))
    with caplog.at_level(logging.WARNING, logger="secondgrader.auditor"):
        claims = extract_llm_claims([_msg(7, MSG)], client=fake)

    assert [c.quote for c in claims] == ["Fixed the bug"]
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert warnings[0].name == "secondgrader.auditor"
    assert "seq 7" in warnings[0].getMessage()
    assert "All tests pass" in warnings[0].getMessage()


# (3) whitespace-normalised match is repaired to the exact substring
def test_whitespace_normalised_quote_is_repaired():
    text = "Handled   empty\ninput by returning {}.\n\nAll done."
    fake = FakeLLM(_reply(
        {"text": "Handles empty input", "kind": "behavior",
         "quote": " Handled empty input by returning {}. ", "files": []},
    ))
    claims = extract_llm_claims([_msg(3, text)], client=fake)
    assert len(claims) == 1
    assert claims[0].quote == "Handled   empty\ninput by returning {}."
    assert claims[0].quote in text

    assert locate_quote("a  b", "a b") == (0, "a  b")
    assert locate_quote("a  b", "a b c") is None
    assert locate_quote("abc", "") is None


# (4) code fences and a wrapper object are tolerated
@pytest.mark.parametrize("raw", [
    '```json\n[{"text": "Bug fixed", "kind": "other", "quote": "Fixed the bug", "files": []}]\n```',
    '```\n{"claims": [{"text": "Bug fixed", "kind": "other", "quote": "Fixed the bug"}]}\n```',
    '{"claims": [{"text": "Bug fixed", "kind": "other", "quote": "Fixed the bug"}]}',
    'Sure, here are the claims:\n[{"text": "Bug fixed", "kind": "other", "quote": "Fixed the bug"}]\nDone.',
])
def test_fences_and_wrappers_are_tolerated(raw):
    claims = claims_from_response(7, MSG, raw)
    assert [c.quote for c in claims] == ["Fixed the bug"]
    assert claims[0].files == []


def test_garbage_reply_yields_no_claims(caplog):
    with caplog.at_level(logging.WARNING, logger="secondgrader.auditor"):
        assert claims_from_response(7, MSG, "I cannot help with that.") == []
        assert claims_from_response(7, MSG, "") == []
        assert claims_from_response(7, MSG, "[]") == []
    assert parse_claims_json("[1, 2, {\"quote\": \"x\"}]") == [{"quote": "x"}]
    assert any("not parseable" in r.getMessage() for r in caplog.records)


# (5) only CLAIMED model_message records reach the LLM
def test_only_claimed_model_messages_reach_the_llm(sample_records):
    fake = FakeLLM("[]")
    extract_llm_claims(sample_records, client=fake)

    claimed_msgs = [r for r in sample_records if r.origin == "CLAIMED" and r.kind == "model_message"]
    assert len(fake.prompts) == len(claimed_msgs) == 3
    for rec, prompt in zip(claimed_msgs, fake.prompts):
        assert rec.payload["text"] in prompt

    seen = "\n".join(fake.prompts)
    # The task prompt (CLAIMED but not a model_message) is not consulted either.
    assert "Do not modify the tests" not in seen
    # Nothing from OBSERVED records: tool output, diffs, test runs.
    for rec in sample_records:
        if rec.origin != "OBSERVED":
            continue
        for key in ("content", "content_sha256", "diff", "output_tail", "command"):
            val = rec.payload.get(key)
            if isinstance(val, str) and val:
                assert val not in seen, f"OBSERVED seq {rec.seq} {key} leaked into the prompt"
    assert "AssertionError" not in seen
    assert "line.partition" not in seen

    # And an OBSERVED tool_output with text in its payload is still skipped.
    fake2 = FakeLLM("[]")
    extract_llm_claims([_tool_output(1, "SECRET TOOL OUTPUT"), _msg(2, "Done.")], client=fake2)
    assert len(fake2.prompts) == 1 and "SECRET TOOL OUTPUT" not in fake2.prompts[0]


# (6) cache hit: the inner LLM is not called again
def test_cache_hit_skips_inner_llm(tmp_path, monkeypatch):
    monkeypatch.setenv("SG_CACHE_DIR", str(tmp_path))
    fake = FakeLLM(_reply({"text": "Bug fixed", "kind": "other", "quote": "Fixed the bug"}))
    cached = CachedLLM(fake)
    assert cached.cache_dir == tmp_path

    first = extract_llm_claims([_msg(7, MSG), _msg(9, "Fixed the bug again.")], client=cached)
    assert len(fake.prompts) == 2
    second = extract_llm_claims([_msg(7, MSG), _msg(9, "Fixed the bug again.")], client=cached)
    assert len(fake.prompts) == 2, "second run must be served from the cache"
    assert [c.id for c in second] == [c.id for c in first] == ["l7-1", "l9-1"]
    assert cached.hits == 2 and cached.misses == 2

    files = sorted(tmp_path.glob("*.txt"))
    assert len(files) == 2
    assert files[0].read_text() == fake.reply  # raw response text is the value

    # A different model name gives a different key even for the same prompt.
    other = CachedLLM(FakeLLM("[]"), tmp_path)
    other.model = "some-other-model"
    assert other.cache_key(fake.prompts[0]) != cached.cache_key(fake.prompts[0])


# (7) no key and no client -> [] without raising
def test_no_key_and_no_client_returns_empty(monkeypatch, tmp_path, caplog):
    monkeypatch.delenv("META_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(llm_claims, "DOTENV_PATH", tmp_path / "no-such.env")
    with caplog.at_level(logging.WARNING, logger="secondgrader.auditor"):
        assert extract_llm_claims([_msg(FINAL_CLAIM_SEQ, MSG)]) == []
    assert any("skipped" in r.getMessage() for r in caplog.records)
    with pytest.raises(RuntimeError):
        llm_claims.default_llm()


def test_load_dotenv_only_sets_unset_vars(monkeypatch, tmp_path):
    env = tmp_path / ".env"
    env.write_text('# comment\nexport ALREADY=from-file\nNEWVAR="quoted value"\nBARE=plain # trailing\n')
    monkeypatch.setenv("ALREADY", "from-env")
    monkeypatch.delenv("NEWVAR", raising=False)
    monkeypatch.delenv("BARE", raising=False)
    loaded = llm_claims.load_dotenv(env)
    assert loaded == {"NEWVAR": "quoted value", "BARE": "plain"}
    import os
    assert os.environ["ALREADY"] == "from-env"
    assert llm_claims.load_dotenv(tmp_path / "missing.env") == {}


def test_llm_failure_is_logged_not_raised(caplog):
    class Boom:
        def complete(self, prompt: str) -> str:
            raise ConnectionError("network down")

    with caplog.at_level(logging.WARNING, logger="secondgrader.auditor"):
        assert extract_llm_claims([_msg(7, MSG)], client=Boom()) == []
    assert any("LLM call failed" in r.getMessage() for r in caplog.records)
