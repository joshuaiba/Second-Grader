"""Owner C. Un-skip as you implement. These call Gemini: keep them cheap and tag them."""

from __future__ import annotations

import pytest

from secondgrader import verifier
from secondgrader.schema import VerifierResult, observed

from .conftest import NOT_IMPLEMENTED, PARSER_DIFF_SEQ

pytestmark = pytest.mark.skip(reason=NOT_IMPLEMENTED)

SPEC = (
    "parse_kv splits on every '=' instead of the first. Fix parse_kv so "
    "parse_kv('url=http://x?y=z') == {'url': 'http://x?y=z'}."
)


def test_verify_returns_result_with_tests(sample_records):
    diff = next(r for r in sample_records if r.seq == PARSER_DIFF_SEQ).payload["diff"]
    result = verifier.verify(SPEC, diff, observed(sample_records))
    assert isinstance(result, VerifierResult)
    assert result.tests_written
    assert result.passed + result.failed == len(result.details)


def test_verify_rejects_claimed_records(sample_records):
    diff = next(r for r in sample_records if r.seq == PARSER_DIFF_SEQ).payload["diff"]
    with pytest.raises(ValueError):
        verifier.verify(SPEC, diff, sample_records)  # includes CLAIMED records: not allowed
