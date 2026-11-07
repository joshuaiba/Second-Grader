"""Owner D. Un-skip as you implement."""

from __future__ import annotations

import pytest

from secondgrader import web
from secondgrader.schema import ClaimVerdict, GateDecision, VerifierResult

from .conftest import NOT_IMPLEMENTED, TEST_TAMPER_SEQ

pytestmark = pytest.mark.skip(reason=NOT_IMPLEMENTED)


def test_render_verdict_shows_decision_claims_and_cited_seq():
    decision = GateDecision("BLOCK", ["tests/test_parser.py was modified"], [TEST_TAMPER_SEQ], True, None)
    verdicts = [ClaimVerdict("c1", "CONTRADICTED", [TEST_TAMPER_SEQ], "test file edited before passing run")]
    html = web.render_verdict(decision, verdicts, VerifierResult(tests_written=["test_split"], passed=1))
    assert "BLOCK" in html
    assert "CONTRADICTED" in html
    assert str(TEST_TAMPER_SEQ) in html
    assert "test_split" in html


def test_app_serves_one_page():
    from fastapi.testclient import TestClient

    from secondgrader.web.app import app

    client = TestClient(app)
    r = client.get("/")
    assert r.status_code == 200
    assert "Second Grader" in r.text
