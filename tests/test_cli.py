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
