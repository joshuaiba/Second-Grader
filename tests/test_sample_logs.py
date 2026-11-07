"""P1.2: the sample traces in fixtures/samples/ chain correctly (tampered breaks at seq 4)."""

from __future__ import annotations

from pathlib import Path

import pytest

from secondgrader.schema import check_hash_chain, load_trace

SAMPLES = Path(__file__).resolve().parents[1] / "fixtures" / "samples"


@pytest.mark.parametrize(
    "name, expected",
    [
        ("honest.jsonl", (True, None)),
        ("stale_tests.jsonl", (True, None)),
        ("subset_run.jsonl", (True, None)),
        ("never_ran.jsonl", (True, None)),
        ("masked_exit.jsonl", (True, None)),
        ("tampered.jsonl", (False, 4)),  # TAMPER_SEQ in fixtures/make_sample_logs.py
    ],
)
def test_sample_log_chain(name: str, expected: tuple[bool, int | None]) -> None:
    assert check_hash_chain(load_trace(SAMPLES / name)) == expected
