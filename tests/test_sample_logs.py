"""P1.2: the sample traces in fixtures/samples/ chain correctly and match the recorder's shape.

tampered.jsonl breaks at seq 5 (TAMPER_SEQ in fixtures/make_sample_logs.py).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from secondgrader.schema import check_hash_chain, load_trace

SAMPLES = Path(__file__).resolve().parents[1] / "fixtures" / "samples"
GOOD = ["honest", "stale_tests", "subset_run", "never_ran", "masked_exit"]

#: full_final exit code per trace: the story each one tells.
FULL_FINAL_EXIT = {"honest": 0, "stale_tests": 1, "subset_run": 1, "never_ran": 0, "masked_exit": 1}


@pytest.mark.parametrize(
    "name, expected",
    [(f"{n}.jsonl", (True, None)) for n in GOOD] + [("tampered.jsonl", (False, 5))],
)
def test_sample_log_chain(name: str, expected: tuple[bool, int | None]) -> None:
    assert check_hash_chain(load_trace(SAMPLES / name)) == expected


@pytest.mark.parametrize("name", GOOD)
def test_sample_log_shape(name: str) -> None:
    recs = load_trace(SAMPLES / f"{name}.jsonl")
    assert recs[0].kind == "prompt" and recs[0].payload["source"] == "runner"

    gt = [r for r in recs if r.payload.get("source") == "ground_truth"]
    assert [(r.kind, r.payload.get("phase")) for r in gt] == [
        ("diff", None), ("test_run", "collect_base"), ("test_run", "collect_final"),
        ("test_run", "full_final")]
    assert recs[-len(gt):] == gt, "ground truth comes last"
    claim = recs[-len(gt) - 1]
    assert claim.kind == "model_message" and claim.payload["event"] == "Stop"

    final_tree = gt[-1].payload["tree"]
    assert gt[0].payload["tree"] == gt[2].payload["tree"] == final_tree
    assert gt[-1].payload["exit_code"] == FULL_FINAL_EXIT[name]

    for i, r in enumerate(recs[:-len(gt)]):
        if r.kind == "test_run":
            assert r.payload["source"] == "agent"
            assert recs[i - 1].kind == "tool_output"
            assert recs[i - 1].payload["tool_use_id"] == r.payload["tool_use_id"]
        if r.kind == "diff":
            assert r.payload["via_tool"] and recs[i - 1].kind == "tool_output"
            assert recs[i - 1].payload["tree"] == r.payload["tree"] != r.payload["tree_before"]
        if r.kind in ("tool_output", "diff", "test_run"):
            assert len(r.payload["tree"]) == 40
