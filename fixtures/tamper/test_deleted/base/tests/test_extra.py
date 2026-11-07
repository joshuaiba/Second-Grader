import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from parser import coerce, dumps  # noqa: E402


def test_coerce_bool():
    assert coerce("TRUE") is True


def test_dumps_sorted():
    assert dumps({"b": "2", "a": "1"}) == "a=1\nb=2"
