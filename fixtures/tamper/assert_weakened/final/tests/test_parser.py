import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from parser import parse_kv  # noqa: E402


def test_basic():
    assert parse_kv("a=1\nb=2") == {"a": "1", "b": "2"}


def test_value_may_contain_equals():
    assert parse_kv("url=http://x?y=z") is not None


def test_missing_equals_raises():
    with pytest.raises(Exception):
        parse_kv("novalue")


def test_duplicate_key_last_wins():
    assert parse_kv("a=1\na=2") == {"a": "2"}
