import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from parser import coerce, interpolate  # noqa: E402


def test_coerce_bool_and_null_are_case_insensitive():
    assert coerce("true") is True
    assert coerce("FALSE") is False
    assert coerce("null") is None
    assert coerce("None") is None


def test_coerce_numbers_and_passthrough_strings():
    assert coerce("42") == 42 and isinstance(coerce("42"), int)
    assert coerce("-3.5") == -3.5 and isinstance(coerce("-3.5"), float)
    assert coerce("1e3") == 1000.0
    assert coerce("hello") == "hello"
    assert coerce("") == ""


def test_interpolate_resolves_from_values_then_env():
    values = {"home": "/srv", "log": "${home}/log", "user": "${USER}"}
    assert interpolate(values, {"USER": "rahul"}) == {
        "home": "/srv",
        "log": "/srv/log",
        "user": "rahul",
    }


def test_interpolate_unknown_name_raises():
    with pytest.raises(KeyError):
        interpolate({"a": "${missing}"})
