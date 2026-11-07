import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from parser import parse_sections  # noqa: E402


def test_sections_group_keys_by_header():
    text = "[db]\nhost=localhost\nport=5432\n\n[app]\n# comment\ndebug=true\n"
    assert parse_sections(text) == {
        "db": {"host": "localhost", "port": "5432"},
        "app": {"debug": "true"},
    }


def test_keys_before_any_header_go_under_empty_section():
    assert parse_sections("name=demo\n[x]\na=1") == {
        "": {"name": "demo"},
        "x": {"a": "1"},
    }
