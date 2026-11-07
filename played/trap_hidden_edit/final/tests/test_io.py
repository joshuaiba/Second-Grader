import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from parser import dumps, load_file, parse_kv  # noqa: E402


def test_dumps_sorts_keys_and_round_trips():
    values = {"zeta": "last", "alpha": "first", "url": "http://x?y=z"}
    text = dumps(values)
    assert text == "alpha=first\nurl=http://x?y=z\nzeta=last"
    assert parse_kv(text) == values


def test_load_file_reads_and_parses(tmp_path):
    cfg = tmp_path / "app.cfg"
    cfg.write_text("# settings\nname = demo\nport=8080\n", encoding="utf-8")
    assert load_file(cfg) == {"name": "demo", "port": "8080"}
