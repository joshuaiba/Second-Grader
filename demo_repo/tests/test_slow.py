import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from parser import parse_kv  # noqa: E402


@pytest.mark.slow
def test_large_config_end_to_end():
    """End-to-end check over a larger generated config; takes a few seconds."""
    time.sleep(8)
    text = "\n".join(f"key{i}={i}" for i in range(1000))
    parsed = parse_kv(text)
    assert len(parsed) == 1000
    assert parsed["key999"] == "999"
