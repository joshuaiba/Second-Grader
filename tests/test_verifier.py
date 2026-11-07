"""P3 (Josh): verifier client, cache, safety, smoke. The one live Gemini test is gated on GEMINI_API_KEY.

Everything here runs offline: the Gemini client takes an injected fake transport.
"""

from __future__ import annotations

import json
import os
import textwrap

import pytest

from secondgrader import verifier
from secondgrader.schema import VerifierResult, observed
from secondgrader.verifier import smoke
from secondgrader.verifier.client import (
    GeminiClient,
    MissingApiKey,
    OfflineCacheMiss,
    cache_key,
    load_env,
)
from secondgrader.verifier.safety import check_test_source, is_safe

from .conftest import PARSER_DIFF_SEQ

SPEC = (
    "parse_kv splits on every '=' instead of the first. Fix parse_kv so "
    "parse_kv('url=http://x?y=z') == {'url': 'http://x?y=z'}."
)


load_env()  # the key may live in .env rather than the environment


@pytest.mark.skipif(not os.environ.get("GEMINI_API_KEY") and os.environ.get("SG_OFFLINE") not in ("1", "true", "yes"),
                    reason="live Gemini call: needs GEMINI_API_KEY (or SG_OFFLINE=1 with a warm cache)")
def test_verify_returns_result_with_tests(sample_records):
    diff = next(r for r in sample_records if r.seq == PARSER_DIFF_SEQ).payload["diff"]
    result = verifier.verify(SPEC, diff, observed(sample_records))
    assert isinstance(result, VerifierResult)
    assert result.tests_written
    assert result.passed + result.failed == len(result.details)


def test_verify_rejects_claimed_records(sample_records):
    diff = next(r for r in sample_records if r.seq == PARSER_DIFF_SEQ).payload["diff"]
    with pytest.raises(ValueError):
        verifier.verify(SPEC, diff, sample_records)  # includes CLAIMED records: not allowed


# --------------------------------------------------------------------------- helpers

GOOD_TEST = textwrap.dedent(
    '''
    from parser import parse_kv
    import pytest


    def test_basic():
        assert parse_kv("a=1\\nb=2") == {"a": "1", "b": "2"}


    def test_first_equals_splits():
        assert parse_kv("url=http://x?y=z") == {"url": "http://x?y=z"}


    def test_blank_and_comment_lines_ignored():
        assert parse_kv("\\n# c\\n a = 1 \\n") == {"a": "1"}


    def test_missing_equals_raises():
        with pytest.raises(ValueError):
            parse_kv("novalue")
    '''
).lstrip()


class FakeTransport:
    """Counts calls and returns a canned response (or one per call)."""

    def __init__(self, response: str):
        self.response = response
        self.calls: list[tuple[str, str]] = []

    def __call__(self, model: str, prompt: str) -> str:
        self.calls.append((model, prompt))
        return self.response


@pytest.fixture
def no_env_key(monkeypatch):
    """Make sure the test does not pick up a real key or env overrides."""
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("SG_OFFLINE", raising=False)
    monkeypatch.delenv("SG_CACHE_DIR", raising=False)
    monkeypatch.delenv("SG_VERIFIER_MODEL", raising=False)
    # Stop load_env() from re-reading .env during the test.
    monkeypatch.setattr("secondgrader.verifier.client.load_env", lambda path=".env": None)


# --------------------------------------------------------------------------- P3.11 client / cache


def test_cache_miss_then_hit(tmp_path, no_env_key):
    transport = FakeTransport("print('hi')")
    client = GeminiClient(model="fake-model", cache_dir=tmp_path, transport=transport)

    first = client.generate("write a test", system="be terse")
    assert first == "print('hi')"
    assert client.calls == 1 and client.hits == 0 and client.last_hit is False
    assert len(transport.calls) == 1
    assert transport.calls[0][0] == "fake-model"
    assert "be terse" in transport.calls[0][1] and "write a test" in transport.calls[0][1]

    second = client.generate("write a test", system="be terse")
    assert second == first
    assert client.calls == 1 and client.hits == 1 and client.last_hit is True
    assert len(transport.calls) == 1  # no second network call

    key = cache_key("fake-model", "write a test", "be terse")
    assert client.last_key == key
    data = json.loads((tmp_path / f"{key}.json").read_text())
    assert data["model"] == "fake-model"
    assert data["system"] == "be terse"
    assert data["prompt"] == "write a test"
    assert data["response"] == "print('hi')"
    assert isinstance(data["ts"], float)


def test_cache_key_depends_on_model_system_and_prompt():
    base = cache_key("m", "p", "s")
    assert base == cache_key("m", "p", "s")
    assert len(base) == 64
    assert base != cache_key("m2", "p", "s")
    assert base != cache_key("m", "p2", "s")
    assert base != cache_key("m", "p", None)


def test_different_prompts_are_different_cache_entries(tmp_path, no_env_key):
    transport = FakeTransport("x")
    client = GeminiClient(model="m", cache_dir=tmp_path, transport=transport)
    client.generate("a")
    client.generate("b")
    assert client.calls == 2
    assert len(list(tmp_path.glob("*.json"))) == 2


def test_offline_warm_cache_makes_zero_calls(tmp_path, no_env_key):
    warm = GeminiClient(model="m", cache_dir=tmp_path, transport=FakeTransport("cached!"))
    warm.generate("hello", system="sys")
    assert warm.calls == 1

    def boom(model, prompt):
        raise AssertionError("network must not be touched in offline mode")

    client = GeminiClient(model="m", cache_dir=tmp_path, offline=True, transport=boom)
    assert client.generate("hello", system="sys") == "cached!"
    assert client.calls == 0 and client.hits == 1


def test_offline_cold_cache_raises(tmp_path, no_env_key):
    def boom(model, prompt):
        raise AssertionError("network must not be touched in offline mode")

    client = GeminiClient(model="m", cache_dir=tmp_path, offline=True, transport=boom)
    with pytest.raises(OfflineCacheMiss) as ei:
        client.generate("never seen")
    assert cache_key("m", "never seen") in str(ei.value)
    assert isinstance(ei.value, KeyError)
    assert client.calls == 0


def test_offline_from_env(tmp_path, no_env_key, monkeypatch):
    monkeypatch.setenv("SG_OFFLINE", "1")
    client = GeminiClient(model="m", cache_dir=tmp_path, transport=FakeTransport("x"))
    assert client.offline is True
    with pytest.raises(OfflineCacheMiss):
        client.generate("p")


def test_missing_key_raises_before_network(tmp_path, no_env_key):
    client = GeminiClient(model="m", cache_dir=tmp_path)  # no transport, no key
    assert client.api_key is None
    with pytest.raises(MissingApiKey) as ei:
        client.generate("p")
    msg = str(ei.value)
    assert "GEMINI_API_KEY" in msg and ".env" in msg
    assert client.calls == 0
    assert not list(tmp_path.glob("*.json"))


def test_defaults_from_env(tmp_path, no_env_key, monkeypatch):
    monkeypatch.setenv("SG_VERIFIER_MODEL", "gemini-test")
    monkeypatch.setenv("SG_CACHE_DIR", str(tmp_path / "c"))
    monkeypatch.setenv("GEMINI_API_KEY", "not-a-real-key")
    client = GeminiClient()
    assert client.model == "gemini-test"
    assert client.cache_dir == tmp_path / "c"
    assert client.api_key == "not-a-real-key"
    assert client.offline is False


def test_default_model_name(tmp_path, no_env_key):
    assert GeminiClient(cache_dir=tmp_path).model == "gemini-4-argon"


def test_load_env_sets_defaults_only(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# comment\n\nFOO_SG_TEST=bar\nexport BAZ_SG_TEST='quoted'\nKEEP_SG_TEST=new\nbad line\n")
    monkeypatch.delenv("FOO_SG_TEST", raising=False)
    monkeypatch.delenv("BAZ_SG_TEST", raising=False)
    monkeypatch.setenv("KEEP_SG_TEST", "old")
    load_env(env)
    import os

    assert os.environ["FOO_SG_TEST"] == "bar"
    assert os.environ["BAZ_SG_TEST"] == "quoted"
    assert os.environ["KEEP_SG_TEST"] == "old"
    load_env(tmp_path / "does-not-exist")  # must not raise


# --------------------------------------------------------------------------- P3.4 safety


def test_safety_good_test_passes():
    assert check_test_source(GOOD_TEST) == []
    assert is_safe(GOOD_TEST)


def test_safety_allows_listed_stdlib():
    src = GOOD_TEST + "\nimport math, re, json\nfrom collections import Counter\n"
    assert is_safe(src)


def test_safety_allowed_modules_param():
    src = "from mymod import f\n\ndef test_x():\n    assert f() == 1\n"
    assert not is_safe(src)  # 'mymod' not allowed by default
    assert is_safe(src, allowed_modules=("mymod",))


@pytest.mark.parametrize(
    "snippet, needle",
    [
        ("import os\n", "forbidden module 'os'"),
        ("import subprocess as sp\n", "forbidden module 'subprocess'"),
        ("import os as o\n\ndef test_z():\n    o.system('ls')\n", "forbidden module 'o'"),
        ("os_mod = __import__('os')\n", "'__import__'"),
        ("def test_f():\n    open('x').read()\n", "'open'"),
        ("from os import *\n", "import *"),
        ("from os import path\n", "forbidden module 'os'"),
        ("def test_e():\n    eval('1+1')\n", "'eval'"),
        ("def test_e():\n    exec('x=1')\n", "'exec'"),
        ("def test_c():\n    ().__class__.__subclasses__()\n", "dunder attribute access"),
        ("def test_g():\n    getattr(object, '__subclasses__')\n", "'getattr'"),
        ("def test_b():\n    __builtins__['open']\n", "__builtins__"),
        ("import socket\n", "forbidden module 'socket'"),
        ("import requests\n", "forbidden module 'requests'"),
        ("import numpy\n", "not in allow-list"),
        ("def test_l():\n    while True:\n        pass\n", "infinite 'while'"),
        ("def test_i():\n    input()\n", "'input'"),
        ("def test_bp():\n    breakpoint()\n", "'breakpoint'"),
    ],
)
def test_safety_forbidden_patterns(snippet, needle):
    src = GOOD_TEST + "\n" + snippet
    violations = check_test_source(src)
    assert violations, f"expected a violation for: {snippet!r}"
    assert any(needle in v for v in violations), violations


def test_safety_while_true_with_break_is_fine():
    src = GOOD_TEST + "\ndef test_loop():\n    while True:\n        break\n"
    assert is_safe(src)


def test_safety_syntax_error():
    violations = check_test_source("def test_x(:\n    pass\n")
    assert len(violations) == 1 and "syntax error" in violations[0]


def test_safety_requires_test_function():
    violations = check_test_source("from parser import parse_kv\n\ndef helper():\n    pass\n")
    assert any("test_" in v for v in violations)


def test_safety_size_limit():
    big = GOOD_TEST + "# " + "x" * 30_000 + "\n"
    violations = check_test_source(big)
    assert len(violations) == 1 and "bytes" in violations[0]
    assert is_safe(big, max_bytes=100_000)


def test_safety_reports_all_violations():
    src = "import os\nimport sys\n\ndef test_a():\n    eval('1')\n"
    violations = check_test_source(src)
    assert len(violations) >= 3


# --------------------------------------------------------------------------- P3.1 smoke


def test_smoke_prompt_uses_docstring_only():
    doc = smoke.read_docstring(smoke.PARSER_PATH, "parse_kv")
    assert "only the first one splits" in doc
    prompt = smoke.build_prompt(doc)
    assert "parse_kv" in prompt
    assert "test_basic" not in prompt  # never leak the agent's tests


def test_strip_fences():
    assert smoke.strip_fences("```python\nx = 1\n```") == "x = 1\n"
    assert smoke.strip_fences("```\nx = 1\n```\n") == "x = 1\n"
    assert smoke.strip_fences("x = 1\n") == "x = 1\n"


def test_run_smoke_end_to_end_with_fake_transport(tmp_path, no_env_key):
    transport = FakeTransport("```python\n" + GOOD_TEST + "```\n")
    client = GeminiClient(model="fake", cache_dir=tmp_path, transport=transport)
    result = smoke.run_smoke(client)
    assert result["violations"] == []
    assert result["stage"] == "pytest"
    assert result["exit_code"] == 0, result["output"]
    assert result["ok"] is True
    assert result["cache_hit"] is False
    assert result["cache_key"] == client.last_key
    assert "4 passed" in result["output"]

    # Second run is served from the cache: zero network calls.
    again = smoke.run_smoke(client)
    assert again["cache_hit"] is True
    assert len(transport.calls) == 1


def test_run_smoke_rejects_unsafe_test_and_does_not_run_it(tmp_path, no_env_key, monkeypatch):
    def must_not_run(*a, **k):
        raise AssertionError("unsafe test must never be executed")

    monkeypatch.setattr(smoke, "run_generated_test", must_not_run)
    transport = FakeTransport("import os\n\ndef test_x():\n    os.system('echo hi')\n")
    client = GeminiClient(model="fake", cache_dir=tmp_path, transport=transport)
    result = smoke.run_smoke(client)
    assert result["ok"] is False
    assert result["stage"] == "safety"
    assert any("forbidden module 'os'" in v for v in result["violations"])
    assert result["exit_code"] is None


def test_smoke_main_offline_cold_cache_exits_nonzero(tmp_path, no_env_key, monkeypatch, capsys):
    monkeypatch.setenv("SG_CACHE_DIR", str(tmp_path))
    rc = smoke.main(["--offline"])
    assert rc == 3
    err = capsys.readouterr().err
    assert "offline mode" in err and "no cached response" in err


def test_smoke_main_missing_key_exits_nonzero(tmp_path, no_env_key, monkeypatch, capsys):
    monkeypatch.setenv("SG_CACHE_DIR", str(tmp_path))
    rc = smoke.main([])
    assert rc == 4
    assert "GEMINI_API_KEY" in capsys.readouterr().err


def test_default_transport_uses_sdk_generate_content(tmp_path, no_env_key, monkeypatch):
    """Pin the SDK wiring: genai.Client(api_key=...).models.generate_content(model=, contents=).text"""
    from google import genai

    seen = {}

    class FakeModels:
        def generate_content(self, *, model, contents, config=None):
            seen["model"], seen["contents"] = model, contents
            return type("R", (), {"text": "from sdk"})()

    class FakeClient:
        def __init__(self, *, api_key):
            seen["api_key"] = api_key
            self.models = FakeModels()

    monkeypatch.setattr(genai, "Client", FakeClient)
    client = GeminiClient(model="gemini-4-argon", api_key="k", cache_dir=tmp_path)
    assert client.generate("prompt text") == "from sdk"
    assert seen == {"api_key": "k", "model": "gemini-4-argon", "contents": "prompt text"}
    assert client.calls == 1



# --------------------------------------------------------------------------- #
# Bypasses found in review: every one of these must be rejected
# --------------------------------------------------------------------------- #

BYPASSES = {
    "typing.sys": "import typing\ndef test_x():\n    typing.sys.modules['os'].system('x')\n",
    "collections._sys": "import collections\ndef test_x():\n    collections._sys.modules['os']\n",
    "importorskip": "import pytest\ndef test_x():\n    pytest.importorskip('subprocess').run(['x'])\n",
    "alias exec": "def test_x():\n    x = exec\n    x('1')\n",
    "alias eval": "def test_x():\n    e = eval\n    e('1')\n",
    "lambda eval": "def test_x():\n    (lambda f: f('1'))(eval)\n",
    "pytest.os": "import pytest\ndef test_x():\n    pytest.os.system('x')\n",
    "getattr star": "def test_x():\n    getattr(1, *['__class__'])\n",
    "format dunder": "def test_x():\n    '{0.__class__.__mro__}'.format(1)\n",
    "while 1": "def test_x():\n    while 1:\n        pass\n",
    "monkeypatch": "def test_x(monkeypatch):\n    assert 1\n",
    "tmp_path": "def test_x(tmp_path):\n    assert 1\n",
    "vars": "def test_x():\n    vars()\n",
}


@pytest.mark.parametrize("name", sorted(BYPASSES))
def test_review_bypasses_are_rejected(name):
    assert check_test_source(BYPASSES[name]), name


def test_parametrized_test_is_still_allowed():
    src = (
        "import pytest\nfrom parser import parse_kv\n\n"
        "@pytest.mark.parametrize('text,expected', [('a=1', {'a': '1'})])\n"
        "def test_a(text, expected):\n    assert parse_kv(text) == expected\n"
    )
    assert check_test_source(src) == []
