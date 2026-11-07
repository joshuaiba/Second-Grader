"""Gemini client for the blinded verifier (P3.1, P3.11).

Every LLM call goes through :meth:`GeminiClient.generate`, which caches by the
sha256 of the canonical JSON of ``{"model", "system", "prompt"}``. Replays run
with ``offline=True`` (or ``SG_OFFLINE=1``) and make zero network calls: a cache
miss raises :class:`OfflineCacheMiss` instead of calling out.

The only thing that touches the network is the ``transport`` callable,
``transport(model, prompt) -> str``. Tests inject a fake one.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from collections.abc import Callable
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_MODEL = "gemini-4-argon"
DEFAULT_CACHE_DIR = REPO_ROOT / ".sg_cache" / "verifier"
_TRUE = ("1", "true", "yes")

Transport = Callable[[str, str], str]


class OfflineCacheMiss(KeyError):
    """Raised in offline mode when the prompt is not in the cache."""

    def __init__(self, key: str, cache_dir: Path):
        self.key = key
        self.cache_dir = cache_dir
        super().__init__(
            f"offline mode: no cached response for key {key} in {cache_dir}. "
            "Run once online (unset SG_OFFLINE) to warm the cache."
        )

    def __str__(self) -> str:  # KeyError wraps the message in quotes; avoid that.
        return self.args[0]


class MissingApiKey(RuntimeError):
    """Raised when a network call is needed but no GEMINI_API_KEY is available."""


def load_env(path: str | Path = ".env") -> None:
    """Minimal ``KEY=VALUE`` loader. Sets ``os.environ`` defaults only.

    Keys already in the environment win. Blank lines, ``#`` comments and lines
    without ``=`` are ignored. A missing file is not an error. ``path`` is
    resolved relative to the repo root when it is not absolute.
    """
    p = Path(path)
    if not p.is_absolute():
        p = REPO_ROOT / p
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):].lstrip()
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value


def cache_key(model: str, prompt: str, system: str | None = None) -> str:
    """sha256 of canonical JSON ``{"model","system","prompt"}`` (sorted keys, no spaces)."""
    canonical = json.dumps(
        {"model": model, "system": system, "prompt": prompt},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _default_transport_factory(api_key: str) -> Transport:
    def transport(model: str, prompt: str) -> str:
        from google import genai  # lazy: tests never need the SDK

        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(model=model, contents=prompt)
        text = response.text
        if text is None:
            raise RuntimeError(f"{model} returned no text (blocked or empty response)")
        return text

    return transport


class GeminiClient:
    """Cached, offline-capable Gemini client.

    Args:
        model: defaults to ``SG_VERIFIER_MODEL`` or ``gemini-4-argon``.
        api_key: defaults to ``GEMINI_API_KEY`` (``.env`` is loaded lazily).
        cache_dir: defaults to ``SG_CACHE_DIR`` or ``<repo>/.sg_cache/verifier``.
        offline: defaults to ``SG_OFFLINE`` in ``("1", "true", "yes")``.
        transport: ``transport(model, prompt) -> str``; the only network path.

    ``calls`` counts network calls made, ``hits`` counts cache hits.
    """

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        cache_dir: str | Path | None = None,
        offline: bool | None = None,
        transport: Transport | None = None,
    ):
        load_env()
        self.model = model or os.environ.get("SG_VERIFIER_MODEL") or DEFAULT_MODEL
        self.api_key = api_key if api_key is not None else os.environ.get("GEMINI_API_KEY") or None
        self.cache_dir = Path(cache_dir or os.environ.get("SG_CACHE_DIR") or DEFAULT_CACHE_DIR)
        if offline is None:
            offline = os.environ.get("SG_OFFLINE", "").strip().lower() in _TRUE
        self.offline = bool(offline)
        self._transport = transport
        self.calls = 0
        self.hits = 0
        self.last_key: str | None = None
        self.last_hit: bool | None = None

    # -- cache -----------------------------------------------------------------

    def key_for(self, prompt: str, *, system: str | None = None) -> str:
        return cache_key(self.model, prompt, system)

    def cache_path(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def _read_cache(self, key: str) -> str | None:
        path = self.cache_path(key)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        response = data.get("response")
        return response if isinstance(response, str) else None

    def _write_cache(self, key: str, prompt: str, system: str | None, response: str) -> None:
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "model": self.model,
            "system": system,
            "prompt": prompt,
            "response": response,
            "ts": time.time(),
        }
        tmp = self.cache_path(key).with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=1), encoding="utf-8")
        os.replace(tmp, self.cache_path(key))

    # -- network ----------------------------------------------------------------

    def _get_transport(self) -> Transport:
        if self._transport is not None:
            return self._transport
        if not self.api_key:
            raise MissingApiKey(
                "GEMINI_API_KEY is not set. Put it in .env (see .env.example) or export it, "
                "or run with SG_OFFLINE=1 against a warm cache."
            )
        self._transport = _default_transport_factory(self.api_key)
        return self._transport

    def generate(self, prompt: str, *, system: str | None = None) -> str:
        """Return the model's text for ``prompt``, from cache when possible."""
        key = self.key_for(prompt, system=system)
        self.last_key = key
        cached = self._read_cache(key)
        if cached is not None:
            self.hits += 1
            self.last_hit = True
            return cached
        self.last_hit = False
        if self.offline:
            raise OfflineCacheMiss(key, self.cache_dir)
        transport = self._get_transport()
        full_prompt = prompt if system is None else f"{system}\n\n{prompt}"
        self.calls += 1
        response = transport(self.model, full_prompt)
        self._write_cache(key, prompt, system, response)
        return response

    def list_models(self) -> list[str]:
        """Model names visible to this key (for confirming names before relying on them)."""
        if not self.api_key:
            raise MissingApiKey("GEMINI_API_KEY is not set; cannot list models. Put it in .env.")
        from google import genai  # lazy

        client = genai.Client(api_key=self.api_key)
        names: list[str] = []
        for m in client.models.list():
            name = getattr(m, "name", None) or ""
            names.append(name.removeprefix("models/"))
        return names


__all__ = [
    "DEFAULT_MODEL",
    "GeminiClient",
    "MissingApiKey",
    "OfflineCacheMiss",
    "cache_key",
    "load_env",
]
