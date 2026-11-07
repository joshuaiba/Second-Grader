"""Map raw Muse Code hook events to records.

Event names and payload fields are from P1.1 discovery (docs/MUSE_HOOKS.md).
Several fields are only third-party observed, so the mapping accepts the
known variants (``command`` or ``cmd``, ``tool_response`` as a dict or as a
JSON string) and never guesses beyond them.

Each event becomes zero or more ``(kind, payload)`` pairs. The service adds
the code fingerprint (``tree``) and, when the tree moved, ``diff`` records,
so shell edits (``sed -i``, ``cat >``) are caught as well as edit-tool edits.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

SHELL_TOOLS = {"bash", "shell", "exec_command", "run_shell_command", "terminal"}
#: Events after which the code may have changed: fingerprint the working copy.
POST_TOOL_EVENTS = {"PostToolUse", "PostToolUseFailure"}
#: Events that may carry the model's own words.
MESSAGE_EVENTS = {"Stop", "SubagentStop", "PostLLMCall"}
CONTENT_LIMIT = 4000

_TEST_CMD = re.compile(r"(^|[\s;&|(])(python3?\s+-m\s+)?(pytest|py\.test)(\s|$)")
_COUNT = re.compile(r"(\d+) (passed|failed|errors?|skipped|deselected|xfailed|xpassed)")
_COLLECTED = re.compile(r"collected (\d+) items?")


def _event_name(event: dict[str, Any]) -> str:
    return str(event.get("hook_event_name") or event.get("event") or "")


def _maybe_json(value: Any) -> Any:
    if isinstance(value, str):
        s = value.strip()
        if s[:1] in "{[":
            try:
                return json.loads(s)
            except json.JSONDecodeError:
                return value
    return value


def shell_command(tool_input: Any) -> str | None:
    if isinstance(tool_input, dict):
        cmd = tool_input.get("command", tool_input.get("cmd"))
        if isinstance(cmd, list):
            cmd = " ".join(map(str, cmd))
        return cmd if isinstance(cmd, str) else None
    return None


def tool_result(event: dict[str, Any]) -> tuple[int | None, str]:
    """``(exit_code, output text)`` from a PostToolUse(/Failure) event."""
    resp = _maybe_json(event.get("tool_response", event.get("tool_output")))
    exit_code: int | None = None
    text = ""
    if isinstance(resp, dict):
        raw_code = resp.get("exit_code", resp.get("exitCode", resp.get("returncode")))
        exit_code = raw_code if isinstance(raw_code, int) else None
        parts = [resp.get(k) for k in ("output", "stdout", "stderr", "content", "result")]
        text = "\n".join(p for p in parts if isinstance(p, str))
        if not text:
            text = json.dumps(resp, sort_keys=True)
    elif resp is not None:
        text = str(resp)
    if _event_name(event) == "PostToolUseFailure":
        err = event.get("error")
        if err:
            text = (text + "\n" + str(err)).strip()
        if exit_code is None and isinstance(err, dict):
            code = err.get("exit_code")
            exit_code = code if isinstance(code, int) else None
    return exit_code, text


def is_test_command(cmd: str | None) -> bool:
    return bool(cmd and _TEST_CMD.search(cmd))


def parse_pytest(output: str) -> dict[str, int | None]:
    """Counts from pytest's summary line. Missing counts are 0; ``collected`` may be None."""
    counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0, "deselected": 0}
    summary = [ln for ln in output.splitlines() if _COUNT.search(ln)]
    if summary:
        for n, word in _COUNT.findall(summary[-1]):
            key = "errors" if word.startswith("error") else word
            if key in counts:
                counts[key] = int(n)
    m = _COLLECTED.search(output)
    collected = int(m.group(1)) if m else None
    selected = counts["passed"] + counts["failed"] + counts["errors"] + counts["skipped"]
    return {**counts, "selected": selected, "collected": collected}


def _clip(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {"content_sha256": hashlib.sha256(text.encode()).hexdigest(),
                           "bytes": len(text.encode())}
    out["content"] = text if len(text) <= CONTENT_LIMIT else text[-CONTENT_LIMIT:]
    out["truncated"] = len(text) > CONTENT_LIMIT
    return out


def _message_text(event: dict[str, Any]) -> str | None:
    for key in ("last_assistant_message", "assistant_message", "message", "response", "text"):
        val = event.get(key)
        if isinstance(val, dict):
            val = val.get("text") or val.get("content")
        if isinstance(val, str) and val.strip():
            return val
    return None


def map_event(event: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """Records for one hook event, without fingerprints (the service adds those)."""
    name = _event_name(event)
    common = {k: event[k] for k in ("tool_use_id", "turn_id") if event.get(k) is not None}
    tool = event.get("tool_name")
    if name == "UserPromptSubmit":
        prompt = event.get("prompt")
        return [("prompt", {"text": prompt})] if isinstance(prompt, str) else []
    if name == "PreToolUse":
        return [("tool_call", {"tool": tool, "args": event.get("tool_input") or {}, **common})]
    if name in POST_TOOL_EVENTS:
        exit_code, text = tool_result(event)
        failed = name == "PostToolUseFailure"
        out: dict[str, Any] = {"tool": tool, "exit_code": exit_code, "failed": failed, **common, **_clip(text)}
        cmd = shell_command(event.get("tool_input"))
        if cmd is not None:
            out["command"] = cmd
        records = [("tool_output", out)]
        if str(tool) in SHELL_TOOLS and is_test_command(cmd):
            records.append(("test_run", {"command": cmd, "exit_code": exit_code, "source": "agent",
                                         **parse_pytest(text), "output_tail": text[-1500:], **common}))
        return records
    if name in MESSAGE_EVENTS:
        text = _message_text(event)
        return [("model_message", {"text": text, "event": name})] if text else []
    return []
