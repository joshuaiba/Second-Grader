"""Recorder service (P1.4): the single writer for one run.

It listens on a Unix socket. Hooks (``scripts/hooks/forward.py``) send each raw
Muse Code event as one JSON line; the service maps it to records, adds the
code fingerprint, and appends them in arrival order under one lock. The
private key is loaded once and held only in this process's memory: hooks
never read it.

Protocol (one request per connection, one JSON line each way):

- ``{"event": {...raw hook payload...}}`` -> ``{"ok": true, "seqs": [...]}``
- ``{"ping": true}``                       -> ``{"ok": true}``

There is deliberately no "append any record" request: the socket is
reachable while the agent runs, so it only accepts hook events, and the
recorder decides kind, tag and timestamp. The auditor, verifier and gate
write their records with :func:`secondgrader.recorder.append` after the
agent has stopped.

Errors come back as ``{"ok": false, "error": "..."}``; the hook then exits 2.
"""

from __future__ import annotations

import json
import os
import socket
import socketserver
import tempfile
import threading
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .fingerprint import changed_files, code_fingerprint, tree_diff
from .hooks import POST_TOOL_EVENTS, map_event
from .writer import TraceWriter


def short_socket_path(tag: str = "rec") -> Path:
    """A socket path short enough for macOS's 104-byte limit."""
    return Path(tempfile.mkdtemp(prefix=f"sg{tag}-", dir="/tmp")) / "s"


class Recorder:
    """Turns events into records for one run. Thread-safe."""

    def __init__(self, trace_path: str | Path, key: Ed25519PrivateKey, repo: str | Path | None = None):
        self.writer = TraceWriter(trace_path, key)
        self.repo = Path(repo) if repo else None
        self._lock = threading.Lock()
        self.tree = code_fingerprint(self.repo) if self.repo else None

    def _diff_records(self, new_tree: str, via: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
        assert self.repo is not None and self.tree is not None
        out = []
        for row in changed_files(self.repo, self.tree, new_tree):
            diff = tree_diff(self.repo, self.tree, new_tree, row["path"])
            added = sum(1 for ln in diff.splitlines() if ln.startswith("+") and not ln.startswith("+++"))
            removed = sum(1 for ln in diff.splitlines() if ln.startswith("-") and not ln.startswith("---"))
            out.append(("diff", {"path": row["path"], "status": row["status"], "diff": diff,
                                 "lines_added": added, "lines_removed": removed,
                                 "tree_before": self.tree, "tree": new_tree, **via}))
        return out

    def handle_event(self, event: dict[str, Any]) -> list[int]:
        with self._lock:
            pairs = map_event(event)
            name = event.get("hook_event_name")
            if self.repo is not None and name in POST_TOOL_EVENTS:
                new_tree = code_fingerprint(self.repo)
                for _, payload in pairs:
                    payload["tree"] = new_tree
                if new_tree != self.tree:
                    via = {"via_tool": event.get("tool_name")}
                    if event.get("tool_use_id"):
                        via["tool_use_id"] = event["tool_use_id"]
                    pairs = pairs[:1] + self._diff_records(new_tree, via) + pairs[1:]
                    self.tree = new_tree
            return [self.writer.append(kind, payload).seq for kind, payload in pairs]

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        try:
            if "event" in request:
                return {"ok": True, "seqs": self.handle_event(request["event"])}
            if request.get("ping"):
                return {"ok": True}
            return {"ok": False, "error": "unknown request"}
        except Exception as exc:  # noqa: BLE001  report every failure; the hook exits 2
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        line = self.rfile.readline()
        try:
            request = json.loads(line)
        except json.JSONDecodeError as exc:
            reply = {"ok": False, "error": f"bad json: {exc}"}
        else:
            reply = self.server.recorder.handle(request)  # type: ignore[attr-defined]
        self.wfile.write((json.dumps(reply) + "\n").encode())


class RecorderServer(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, sock_path: str | Path, recorder: Recorder):
        self.recorder = recorder
        self.sock_path = Path(sock_path)
        if self.sock_path.exists():
            self.sock_path.unlink()
        super().__init__(str(self.sock_path), _Handler)
        os.chmod(self.sock_path, 0o600)

    def start_background(self) -> threading.Thread:
        t = threading.Thread(target=self.serve_forever, name="sg-recorder", daemon=True)
        t.start()
        return t

    def close(self) -> None:
        self.shutdown()
        self.server_close()
        self.sock_path.unlink(missing_ok=True)


def send(sock_path: str | Path, request: dict[str, Any], timeout: float = 5.0) -> dict[str, Any]:
    """Client side: one request, one reply."""
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(str(sock_path))
        s.sendall((json.dumps(request) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return json.loads(buf)
