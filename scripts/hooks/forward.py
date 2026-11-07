#!/usr/bin/env python3
"""Muse Code hook (P1.3): forward one event to the recorder service. Fails closed.

    forward.py --sock <unix socket> [--event <name>]

Reads the raw hook event (JSON) on stdin and sends it to the recorder service
over its Unix socket. The service numbers, tags, fingerprints, chains and signs
it. This script never sees the signing key.

Exit 0 only when the recorder confirms the write. Exit 2 on ANY error,
including a 1.5 s hard timer that fires before Muse Code's 2 s hook timeout
(a timeout would let the action through unrecorded). Stdlib only, so it
starts fast. Muse Code clears the environment for hooks, so the socket path
comes on the command line.
"""
import json
import signal
import socket
import sys

DEADLINE_S = 1.5


def _timeout(signum, frame):  # noqa: ARG001
    raise TimeoutError(f"recorder did not answer within {DEADLINE_S}s")


def main(argv: list[str]) -> int:
    signal.signal(signal.SIGALRM, _timeout)
    signal.setitimer(signal.ITIMER_REAL, DEADLINE_S)
    try:
        args = dict(zip(argv[1::2], argv[2::2]))
        sock_path = args["--sock"]
        event = json.loads(sys.stdin.read())
        if not isinstance(event, dict):
            raise ValueError("hook payload is not a JSON object")
        if "--event" in args:
            event.setdefault("hook_event_name", args["--event"])
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(sock_path)
            s.sendall((json.dumps({"event": event}) + "\n").encode())
            buf = b""
            while not buf.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                buf += chunk
        reply = json.loads(buf)
        if not reply.get("ok"):
            raise RuntimeError(reply.get("error", "recorder refused the event"))
        signal.setitimer(signal.ITIMER_REAL, 0)
        return 0
    except BaseException as exc:  # noqa: BLE001  deliberate: any failure blocks the action
        print(f"secondgrader hook failed, blocking: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
