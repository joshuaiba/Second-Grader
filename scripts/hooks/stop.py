#!/usr/bin/env python3
"""Muse Code hook: stop. Placeholder owned by A.

Reads the hook event as JSON on stdin, maps it to a Record and calls
secondgrader.recorder.append. Exits 2 on ANY error: a timeout or a silent
failure would let the agent's action through unrecorded.
"""
import json
import sys


def main() -> int:
    try:
        event = json.load(sys.stdin)
        from secondgrader import recorder  # noqa: F401  (import inside try: exit 2 on failure)

        # TODO(owner A): map `event` to {"kind", "origin", "payload"} and call recorder.append(...)
        raise NotImplementedError("stop hook: owner A")
    except Exception as exc:  # noqa: BLE001  deliberate: any failure blocks the action
        print(f"secondgrader hook stop failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
