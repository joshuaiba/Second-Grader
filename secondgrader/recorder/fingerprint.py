"""Code fingerprint (P1.5): the git tree hash of the working copy, right now.

We don't trust edit-tool events to tell us what changed: an agent can edit
files with ``sed -i`` or ``cat >`` through the shell. So after every step we
hash the whole working copy. If the tree hash moved, the code changed, no
matter which tool did it.

The agent's own git index is never touched: we stage into a temporary index
file (``GIT_INDEX_FILE``), seeded from a copy of the real one so git can skip
unchanged files quickly.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path


def _git(repo: str | Path, *args: str, env: dict[str, str] | None = None) -> str:
    out = subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                         text=True, env=env, timeout=10)
    return out.stdout.strip()


def code_fingerprint(repo: str | Path) -> str:
    """Git tree hash (40 hex) of every non-ignored file in ``repo``'s working copy."""
    real_index = Path(repo) / _git(repo, "rev-parse", "--git-path", "index")
    with tempfile.TemporaryDirectory(prefix="sg-index-") as tmp:
        index = Path(tmp) / "index"
        if real_index.exists():
            shutil.copyfile(real_index, index)
        env = {**os.environ, "GIT_INDEX_FILE": str(index)}
        _git(repo, "add", "-A", ".", env=env)
        return _git(repo, "write-tree", env=env)


def changed_files(repo: str | Path, tree_a: str, tree_b: str) -> list[dict[str, str]]:
    """Files that differ between two trees: ``[{"status": "M", "path": "parser.py"}, ...]``."""
    out = _git(repo, "diff-tree", "-r", "--no-renames", "--name-status", tree_a, tree_b)
    rows = []
    for line in out.splitlines():
        status, _, path = line.partition("\t")
        rows.append({"status": status, "path": path})
    return rows


def tree_diff(repo: str | Path, tree_a: str, tree_b: str, path: str | None = None) -> str:
    """Unified diff between two trees, optionally for one path."""
    args = ["diff", "--no-color", "--no-renames", tree_a, tree_b]
    if path:
        args += ["--", path]
    return _git(repo, *args)
