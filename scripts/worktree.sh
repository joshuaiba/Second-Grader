#!/usr/bin/env bash
# Usage: scripts/worktree.sh <name>
# Creates ../sg-<name> as a git worktree on branch <name> (created from main if missing).
set -euo pipefail

name="${1:?usage: scripts/worktree.sh <name>}"
root="$(git rev-parse --show-toplevel)"
dest="$(dirname "$root")/sg-$name"

if [ -e "$dest" ]; then
  echo "already exists: $dest" >&2
  exit 1
fi

if git -C "$root" show-ref --verify --quiet "refs/heads/$name"; then
  git -C "$root" worktree add "$dest" "$name"
else
  git -C "$root" worktree add -b "$name" "$dest" main
fi

echo "worktree ready: $dest (branch $name)"
echo "  cd $dest && uv sync && uv run pytest"
