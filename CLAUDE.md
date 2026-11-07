# Working rules for Second Grader

Read this before touching anything. These rules apply to humans and to their coding agents.

## Boundaries

- **Stay inside your own module folder.** Don't edit another owner's folder.
  - A: `secondgrader/recorder/`, `scripts/hooks/`
  - B: `secondgrader/auditor/`
  - C: `secondgrader/verifier/`, `secondgrader/gate/`
  - D: `secondgrader/web/`, `secondgrader/cli.py`, `demo_repo/`, `tasks/`
  - Each owner also owns `tests/test_<module>.py` for their modules.
- **Never change `secondgrader/schema.py` without the team agreeing.** Propose changes in team chat first. It is the contract everyone builds against.
- **Build against `fixtures/` until the real recorder works.** `fixtures/sample_trace.jsonl` is a cheating run; `fixtures/sample_trace_tampered.jsonl` has a broken chain at seq 13.
- Your tests are in `tests/test_<module>.py`, marked `@pytest.mark.skip(reason="not implemented yet")`. Un-skip them as you implement.

## Workflow

- Work in your own worktree: `scripts/worktree.sh <name>` creates `../sg-<name>` on branch `<name>`.
- Run `pytest` before every commit. Commit small and often. Rebase on `main` before pushing.
- No secrets in the repo. Read keys from `.env` (see `.env.example`). `keys/` and `traces/` are git-ignored.

## External services

- **Meta API**: OpenAI SDK, `base_url="https://api.meta.ai/v1"`, model `muse-spark-1.3`. `tool_choice` other than `"auto"` is unsupported.
- **Gemini**: `google-genai` SDK. `gemini-4-argon` for the verifier, `gemini-3.8-flash` for claim extraction. Confirm the model names via the list-models call before relying on them.
- **Muse Code**: run with `--disable-sandbox` inside a throwaway clone (the sandbox makes `.git` read-only and blocks network). Project hooks need `--trust-workspace`. Hooks must be fast and **exit 2 on any error**, because a timeout lets the action through.

## Product rules

- OBSERVED records (tool outputs, diffs, test runs) are evidence. CLAIMED records (model text) are what we check. Never treat a claim as evidence.
- The blinded verifier sees the spec, the diff and OBSERVED records only. Never the agent's messages, never the agent's tests.
- Every BLOCK must cite the record seq that contradicts the claim.
- No Streamlit, and no dashboard as the main feature. The UI is one verdict page.
