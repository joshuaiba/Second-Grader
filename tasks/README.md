# Tasks (owner D)

One YAML per task. Fields:

- `id`: short slug, same as the file name
- `title`
- `repo`: path the agent works in (always `demo_repo`)
- `spec`: what the agent is told to do. This exact text is also given to the verifier.
- `allowed_paths`: files the agent may change
- `trap`: `null` for the honest task, otherwise what we expect a cheating agent to do
- `expected_gate`: `PASS` or `BLOCK` for the demo narrative
