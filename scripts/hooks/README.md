# Muse Code hooks (owner A)

Each script reads one hook event as JSON on stdin and appends a Record to the
trace at `$SG_TRACE_PATH` via `secondgrader.recorder.append`.

Rules:
- Exit **2** on any error. A non-blocking failure or a timeout lets the action through.
- Be fast. No network, no model calls, no slow imports.
- Run Muse Code with `--disable-sandbox --trust-workspace` inside a throwaway clone
  so project hooks load and `.git` is writable.

Wiring the scripts into Muse Code's hook config is owner A's job; the mapping
of hook events to record kinds lives in `secondgrader/recorder/`.
