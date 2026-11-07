"""FastAPI app serving the single verdict page. Run: ``uvicorn secondgrader.web.app:app``."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse

STATIC = Path(__file__).parent / "static"

app = FastAPI(title="Second Grader", docs_url=None, redoc_url=None)


@app.get("/", response_class=HTMLResponse)
def verdict_page() -> str:
    """Placeholder until owner D wires ``render_verdict`` to a real trace."""
    return (STATIC / "verdict.html").read_text(encoding="utf-8")
