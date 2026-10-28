"""Sentinel API: FastAPI app exposing a streaming scan endpoint and config.

The scan endpoint streams Server-Sent Events so the React dashboard can render
the agent's progress live. A static-file mount serves a built frontend if one
is present, so the whole thing can run from a single process in a demo.
"""
from __future__ import annotations

import json
import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles

from .agent.orchestrator import run_scan
from .config import get_settings
from .models import ScanRequest
from .safety.allowlist import is_allowed

app = FastAPI(title="Sentinel", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # demo-friendly; tighten for any real deployment
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
async def health() -> dict:
    s = get_settings()
    return {
        "status": "ok",
        "nebius_enabled": s.nebius_enabled,
        "tavily_enabled": s.tavily_enabled,
        "planner_model": s.planner_model,
        "triage_model": s.triage_model,
        "allowed_hosts": s.allowed_hosts,
    }


@app.post("/api/validate")
async def validate(req: ScanRequest) -> dict:
    """Pre-flight check so the UI can warn before a scan is attempted."""
    return {"target": req.target, "allowed": is_allowed(req.target)}


@app.post("/api/scan")
async def scan(req: ScanRequest) -> StreamingResponse:
    async def event_stream():
        async for event in run_scan(req.target, req.max_pages):
            yield f"data: {json.dumps(event.model_dump())}\n\n"

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",  # disable proxy buffering for live stream
        },
    )


# Serve the built frontend (frontend/dist) if it exists.
_DIST = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
if os.path.isdir(_DIST):
    app.mount("/", StaticFiles(directory=_DIST, html=True), name="static")
