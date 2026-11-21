"""Local-only web GUI.

Security posture for v0.1:
  * binds loopback by default
  * every mutating request needs the per-process CSRF token
  * no shell execution anywhere (argv only, via the tool runner)
  * API keys are written to a 0600 file, never returned unmasked
This is a single-user local tool, not a hosted service.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import threading
import uuid
from pathlib import Path
from typing import Any, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from .. import __version__, db
from ..config import (
    USAGE_LEVELS,
    load_config,
    masked_keys,
    runs_dir,
    save_config,
    set_api_key,
)
from ..llm.providers import all_models, get_provider, provider_list
from ..pipeline import pipeline_summary, start_run
from ..scope import Scope, ScopeError
from ..tools import status as tool_status

STATIC = Path(__file__).parent / "static"
CSRF_TOKEN = secrets.token_urlsafe(24)

app = FastAPI(title="DragonEye", version=__version__, docs_url=None, redoc_url=None)

_ACTIVE: dict[str, threading.Thread] = {}
_LOCK = threading.Lock()


# --- dependencies ---------------------------------------------------------


def get_db():
    con = db.connect()
    try:
        yield con
    finally:
        con.close()


def require_token(request: Request) -> None:
    provided = request.headers.get("x-dragoneye-token") or request.query_params.get("token") or ""
    if not secrets.compare_digest(provided, CSRF_TOKEN):
        raise HTTPException(status_code=403, detail="missing or invalid X-DragonEye-Token")


# --- schemas --------------------------------------------------------------


class ProgramIn(BaseModel):
    name: str
    in_scope: str = ""
    out_of_scope: str = ""
    platform: Optional[str] = None
    note: Optional[str] = None


class RunIn(BaseModel):
    program_id: int
    dry_run: bool = False
    passive: bool = False
    usage: str = "balanced"
    provider: Optional[str] = None
    model: Optional[str] = None


class ConfigIn(BaseModel):
    provider: Optional[str] = None
    model: Optional[str] = None
    usage: Optional[str] = None
    base_url: Optional[str] = None
    max_cost_usd: Optional[float] = None
    api_key: Optional[str] = None


class ValidationIn(BaseModel):
    validated: Optional[str] = None


# --- static ---------------------------------------------------------------


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC / "index.html")


@app.get("/api/session")
def session() -> dict[str, Any]:
    return {"token": CSRF_TOKEN, "version": __version__}


# --- programs -------------------------------------------------------------


@app.get("/api/programs")
def list_programs(con=Depends(get_db)) -> dict[str, Any]:
    rows = db.list_programs(con)
    for row in rows:
        row["asset_count"] = db.count_assets(con, int(row["id"]))
        row["run_count"] = db.count_runs(con, int(row["id"]))
    return {"programs": rows}


@app.get("/api/programs/{program_id}")
def get_program(program_id: int, con=Depends(get_db)) -> dict[str, Any]:
    program = db.get_program(con, program_id)
    if not program:
        raise HTTPException(404, "program not found")
    program["runs"] = db.list_runs(con, program_id, 10)
    try:
        program["scope_summary"] = Scope(
            program.get("in_scope") or [],
            program.get("out_of_scope") or [],
            allow_private=load_config().allow_private,
        ).summary()
    except ScopeError as exc:
        program["scope_summary"] = {"error": str(exc)}
    return program


@app.post("/api/programs", dependencies=[Depends(require_token)])
def create_program(payload: ProgramIn, con=Depends(get_db)) -> dict[str, Any]:
    in_scope = _lines(payload.in_scope)
    out_scope = _lines(payload.out_of_scope)
    if not in_scope:
        raise HTTPException(400, "at least one in-scope rule is required")
    try:
        Scope(in_scope, out_scope)
    except ScopeError as exc:
        raise HTTPException(400, f"invalid scope: {exc}") from exc
    program_id = db.add_program(
        con, payload.name.strip(), in_scope, out_scope, payload.platform, payload.note
    )
    return {"id": program_id, "program": db.get_program(con, program_id)}


@app.delete("/api/programs/{program_id}", dependencies=[Depends(require_token)])
def delete_program(program_id: int, con=Depends(get_db)) -> dict[str, bool]:
    if not db.delete_program(con, program_id):
        raise HTTPException(404, "program not found")
    return {"deleted": True}


@app.get("/api/scope/check")
def scope_check(program_id: int, target: str, con=Depends(get_db)) -> dict[str, Any]:
    program = db.get_program(con, program_id)
    if not program:
        raise HTTPException(404, "program not found")
    try:
        decision = Scope(
            program.get("in_scope") or [],
            program.get("out_of_scope") or [],
            allow_private=load_config().allow_private,
        ).check(target)
    except ScopeError as exc:
        raise HTTPException(400, str(exc)) from exc
    return {
        "allowed": decision.allowed,
        "host": decision.host,
        "reason": decision.reason,
        "rule": decision.rule,
    }


# --- runs -----------------------------------------------------------------


@app.post("/api/runs", dependencies=[Depends(require_token)])
def create_run(payload: RunIn, con=Depends(get_db)) -> dict[str, Any]:
    program = db.get_program(con, payload.program_id)
    if not program:
        raise HTTPException(404, "program not found")
    if payload.usage not in USAGE_LEVELS:
        raise HTTPException(400, f"usage must be one of {', '.join(USAGE_LEVELS)}")

    cfg = load_config()
    try:
        Scope(program.get("in_scope") or [], program.get("out_of_scope") or [], allow_private=cfg.allow_private)
    except ScopeError as exc:
        raise HTTPException(400, f"invalid scope: {exc}") from exc

    run_id = uuid.uuid4().hex[:12]
    options = dict(
        dry_run=payload.dry_run,
        passive_only=payload.passive or None,
        llm_usage=payload.usage,
        provider=payload.provider,
        model=payload.model,
        run_id=run_id,
    )

    def worker() -> None:
        thread_con = db.connect()
        try:
            start_run(thread_con, program, cfg, echo=lambda _message: None, **options)
        except Exception as exc:  # noqa: BLE001
            db.update_run(thread_con, run_id, status="failed", finished_at=db.utcnow(), error=str(exc))
        finally:
            thread_con.close()
            with _LOCK:
                _ACTIVE.pop(run_id, None)

    thread = threading.Thread(target=worker, name=f"dragoneye-{run_id}", daemon=True)
    with _LOCK:
        _ACTIVE[run_id] = thread
    thread.start()
    return {"run_id": run_id, "status": "running"}


@app.get("/api/runs")
def list_runs(program_id: Optional[int] = None, limit: int = 20, con=Depends(get_db)) -> dict[str, Any]:
    return {"runs": db.list_runs(con, program_id, limit)}


@app.get("/api/runs/{run_id}")
def get_run(run_id: str, con=Depends(get_db)) -> dict[str, Any]:
    run = db.resolve_run(con, run_id)
    if not run:
        raise HTTPException(404, "run not found")
    data = pipeline_summary(con, run["id"])
    data["active"] = run["id"] in _ACTIVE
    data["report"] = {
        "html": f"/api/runs/{run['id']}/report?format=html",
        "md": f"/api/runs/{run['id']}/report?format=md",
        "json": f"/api/runs/{run['id']}/report?format=json",
    }
    return data


@app.get("/api/runs/{run_id}/events")
async def run_events(run_id: str, con=Depends(get_db)) -> StreamingResponse:
    if not db.get_run(con, run_id):
        raise HTTPException(404, "run not found")
    log_path = runs_dir() / run_id / "run.log"

    async def stream():
        position = 0
        idle = 0
        while True:
            chunk = ""
            if log_path.exists():
                try:
                    with open(log_path, "r", errors="replace") as handle:
                        handle.seek(position)
                        chunk = handle.read()
                        position = handle.tell()
                except OSError:
                    chunk = ""
            for line in chunk.splitlines():
                yield f"data: {json.dumps(line)}\n\n"
            if chunk:
                idle = 0
            else:
                idle += 1

            active = run_id in _ACTIVE
            if not active and idle >= 2:
                con = db.connect()
                run = db.get_run(con, run_id)
                con.close()
                if run and run["status"] in ("done", "failed"):
                    yield "event: done\ndata: {}\n\n"
                    return
            if idle > 1200:  # ~20 min of silence
                yield "event: done\ndata: {}\n\n"
                return
            await asyncio.sleep(0.5)

    return StreamingResponse(
        stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/api/runs/{run_id}/report")
def get_report(run_id: str, format: str = "html", con=Depends(get_db)) -> FileResponse:
    run = db.resolve_run(con, run_id)
    if not run:
        raise HTTPException(404, "run not found")
    name = {"html": "report.html", "md": "report.md", "json": "report.json"}.get(format)
    if not name:
        raise HTTPException(400, "format must be html, md or json")
    path = Path(run["outdir"]) / name
    if not path.exists():
        raise HTTPException(404, "report not generated yet")
    media = {"html": "text/html", "md": "text/markdown", "json": "application/json"}[format]
    return FileResponse(path, media_type=media, filename=f"dragoneye-{run_id}.{format}")


@app.post("/api/runs/{run_id}/resume", dependencies=[Depends(require_token)])
def resume_run(run_id: str, con=Depends(get_db)) -> dict[str, Any]:
    run = db.resolve_run(con, run_id)
    if not run:
        raise HTTPException(404, "run not found")
    if run["id"] in _ACTIVE:
        raise HTTPException(409, "run already active")
    program = db.get_program(con, int(run["program_id"]))
    cfg = load_config()

    def worker() -> None:
        thread_con = db.connect()
        try:
            start_run(thread_con, program, cfg, resume_run_id=run["id"], echo=lambda _m: None)
        except Exception as exc:  # noqa: BLE001
            db.update_run(thread_con, run["id"], status="failed", error=str(exc))
        finally:
            thread_con.close()
            with _LOCK:
                _ACTIVE.pop(run["id"], None)

    thread = threading.Thread(target=worker, name=f"dragoneye-{run['id']}", daemon=True)
    with _LOCK:
        _ACTIVE[run["id"]] = thread
    thread.start()
    return {"run_id": run["id"], "status": "resumed"}


@app.post("/api/findings/{finding_id}/validation", dependencies=[Depends(require_token)])
def validate_finding(
    finding_id: int, payload: Optional[ValidationIn] = None, con=Depends(get_db)
) -> dict[str, Any]:
    validated = payload.validated if payload else None
    if validated not in (None, "confirmed", "false-positive"):
        raise HTTPException(400, "validated must be confirmed, false-positive or omitted")
    if not db.get_finding(con, finding_id):
        raise HTTPException(404, "finding not found")
    db.set_verdict_validation(con, finding_id, validated)
    return {"finding_id": finding_id, "validated": validated}


# --- meta -----------------------------------------------------------------


@app.get("/api/tools")
def tools() -> dict[str, Any]:
    return {"tools": tool_status(with_version=True)}


@app.get("/api/models")
def models(provider: Optional[str] = None) -> dict[str, Any]:
    entries = all_models()
    if provider:
        entries = [e for e in entries if e["provider"] == provider]
    return {"providers": provider_list(), "models": entries}


@app.get("/api/config")
def get_config() -> dict[str, Any]:
    cfg = load_config().to_dict()
    return {"config": cfg, "keys": masked_keys(), "usage_levels": list(USAGE_LEVELS)}


@app.post("/api/config", dependencies=[Depends(require_token)])
def update_config(payload: ConfigIn) -> JSONResponse:
    cfg = load_config()
    if payload.provider is not None:
        if not get_provider(payload.provider):
            raise HTTPException(400, f"unknown provider {payload.provider!r}")
        cfg.llm.provider = payload.provider
    if payload.model is not None:
        cfg.llm.model = payload.model
    if payload.usage is not None:
        if payload.usage not in USAGE_LEVELS:
            raise HTTPException(400, f"usage must be one of {', '.join(USAGE_LEVELS)}")
        cfg.llm.usage = payload.usage
    if payload.base_url is not None:
        cfg.llm.base_url = payload.base_url or None
    if payload.max_cost_usd is not None:
        cfg.llm.max_cost_usd = payload.max_cost_usd or None
    save_config(cfg)
    if payload.api_key is not None and payload.provider:
        set_api_key(payload.provider, payload.api_key)
    return JSONResponse({"saved": True, "keys": masked_keys()})


def _lines(text: str) -> list[str]:
    return [
        line.strip()
        for line in (text or "").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
