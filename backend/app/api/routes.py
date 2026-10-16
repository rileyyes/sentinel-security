"""HTTP API. Thin: validation and orchestration only — no security logic here."""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Response, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse

from app.ai.assistant import ask
from app.api.deps import get_llm_provider, get_settings, get_store
from app.api.schemas import AskRequest, AskResponse, InvestigationSummary
from app.core.logging import log_event
from app.evidence.models import Investigation, to_plain
from app.ingestion.validators import IngestionError
from app.reports.html_report import csp_header
from app.workflow.investigate import investigate

router = APIRouter()


def _error(code: str, message: str, status: int) -> JSONResponse:
    return JSONResponse({"code": code, "message": message}, status_code=status)


@router.get("/health")
def health() -> dict:
    return {"status": "ok"}


@router.post("/investigations/{mode}")
async def create_investigation(mode: Literal["software", "code"], file: UploadFile):
    settings = get_settings()
    try:
        inv = investigate(mode, file.file, file.filename, settings, isolated=False)
    except IngestionError as exc:
        log_event("ingest_rejected", code=exc.code, mode=mode)
        return _error(exc.code, exc.message, 400)
    except Exception:  # noqa: BLE001 - never leak internals to the client
        log_event("investigation_unhandled_error", mode=mode)
        return _error("internal_error", "The investigation could not be completed.", 500)
    get_store().save(inv)
    return JSONResponse(to_plain(inv), status_code=201)


@router.get("/investigations")
def list_investigations() -> list[InvestigationSummary]:
    return get_store().list()  # type: ignore[return-value]


@router.get("/investigations/{inv_id}")
def get_investigation(inv_id: str):
    from app.storage.store import NotFound

    try:
        inv = get_store().load(inv_id)
    except NotFound:
        raise HTTPException(404, "Investigation not found")
    return JSONResponse(to_plain(inv))


@router.get("/investigations/{inv_id}/report.html")
def get_report_html(inv_id: str):
    from app.storage.store import NotFound

    try:
        html = get_store().report_html(inv_id)
    except NotFound:
        raise HTTPException(404, "Investigation not found")
    return HTMLResponse(html, headers=csp_header())


@router.get("/investigations/{inv_id}/export")
def export_investigation(inv_id: str):
    import tempfile
    from pathlib import Path

    from app.storage.store import NotFound

    tmp = Path(tempfile.mkstemp(suffix=".zip")[1])
    try:
        get_store().export_zip(inv_id, tmp)
    except NotFound:
        raise HTTPException(404, "Investigation not found")
    data = tmp.read_bytes()
    tmp.unlink(missing_ok=True)
    return Response(data, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{inv_id}.sentinel.zip"'})


@router.delete("/investigations/{inv_id}")
def delete_investigation(inv_id: str):
    from app.storage.store import NotFound

    try:
        get_store().delete(inv_id)
    except NotFound:
        raise HTTPException(404, "Investigation not found")
    return Response(status_code=204)


@router.post("/investigations/{inv_id}/ask", response_model=AskResponse)
def ask_ai(inv_id: str, body: AskRequest):
    from app.storage.store import NotFound

    try:
        inv = get_store().load(inv_id)
    except NotFound:
        raise HTTPException(404, "Investigation not found")
    result = ask(inv, body.question, get_llm_provider())
    return AskResponse(ok=result.ok, answer=result.text, issues=result.issues)


def create_app() -> FastAPI:
    app = FastAPI(title="Sentinel Security Investigation Platform", version="0.1.0")
    origins = __import__("os").environ.get("SENTINEL_CORS_ORIGINS", "http://localhost:5173").split(",")
    app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["GET", "POST", "DELETE"],
                       allow_headers=["*"], max_age=600)
    app.include_router(router, prefix="/api")

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response

    return app
