"""
SecureAgent — FastAPI MCP Server

Exposes two MCP tools:
  POST /tools/audit_repo   — audit a public GitHub repository
  POST /tools/audit_code   — audit a raw code snippet
  GET  /tools              — MCP tool discovery
  GET  /health             — health check
"""
from __future__ import annotations

import logging
import os
import sys
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from agents.orchestrator import run_audit
from mcp_server.config import get_settings
from mcp_server.tools import (
    AuditCodeRequest,
    AuditRepoRequest,
    AuditResponse,
    ErrorResponse,
    SeveritySummary,
    TOOL_REGISTRY,
)
from utils.github_fetcher import GitHubFetchError, fetch_repo_files
from utils.github_fetcher import FileContent  # for inline code wrapping

# ── Logging setup ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
logger = logging.getLogger("secureagent")


# ── Lifespan ──────────────────────────────────────────────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    logger.info("SecureAgent MCP Server starting...")
    logger.info("LLM provider: %s | model: %s", settings.llm_provider, settings.llm_model)
    if not settings.active_llm_key:
        logger.warning(
            "No LLM API key found — server will run in pattern-only mode. "
            "Add OPENAI_API_KEY or GEMINI_API_KEY to .env to enable LLM enrichment."
        )
    yield
    logger.info("SecureAgent MCP Server shutting down.")


# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SecureAgent MCP Server",
    description=(
        "AI-powered security audit tool. "
        "Exposes MCP-compatible tools for scanning GitHub repositories "
        "and raw code snippets for security vulnerabilities."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Global error handler ──────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"error": "Internal server error.", "detail": str(exc)},
    )


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health():
    """Server health check."""
    settings = get_settings()
    return {
        "status": "ok",
        "llm_provider": settings.llm_provider,
        "llm_configured": bool(settings.active_llm_key),
        "github_token_set": bool(settings.github_token),
    }


# ── MCP tool discovery ────────────────────────────────────────────────────────
@app.get("/tools", tags=["MCP"])
async def list_tools():
    """MCP tool discovery endpoint — lists all available tools."""
    return {"tools": [t.model_dump() for t in TOOL_REGISTRY]}


# ── audit_repo ────────────────────────────────────────────────────────────────
@app.post(
    "/tools/audit_repo",
    response_model=AuditResponse,
    responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    tags=["MCP Tools"],
    summary="Audit a public GitHub repository",
)
async def audit_repo(req: AuditRepoRequest):
    """
    Fetch a public GitHub repository and run the full 3-agent security audit pipeline.

    Returns a prioritised markdown security report.
    """
    logger.info("audit_repo called: %s", req.github_url)

    # 1. Fetch repo files
    try:
        repo = fetch_repo_files(req.github_url)
    except GitHubFetchError as exc:
        logger.warning("GitHub fetch failed: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error fetching repo: %s", exc)
        raise HTTPException(status_code=500, detail=f"Failed to fetch repository: {exc}")

    if not repo.source_files and not repo.dep_files:
        raise HTTPException(
            status_code=400,
            detail=(
                f"No scannable files found in {req.github_url}. "
                "The repository may be empty or contain only unsupported file types."
            ),
        )

    # 2. Run audit pipeline
    try:
        result = run_audit(
            files=repo.source_files,
            dep_files=repo.dep_files,
            target=req.github_url,
            use_llm=req.use_llm,
            min_severity=req.min_severity,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Audit pipeline failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Audit failed: {exc}")

    # Save to audit folder
    os.makedirs("audit", exist_ok=True)
    safe_target = req.github_url.split("/")[-1]
    report_filename = f"audit/report_{safe_target}_{int(time.time())}.md"
    try:
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(result.report)
    except Exception as exc:
        logger.warning("Failed to save report to disk: %s", exc)

    return AuditResponse(
        report=result.report,
        summary=SeveritySummary(**result.summary.to_dict()),
        target=req.github_url,
    )


# ── audit_code ────────────────────────────────────────────────────────────────
@app.post(
    "/tools/audit_code",
    response_model=AuditResponse,
    responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    tags=["MCP Tools"],
    summary="Audit a raw code snippet",
)
async def audit_code(req: AuditCodeRequest):
    """
    Audit a raw code snippet for security vulnerabilities.

    Accepts any code as a string and runs the pattern scanner.
    Dependency audit is skipped unless the code contains a parseable
    requirements.txt or package.json.
    """
    logger.info("audit_code called: filename=%s, len=%d", req.filename, len(req.code))

    # Wrap code as a virtual FileContent
    virtual_file = FileContent(
        path=req.filename,
        content=req.code,
        size_bytes=len(req.code.encode()),
    )

    # Check if the pasted code is a dependency file
    dep_files: dict[str, str] = {}
    if req.filename in ("requirements.txt", "package.json", "pyproject.toml"):
        dep_files[req.filename] = req.code
        source_files = []
    else:
        source_files = [virtual_file]

    try:
        result = run_audit(
            files=source_files,
            dep_files=dep_files,
            target=f"inline:{req.filename}",
            use_llm=req.use_llm,
            min_severity=req.min_severity,
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Audit pipeline failed: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Audit failed: {exc}")

    # Save to audit folder
    os.makedirs("audit", exist_ok=True)
    safe_target = req.filename.replace("/", "_").replace("\\", "_")
    report_filename = f"audit/report_code_{safe_target}_{int(time.time())}.md"
    try:
        with open(report_filename, "w", encoding="utf-8") as f:
            f.write(result.report)
    except Exception as exc:
        logger.warning("Failed to save report to disk: %s", exc)

    return AuditResponse(
        report=result.report,
        summary=SeveritySummary(**result.summary.to_dict()),
        target=f"inline:{req.filename}",
    )


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    settings = get_settings()
    uvicorn.run(
        "mcp_server.main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level,
        reload=True,
    )
