"""FastAPI service exposing the validation gate over HTTP.

Endpoints
---------
``GET  /``                 browser front-end (works with or without an LLM key).
``GET  /health``           liveness/readiness probe with configuration summary.
``POST /validate-code``    full multi-agent pipeline on an intent spec (needs a key).
``POST /scan``             deterministic static/security scan only (no LLM, no cost).

Run locally::

    uvicorn api:app --reload --port 8000
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal, cast

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from src import __version__
from src.config import get_settings
from src.graph import validate_code
from src.state import IntentSpec
from src.web_policy import extra_allowed_origins

STATIC_DIR = Path(__file__).resolve().parent / "static"

# Serverless platforms cap a request at 10-60s. A full validation (coder call +
# up to 3 attempts + reviewer) cannot fit, so we refuse explicitly instead of
# letting the platform kill the request with an opaque timeout.
SERVERLESS = bool(os.getenv("VERCEL") or os.getenv("AWS_LAMBDA_FUNCTION_NAME"))
MAX_ITERATIONS_SERVERLESS = 1
MAX_ITERATIONS_LOCAL = 6

app = FastAPI(
    title="codeguard-multiagent",
    version=__version__,
    description=(
        "Multi-agent AI code validator and CI/CD quality gate. Deterministic "
        "AST/security scanning and a sandboxed pytest runner decide every "
        "verdict; the LLM only writes code and explains fixes."
    ),
)

# The front-end is served by this same app, so its origin is never known at
# build time (localhost, preview deploy, production). Reflecting a validated
# origin is safe here because the API carries no cookies or ambient credentials.
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"https?://[^\s/]+",
    allow_origins=extra_allowed_origins(),
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)


class IntentSpecModel(BaseModel):
    """Structured intent prompt accepted by the API."""

    task_id: str = Field(default="", description="Optional caller-supplied id")
    title: str = Field(min_length=1, max_length=200)
    description: str = Field(min_length=1, max_length=4000)
    function_name: str = Field(default="solve", max_length=100)
    signature: str = Field(default="", max_length=300)
    requirements: list[str] = Field(default_factory=list, max_length=30)
    example: str = Field(default="", max_length=1000)
    buggy_code: str = Field(default="", max_length=20000)


class ValidateRequest(BaseModel):
    """Request body for ``/validate-code``."""

    intent_spec: IntentSpecModel
    max_iterations: int | None = Field(default=None, ge=1, le=6)


class IssueModel(BaseModel):
    """A single deterministic finding."""

    code: str
    severity: Literal["low", "medium", "high", "critical"]
    category: Literal["security", "style", "typing", "correctness"]
    line: int
    message: str
    snippet: str = ""


class ValidateResponse(BaseModel):
    """Gate result returned to the caller."""

    task_id: str
    verdict: Literal["PASS", "FAIL", "ESCALATE_TO_HUMAN"]
    iterations: int
    latency_s: float
    generated_code: str
    static_issues: list[IssueModel] = Field(default_factory=list)
    security_issues: list[IssueModel] = Field(default_factory=list)
    test_results: dict[str, Any] = Field(default_factory=dict)
    reviewer_feedback: str = ""
    escalate_reason: str = ""
    history: list[dict[str, Any]] = Field(default_factory=list)


class ScanRequest(BaseModel):
    """Request body for ``/scan``."""

    code: str = Field(min_length=1, max_length=200_000)


class ScanResponse(BaseModel):
    """Deterministic scan result."""

    passed: bool
    blocking: list[IssueModel] = Field(default_factory=list)
    issues: list[IssueModel] = Field(default_factory=list)


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    """Serve the single-page front-end."""
    page = STATIC_DIR / "index.html"
    if not page.is_file():  # pragma: no cover - packaging error
        raise HTTPException(status_code=404, detail="front-end not built")
    return FileResponse(page, media_type="text/html")


@app.get("/health")
def health() -> dict[str, Any]:
    """Report service health.

    Deliberately omits the provider base URL: it identifies the upstream vendor
    and a health probe does not need it.
    """
    settings = get_settings()
    return {
        "status": "ok",
        "version": __version__,
        "model": settings.model,
        "api_key_configured": bool(settings.api_key),
        "max_iterations": settings.max_iterations,
        "serverless": SERVERLESS,
        "full_pipeline_available": bool(settings.api_key) and not SERVERLESS,
        "scan_available": True,
    }


@app.post("/validate-code", response_model=ValidateResponse)
def validate(request: ValidateRequest) -> ValidateResponse:
    """Run coder -> static/security -> tests -> reviewer until the gate settles."""
    settings = get_settings()
    if not settings.api_key:
        raise HTTPException(
            status_code=503,
            detail=(
                "LLM API key is not configured on this server. The free /scan "
                "endpoint (deterministic, no LLM) is still available."
            ),
        )
    if SERVERLESS:
        raise HTTPException(
            status_code=501,
            detail=(
                "A full validation takes 12-90s and cannot finish inside a serverless "
                "request limit. Use the containerised deployment for this endpoint, "
                "or /scan on this host."
            ),
        )
    if request.max_iterations is not None:
        cap = MAX_ITERATIONS_SERVERLESS if SERVERLESS else MAX_ITERATIONS_LOCAL
        settings = type(settings)(
            **{
                **settings.__dict__,
                "max_iterations": min(request.max_iterations, cap),
            }
        )
    try:
        intent = cast(IntentSpec, request.intent_spec.model_dump())
        final = validate_code(intent, settings=settings)
    except Exception as exc:  # surface as a clean 502
        raise HTTPException(status_code=502, detail=f"validation failed: {exc}") from exc
    return ValidateResponse(
        task_id=final.get("task_id") or request.intent_spec.task_id,
        verdict=final.get("verdict", "ESCALATE_TO_HUMAN"),  # type: ignore[arg-type]
        iterations=int(final.get("iterations") or 0),
        latency_s=float(final.get("latency_s") or 0.0),
        generated_code=final.get("generated_code") or "",
        static_issues=final.get("static_issues") or [],
        security_issues=final.get("security_issues") or [],
        test_results=final.get("test_results") or {},
        reviewer_feedback=final.get("reviewer_feedback") or "",
        escalate_reason=final.get("escalate_reason") or "",
        history=final.get("history") or [],
    )


@app.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest) -> ScanResponse:
    """Run only the deterministic scanner — no LLM, no cost, no latency."""
    from src.agents.static_security_agent import agent_report

    report = agent_report(request.code)
    return ScanResponse(
        passed=bool(report["passed"]),
        blocking=report["blocking"],
        issues=report["issues"],
    )
