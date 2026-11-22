"""FastAPI service exposing the validation gate over HTTP.

Endpoints
---------
``GET  /health``         liveness/readiness probe with configuration summary.
``POST /validate-code``  run the full multi-agent pipeline on an intent spec.
``POST /scan``           deterministic static/security scan only (no LLM).

Run locally::

    uvicorn api:app --reload --port 8000

Example::

    curl -X POST http://127.0.0.1:8000/validate-code \\
      -H 'Content-Type: application/json' \\
      -d '{"intent_spec": {"title": "Slug", "description": "Make a slug",
           "function_name": "slugify", "requirements": ["lowercase"]}}'
"""

from __future__ import annotations

from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from src import __version__
from src.config import get_settings
from src.graph import validate_code

app = FastAPI(
    title="codeguard-multiagent",
    version=__version__,
    description="Multi-agent AI code validator and CI/CD quality gate.",
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


@app.get("/health")
def health() -> dict[str, Any]:
    """Report service health and non-secret configuration."""
    settings = get_settings()
    return {
        "status": "ok",
        "version": __version__,
        "model": settings.model,
        "base_url": settings.base_url,
        "api_key_configured": bool(settings.api_key),
        "max_iterations": settings.max_iterations,
    }


@app.post("/validate-code", response_model=ValidateResponse)
def validate(request: ValidateRequest) -> ValidateResponse:
    """Run coder -> static/security -> tests -> reviewer until the gate settles."""
    settings = get_settings()
    if not settings.api_key:
        raise HTTPException(
            status_code=503,
            detail="LLM API key is not configured on the server.",
        )
    if request.max_iterations is not None:
        settings = type(settings)(
            **{
                **settings.__dict__,
                "max_iterations": request.max_iterations,
            }
        )
    try:
        final = validate_code(request.intent_spec.model_dump(), settings=settings)
    except Exception as exc:
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
