"""Reviewer agent: a temperature-0 LLM judge returning validated JSON.

The judge never decides the gate by itself — the static scanner and pytest
own that. Its single job is to explain *how to fix* the failure, in a format
the coder can consume on the next loop iteration.
"""

from __future__ import annotations

import json
import re
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

from src.config import Settings, get_settings
from src.llm_client import LLMClient
from src.state import CodeGuardState

SYSTEM_PROMPT = """You are a meticulous senior code reviewer performing a gate review.

You receive candidate Python code, deterministic static/security findings, and
real pytest output. Judge only on the evidence provided; never invent a failure
that is not in the evidence.

Return ONLY a JSON object with exactly these keys:
{
  "verdict": "PASS" | "FAIL",
  "summary": "one or two sentences",
  "fix_instructions": ["imperative instruction the author must apply", ...],
  "severity": "low" | "medium" | "high" | "critical",
  "confidence": 0.0-1.0
}

Rules:
- "verdict" must be "FAIL" if any critical/high finding exists or any test failed.
- Each fix instruction must be actionable and cite the line or rule code.
- Maximum 8 fix instructions, ordered by importance.
- No markdown, no prose outside the JSON object.
"""

_JSON_RE = re.compile(r"\{.*\}", re.DOTALL)


class ReviewVerdict(BaseModel):
    """Structured judge output. Extra keys are rejected to keep prompts honest."""

    model_config = {"extra": "forbid"}

    verdict: Literal["PASS", "FAIL"]
    summary: str = Field(min_length=1, max_length=2000)
    fix_instructions: list[str] = Field(default_factory=list, max_length=8)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)

    @field_validator("fix_instructions")
    @classmethod
    def _strip_items(cls, value: list[str]) -> list[str]:
        """Drop blank instructions and trim whitespace."""
        return [item.strip() for item in value if item and item.strip()]


def parse_review_json(text: str) -> ReviewVerdict:
    """Parse and validate a judge response.

    Raises ``ValueError`` when the payload is not valid, so the caller can
    fall back to a deterministic verdict instead of trusting garbage.
    """
    raw = (text or "").strip()
    if not raw:
        raise ValueError("empty reviewer response")
    match = _JSON_RE.search(raw)
    if not match:
        raise ValueError("no JSON object found in reviewer response")
    try:
        payload = json.loads(match.group(0))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON from reviewer: {exc}") from exc
    try:
        return ReviewVerdict.model_validate(payload)
    except ValidationError as exc:
        raise ValueError(f"reviewer JSON failed schema validation: {exc}") from exc


def deterministic_verdict(
    blocking: list[dict[str, Any]], test_results: dict[str, Any]
) -> ReviewVerdict:
    """Build a verdict from evidence alone when the LLM is unusable."""
    instructions: list[str] = []
    for issue in blocking:
        instructions.append(
            f"Fix {issue.get('code')} at line {issue.get('line')}: {issue.get('message')}"
        )
    for failure in (test_results.get("failures") or [])[:4]:
        instructions.append(f"Make this test pass: {failure}")
    failed = bool(instructions)
    return ReviewVerdict(
        verdict="FAIL" if failed else "PASS",
        summary=(
            "Deterministic fallback review: blocking findings or failing tests present."
            if failed
            else "Deterministic fallback review: no blocking findings and all tests passed."
        ),
        fix_instructions=instructions[:8],
        severity="high" if failed else "low",
        confidence=0.4,
    )


def build_review_prompt(state: CodeGuardState) -> str:
    """Render the evidence bundle for the judge. Pure function."""
    from src.agents.static_security_agent import format_issues

    intent = state.get("intent_spec") or {}
    static = state.get("static_issues") or []
    security = state.get("security_issues") or []
    tests = state.get("test_results") or {}
    stdout = (tests.get("stdout") or "").strip()
    if len(stdout) > 2500:
        stdout = stdout[-2500:]
    return "\n".join(
        [
            f"## Task\n{intent.get('title', '')}: {intent.get('description', '')}",
            f"\n## Candidate code\n```python\n{state.get('generated_code', '')}\n```",
            f"\n## Static findings\n{format_issues(static)}",
            f"\n## Security findings\n{format_issues(security)}",
            (
                "\n## Test results\n"
                f"passed={tests.get('passed')} "
                f"passed_count={tests.get('passed_count', 0)} "
                f"failed_count={tests.get('failed_count', 0)} "
                f"timed_out={tests.get('timed_out', False)}\n"
                f"failures:\n" + "\n".join(tests.get("failures") or ["(none)"])
            ),
            f"\n## pytest output (tail)\n{stdout or '(none)'}",
            "\nReturn the JSON verdict now.",
        ]
    )


def make_reviewer_node(settings: Settings | None = None, client: Any | None = None):
    """Factory returning the judge node (temperature 0, JSON validated).

    The LLM client is created lazily so graph construction needs no API key.
    """
    cfg = settings or get_settings()
    holder: dict[str, Any] = {"llm": client}

    def _llm() -> Any:
        if holder["llm"] is None:
            holder["llm"] = LLMClient(cfg)
        return holder["llm"]

    def reviewer_node(state: CodeGuardState) -> dict[str, Any]:
        from src.agents.static_security_agent import blocking_issues

        blocking = blocking_issues(
            (state.get("static_issues") or []) + (state.get("security_issues") or [])
        )
        tests = state.get("test_results") or {}
        prompt = build_review_prompt(state)
        source = "llm"
        try:
            resp = _llm().complete(
                SYSTEM_PROMPT,
                prompt,
                temperature=cfg.reviewer_temperature,
                max_tokens=1600,
            )
            review = parse_review_json(resp.text)
        except Exception:
            review = deterministic_verdict(blocking, tests)
            source = "fallback"

        feedback = "\n".join(f"{i}. {item}" for i, item in enumerate(review.fix_instructions, 1))
        if not feedback:
            feedback = f"Address the failing evidence:\n{review.summary}"
        return {
            "reviewer_feedback": feedback,
            "review_payload": {**review.model_dump(), "source": source},
            "history": [
                {
                    "node": "reviewer",
                    "iteration": int(state.get("iterations") or 0),
                    "source": source,
                    "verdict": review.verdict,
                    "fixes": len(review.fix_instructions),
                }
            ],
        }

    return reviewer_node
