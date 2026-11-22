"""LangGraph state schema shared by every node in the validation graph."""

from __future__ import annotations

from typing import Annotated, Any, Literal, TypedDict


def _append(left: list, right: list) -> list:
    """Reducer used by LangGraph to concatenate list-valued channels."""
    return (left or []) + (right or [])


Verdict = Literal["PASS", "FAIL", "ESCALATE_TO_HUMAN"]


class IntentSpec(TypedDict, total=False):
    """Structured description of what the code should do."""

    task_id: str
    title: str
    description: str
    function_name: str
    signature: str
    requirements: list[str]
    example: str
    buggy_code: str


class StaticIssue(TypedDict, total=False):
    """A single deterministic finding from the static/security scanner."""

    code: str
    severity: Literal["low", "medium", "high", "critical"]
    category: Literal["security", "style", "typing", "correctness"]
    line: int
    message: str
    snippet: str


class TestResults(TypedDict, total=False):
    """Outcome of running pytest against the generated code."""

    passed: bool
    total: int
    passed_count: int
    failed_count: int
    duration_s: float
    failures: list[str]
    stdout: str
    stderr: str
    timed_out: bool


class CodeGuardState(TypedDict, total=False):
    """Full graph state.

    ``iterations`` counts completed code-generation attempts (0 before the
    coder runs for the first time), which is what makes the 3-attempt loop
    bound well defined.
    """

    # Inputs
    intent_spec: IntentSpec
    task_id: str

    # Pipeline artifacts (per-attempt: each pass overwrites, so a fixed
    # finding cannot keep blocking the gate on the next iteration)
    generated_code: str
    static_issues: list[StaticIssue]
    security_issues: list[StaticIssue]
    test_results: TestResults

    # Loop control (history accumulates across attempts for the audit trail)
    reviewer_feedback: str
    review_payload: dict[str, Any]
    iterations: int
    history: Annotated[list[dict[str, Any]], _append]

    # Outcome
    verdict: Verdict
    escalate_reason: str
    latency_s: float
