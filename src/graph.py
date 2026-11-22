"""Cyclic LangGraph assembly and the CI/CD quality-gate policy.

Topology::

    START -> coder -> static_security -> test_runner -> gate
                                                        |-- PASS  -> END
                                                        |-- fail & iters < max
                                                        |      -> reviewer -> coder
                                                        `-- else  -> escalate -> END

The gate decision is deterministic and lives in one pure function
(:func:`decide_route`) so it can be unit tested without a model or a graph.
"""

from __future__ import annotations

import time
from typing import Any, Literal

from langgraph.graph import END, START, StateGraph

from src.agents.coder_agent import make_coder_node
from src.agents.reviewer_agent import make_reviewer_node
from src.agents.static_security_agent import blocking_issues, make_static_security_node
from src.agents.test_runner_agent import make_test_runner_node
from src.config import Settings, get_settings
from src.state import CodeGuardState, IntentSpec

Route = Literal["pass", "retry", "escalate"]


def collect_blocking(state: CodeGuardState) -> list[dict[str, Any]]:
    """All findings severe enough to fail the gate, from both scanners."""
    combined = list(state.get("static_issues") or []) + list(state.get("security_issues") or [])
    return [dict(i) for i in blocking_issues(combined)]


def decide_route(state: CodeGuardState, max_iterations: int = 3) -> Route:
    """Deterministic gate: PASS, retry with reviewer, or escalate to a human."""
    blocking = collect_blocking(state)
    tests = state.get("test_results") or {}
    tests_ok = bool(tests.get("passed")) and not tests.get("timed_out", False)
    iterations = int(state.get("iterations") or 0)

    if not blocking and tests_ok:
        return "pass"
    if iterations < max_iterations:
        return "retry"
    return "escalate"


def gate_node(state: CodeGuardState, max_iterations: int = 3) -> dict[str, Any]:
    """Record the routing decision in state without ending the graph."""
    route = decide_route(state, max_iterations)
    blocking = collect_blocking(state)
    tests = state.get("test_results") or {}
    reason = ""
    if route == "pass":
        verdict = "PASS"
    elif route == "retry":
        verdict = "FAIL"
        reason = f"Attempt {state.get('iterations')} failed the gate; sending fixes to the coder."
    else:
        verdict = "ESCALATE_TO_HUMAN"
        reason = (
            f"Gate still failing after {state.get('iterations')} attempt(s): "
            f"{len(blocking)} blocking finding(s), "
            f"tests passed={tests.get('passed', False)}."
        )
    return {
        "verdict": verdict,
        "escalate_reason": reason,
        "history": [
            {
                "node": "gate",
                "iteration": int(state.get("iterations") or 0),
                "route": route,
                "blocking": len(blocking),
                "tests_passed": tests.get("passed", False),
            }
        ],
    }


def make_escalate_node():
    """Terminal node: hand the case to a human with a full evidence bundle."""

    def escalate_node(state: CodeGuardState) -> dict[str, Any]:
        blocking = collect_blocking(state)
        tests = state.get("test_results") or {}
        summary = [
            "task_id="
            + str(state.get("task_id") or (state.get("intent_spec") or {}).get("task_id", "?")),
            f"attempts={state.get('iterations')}",
            f"blocking_findings={len(blocking)}",
            f"tests_passed={tests.get('passed', False)}",
        ]
        for issue in blocking[:10]:
            summary.append(
                f"- [{issue.get('severity')}] {issue.get('code')} line "
                f"{issue.get('line')}: {issue.get('message')}"
            )
        return {
            "verdict": "ESCALATE_TO_HUMAN",
            "escalate_reason": (state.get("escalate_reason") or "") + "\n" + "\n".join(summary),
            "history": [
                {
                    "node": "escalate",
                    "iteration": int(state.get("iterations") or 0),
                    "blocking": len(blocking),
                }
            ],
        }

    return escalate_node


def build_graph(settings: Settings | None = None, *, with_reviewer: bool = True):
    """Compile the validation graph.

    ``settings`` controls the iteration cap and model; ``with_reviewer=False``
    is used by tests that want the loop without LLM calls.
    """
    cfg = settings or get_settings()
    max_iterations = cfg.max_iterations

    graph = StateGraph(CodeGuardState)
    graph.add_node("coder", make_coder_node(cfg))
    graph.add_node("static_security", make_static_security_node())
    graph.add_node("test_runner", make_test_runner_node(cfg))
    graph.add_node("gate", lambda state: gate_node(state, max_iterations))
    graph.add_node("escalate", make_escalate_node())

    graph.add_edge(START, "coder")
    graph.add_edge("coder", "static_security")
    graph.add_edge("static_security", "test_runner")
    graph.add_edge("test_runner", "gate")

    if with_reviewer:
        graph.add_node("reviewer", make_reviewer_node(cfg))
        targets: dict[Route, str] = {
            "pass": END,
            "retry": "reviewer",
            "escalate": "escalate",
        }
    else:
        targets = {"pass": END, "retry": "coder", "escalate": "escalate"}

    graph.add_conditional_edges(
        "gate",
        lambda state: decide_route(state, max_iterations),
        targets,
    )
    if with_reviewer:
        graph.add_edge("reviewer", "coder")
    graph.add_edge("escalate", END)
    return graph.compile()


def validate_code(
    intent_spec: IntentSpec,
    *,
    settings: Settings | None = None,
    with_reviewer: bool = True,
) -> dict[str, Any]:
    """Run one full validation cycle and return the final state.

    Adds wall-clock latency to the returned state under ``latency_s``.
    """
    cfg = settings or get_settings()
    app = build_graph(cfg, with_reviewer=with_reviewer)
    initial: CodeGuardState = {
        "intent_spec": intent_spec,
        "task_id": intent_spec.get("task_id", ""),
        "iterations": 0,
        "static_issues": [],
        "security_issues": [],
        "history": [],
    }
    start = time.perf_counter()
    final = app.invoke(initial, {"recursion_limit": 4 * (cfg.max_iterations + 2)})
    final["latency_s"] = round(time.perf_counter() - start, 3)
    return final
