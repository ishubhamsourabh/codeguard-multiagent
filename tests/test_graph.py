"""Tests for the graph: gate policy, routing, and the cyclic loop end-to-end."""

from __future__ import annotations

from src.agents.coder_agent import build_coder_prompt
from src.graph import (
    build_graph,
    collect_blocking,
    decide_route,
    gate_node,
    make_escalate_node,
)
from src.llm_client import LLMResponse

CLEAN = '''\
def solve(x: int) -> int:
    """Double the input."""
    return x * 2
'''

UNSAFE = """\
API_KEY = "sk-live-9f8a7b6c5d4e3f2a1b0c"


def solve(x):
    eval(x)
    return x
"""


def make_state(
    *,
    code: str = CLEAN,
    static: list | None = None,
    security: list | None = None,
    passed: bool = True,
    iterations: int = 1,
) -> dict:
    """Build a representative state dict for gate tests."""
    return {
        "intent_spec": {
            "task_id": "t1",
            "title": "T",
            "description": "D",
            "function_name": "solve",
        },
        "task_id": "t1",
        "generated_code": code,
        "static_issues": static or [],
        "security_issues": security or [],
        "test_results": {
            "passed": passed,
            "timed_out": False,
            "failures": [] if passed else ["boom"],
        },
        "iterations": iterations,
        "history": [],
    }


CRITICAL = [
    {
        "code": "EVAL_EXEC",
        "severity": "critical",
        "category": "security",
        "line": 4,
        "message": "eval",
        "snippet": "eval(x)",
    }
]
LOW = [
    {
        "code": "MISSING_DOCSTRING",
        "severity": "low",
        "category": "style",
        "line": 2,
        "message": "no docstring",
        "snippet": "def f",
    }
]


def test_clean_state_passes():
    assert decide_route(make_state(), max_iterations=3) == "pass"


def test_failing_tests_retry_when_budget_remains():
    assert decide_route(make_state(passed=False, iterations=1), max_iterations=3) == "retry"


def test_critical_finding_blocks_even_when_tests_pass():
    state = make_state(security=CRITICAL, passed=True)
    assert decide_route(state, max_iterations=3) == "retry"


def test_low_severity_does_not_block():
    state = make_state(static=LOW, passed=True)
    assert decide_route(state, max_iterations=3) == "pass"


def test_escalates_at_iteration_cap():
    state = make_state(security=CRITICAL, passed=False, iterations=3)
    assert decide_route(state, max_iterations=3) == "escalate"


def test_no_escalation_before_cap():
    state = make_state(security=CRITICAL, passed=False, iterations=2)
    assert decide_route(state, max_iterations=3) == "retry"


def test_timeout_counts_as_failure():
    state = make_state()
    state["test_results"] = {"passed": True, "timed_out": True}
    assert decide_route(state, max_iterations=3) == "retry"


def test_collect_blocking_merges_both_scanners():
    state = make_state(security=CRITICAL, static=LOW)
    blocking = collect_blocking(state)
    assert [b["code"] for b in blocking] == ["EVAL_EXEC"]


def test_gate_node_writes_pass_verdict():
    out = gate_node(make_state(), max_iterations=3)
    assert out["verdict"] == "PASS"
    assert out["escalate_reason"] == ""


def test_gate_node_writes_escalation_reason():
    out = gate_node(make_state(security=CRITICAL, iterations=3), max_iterations=3)
    assert out["verdict"] == "ESCALATE_TO_HUMAN"
    assert "attempt" in out["escalate_reason"].lower()


def test_escalate_node_summarises_evidence():
    state = make_state(security=CRITICAL, passed=False, iterations=3)
    out = make_escalate_node()(state)
    assert out["verdict"] == "ESCALATE_TO_HUMAN"
    assert "EVAL_EXEC" in out["escalate_reason"]
    assert "attempts=3" in out["escalate_reason"]


def test_coder_prompt_includes_feedback_and_previous_code():
    intent = {
        "title": "Double",
        "description": "Return double the input",
        "function_name": "solve",
        "signature": "solve(x: int) -> int",
        "requirements": ["no eval"],
    }
    prompt = build_coder_prompt(
        intent, feedback="1. remove eval", previous_code="def solve(x): eval(x)"
    )
    assert "Double" in prompt
    assert "no eval" in prompt
    assert "1. remove eval" in prompt
    assert "previous attempt" in prompt


def test_coder_prompt_without_feedback():
    prompt = build_coder_prompt({"title": "T", "description": "D"})
    assert "previous attempt" not in prompt
    assert "Write the complete module now." in prompt


class ScriptedCoder:
    """LLM fake that returns a scripted sequence of responses."""

    def __init__(self, responses: list[str]):
        self.responses = list(responses)
        self.calls = 0

    def complete(self, system, user, *, temperature=0.0, max_tokens=4000):
        self.calls += 1
        text = self.responses[min(self.calls - 1, len(self.responses) - 1)]
        return LLMResponse(text=text, latency_s=0.0)


def _fenced(code: str) -> str:
    return f"```python\n{code}\n```"


def test_graph_passes_clean_code_first_time():
    from src.agents.coder_agent import make_coder_node

    fake = ScriptedCoder([_fenced(CLEAN)])
    # Rebuild with the fake coder injected by replacing the node function.
    from langgraph.graph import END, START, StateGraph
    from src.agents.static_security_agent import make_static_security_node
    from src.agents.test_runner_agent import make_test_runner_node
    from src.state import CodeGuardState

    g = StateGraph(CodeGuardState)
    g.add_node("coder", make_coder_node(client=fake))
    g.add_node("static_security", make_static_security_node())
    g.add_node("test_runner", make_test_runner_node())
    g.add_node("gate", lambda s: gate_node(s, 3))
    g.add_node("escalate", make_escalate_node())
    g.add_edge(START, "coder")
    g.add_edge("coder", "static_security")
    g.add_edge("static_security", "test_runner")
    g.add_edge("test_runner", "gate")
    g.add_conditional_edges(
        "gate",
        lambda s: decide_route(s, 3),
        {"pass": END, "retry": "coder", "escalate": "escalate"},
    )
    g.add_edge("escalate", END)
    compiled = g.compile()

    final = compiled.invoke(
        {
            "intent_spec": {"title": "T", "description": "D", "function_name": "solve"},
            "iterations": 0,
            "static_issues": [],
            "security_issues": [],
            "history": [],
        },
        {"recursion_limit": 40},
    )
    assert final["verdict"] == "PASS"
    assert final["iterations"] == 1
    assert fake.calls == 1


def test_graph_escalates_after_cap_with_persistent_offender():
    from langgraph.graph import END, START, StateGraph
    from src.agents.coder_agent import make_coder_node
    from src.agents.static_security_agent import make_static_security_node
    from src.agents.test_runner_agent import make_test_runner_node
    from src.state import CodeGuardState

    fake = ScriptedCoder([_fenced(UNSAFE)])
    g = StateGraph(CodeGuardState)
    g.add_node("coder", make_coder_node(client=fake))
    g.add_node("static_security", make_static_security_node())
    g.add_node("test_runner", make_test_runner_node())
    g.add_node("gate", lambda s: gate_node(s, 2))
    g.add_node("escalate", make_escalate_node())
    g.add_edge(START, "coder")
    g.add_edge("coder", "static_security")
    g.add_edge("static_security", "test_runner")
    g.add_edge("test_runner", "gate")
    g.add_conditional_edges(
        "gate",
        lambda s: decide_route(s, 2),
        {"pass": END, "retry": "coder", "escalate": "escalate"},
    )
    g.add_edge("escalate", END)

    final = g.compile().invoke(
        {
            "intent_spec": {"title": "T", "description": "D", "function_name": "solve"},
            "iterations": 0,
            "static_issues": [],
            "security_issues": [],
            "history": [],
        },
        {"recursion_limit": 40},
    )
    assert final["verdict"] == "ESCALATE_TO_HUMAN"
    assert final["iterations"] == 2
    assert fake.calls == 2
    assert any(i["code"] == "HARDCODED_SECRET" for i in final["security_issues"])


def test_build_graph_compiles():
    app = build_graph(with_reviewer=True)
    assert app is not None
    nodes = set(app.get_graph().nodes)
    assert {"coder", "static_security", "test_runner", "gate", "reviewer", "escalate"} <= nodes
