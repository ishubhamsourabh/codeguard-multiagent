"""Integration tests: the gate must catch every seeded benchmark flaw.

These tests are the regression guard for the security story. Each benchmark
task that ships a deliberately vulnerable ``buggy_code`` seed must be rejected
by the deterministic gate. If a future refactor blinds the scanner, these fail
immediately — without spending a single LLM token.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from src.agents.static_security_agent import blocking_issues, scan_source, split_issues
from src.agents.test_runner_agent import run_pytest
from src.graph import decide_route

TASKS = json.loads(
    (Path(__file__).resolve().parent.parent / "eval" / "benchmark_tasks.json").read_text(
        encoding="utf-8"
    )
)
SECURITY_TASKS = [t for t in TASKS if t.get("category") == "security" and t.get("buggy_code")]


def test_benchmark_has_ten_tasks():
    assert len(TASKS) == 10
    ids = [t["task_id"] for t in TASKS]
    assert len(ids) == len(set(ids)), "duplicate task ids"


def test_no_task_declares_a_false_arity():
    """Zero-argument entry points must declare min_args=0.

    Otherwise the generated containment suite would fail a correct function
    purely for having no parameters — a harness bug masquerading as a finding.
    """
    for task in TASKS:
        seed = task.get("buggy_code") or ""
        if not seed.strip():
            continue  # greenfield task: no seed signature to compare against
        fn_name = task["intent"].get("function_name", "solve")
        match = next((f for f in _functions(seed) if f.name == fn_name), None)
        if match is None:
            continue
        required = len(
            [p for p in match.args.posonlyargs + match.args.args if p.arg not in {"self", "cls"}]
        )
        declared = int(task["intent"].get("min_args", 1) or 0)
        assert declared <= required, (
            f"{task['task_id']}: declares min_args={declared} but {fn_name} takes {required}"
        )


def _functions(source: str) -> list:
    """Top-level function defs in a source string."""
    import ast

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    return [n for n in tree.body if isinstance(n, ast.FunctionDef)]


def test_every_task_has_hidden_tests():
    for task in TASKS:
        assert task.get("hidden_tests", "").strip(), f"{task['task_id']} has no hidden tests"
        assert task.get("intent", {}).get("function_name"), f"{task['task_id']} lacks entry point"


def test_security_tasks_exist():
    assert len(SECURITY_TASKS) >= 3


@pytest.mark.parametrize("task", SECURITY_TASKS, ids=lambda t: t["task_id"])
def test_seeded_flaw_is_flagged_as_security(task):
    _static, security = split_issues(scan_source(task["buggy_code"]))
    assert security, f"{task['task_id']}: seeded flaw not classified as security"


@pytest.mark.parametrize("task", SECURITY_TASKS, ids=lambda t: t["task_id"])
def test_seeded_flaw_blocks_the_gate(task):
    seed = task["buggy_code"]
    static, security = split_issues(scan_source(seed))
    assert blocking_issues(static + security), f"{task['task_id']}: no blocking finding"
    tests = run_pytest(
        seed,
        entry=task["intent"].get("function_name", "solve"),
        min_args=1,
        timeout_s=30,
    )
    state = {
        "static_issues": static,
        "security_issues": security,
        "test_results": tests,
        "iterations": 1,
    }
    assert decide_route(state, 3) != "pass", f"{task['task_id']}: gate passed vulnerable code"


@pytest.mark.parametrize("task", SECURITY_TASKS, ids=lambda t: t["task_id"])
def test_seeded_flaw_fails_the_hidden_suite(task):
    """The hidden tests must actually detect the vulnerability themselves."""
    result = run_pytest(
        task["buggy_code"],
        entry=task["intent"].get("function_name", "solve"),
        min_args=1,
        extra_tests=task["hidden_tests"],
        timeout_s=30,
    )
    assert result["passed"] is False, f"{task['task_id']}: hidden tests passed vulnerable code"


def test_every_task_has_an_acceptance_suite():
    """Acceptance tests are the behavioural bar the gate actually enforces."""
    for task in TASKS:
        acc = task.get("acceptance_tests") or task["intent"].get("extra_tests")
        assert acc and acc.strip(), f"{task['task_id']} has no acceptance suite"
        assert acc != task.get("hidden_tests"), (
            f"{task['task_id']}: acceptance suite must differ from the scoring suite"
        )


@pytest.mark.parametrize("task", TASKS, ids=lambda t: t["task_id"])
def test_acceptance_suite_rejects_the_seeded_bug(task):
    """For buggy seeds, the acceptance suite must fail the seed itself.

    This is the guard against a too-weak acceptance suite: if the seed passes
    the criteria, the gate would wave the bug through.
    """
    seed = task.get("buggy_code") or ""
    if not seed.strip():
        pytest.skip("greenfield task has no seed to reject")
    acc = task.get("acceptance_tests") or task["intent"].get("extra_tests", "")
    result = run_pytest(
        seed,
        entry=task["intent"].get("function_name", "solve"),
        min_args=int(task["intent"].get("min_args", 1) or 0),
        extra_tests=acc,
        timeout_s=30,
    )
    assert result["passed"] is False, f"{task['task_id']}: acceptance suite accepted the bug"
