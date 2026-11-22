"""Unit tests for the sandboxed pytest runner."""

from __future__ import annotations

from src.agents.test_runner_agent import (
    build_test_source,
    parse_pytest_output,
    run_pytest,
)

GOOD = '''\
def solve(x: int) -> int:
    """Double a number."""
    return x * 2
'''

BROKEN = '''\
def solve(x: int) -> int:
    """Double a number."""
    return x * 3
'''

RAISES = '''\
def solve(x: int) -> int:
    """Explode."""
    raise RuntimeError("boom")
'''


def test_good_code_passes():
    result = run_pytest(GOOD, entry="solve", min_args=1, timeout_s=60)
    assert result["passed"] is True
    assert result["failed_count"] == 0
    assert result["passed_count"] >= 3
    assert result["timed_out"] is False


def test_missing_entry_point_fails():
    code = 'def other(x: int) -> int:\n    """Wrong name."""\n    return x\n'
    result = run_pytest(code, entry="solve", min_args=1, timeout_s=60)
    assert result["passed"] is False
    assert result["failed_count"] > 0
    assert any("entry point" in f.lower() for f in result["failures"])


def test_signature_arity_checked():
    code = 'def solve() -> int:\n    """No args."""\n    return 1\n'
    result = run_pytest(code, entry="solve", min_args=2, timeout_s=60)
    assert result["passed"] is False


def test_syntax_error_fails_import():
    result = run_pytest("def broken(:\n", entry="solve", timeout_s=60)
    assert result["passed"] is False
    assert result["failed_count"] > 0


def test_runtime_error_is_a_failure():
    result = run_pytest(RAISES, entry="solve", min_args=1, timeout_s=60)
    assert result["passed"] is False


def test_timeout_is_enforced():
    code = (
        "import time\n"
        "\n"
        "def solve(x: int) -> int:\n"
        '    """Sleep forever."""\n'
        "    time.sleep(30)\n"
        "    return x\n"
    )
    result = run_pytest(code, entry="solve", min_args=1, timeout_s=5)
    assert result["passed"] is False
    assert result["timed_out"] is True


def test_extra_tests_are_appended():
    extra = (
        "def test_double_of_four():\n"
        '    """Check the entry point behaves."""\n'
        "    import candidate\n"
        "    assert candidate.solve(4) == 8\n"
    )
    result = run_pytest(GOOD, entry="solve", min_args=1, extra_tests=extra, timeout_s=60)
    assert result["passed"] is True


def test_extra_test_failure_is_reported():
    extra = (
        "def test_wrong_expectation():\n"
        '    """Deliberately wrong."""\n'
        "    import candidate\n"
        "    assert candidate.solve(4) == 5\n"
    )
    result = run_pytest(GOOD, entry="solve", min_args=1, extra_tests=extra, timeout_s=60)
    assert result["passed"] is False
    assert result["failed_count"] >= 1


def test_generated_test_source_mentions_entry_point():
    src = build_test_source(entry="transform", min_args=2)
    assert "transform" in src
    assert "MIN_ARGS = 2" in src


def test_parse_counts_from_output():
    out = "3 passed, 1 failed in 0.12s\nFAILED test_candidate.py::test_x\n"
    parsed = parse_pytest_output(out, "")
    assert parsed["passed_count"] == 3
    assert parsed["failed_count"] == 1
    assert parsed["total"] == 4
    assert any("test_x" in f for f in parsed["failures"])


def test_parse_handles_empty_output():
    parsed = parse_pytest_output("", "")
    assert parsed["total"] == 0
    assert parsed["failures"] == []


def test_sandbox_is_cleaned_up():
    from src.agents.test_runner_agent import Sandbox

    box = Sandbox(root=__import__("pathlib").Path(__import__("tempfile").mkdtemp()))
    box.write("x: int = 1\n", "def test_a():\n    pass\n")
    assert box.module_path.exists()
    box.cleanup()
    assert not box.root.exists()
