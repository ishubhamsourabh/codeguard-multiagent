"""Unit tests for the deterministic static + security scanner."""

from __future__ import annotations

from src.agents.static_security_agent import (
    blocking_issues,
    format_issues,
    scan_source,
    split_issues,
)


def codes(issues: list) -> set[str]:
    """Rule codes present in a finding list."""
    return {i["code"] for i in issues}


GOOD_CODE = '''
import os
from typing import Optional


def get_token(name: str = "app") -> Optional[str]:
    """Read a token from the environment.

    Args:
        name: Prefix of the environment variable.

    Returns:
        The token, or None when unset.
    """
    value = os.environ.get(f"{name.upper()}_TOKEN")
    if value is None:
        raise ValueError("missing token")
    return value
'''


def test_clean_code_has_no_security_findings():
    issues = scan_source(GOOD_CODE)
    _static, security = split_issues(issues)
    assert security == []
    assert blocking_issues(issues) == []


def test_detects_hardcoded_api_key():
    src = 'API_KEY = "sk-live-9f8a7b6c5d4e3f2a1b0c"\n'
    issues = scan_source(src)
    assert "HARDCODED_SECRET" in codes(issues)
    assert blocking_issues(issues)


def test_placeholder_is_not_flagged():
    src = 'API_KEY = "your-api-key-here"\n'
    issues = scan_source(src)
    assert "HARDCODED_SECRET" not in codes(issues)


def test_detects_aws_and_github_token_shapes():
    src = 'aws = "AKIAIOSFODNN7EXAMPLE"\ngh = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n'
    issues = scan_source(src)
    assert "HARDCODED_SECRET" in codes(issues)
    assert len(blocking_issues(issues)) >= 1


def test_detects_eval_and_exec():
    src = 'def f(x: str) -> None:\n    """Run."""\n    eval(x)\n'
    issues = scan_source(src)
    assert "EVAL_EXEC" in codes(issues)


def test_detects_bare_except():
    src = (
        "def f() -> int:\n"
        '    """Do."""\n'
        "    try:\n"
        "        return 1\n"
        "    except:\n"
        "        return 0\n"
    )
    issues = scan_source(src)
    assert "BARE_EXCEPT" in codes(issues)


def test_bare_except_does_not_fire_on_typed_except():
    src = (
        "def f() -> int:\n"
        '    """Do."""\n'
        "    try:\n"
        "        return 1\n"
        "    except ValueError:\n"
        "        return 0\n"
    )
    assert "BARE_EXCEPT" not in codes(scan_source(src))


def test_detects_sql_fstring_in_execute():
    src = (
        "def q(cursor, uid: int) -> None:\n"
        '    """Query."""\n'
        '    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")\n'
    )
    issues = scan_source(src)
    assert "SQL_STRING_FORMAT" in codes(issues)


def test_detects_sql_percent_format_assignment():
    src = (
        "def q(uid: int) -> str:\n"
        '    """Query."""\n'
        '    query = "SELECT name FROM users WHERE id = %s" % uid\n'
        "    return query\n"
    )
    assert "SQL_STRING_FORMAT" in codes(scan_source(src))


def test_parameterised_sql_does_not_fire():
    src = (
        "def q(cursor, uid: int) -> None:\n"
        '    """Query."""\n'
        '    cursor.execute("SELECT name FROM users WHERE id = ?", (uid,))\n'
    )
    assert "SQL_STRING_FORMAT" not in codes(scan_source(src))


def test_detects_missing_type_hints():
    src = 'def add(a, b):\n    """Add."""\n    return a + b\n'
    issues = scan_source(src)
    assert "MISSING_TYPE_HINT" in codes(issues)
    typing_issues = [i for i in issues if i["code"] == "MISSING_TYPE_HINT"]
    assert "return" in typing_issues[0]["message"]


def test_fully_typed_private_helper_not_flagged_for_hints():
    src = "def _helper(a: int) -> int:\n    return a + 1\n"
    assert "MISSING_TYPE_HINT" not in codes(scan_source(src))


def test_detects_syntax_error_as_blocking():
    issues = scan_source("def broken(:\n    pass\n")
    assert codes(issues) == {"SYNTAX_ERROR"}
    assert issues[0]["severity"] == "critical"
    assert blocking_issues(issues)


def test_detects_mutable_default_argument():
    src = 'def f(items: list = []) -> int:\n    """Count."""\n    return len(items)\n'
    assert "MUTABLE_DEFAULT_ARG" in codes(scan_source(src))


def test_detects_shell_true_with_dynamic_command():
    src = (
        "import subprocess\n"
        "\n"
        "def run(cmd: str) -> int:\n"
        '    """Run."""\n'
        "    return subprocess.run(cmd, shell=True).returncode\n"
    )
    assert "SHELL_INJECTION" in codes(scan_source(src))


def test_detects_pickle_loads():
    src = (
        "import pickle\n"
        "\n"
        "def load(data: bytes) -> object:\n"
        '    """Load."""\n'
        "    return pickle.loads(data)\n"
    )
    assert "UNSAFE_DESERIALIZE" in codes(scan_source(src))


def test_findings_are_deduplicated_and_ordered():
    src = (
        'KEY = "sk-live-9f8a7b6c5d4e3f2a1b0c"\n'
        "def f() -> None:\n"
        "    try:\n"
        "        eval('1')\n"
        "    except:\n"
        "        pass\n"
    )
    issues = scan_source(src)
    pairs = [(i["line"], i["code"]) for i in issues]
    assert len(pairs) == len(set(pairs)), "duplicate (line, code) findings"
    assert pairs == sorted(pairs)


def test_scan_is_deterministic():
    src = 'KEY = "sk-live-9f8a7b6c5d4e3f2a1b0c"\ndef f(a):\n    return a\n'
    assert scan_source(src) == scan_source(src)


def test_scan_empty_source():
    assert scan_source("") == []


def test_format_issues_renders_bullets():
    issues = scan_source("eval('x')\n")
    text = format_issues(issues)
    assert text.startswith("- [CRITICAL] EVAL_EXEC")
    assert format_issues([]) == "No issues found."
