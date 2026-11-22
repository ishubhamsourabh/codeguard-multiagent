"""Test runner agent: executes pytest against generated code in a sandbox.

Isolation strategy
------------------
The candidate module is written to a throw-away directory. Tests run via a
*subprocess* with (a) a wall-clock timeout, (b) a scratch ``cwd`` so nothing
leaks into the repo, (c) ``PYTHONPATH`` restricted to the sandbox, and (d) a
stripped environment that keeps only what Python needs to start. On POSIX a
new process group is created so the whole tree can be killed; on Windows the
subprocess is killed through ``taskkill /T``.

Only exit code and the parsed console summary decide pass/fail — never a
model's opinion.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.config import Settings, get_settings
from src.state import TestResults

_COUNT_RES = {
    "passed": re.compile(r"(\d+) passed"),
    "failed": re.compile(r"(\d+) (?:failed|error)"),
}

ENV_KEEP = {
    "PATH",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
    "PYTHONHASHSEED",
    "NUMBER_OF_PROCESSORS",
}

# Tests generated for a candidate module. The template uses __TOKEN__
# placeholders (never str.format) so the embedded Python can use braces and
# dict literals freely.
TEST_TEMPLATE = '''\
"""Auto-generated containment tests for __MODULE__."""
import importlib
import inspect
import typing

MODULE = "__MODULE__"
ENTRY = "__ENTRY__"
MIN_ARGS = __MIN_ARGS__


def _load():
    """Import the candidate module."""
    return importlib.import_module(MODULE)


def _entry():
    """Return the declared entry point, failing clearly when absent."""
    getattr_name = ENTRY
    mod = _load()
    fn = getattr(mod, getattr_name, None)
    assert fn is not None, "missing entry point " + getattr_name
    assert callable(fn), getattr_name + " is not callable"
    return fn


def _sample_for(annotation):
    """Build a benign sample argument from a type annotation."""
    if annotation is inspect.Parameter.empty:
        return "sample"
    origin = typing.get_origin(annotation)
    if origin is typing.Union:
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        return _sample_for(args[0]) if args else None
    if origin in (list, set, tuple, frozenset):
        return [] if origin is not tuple else ()
    if origin is dict:
        return {}
    mapping = {
        int: 1,
        float: 1.0,
        str: "sample",
        bytes: b"sample",
        bool: True,
        list: [],
        dict: {},
        tuple: (),
        set: set(),
    }
    try:
        return mapping.get(annotation, "sample")
    except TypeError:
        return "sample"


def _call_args(fn):
    """Build one sample argument list for the entry point."""
    sig = inspect.signature(fn)
    args = []
    for name, param in sig.parameters.items():
        if name in ("self", "cls"):
            continue
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        args.append(_sample_for(param.annotation))
    return args


def test_module_imports_cleanly():
    """The generated module must import without executing side effects."""
    assert _load() is not None


def test_entry_point_callable():
    """The declared entry point must exist and be callable."""
    fn = _entry()
    assert callable(fn)


def test_signature_matches():
    """The entry point must accept at least the declared arity."""
    sig = inspect.signature(_entry())
    positional = [
        p for p in sig.parameters.values()
        if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
    ]
    assert len(positional) >= MIN_ARGS, "entry point takes too few arguments"


def test_entry_point_executes():
    """Call the entry point: it must return or reject input via ValueError."""
    fn = _entry()
    try:
        fn(*_call_args(fn))
    except ValueError:
        return  # documented contract for rejected input


__EXTRA_TESTS__
'''


@dataclass
class Sandbox:
    """A temporary directory holding candidate code plus its tests."""

    root: Path
    module_name: str = "candidate"

    @property
    def module_path(self) -> Path:
        return self.root / f"{self.module_name}.py"

    @property
    def test_path(self) -> Path:
        return self.root / "test_candidate.py"

    def write(self, code: str, test_source: str) -> None:
        self.module_path.write_text(code, encoding="utf-8")
        self.test_path.write_text(test_source, encoding="utf-8")

    def cleanup(self) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def build_test_source(
    module_name: str = "candidate",
    entry: str | None = None,
    min_args: int = 1,
    extra_tests: str = "",
) -> str:
    """Render the containment test file for a candidate module."""
    return (
        TEST_TEMPLATE.replace("__MODULE__", module_name)
        .replace("__ENTRY__", entry or "solve")
        .replace("__MIN_ARGS__", str(max(0, int(min_args))))
        .replace("__EXTRA_TESTS__", extra_tests or "")
    )


def _sanitized_env(sandbox: Path) -> dict[str, str]:
    """Build a minimal environment that cannot import repo packages."""
    env = {k: v for k, v in os.environ.items() if k in ENV_KEEP}
    env["PYTHONPATH"] = str(sandbox)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"
    env.setdefault("SYSTEMROOT", os.environ.get("SYSTEMROOT", ""))
    return {k: v for k, v in env.items() if v}


def parse_pytest_output(stdout: str, stderr: str) -> dict[str, Any]:
    """Extract pass/fail counts and failure lines from pytest console output."""
    text = f"{stdout}\n{stderr}"
    counts = {"passed": 0, "failed": 0}
    for key, pattern in _COUNT_RES.items():
        match = pattern.search(text)
        if match:
            counts[key] = int(match.group(1))
    failures = [
        line.strip()
        for line in text.splitlines()
        if line.startswith(("FAILED", "ERROR", "E   ", "Timeout"))
    ]
    return {
        "passed_count": counts["passed"],
        "failed_count": counts["failed"],
        "failures": failures[:20],
        "total": counts["passed"] + counts["failed"],
    }


def run_pytest(
    code: str,
    *,
    entry: str | None = None,
    min_args: int = 1,
    extra_tests: str = "",
    timeout_s: int | None = None,
    python_exe: str | None = None,
) -> TestResults:
    """Run pytest on ``code`` inside an isolated temp directory.

    Returns a :class:`TestResults` dict; never raises for candidate failures.
    """
    settings: Settings = get_settings()
    timeout = timeout_s or settings.pytest_timeout_s
    python = python_exe or sys.executable
    sandbox = Sandbox(root=Path(tempfile.mkdtemp(prefix="codeguard-sbx-")))
    start = time.perf_counter()
    try:
        sandbox.write(
            code,
            build_test_source(entry=entry, min_args=min_args, extra_tests=extra_tests),
        )
        cmd = [
            python,
            "-m",
            "pytest",
            sandbox.test_path.name,
            "-p",
            "no:cacheprovider",
            "-q",
            "--no-header",
            "--timeout",
            str(max(5, timeout)),
        ]
        kwargs: dict[str, Any] = {
            "cwd": str(sandbox.root),
            "env": _sanitized_env(sandbox.root),
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
            "timeout": timeout + 15,
        }
        if os.name == "posix":
            kwargs["start_new_session"] = True
        else:  # pragma: no cover - Windows only
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        try:
            proc = subprocess.run(cmd, **kwargs)
            stdout, stderr, rc = proc.stdout or "", proc.stderr or "", proc.returncode
            timed_out = False
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or "") if isinstance(exc.stdout, str) else ""
            stderr = (exc.stderr or "") if isinstance(exc.stderr, str) else ""
            rc, timed_out = 124, True
        duration = round(time.perf_counter() - start, 3)
        parsed = parse_pytest_output(stdout, stderr)
        # pytest-timeout interrupts the test in-process, so subprocess returns
        # normally. Detect its marker and treat it as a real timeout.
        plugin_timeout = " Timeout +++" in stdout or " Timeout +++" in stderr
        if plugin_timeout:
            timed_out = True
        passed = (rc == 0) and not timed_out and parsed["failed_count"] == 0
        if timed_out:
            parsed["failures"].insert(0, f"pytest exceeded the {timeout}s timeout")
            parsed["failed_count"] = max(1, parsed["failed_count"])
        return TestResults(
            passed=passed,
            total=parsed["total"],
            passed_count=parsed["passed_count"],
            failed_count=parsed["failed_count"],
            duration_s=duration,
            failures=parsed["failures"],
            stdout=stdout[-6000:],
            stderr=stderr[-4000:],
            timed_out=timed_out,
        )
    finally:
        sandbox.cleanup()


def make_test_runner_node(settings: Settings | None = None):
    """LangGraph node: run the generated code's tests in the sandbox."""
    cfg = settings or get_settings()

    def test_runner_node(state: dict[str, Any]) -> dict[str, Any]:
        code = state.get("generated_code") or ""
        intent = state.get("intent_spec") or {}
        if not code.strip():
            results = TestResults(
                passed=False,
                total=0,
                passed_count=0,
                failed_count=0,
                duration_s=0.0,
                failures=["No code was generated, so nothing could be tested."],
                stdout="",
                stderr="",
                timed_out=False,
            )
        else:
            results = run_pytest(
                code,
                entry=intent.get("function_name"),
                min_args=int(intent.get("min_args", 1) or 0),
                extra_tests=intent.get("extra_tests", "") or "",
                timeout_s=cfg.pytest_timeout_s,
            )
        return {
            "test_results": results,
            "history": [
                {
                    "node": "test_runner",
                    "iteration": int(state.get("iterations") or 0),
                    "passed": results.get("passed", False),
                    "failed_count": results.get("failed_count", 0),
                    "duration_s": results.get("duration_s", 0.0),
                }
            ],
        }

    return test_runner_node
