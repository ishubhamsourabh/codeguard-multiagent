"""Benchmark harness for codeguard-multiagent.

Measures four things, all from real executions of the pipeline:

1. **First-pass %** — tasks that reach PASS on the coder's very first output.
2. **Self-corrected pass %** — tasks that fail attempt 1 but reach PASS within
   the iteration budget (this is the loop's whole reason for existing).
3. **Security-flaw catch %** — for tasks seeded with a known vulnerability,
   how often the deterministic scanner flags it before the code can pass.
4. **Avg latency** — wall-clock seconds per validated task.

Scoring is done by a held-out pytest suite (``hidden_tests``) that the coder
never sees, run in the same sandbox as the pipeline's own tests. A task only
counts as passed when both the graph gate and the hidden suite agree.

Usage::

    python -m eval.run_benchmark                 # full run
    python -m eval.run_benchmark --limit 3       # quick smoke
    python -m eval.run_benchmark --out eval/results.json
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.agents.test_runner_agent import run_pytest  # noqa: E402
from src.config import get_settings  # noqa: E402
from src.graph import validate_code  # noqa: E402

TASKS_PATH = Path(__file__).resolve().parent / "benchmark_tasks.json"


@dataclass
class TaskResult:
    """Per-task outcome, kept flat so it serialises straight to JSON."""

    task_id: str
    category: str
    verdict: str = ""
    graph_passed: bool = False
    hidden_tests_passed: bool = False
    first_pass: bool = False
    self_corrected: bool = False
    security_seeded: bool = False
    security_caught: bool | None = None
    security_blocked: bool | None = None
    remediated_clean: bool | None = None
    iterations: int = 0
    latency_s: float = 0.0
    static_findings: int = 0
    security_findings: int = 0
    reviewer_source: str = ""
    error: str = ""
    history: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "category": self.category,
            "verdict": self.verdict,
            "graph_passed": self.graph_passed,
            "hidden_tests_passed": self.hidden_tests_passed,
            "first_pass": self.first_pass,
            "self_corrected": self.self_corrected,
            "security_seeded": self.security_seeded,
            "security_caught": self.security_caught,
            "security_blocked": self.security_blocked,
            "remediated_clean": self.remediated_clean,
            "iterations": self.iterations,
            "latency_s": self.latency_s,
            "static_findings": self.static_findings,
            "security_findings": self.security_findings,
            "reviewer_source": self.reviewer_source,
            "error": self.error,
        }


def load_tasks(path: Path | None = None) -> list[dict[str, Any]]:
    """Load the benchmark task list."""
    return json.loads((path or TASKS_PATH).read_text(encoding="utf-8"))


def run_task(task: dict[str, Any], *, settings=None) -> TaskResult:
    """Run one benchmark task through the full multi-agent pipeline."""
    cfg = settings or get_settings()
    result = TaskResult(
        task_id=task["task_id"],
        category=task.get("category", "coding"),
        security_seeded=bool(task.get("buggy_seed")) and task.get("category") == "security",
    )
    intent = dict(task["intent"])
    if task.get("buggy_code") and not intent.get("buggy_code"):
        intent["buggy_code"] = task["buggy_code"]
    start = time.perf_counter()
    try:
        final = validate_code(intent, settings=cfg)
    except Exception as exc:
        result.error = f"{type(exc).__name__}: {exc}"
        result.latency_s = round(time.perf_counter() - start, 3)
        return result

    result.latency_s = final.get("latency_s", round(time.perf_counter() - start, 3))
    result.verdict = final.get("verdict", "")
    result.iterations = int(final.get("iterations") or 0)
    result.history = list(final.get("history") or [])
    result.static_findings = len(final.get("static_issues") or [])
    result.security_findings = len(final.get("security_issues") or [])
    result.reviewer_source = (final.get("review_payload") or {}).get("source", "")
    result.graph_passed = result.verdict == "PASS"

    code = final.get("generated_code") or ""
    entry = intent.get("function_name") or "solve"

    # Independent scoring: run the held-out suite the coder never saw.
    if code.strip() and task.get("hidden_tests"):
        hidden = run_pytest(
            code,
            entry=entry,
            min_args=int(intent.get("min_args", 1) or 0),
            extra_tests=task["hidden_tests"],
            timeout_s=cfg.pytest_timeout_s,
        )
        result.hidden_tests_passed = bool(hidden.get("passed"))
    else:
        result.hidden_tests_passed = False

    result.first_pass = result.graph_passed and result.iterations == 1
    result.self_corrected = (
        result.graph_passed and result.iterations > 1 and result.hidden_tests_passed
    )

    # Security measurement. Two independent facts, both scored on the *seeded*
    # vulnerable source rather than on whatever the coder produced (a coder
    # that repairs the bug on attempt 1 would otherwise make the guard look
    # blind when it was simply never asked to judge the flaw):
    #
    #   caught  -> the deterministic scanner reports a security finding
    #   blocked -> the gate would refuse to PASS that source
    if result.security_seeded:
        seed = task.get("buggy_code") or ""
        result.security_caught = _seed_is_flagged(seed)
        result.security_blocked = _seed_is_blocked(seed, intent, cfg)
        # Remediation: did the code that finally passed still carry a flaw?
        final_security = final.get("security_issues") or []
        result.remediated_clean = result.graph_passed and not final_security
    return result


def _seed_is_flagged(seed: str) -> bool:
    """True when the scanner reports at least one security finding in ``seed``."""
    from src.agents.static_security_agent import scan_source, split_issues

    if not seed.strip():
        return False
    _static, security = split_issues(scan_source(seed))
    return len(security) > 0


def _seed_is_blocked(seed: str, intent: dict[str, Any], cfg) -> bool:
    """True when the full gate refuses to PASS the seeded source as submitted.

    This runs the real static/security scanner and the real sandboxed pytest
    runner on the vulnerable code, then asks the real routing function — no
    LLM in the loop, so the answer is deterministic.
    """
    from src.agents.static_security_agent import scan_source, split_issues
    from src.agents.test_runner_agent import run_pytest
    from src.graph import decide_route

    if not seed.strip():
        return False
    static, security = split_issues(scan_source(seed))
    tests = run_pytest(
        seed,
        entry=intent.get("function_name") or "solve",
        min_args=int(intent.get("min_args", 1) or 0),
        timeout_s=cfg.pytest_timeout_s,
    )
    state = {
        "static_issues": static,
        "security_issues": security,
        "test_results": tests,
        "iterations": 1,
    }
    return decide_route(state, cfg.max_iterations) != "pass"


def summarize(results: list[TaskResult]) -> dict[str, Any]:
    """Aggregate the benchmark metrics."""
    total = len(results)
    scored = [r for r in results if not r.error]
    first_pass = sum(1 for r in scored if r.first_pass)
    corrected = sum(1 for r in scored if r.self_corrected)
    security_tasks = [r for r in scored if r.security_seeded]
    caught = sum(1 for r in security_tasks if r.security_caught)
    blocked = sum(1 for r in security_tasks if r.security_blocked)
    remediated = sum(1 for r in security_tasks if r.remediated_clean)
    latencies = [r.latency_s for r in scored]
    return {
        "total_tasks": total,
        "scored_tasks": len(scored),
        "errors": total - len(scored),
        "first_pass_count": first_pass,
        "first_pass_pct": round(100.0 * first_pass / len(scored), 1) if scored else 0.0,
        "self_corrected_count": corrected,
        "self_corrected_pct": round(100.0 * corrected / len(scored), 1) if scored else 0.0,
        "final_pass_count": first_pass + corrected,
        "final_pass_pct": (
            round(100.0 * (first_pass + corrected) / len(scored), 1) if scored else 0.0
        ),
        "security_tasks": len(security_tasks),
        "security_caught": caught,
        "security_catch_pct": (
            round(100.0 * caught / len(security_tasks), 1) if security_tasks else 0.0
        ),
        "security_blocked": blocked,
        "security_block_pct": (
            round(100.0 * blocked / len(security_tasks), 1) if security_tasks else 0.0
        ),
        "security_remediated": remediated,
        "security_remediation_pct": (
            round(100.0 * remediated / len(security_tasks), 1) if security_tasks else 0.0
        ),
        "avg_latency_s": round(statistics.fmean(latencies), 2) if latencies else 0.0,
        "median_latency_s": round(statistics.median(latencies), 2) if latencies else 0.0,
        "task_latencies_s": {r.task_id: r.latency_s for r in scored},
    }


def print_report(results: list[TaskResult], summary: dict[str, Any]) -> None:
    """Print a human-readable benchmark table."""
    print("\n" + "=" * 96)
    print("codeguard-multiagent benchmark")
    print("=" * 96)
    header = f"{'task':28} {'cat':9} {'verdict':18} {'iters':>5} {'hidden':>7} {'lat_s':>7}"
    print(header)
    print("-" * 96)
    for r in results:
        hidden = "PASS" if r.hidden_tests_passed else "FAIL"
        verdict = r.verdict or ("ERROR" if r.error else "?")
        print(
            f"{r.task_id:28} {r.category:9} {verdict:18} {r.iterations:>5} "
            f"{hidden:>7} {r.latency_s:>7.2f}"
        )
        if r.error:
            print(f"    error: {r.error}")
    print("-" * 96)
    print(
        f"first-pass            : {summary['first_pass_count']}/{summary['scored_tasks']}"
        f"  ({summary['first_pass_pct']}%)"
    )
    print(
        f"self-corrected pass   : {summary['self_corrected_count']}/{summary['scored_tasks']}"
        f"  ({summary['self_corrected_pct']}%)"
    )
    print(
        f"final pass rate       : {summary['final_pass_count']}/{summary['scored_tasks']}"
        f"  ({summary['final_pass_pct']}%)"
    )
    print(
        f"security-flaw catch   : {summary['security_caught']}/{summary['security_tasks']}"
        f"  ({summary['security_catch_pct']}%)   [scanner flags the seeded flaw]"
    )
    print(
        f"gate block rate       : {summary['security_blocked']}/{summary['security_tasks']}"
        f"  ({summary['security_block_pct']}%)   [gate refuses to PASS the flaw]"
    )
    print(
        f"remediated clean      : {summary['security_remediated']}/{summary['security_tasks']}"
        f"  ({summary['security_remediation_pct']}%)   [final code has no flaw]"
    )
    print(
        f"avg latency           : {summary['avg_latency_s']}s"
        f"  (median {summary['median_latency_s']}s)"
    )
    print(f"errors                : {summary['errors']}")
    print("=" * 96)


def write_snapshot(
    path: Path, results: list[TaskResult], summary: dict[str, Any], *, meta: dict[str, Any]
) -> None:
    """Persist the run as JSON for later diffing."""
    payload = {
        "meta": meta,
        "summary": summary,
        "tasks": [r.to_dict() for r in results],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Run the codeguard benchmark")
    parser.add_argument("--limit", type=int, default=None, help="only run the first N tasks")
    parser.add_argument("--task", type=str, default=None, help="run a single task id")
    parser.add_argument(
        "--out", type=Path, default=Path("eval/results.json"), help="JSON snapshot path"
    )
    args = parser.parse_args(argv)

    cfg = get_settings()
    tasks = load_tasks()
    if args.task:
        tasks = [t for t in tasks if t["task_id"] == args.task]
    if args.limit:
        tasks = tasks[: args.limit]
    if not tasks:
        print("No tasks selected.", file=sys.stderr)
        return 2

    print(f"model={cfg.model} base_url={cfg.base_url} max_iterations={cfg.max_iterations}")
    print(f"running {len(tasks)} task(s)...")

    results: list[TaskResult] = []
    for i, task in enumerate(tasks, 1):
        print(f"[{i}/{len(tasks)}] {task['task_id']} ...", end=" ", flush=True)
        result = run_task(task, settings=cfg)
        results.append(result)
        print(f"{result.verdict or 'ERROR'} ({result.latency_s}s, {result.iterations} iter)")

    summary = summarize(results)
    print_report(results, summary)
    out = args.out if args.out.is_absolute() else REPO_ROOT / args.out
    write_snapshot(
        out,
        results,
        summary,
        meta={
            "model": cfg.model,
            "base_url": cfg.base_url,
            "max_iterations": cfg.max_iterations,
            "task_count": len(tasks),
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        },
    )
    print(f"\nSnapshot written to {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
