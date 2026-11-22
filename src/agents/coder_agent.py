"""Coder agent: turns a structured Intent Prompt into Python source."""

from __future__ import annotations

from typing import Any

from src.config import Settings, get_settings
from src.llm_client import LLMClient, extract_python
from src.state import CodeGuardState, IntentSpec

SYSTEM_PROMPT = """You are a senior Python engineer writing production-quality code.

Rules you must follow every single time:
1. Output ONLY a single Python code block. No prose, no explanation, no tests.
2. Full type hints on every function and method (including return types).
3. Google-style docstring on every public function and class.
4. Explicit, specific exception handling. NEVER use a bare `except:`.
5. NEVER use eval(), exec(), compile(), or os.system().
6. NEVER hardcode secrets, API keys, tokens, or passwords. Read them from
   os.environ and raise ValueError when missing.
7. Build SQL with parameterised queries (placeholders + params tuple).
   Never use f-strings, %, or .format() to inject values into SQL.
8. Standard library only unless the intent explicitly allows otherwise.
9. Raise ValueError for invalid input; validate arguments up front.
10. Keep the module importable on its own with no side effects at import time.
"""


def build_coder_prompt(
    intent_spec: IntentSpec,
    *,
    feedback: str | None = None,
    previous_code: str | None = None,
) -> str:
    """Render the user message for the coder LLM.

    Pure function: no I/O, easy to unit test.

    When the intent carries ``buggy_code`` the task is a *repair*: the coder is
    shown the defective source and told to fix it rather than start over.
    """
    requirements = intent_spec.get("requirements") or []
    lines = [
        "## Intent",
        f"Title: {intent_spec.get('title', 'Untitled task')}",
        f"Description: {intent_spec.get('description', '')}",
    ]
    if fn := intent_spec.get("function_name"):
        lines.append(f"Required entry point: {fn}")
    if sig := intent_spec.get("signature"):
        lines.append(f"Required signature: {sig}")
    if requirements:
        lines.append("Requirements:")
        lines.extend(f"- {r}" for r in requirements)
    if example := intent_spec.get("example"):
        lines.append(f"Example usage:\n{example}")

    seed = intent_spec.get("buggy_code") or ""
    if seed and not previous_code:
        lines.append(f"\n## Existing buggy implementation — repair it\n```python\n{seed}\n```")
        lines.append(
            "\nKeep the same public API, but fix every defect listed above. "
            "Rewrite the whole module."
        )

    if previous_code:
        lines.append(
            f"\n## Your previous attempt (which FAILED validation)\n```python\n{previous_code}\n```"
        )
    if feedback:
        lines.append("\n## Reviewer feedback — you MUST fix every item\n" + feedback.strip())
        lines.append(
            "\nRewrite the whole module from scratch, applying every fix. "
            "Do not repeat the previous mistakes."
        )
    else:
        lines.append("\nWrite the complete module now.")
    return "\n".join(lines)


def make_coder_node(settings: Settings | None = None, client: Any | None = None):
    """Factory returning a LangGraph node.

    The LLM client is built lazily on first use so that compiling the graph
    (CI, unit tests) never requires an API key.
    """
    cfg = settings or get_settings()
    holder: dict[str, Any] = {"llm": client}

    def _llm() -> Any:
        if holder["llm"] is None:
            holder["llm"] = LLMClient(cfg)
        return holder["llm"]

    def coder_node(state: CodeGuardState) -> dict[str, Any]:
        intent = state.get("intent_spec") or {}
        prompt = build_coder_prompt(
            intent,
            feedback=state.get("reviewer_feedback"),
            previous_code=state.get("generated_code") if state.get("iterations") else None,
        )
        resp = _llm().complete(
            SYSTEM_PROMPT,
            prompt,
            temperature=cfg.coder_temperature,
            max_tokens=4000,
        )
        code = extract_python(resp.text)
        iteration = int(state.get("iterations") or 0) + 1
        return {
            "generated_code": code,
            "iterations": iteration,
            "history": [
                {
                    "node": "coder",
                    "iteration": iteration,
                    "chars": len(code),
                    "latency_s": resp.latency_s,
                    "empty": not code,
                }
            ],
        }

    return coder_node
