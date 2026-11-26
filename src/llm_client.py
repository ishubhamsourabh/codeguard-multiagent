"""Thin OpenAI-compatible chat client used by the LLM-backed agents.

Kept separate from the agents so they can be unit tested with a fake client
and so the provider is swappable purely through environment variables.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from openai import OpenAI

from src.config import Settings, get_settings

_FENCE_RE = re.compile(r"```(?:python|py)?\s*\n(.*?)```", re.DOTALL)


@dataclass
class LLMResponse:
    """Normalised chat completion result."""

    text: str
    prompt_tokens: int = 0
    completion_tokens: int = 0
    latency_s: float = 0.0


def extract_python(text: str) -> str:
    """Return the Python source contained in ``text``.

    Prefers the first fenced code block; otherwise returns the text as-is.
    Never invents code — an empty fence yields an empty string.
    """
    blocks = _FENCE_RE.findall(text or "")
    if blocks:
        return blocks[0].strip("\n")
    return (text or "").strip("\n")


class LLMClient:
    """Small wrapper around ``openai.OpenAI`` with deterministic helpers."""

    def __init__(self, settings: Settings | None = None, client: Any | None = None):
        self.settings = settings or get_settings()
        self._client = client or OpenAI(
            api_key=self.settings.require_key(),
            base_url=self.settings.base_url,
            timeout=self.settings.request_timeout_s,
        )

    def complete(
        self,
        system: str,
        user: str,
        *,
        temperature: float = 0.0,
        max_tokens: int = 4000,
    ) -> LLMResponse:
        """Run one chat completion and return normalised text + usage."""
        import time

        start = time.perf_counter()
        resp = self._client.chat.completions.create(
            model=self.settings.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
        )
        elapsed = time.perf_counter() - start
        choice = resp.choices[0].message
        text = (choice.content or "").strip()
        if not text:
            # Reasoning models can spend the whole budget on hidden thinking.
            reasoning = getattr(choice, "reasoning_content", None) or ""
            text = reasoning.strip()
        usage = getattr(resp, "usage", None)
        return LLMResponse(
            text=text,
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
            latency_s=round(elapsed, 3),
        )
