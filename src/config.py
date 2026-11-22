"""Shared configuration for codeguard-multiagent.

All settings come from the environment (optionally via a ``.env`` file next to
the repository root).  Nothing here performs network I/O, so importing this
module is safe inside tests and CI.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(REPO_ROOT / ".env", override=False)


def _env_float(name: str, default: float) -> float:
    """Parse a float env var, falling back to ``default`` when unset/invalid."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    """Parse an int env var, falling back to ``default`` when unset/invalid."""
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    """Runtime configuration for the multi-agent graph."""

    api_key: str = field(
        default_factory=lambda: (
            os.getenv("CODEGUARD_API_KEY")
            or os.getenv("COMMANDCODE_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or ""
        )
    )
    base_url: str = field(
        default_factory=lambda: (
            os.getenv("CODEGUARD_BASE_URL")
            or os.getenv("COMMANDCODE_BASE_URL")
            or os.getenv("OPENAI_BASE_URL")
            or "https://api.openai.com/v1"
        )
    )
    model: str = field(
        default_factory=lambda: (
            os.getenv("CODEGUARD_MODEL")
            or os.getenv("OPENAI_MODEL")
            or "deepseek/deepseek-v4.1-flash"
        )
    )
    coder_temperature: float = field(
        default_factory=lambda: _env_float("CODEGUARD_CODER_TEMPERATURE", 0.2)
    )
    reviewer_temperature: float = field(
        default_factory=lambda: _env_float("CODEGUARD_REVIEWER_TEMPERATURE", 0.0)
    )
    max_iterations: int = field(default_factory=lambda: _env_int("CODEGUARD_MAX_ITERATIONS", 3))
    pytest_timeout_s: int = field(default_factory=lambda: _env_int("CODEGUARD_PYTEST_TIMEOUT", 30))
    request_timeout_s: int = field(
        default_factory=lambda: _env_int("CODEGUARD_REQUEST_TIMEOUT", 120)
    )

    def require_key(self) -> str:
        """Return the API key or raise a descriptive error."""
        if not self.api_key:
            raise RuntimeError(
                "No LLM API key configured. Set CODEGUARD_API_KEY (or "
                "COMMANDCODE_API_KEY / OPENAI_API_KEY) in the environment or .env"
            )
        return self.api_key


def get_settings() -> Settings:
    """Load settings fresh from the environment (cheap, no caching)."""
    return Settings()
