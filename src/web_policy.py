"""Public URL and CORS policy.

When the API is served with a browser front-end (``/``), the page's own origin is
trusted automatically — derived at runtime instead of hardcoded, so the same code
works on localhost, on any Vercel preview domain, and in production.

``CODEGUARD_ALLOWED_ORIGINS`` is an optional comma-separated allowlist for extra
origins (e.g. a separate marketing site). Wildcards are rejected because
``allow_credentials`` with ``*`` is both invalid per spec and a security smell.
"""

from __future__ import annotations

import os
from urllib.parse import urlparse

# Hosts that are only ever local development. Never trust them in production.
_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "0.0.0.0", "::1"})


def is_local_host(host: str) -> bool:
    """True when ``host`` refers to a local development address."""
    cleaned = (host or "").strip().lower()
    if not cleaned:
        return False
    if cleaned in _LOCAL_HOSTS:
        return True
    hostname = cleaned.split(":", 1)[0]
    return hostname in _LOCAL_HOSTS


def extra_allowed_origins() -> list[str]:
    """Parse ``CODEGUARD_ALLOWED_ORIGINS`` into a validated list.

    Wildcards are dropped: they cannot be combined with credentialed CORS, and
    silently sending a broken origin list is worse than sending none.
    """
    raw = os.getenv("CODEGUARD_ALLOWED_ORIGINS", "")
    origins: list[str] = []
    for item in raw.split(","):
        candidate = item.strip().rstrip("/")
        if not candidate or candidate == "*" or "*" in candidate:
            continue
        parsed = urlparse(candidate)
        if parsed.scheme in {"http", "https"} and parsed.netloc:
            origins.append(candidate)
    return origins


def same_origin_ok(origin: str) -> bool:
    """Validate a reflected origin before echoing it back in CORS headers."""
    if not origin:
        return False
    parsed = urlparse(origin)
    if parsed.scheme not in {"http", "https"}:
        return False
    return bool(parsed.netloc)
