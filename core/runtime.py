"""Runtime helpers: env flags, Docker proxy rewrite, display mode."""

from __future__ import annotations

import os
import re
import sys


def env_truthy(name: str, default: str = "0") -> bool:
    return str(os.environ.get(name, default)).lower() in {"1", "true", "yes", "on"}


# Back-compat alias used across the monolith / tests.
_env_truthy = env_truthy


def normalize_proxy_for_runtime(proxy: str) -> str:
    """In Docker, map loopback proxy hosts to host.docker.internal."""
    raw = str(proxy or "").strip()
    if not raw:
        return ""
    in_docker = str(os.environ.get("GROK_REG_IN_DOCKER", "0")).lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not in_docker:
        return raw
    return re.sub(
        r"(?<=://)(127\.0\.0\.1|localhost)(?=[:/]|$)",
        "host.docker.internal",
        raw,
    )


def should_run_headless() -> bool:
    if env_truthy("GROK_REG_IN_DOCKER") and not env_truthy("GROK_REG_ALLOW_HEADLESS"):
        return False
    return env_truthy("GROK_REG_HEADLESS")


def should_apply_container_chrome_flags() -> bool:
    return env_truthy("GROK_REG_IN_DOCKER") or sys.platform.startswith("linux")
