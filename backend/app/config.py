"""Central configuration for Sentinel.

Everything sensitive (API keys) and everything environment-specific (the host
allowlist, model names, base URLs) is read from the environment so nothing is
ever hardcoded into the source tree. See .env.example for the full list.
"""
from __future__ import annotations

import os
from functools import lru_cache

from dotenv import load_dotenv

# Load a local .env if present. In production the real environment wins.
load_dotenv()


def _split_csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


class Settings:
    """Runtime settings, resolved once and cached."""

    def __init__(self) -> None:
        # --- Nebius Token Factory (OpenAI-compatible endpoint) ---
        self.nebius_api_key: str | None = os.getenv("NEBIUS_API_KEY")
        self.nebius_base_url: str = os.getenv(
            "NEBIUS_BASE_URL", "https://api.studio.nebius.com/v1"
        )
        # Large reasoning model for planning (the "Ultra/Super" tier).
        self.planner_model: str = os.getenv(
            "NEBIUS_PLANNER_MODEL", "nvidia/Llama-3_3-Nemotron-Super-49B-v1"
        )
        # Small, fast model for high-volume triage (the "Nano" tier).
        self.triage_model: str = os.getenv(
            "NEBIUS_TRIAGE_MODEL", "nvidia/Llama-3_1-Nemotron-Nano-8B-v1"
        )

        # --- Tavily live threat intelligence ---
        self.tavily_api_key: str | None = os.getenv("TAVILY_API_KEY")

        # --- Safety: host allowlist ---
        # Only hosts in this list may ever be scanned. Defaults to localhost so
        # a fresh checkout can safely test a local Juice Shop and nothing else.
        self.allowed_hosts: list[str] = _split_csv(
            os.getenv("ALLOWED_HOSTS", "localhost,127.0.0.1")
        )
        # Whether to permit targets that resolve to private/loopback IPs. On by
        # default because the canonical demo (Juice Shop) runs on localhost.
        self.allow_private_targets: bool = (
            os.getenv("ALLOW_PRIVATE_TARGETS", "true").lower() == "true"
        )

        # --- HTTP execution engine ---
        self.request_timeout: float = float(os.getenv("REQUEST_TIMEOUT", "15"))
        self.max_crawl_pages: int = int(os.getenv("MAX_CRAWL_PAGES", "25"))
        self.user_agent: str = os.getenv(
            "SENTINEL_USER_AGENT",
            "Sentinel/0.1 (authorized-security-testing)",
        )

    @property
    def nebius_enabled(self) -> bool:
        return bool(self.nebius_api_key)

    @property
    def tavily_enabled(self) -> bool:
        return bool(self.tavily_api_key)


@lru_cache
def get_settings() -> Settings:
    return Settings()
