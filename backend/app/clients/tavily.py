"""Tavily client for live threat-intelligence lookups.

For each confirmed finding we query Tavily for current CVE advisories and
remediation guidance, then attach the dated, linked sources to the report.
This is what keeps fix advice sourced and current instead of invented.

We call the REST endpoint directly with httpx to avoid an extra dependency and
to keep full control over the request shape.
"""
from __future__ import annotations

import httpx

from ..config import get_settings
from ..models import RemediationSource


class TavilyUnavailable(Exception):
    pass


TAVILY_URL = "https://api.tavily.com/search"


async def search(query: str, *, max_results: int = 4) -> list[RemediationSource]:
    settings = get_settings()
    if not settings.tavily_enabled:
        raise TavilyUnavailable("TAVILY_API_KEY is not set.")

    payload = {
        "api_key": settings.tavily_api_key,
        "query": query,
        "search_depth": "advanced",
        "max_results": max_results,
        "include_answer": False,
    }
    async with httpx.AsyncClient(timeout=settings.request_timeout) as client:
        resp = await client.post(TAVILY_URL, json=payload)
        resp.raise_for_status()
        data = resp.json()

    sources: list[RemediationSource] = []
    for item in data.get("results", []):
        sources.append(
            RemediationSource(
                title=item.get("title", "(untitled)"),
                url=item.get("url", ""),
                published=item.get("published_date"),
                snippet=(item.get("content") or "")[:400],
            )
        )
    return sources
