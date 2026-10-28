"""Nebius Token Factory client.

Token Factory exposes an OpenAI-compatible API, so we drive both the large
planner model and the small triage model through the one `openai` SDK, just
with different model ids. All calls degrade gracefully: if no API key is set,
the caller gets a clear signal and can fall back to heuristics rather than
crashing the scan.
"""
from __future__ import annotations

import json
import logging
import re
from typing import Any

from openai import AsyncOpenAI

from ..config import get_settings

logger = logging.getLogger("sentinel.nebius")


class NebiusUnavailable(Exception):
    pass


_JSON_BLOCK = re.compile(r"\{.*\}|\[.*\]", re.DOTALL)
# Nemotron reasoning models wrap their chain-of-thought in <think>…</think>.
_THINK_RE = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
# ```json … ``` fenced blocks.
_FENCE_RE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL | re.IGNORECASE)


def _reasoning_content(message: Any) -> str:
    """Pull `reasoning_content` off a message however the SDK exposed it."""
    val = getattr(message, "reasoning_content", None)
    if not val:
        extra = getattr(message, "model_extra", None)
        if isinstance(extra, dict):
            val = extra.get("reasoning_content")
    return (val or "").strip()


def _client() -> AsyncOpenAI:
    settings = get_settings()
    if not settings.nebius_enabled:
        raise NebiusUnavailable("NEBIUS_API_KEY is not set.")
    return AsyncOpenAI(
        api_key=settings.nebius_api_key,
        base_url=settings.nebius_base_url,
    )


def _extract_json(text: str) -> Any:
    """Best-effort JSON extraction from a model response.

    Handles reasoning-model output: strips any <think>…</think> prose, unwraps a
    ```json fenced block, then falls back to grabbing the outermost {…}/[…].
    """
    text = (text or "").strip()
    if not text:
        raise ValueError("Empty model output.")
    # Drop reasoning prose so it can't confuse the JSON scan.
    text = _THINK_RE.sub("", text).strip()
    if "</think>" in text:  # unclosed/!matched <think> — keep what follows it
        text = text.split("</think>", 1)[1].strip()
    fence = _FENCE_RE.search(text)
    if fence:
        inner = fence.group(1).strip()
        try:
            return json.loads(inner)
        except json.JSONDecodeError:
            text = inner
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    match = _JSON_BLOCK.search(text)
    if match:
        return json.loads(match.group(0))
    raise ValueError("No JSON object found in model output.")


async def chat_json(
    model: str,
    system: str,
    user: str,
    *,
    temperature: float = 0.2,
    max_tokens: int = 2048,
) -> Any:
    """Call a model and parse its reply as JSON.

    Requests a JSON response_format first and falls back to extraction if the
    model wraps the object in prose. Reasoning models (Nemotron) often leave
    `message.content` empty and emit the answer in `message.reasoning_content`
    instead, so we fall back to that before giving up.
    """
    client = _client()
    kwargs: dict[str, Any] = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "temperature": temperature,
        "max_tokens": max_tokens,
    }
    try:
        resp = await client.chat.completions.create(
            response_format={"type": "json_object"}, **kwargs
        )
    except Exception as exc:
        # Some model builds reject response_format; retry without it. A real
        # transport/HTTP error on the retry propagates to the caller.
        logger.debug("response_format rejected (%s); retrying without it", exc)
        resp = await client.chat.completions.create(**kwargs)

    message = resp.choices[0].message
    content = (message.content or "").strip()
    source = "content"
    if not content:
        content = _reasoning_content(message)
        source = "reasoning_content"
    if not content:
        raise NebiusUnavailable(
            "Model returned neither content nor reasoning_content "
            f"(finish_reason={resp.choices[0].finish_reason})."
        )
    logger.debug("chat_json parsed from %s for model %s", source, model)
    return _extract_json(content)


async def chat_text(
    model: str,
    system: str,
    user: str,
    *,
    temperature: float = 0.3,
    max_tokens: int = 1024,
) -> str:
    client = _client()
    resp = await client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        temperature=temperature,
        max_tokens=max_tokens,
    )
    return (resp.choices[0].message.content or "").strip()
