"""Recon stage: crawl the target, discover pages, forms and endpoints.

This is a lightweight, polite crawler bounded by a page budget. It stays on the
target origin and only touches hosts the allowlist has approved.
"""
from __future__ import annotations

import re
from collections import deque
from urllib.parse import urljoin, urlparse

# Known high-value endpoints for SPA/API targets (e.g. Juice Shop). A pure crawl
# of an Angular/React SPA finds no query params, so real injection points are
# never discovered. Seeding these ensures the planner sees concrete, testable
# endpoints. Each is (method, path, params, source). Only ever hit on the
# allowlisted target origin.
_SEED_ENDPOINTS = [
    ("POST", "/rest/user/login", ["email", "password"], "seed-auth"),
    ("GET", "/rest/products/search", ["q"], "seed-search"),
    ("GET", "/api/Products", [], "seed-api"),
    ("GET", "/api/BasketItems/{id}", ["id"], "seed-idor"),
    ("GET", "/rest/user/whoami", [], "seed-auth"),
]

import httpx

from ..config import get_settings
from ..models import DiscoveredEndpoint, DiscoveredForm, ReconResult
from ..safety.allowlist import assert_allowed

_LINK_RE = re.compile(r"""href\s*=\s*["']([^"'#]+)["']""", re.IGNORECASE)
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
_ACTION_RE = re.compile(r"""action\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_METHOD_RE = re.compile(r"""method\s*=\s*["']([^"']*)["']""", re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r"""name\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r"""src\s*=\s*["']([^"']+\.js[^"']*)["']""", re.IGNORECASE)

# Fingerprints for a few common stacks (kept deliberately small).
_TECH_HINTS = {
    "express": "Express.js",
    "angular": "Angular",
    "react": "React",
    "vue": "Vue.js",
    "jquery": "jQuery",
    "x-powered-by": "",  # handled via headers
}


def _same_origin(base: str, candidate: str) -> bool:
    b, c = urlparse(base), urlparse(candidate)
    return (b.scheme, b.netloc) == (c.scheme, c.netloc)


async def run_recon(target: str, max_pages: int | None = None) -> ReconResult:
    settings = get_settings()
    assert_allowed(target)
    budget = max_pages or settings.max_crawl_pages

    result = ReconResult(target=target)
    seen: set[str] = set()
    queue: deque[str] = deque([target])
    headers = {"User-Agent": settings.user_agent}
    reachable = False

    async with httpx.AsyncClient(
        timeout=settings.request_timeout,
        headers=headers,
        follow_redirects=True,
    ) as client:
        while queue and len(seen) < budget:
            url = queue.popleft()
            if url in seen:
                continue
            seen.add(url)
            try:
                resp = await client.get(url)
            except httpx.HTTPError as exc:
                result.notes.append(f"Fetch failed for {url}: {exc}")
                continue
            reachable = True

            # Technology fingerprinting from headers.
            powered = resp.headers.get("x-powered-by")
            if powered and powered not in result.technologies:
                result.technologies.append(powered)
            server = resp.headers.get("server")
            if server and server not in result.technologies:
                result.technologies.append(server)

            ctype = resp.headers.get("content-type", "")
            if "text/html" not in ctype:
                continue
            body = resp.text

            for hint, label in _TECH_HINTS.items():
                if label and label not in result.technologies and hint in body.lower():
                    result.technologies.append(label)

            # Record this page as a GET endpoint with its query params.
            parsed = urlparse(url)
            params = [p.split("=")[0] for p in parsed.query.split("&") if p]
            result.endpoints.append(
                DiscoveredEndpoint(url=url, method="GET", params=params, source="crawl")
            )

            # Extract forms.
            for form_html in _FORM_RE.findall(body):
                action_m = _ACTION_RE.search(form_html) or _ACTION_RE.search(
                    body[: body.find(form_html)][-200:]
                )
                action = urljoin(url, action_m.group(1)) if action_m else url
                method_m = _METHOD_RE.search(body[max(0, body.find(form_html) - 200):body.find(form_html) + 1])
                method = (method_m.group(1).upper() if method_m else "POST")
                inputs = _INPUT_NAME_RE.findall(form_html)
                if _same_origin(target, action):
                    result.forms.append(
                        DiscoveredForm(action=action, method=method, inputs=inputs)
                    )
                    result.endpoints.append(
                        DiscoveredEndpoint(
                            url=action, method=method, params=inputs, source="form"
                        )
                    )

            # Note client-side JS bundles (useful for API discovery hints).
            for src in _SCRIPT_SRC_RE.findall(body):
                full = urljoin(url, src)
                if _same_origin(target, full) and "api" in full.lower():
                    result.endpoints.append(
                        DiscoveredEndpoint(url=full, method="GET", source="api")
                    )

            # Enqueue same-origin links.
            for href in _LINK_RE.findall(body):
                nxt = urljoin(url, href)
                if _same_origin(target, nxt) and nxt not in seen:
                    queue.append(nxt)

    result.pages_crawled = len([e for e in result.endpoints if e.source == "crawl"])

    # Seed known API/SPA endpoints so the planner has real injection points even
    # when the crawl (of a JS-rendered SPA) surfaces none. Scoped to the target
    # origin, so the allowlist guard still governs every request later.
    if reachable:
        origin = "{0.scheme}://{0.netloc}".format(urlparse(target))
        for method, path, params, source in _SEED_ENDPOINTS:
            url = urljoin(origin + "/", path.lstrip("/"))
            result.endpoints.append(
                DiscoveredEndpoint(url=url, method=method, params=params, source=source)
            )
            if source == "seed-auth" and params:
                # Record the login as a form too, so the heuristic planner also
                # emits a broken_auth case for it.
                result.forms.append(
                    DiscoveredForm(action=url, method=method, inputs=params)
                )
        result.notes.append(
            f"Seeded {len(_SEED_ENDPOINTS)} known API endpoints for SPA/API coverage."
        )

    # De-duplicate endpoints by (method, url).
    uniq: dict[tuple[str, str], DiscoveredEndpoint] = {}
    for ep in result.endpoints:
        uniq.setdefault((ep.method, ep.url), ep)
    result.endpoints = list(uniq.values())
    return result
