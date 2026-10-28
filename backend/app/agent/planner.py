"""Planning stage: reason about which OWASP categories apply to THIS target.

The planner runs on the large Nemotron model (the reasoning tier). It receives
the recon summary and must emit a strictly-structured JSON test plan. If Nebius
is unavailable it falls back to a deterministic heuristic plan so the pipeline
still runs end-to-end.
"""
from __future__ import annotations

import json
import logging

from ..clients import nebius
from ..config import get_settings
from ..models import OwaspCategory, ReconResult, TestCase, TestPlan

logger = logging.getLogger("sentinel.planner")

_SYSTEM = """You are a senior application-security tester planning an authorized \
assessment. You reason about a specific target from its recon data and decide \
which OWASP Top 10 (2021) categories are actually worth testing here, then emit \
concrete test cases. You test ONLY the authorized target. Respond with a single \
JSON object, no prose."""

_SCHEMA_HINT = """Return JSON shaped exactly like:
{
  "summary": "one-sentence scope summary",
  "reasoning": "2-4 sentences on why these categories apply to THIS target",
  "cases": [
    {
      "id": "tc-1",
      "category": "A03:2021-Injection",
      "technique": "sql_injection",
      "target_endpoint": "http://host/path",
      "method": "POST",
      "parameter": "q",
      "rationale": "why this endpoint/param is a candidate"
    }
  ]
}
Allowed techniques: sql_injection, reflected_xss, idor, broken_auth,
security_headers. Allowed categories are the OWASP 2021 identifiers. Use the
endpoint's "method" from recon (login endpoints are POST with a JSON body).
Prefer endpoints and parameters that actually appeared in recon. For a login
endpoint, plan BOTH sql_injection (parameter "email", for authentication bypass)
and broken_auth. For search-style query parameters plan sql_injection and
reflected_xss. For object-id endpoints plan idor."""


def _recon_digest(recon: ReconResult) -> str:
    eps = [
        {"url": e.url, "method": e.method, "params": e.params, "source": e.source}
        for e in recon.endpoints[:40]
    ]
    forms = [
        {"action": f.action, "method": f.method, "inputs": f.inputs}
        for f in recon.forms[:20]
    ]
    return json.dumps(
        {
            "target": recon.target,
            "technologies": recon.technologies,
            "endpoints": eps,
            "forms": forms,
        },
        indent=2,
    )


def _heuristic_plan(recon: ReconResult) -> TestPlan:
    """Deterministic fallback when the reasoning model is unavailable."""
    cases: list[TestCase] = []
    n = 0

    def add(cat: OwaspCategory, tech: str, ep: str, param: str | None, why: str,
            method: str = "GET"):
        nonlocal n
        n += 1
        cases.append(
            TestCase(
                id=f"tc-{n}",
                category=cat,
                technique=tech,
                target_endpoint=ep,
                parameter=param,
                rationale=why,
                method=method,
            )
        )

    # Security headers always worth a baseline check on the root.
    add(
        OwaspCategory.SECURITY_MISCONFIG,
        "security_headers",
        recon.target,
        None,
        "Baseline check for missing security headers on the target root.",
    )

    for ep in recon.endpoints:
        is_login = "login" in ep.url.lower() or "pass" in " ".join(ep.params).lower()
        for param in ep.params or []:
            lname = param.lower()
            if any(k in lname for k in ("q", "search", "id", "name", "query", "email")):
                add(
                    OwaspCategory.INJECTION,
                    "sql_injection",
                    ep.url,
                    param,
                    f"Parameter {param!r} looks like a data lookup candidate.",
                    method=ep.method,
                )
                # Reflected-XSS only makes sense for GET query parameters.
                if ep.method.upper() == "GET":
                    add(
                        OwaspCategory.INJECTION,
                        "reflected_xss",
                        ep.url,
                        param,
                        f"Parameter {param!r} may be reflected unescaped.",
                        method=ep.method,
                    )
            if "id" in lname:
                add(
                    OwaspCategory.BROKEN_ACCESS_CONTROL,
                    "idor",
                    ep.url,
                    param,
                    f"Numeric-looking id parameter {param!r}; test object access.",
                    method=ep.method,
                )
        if is_login:
            add(
                OwaspCategory.AUTH_FAILURES,
                "broken_auth",
                ep.url,
                None,
                "Login endpoint present; test for default/weak credentials.",
                method=ep.method or "POST",
            )

    # Login forms -> broken auth.
    for form in recon.forms:
        inames = [i.lower() for i in form.inputs]
        if any("pass" in i for i in inames):
            add(
                OwaspCategory.AUTH_FAILURES,
                "broken_auth",
                form.action,
                None,
                "Authentication form present; test for weak controls.",
                method=form.method or "POST",
            )

    return TestPlan(
        summary=f"Heuristic plan for {recon.target} ({len(cases)} cases).",
        reasoning=(
            "Nebius reasoning model unavailable; generated a deterministic plan "
            "from recon signals (parameter names, forms, headers)."
        ),
        cases=cases[:40],
        generated_by="heuristic",
    )


async def build_plan(recon: ReconResult) -> TestPlan:
    settings = get_settings()
    if not settings.nebius_enabled:
        logger.info("Nebius disabled (no API key); using heuristic planner.")
        return _heuristic_plan(recon)

    # Map discovered endpoints to their HTTP method so a plan that names an
    # endpoint inherits the right verb even if the model omits it.
    method_by_url = {e.url: e.method for e in recon.endpoints}

    user = f"{_SCHEMA_HINT}\n\nRecon data:\n{_recon_digest(recon)}"
    try:
        # max_tokens must be generous: Nemotron spends tokens reasoning before
        # it emits the final JSON, so a small budget truncates the answer.
        raw = await nebius.chat_json(
            settings.planner_model, _SYSTEM, user, temperature=0.2, max_tokens=4000
        )
    except Exception as exc:
        # Only a real failure (network / 4xx / 5xx / unparseable) lands here.
        logger.warning("Planner LLM call failed (%s: %s); falling back to heuristic.",
                       type(exc).__name__, exc)
        return _heuristic_plan(recon)

    cases = []
    for i, c in enumerate(raw.get("cases", []), start=1):
        try:
            endpoint = c["target_endpoint"]
            method = (c.get("method") or method_by_url.get(endpoint) or "GET").upper()
            cases.append(
                TestCase(
                    id=c.get("id") or f"tc-{i}",
                    category=OwaspCategory(c["category"]),
                    technique=c["technique"],
                    target_endpoint=endpoint,
                    parameter=c.get("parameter"),
                    rationale=c.get("rationale", ""),
                    method=method,
                )
            )
        except (KeyError, ValueError):
            continue  # skip malformed case, keep the rest
    if not cases:
        logger.warning("Planner LLM returned no usable cases; falling back to heuristic.")
        return _heuristic_plan(recon)
    return TestPlan(
        summary=raw.get("summary", f"Plan for {recon.target}"),
        reasoning=raw.get("reasoning", ""),
        cases=cases,
        generated_by=settings.planner_model,
    )
