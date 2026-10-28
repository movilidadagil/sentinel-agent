"""Triage stage: classify each raw result as confirmed / likely / false-positive.

This is the high-volume step, so it runs on the small, fast Nemotron model (the
Nano tier) to keep latency and credit usage low. It assigns a verdict, CWE and
severity, and discards the noise. A deterministic fallback keeps the pipeline
working without Nebius.
"""
from __future__ import annotations

import json
import logging

from ..clients import nebius
from ..config import get_settings
from ..models import (
    Evidence,
    Finding,
    RawResult,
    Severity,
    Verdict,
)

logger = logging.getLogger("sentinel.triage")

_SYSTEM ="""You are a security triage analyst. Given a single probe result \
with its evidence, decide whether it is a real vulnerability. Be strict: prefer \
false_positive when evidence is weak. Respond with one JSON object, no prose."""

_SCHEMA = """Return JSON:
{
  "verdict": "confirmed|likely|false_positive",
  "severity": "critical|high|medium|low|info",
  "cwe": "CWE-89",
  "title": "short finding title",
  "rationale": "1-2 sentences justifying the verdict from the evidence"
}"""

# Technique -> (default CWE, default severity) used by the fallback.
_DEFAULTS = {
    "sql_injection": ("CWE-89", Severity.CRITICAL),
    "reflected_xss": ("CWE-79", Severity.HIGH),
    "idor": ("CWE-639", Severity.HIGH),
    "broken_auth": ("CWE-287", Severity.CRITICAL),
    "security_headers": ("CWE-693", Severity.LOW),
}


def _heuristic_triage(raw: RawResult) -> Finding:
    cwe, sev = _DEFAULTS.get(raw.case.technique, ("CWE-noinfo", Severity.INFO))
    if not raw.suspicious:
        verdict = Verdict.FALSE_POSITIVE
        sev = Severity.INFO
    elif raw.case.technique in ("sql_injection", "broken_auth", "reflected_xss"):
        # Strong, directly-observed signatures -> confirmed.
        verdict = Verdict.CONFIRMED
    else:
        verdict = Verdict.LIKELY
    return Finding(
        id=raw.case.id,
        category=raw.case.category,
        technique=raw.case.technique,
        title=f"{raw.case.technique.replace('_', ' ').title()} at {raw.case.target_endpoint}",
        verdict=verdict,
        severity=sev,
        cwe=cwe,
        endpoint=raw.case.target_endpoint,
        evidence=raw.evidence,
        triage_rationale=(
            raw.evidence.indicator or "Heuristic classification from probe signal."
        ),
    )


async def triage_result(raw: RawResult) -> Finding:
    settings = get_settings()
    base = _heuristic_triage(raw)
    if not settings.nebius_enabled:
        return base

    payload = {
        "technique": raw.case.technique,
        "category": raw.case.category.value,
        "endpoint": raw.case.target_endpoint,
        "suspicious": raw.suspicious,
        "indicator": raw.evidence.indicator,
        "response_status": raw.evidence.response_status,
        "response_snippet": (raw.evidence.response_snippet or "")[:800],
    }
    user = f"{_SCHEMA}\n\nProbe result:\n{json.dumps(payload, indent=2)}"
    try:
        # Reasoning models need headroom to finish thinking AND emit the JSON.
        raw_json = await nebius.chat_json(
            settings.triage_model, _SYSTEM, user, temperature=0.0, max_tokens=2000
        )
        verdict = Verdict(raw_json.get("verdict", base.verdict.value))
        severity = Severity(raw_json.get("severity", base.severity.value))
        return Finding(
            id=base.id,
            category=base.category,
            technique=base.technique,
            title=raw_json.get("title") or base.title,
            verdict=verdict,
            severity=severity,
            cwe=raw_json.get("cwe") or base.cwe,
            endpoint=base.endpoint,
            evidence=base.evidence,
            triage_rationale=raw_json.get("rationale", base.triage_rationale),
        )
    except Exception as exc:
        logger.warning("Triage LLM call failed (%s: %s); using heuristic verdict.",
                       type(exc).__name__, exc)
        return base
