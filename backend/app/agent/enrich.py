"""Enrichment stage: attach live CVE/advisory intelligence to confirmed findings.

For each confirmed (or likely) finding we query Tavily for current advisories
and remediation, and — when Nebius is available — have the small model distill a
short, sourced remediation paragraph from those results. Nothing is invented:
if Tavily is unavailable the finding keeps a static, clearly-labelled fallback.
"""
from __future__ import annotations

from ..clients import nebius, tavily
from ..config import get_settings
from ..models import Finding, RemediationSource, Verdict

# Static fallback remediation keyed by technique (used when Tavily is off).
_FALLBACK = {
    "sql_injection": "Use parameterized queries / prepared statements and an ORM; never concatenate user input into SQL. Validate and least-privilege the DB account.",
    "reflected_xss": "Context-aware output encoding, a strict Content-Security-Policy, and framework auto-escaping. Treat all user input as untrusted.",
    "idor": "Enforce per-object authorization server-side on every request; do not rely on unguessable ids. Use indirect object references.",
    "broken_auth": "Remove default credentials, enforce strong password policy and rate limiting, and rotate secrets. Add MFA for privileged accounts.",
    "security_headers": "Set CSP, HSTS, X-Frame-Options, and X-Content-Type-Options at the edge or in the app framework.",
}


def _query_for(finding: Finding) -> str:
    return (
        f"{finding.technique.replace('_', ' ')} {finding.cwe} "
        "vulnerability latest CVE advisory remediation 2025"
    )


async def _summarize(finding: Finding, sources: list[RemediationSource]) -> str:
    settings = get_settings()
    if not settings.nebius_enabled or not sources:
        return _FALLBACK.get(finding.technique, "Review and remediate per OWASP guidance.")
    src_text = "\n".join(f"- {s.title}: {s.snippet}" for s in sources[:4])
    system = (
        "You write concise, accurate security remediation. Use ONLY the provided "
        "sources. 2-3 sentences. Do not invent CVE numbers."
    )
    user = (
        f"Finding: {finding.title} ({finding.cwe}).\n"
        f"Sources:\n{src_text}\n\nWrite the remediation paragraph."
    )
    try:
        return await nebius.chat_text(
            settings.triage_model, system, user, temperature=0.2, max_tokens=300
        )
    except Exception:
        return _FALLBACK.get(finding.technique, "Review and remediate per OWASP guidance.")


async def enrich_finding(finding: Finding) -> Finding:
    """Enrich a single finding in place-ish (returns an updated copy)."""
    settings = get_settings()
    if finding.verdict == Verdict.FALSE_POSITIVE:
        return finding  # don't spend credits on noise

    sources: list[RemediationSource] = []
    if settings.tavily_enabled:
        try:
            sources = await tavily.search(_query_for(finding))
        except Exception:
            sources = []

    remediation = await _summarize(finding, sources)
    return finding.model_copy(update={"sources": sources, "remediation": remediation})
