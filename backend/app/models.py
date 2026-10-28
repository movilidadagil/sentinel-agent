"""Pydantic models shared across the agent pipeline and the API."""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class OwaspCategory(str, Enum):
    """The subset of the OWASP Top 10 (2021) Sentinel actively tests for."""

    BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    CRYPTOGRAPHIC_FAILURES = "A02:2021-Cryptographic Failures"
    INJECTION = "A03:2021-Injection"
    INSECURE_DESIGN = "A04:2021-Insecure Design"
    SECURITY_MISCONFIG = "A05:2021-Security Misconfiguration"
    VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Verdict(str, Enum):
    CONFIRMED = "confirmed"
    LIKELY = "likely"
    FALSE_POSITIVE = "false_positive"


class ScanRequest(BaseModel):
    target: str = Field(..., description="Base URL of the running app to test.")
    max_pages: int | None = Field(
        default=None, description="Override for the crawl page budget."
    )


class DiscoveredForm(BaseModel):
    action: str
    method: str = "GET"
    inputs: list[str] = Field(default_factory=list)


class DiscoveredEndpoint(BaseModel):
    url: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list)
    source: str = "crawl"  # crawl | form | api


class ReconResult(BaseModel):
    target: str
    pages_crawled: int = 0
    endpoints: list[DiscoveredEndpoint] = Field(default_factory=list)
    forms: list[DiscoveredForm] = Field(default_factory=list)
    technologies: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class TestCase(BaseModel):
    """One concrete thing to try, produced by the planner."""

    id: str
    category: OwaspCategory
    technique: str  # e.g. "sql_injection", "reflected_xss", "idor"
    target_endpoint: str
    rationale: str
    parameter: str | None = None
    method: str = "GET"  # HTTP method of the endpoint under test


class TestPlan(BaseModel):
    summary: str
    reasoning: str
    cases: list[TestCase] = Field(default_factory=list)
    generated_by: str = "heuristic"  # which model/strategy produced it


class Evidence(BaseModel):
    request_line: str
    request_body: str | None = None
    response_status: int | None = None
    response_snippet: str | None = None
    indicator: str | None = None  # what in the response signalled the issue


class RawResult(BaseModel):
    """Output of executing a single TestCase, pre-triage."""

    case: TestCase
    suspicious: bool
    evidence: Evidence
    raw_indicator: str | None = None


class RemediationSource(BaseModel):
    title: str
    url: str
    published: str | None = None
    snippet: str | None = None


class Finding(BaseModel):
    id: str
    category: OwaspCategory
    technique: str
    title: str
    verdict: Verdict
    severity: Severity
    cwe: str | None = None
    endpoint: str
    evidence: Evidence
    triage_rationale: str = ""
    remediation: str = ""
    sources: list[RemediationSource] = Field(default_factory=list)


class ScanReport(BaseModel):
    target: str
    recon: ReconResult
    plan: TestPlan
    findings: list[Finding] = Field(default_factory=list)
    stats: dict[str, Any] = Field(default_factory=dict)


# --- Streaming event envelope -------------------------------------------------

class StreamEvent(BaseModel):
    """A single server-sent event in the live scan stream."""

    stage: str  # recon | plan | execute | triage | enrich | report | error
    kind: str  # status | result | done
    message: str = ""
    data: dict[str, Any] | None = None
