"""Orchestrator: run the full recon -> plan -> execute -> triage -> enrich ->
report pipeline as an async stream of StreamEvents so the UI can watch the
agent think and test in real time.
"""
from __future__ import annotations

import time
from collections import Counter
from typing import AsyncIterator

from ..models import (
    Finding,
    ScanReport,
    StreamEvent,
    Verdict,
)
from ..safety.allowlist import TargetNotAllowed, assert_allowed
from . import enrich, executor, planner, recon, triage


def _evt(stage: str, kind: str, message: str = "", data=None) -> StreamEvent:
    return StreamEvent(stage=stage, kind=kind, message=message, data=data)


async def run_scan(target: str, max_pages: int | None = None) -> AsyncIterator[StreamEvent]:
    started = time.time()

    # --- Safety gate (fail closed before any traffic) ---
    try:
        host = assert_allowed(target)
    except TargetNotAllowed as exc:
        yield _evt("error", "done", str(exc))
        return

    yield _evt("recon", "status", f"Authorized host {host}. Starting recon…")

    # --- Recon ---
    try:
        recon_result = await recon.run_recon(target, max_pages)
    except Exception as exc:  # noqa: BLE001
        yield _evt("error", "done", f"Recon failed: {exc}")
        return
    yield _evt(
        "recon",
        "result",
        f"Crawled {recon_result.pages_crawled} pages, "
        f"{len(recon_result.endpoints)} endpoints, {len(recon_result.forms)} forms.",
        data=recon_result.model_dump(),
    )

    # --- Plan ---
    yield _evt("plan", "status", "Reasoning about applicable OWASP categories…")
    plan = await planner.build_plan(recon_result)
    yield _evt(
        "plan",
        "result",
        f"Plan ready ({len(plan.cases)} test cases) via {plan.generated_by}.",
        data=plan.model_dump(),
    )

    # --- Execute + Triage (per case) ---
    findings: list[Finding] = []
    total = len(plan.cases)
    for i, case in enumerate(plan.cases, start=1):
        yield _evt(
            "execute",
            "status",
            f"[{i}/{total}] {case.technique} → {case.target_endpoint}",
            data={"case": case.model_dump()},
        )
        try:
            raw = await executor.execute_case(case)
        except TargetNotAllowed as exc:
            yield _evt("execute", "status", f"Skipped (allowlist): {exc}")
            continue
        except Exception as exc:  # noqa: BLE001
            yield _evt("execute", "status", f"Probe error: {exc}")
            continue

        finding = await triage.triage_result(raw)

        yield _evt(
            "triage",
            "result",
            f"{finding.verdict.value.upper()} · {finding.severity.value} · {finding.cwe}",
            data=finding.model_dump(),
        )
        findings.append(finding)

    # --- Enrich confirmed/likely findings ---
    enriched: list[Finding] = []
    to_enrich = [f for f in findings if f.verdict != Verdict.FALSE_POSITIVE]
    yield _evt(
        "enrich",
        "status",
        f"Pulling live threat intel for {len(to_enrich)} findings…",
    )
    for finding in findings:
        if finding.verdict == Verdict.FALSE_POSITIVE:
            enriched.append(finding)
            continue
        updated = await enrich.enrich_finding(finding)
        enriched.append(updated)
        yield _evt(
            "enrich",
            "result",
            f"Enriched {updated.title} ({len(updated.sources)} sources).",
            data=updated.model_dump(),
        )

    # --- Report ---
    real = [f for f in enriched if f.verdict != Verdict.FALSE_POSITIVE]
    stats = {
        "duration_seconds": round(time.time() - started, 1),
        "cases_run": total,
        "findings_total": len(real),
        "by_severity": dict(Counter(f.severity.value for f in real)),
        "by_verdict": dict(Counter(f.verdict.value for f in enriched)),
        "by_category": dict(Counter(f.category.value for f in real)),
    }
    report = ScanReport(
        target=target,
        recon=recon_result,
        plan=plan,
        findings=enriched,
        stats=stats,
    )
    yield _evt(
        "report",
        "done",
        f"Scan complete: {len(real)} findings in {stats['duration_seconds']}s.",
        data=report.model_dump(),
    )
