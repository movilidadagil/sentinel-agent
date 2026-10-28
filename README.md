# Sentinel

**An autonomous application-security testing agent.** Point it at a running web
app and it recons the target, *reasons* about which OWASP Top 10 categories
actually apply, executes real crafted probes, triages the results into
confirmed / likely / false-positive, and enriches every real finding with
*live, cited* CVE and remediation intelligence — all streamed to a live
dashboard.

> **Authorized testing only.** Sentinel sends real attack traffic. It will only
> ever touch hosts on an explicit allowlist (`ALLOWED_HOSTS`) and fails closed
> for everything else. Only scan systems you own or are authorized to test. The
> canonical demo target is [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/),
> a deliberately vulnerable app built for exactly this.

## Architecture

```
 target URL
     │
     ▼
 ┌─────────┐   ┌──────────┐   ┌──────────┐   ┌─────────┐   ┌──────────┐   ┌────────┐
 │  Recon  │──▶│   Plan   │──▶│ Execute  │──▶│ Triage  │──▶│  Enrich  │──▶│ Report │
 │ crawl   │   │ Nemotron │   │  httpx   │   │ Nemotron│   │  Tavily  │   │  SSE   │
 │ forms   │   │ (Super)  │   │ probes   │   │ (Nano)  │   │ live CVE │   │ stream │
 └─────────┘   └──────────┘   └──────────┘   └─────────┘   └──────────┘   └────────┘
                    │              │                            │
              reasoning tier   allowlist guard            dated, linked
              (large model)    on every request            sources
```

- **Reasoning & triage — NVIDIA Nemotron on Nebius Token Factory.** Planning
  runs on a large Nemotron model (the reasoning tier); high-volume triage runs
  on a small, fast Nemotron model to keep latency and credit usage low. Both are
  driven through one OpenAI-compatible SDK.
- **Live threat intel — Tavily.** Each confirmed finding triggers a Tavily
  search for current advisories/CVEs; the dated, linked sources are attached to
  the report so remediation is sourced, not invented.
- **Execution engine — Python + FastAPI + httpx**, with a hard host-allowlist
  guard (`backend/app/safety/allowlist.py`) that every outbound request passes
  through.
- **Dashboard — React (Vite)** streaming agent progress over Server-Sent Events.

**Graceful degradation:** with no Nebius key the planner/triage fall back to
deterministic heuristics; with no Tavily key remediation uses clearly-labelled
static guidance. The full pipeline runs end-to-end either way.

## Quick start

### 1. Backend

```bash
cd backend
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env     # then add your keys + allowlist
uvicorn app.main:app --reload --port 8000
```

Or just `./run.sh` from the repo root.

Set in `backend/.env`:

| Variable | Purpose |
| --- | --- |
| `NEBIUS_API_KEY` | Nebius Token Factory key (planning + triage). |
| `NEBIUS_PLANNER_MODEL` | Large reasoning model (default Nemotron Super 49B). |
| `NEBIUS_TRIAGE_MODEL` | Small fast model (default Nemotron Nano 8B). |
| `TAVILY_API_KEY` | Tavily key for live CVE/remediation lookups. |
| `ALLOWED_HOSTS` | **Required.** Comma-separated hosts you may test. |

### 2. Frontend (needs Node 18+)

```bash
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api to :8000
```

For a single-process demo, `npm run build` emits `frontend/dist`, which the
backend serves automatically at `http://localhost:8000`.

### 3. Demo target (Juice Shop)

```bash
docker run --rm -p 3000:3000 bkimminich/juice-shop
```

Add `localhost` to `ALLOWED_HOSTS` (the default), point Sentinel at
`http://localhost:3000`, and run a scan.

## API

| Method | Path | Description |
| --- | --- | --- |
| `GET` | `/api/health` | Config + which integrations are live. |
| `POST` | `/api/validate` | Pre-flight allowlist check for a target. |
| `POST` | `/api/scan` | Runs a scan, streaming `StreamEvent`s as SSE. |

## OWASP coverage (current)

| Category | Technique | CWE |
| --- | --- | --- |
| A01 Broken Access Control | IDOR probe | CWE-639 |
| A03 Injection | SQL injection, reflected XSS | CWE-89, CWE-79 |
| A05 Security Misconfiguration | Security-header baseline | CWE-693 |
| A07 Auth Failures | Default-credential check | CWE-287 |

## Safety model

- **Allowlist, fail closed.** `assert_allowed()` gates every request; unresolvable
  or non-allowlisted hosts are rejected. There is no per-request bypass in the API.
- **Non-destructive probes.** No writes, deletes, or data exfiltration; probes
  read responses and look for signatures.
- **No invented advisories.** Remediation is either Tavily-sourced (with links)
  or clearly-labelled static OWASP guidance.

## Project layout

```
backend/
  app/
    main.py              FastAPI app + SSE scan endpoint
    config.py            env-driven settings
    models.py            pydantic models
    safety/allowlist.py  host-allowlist guard (fail closed)
    clients/             nebius (Nemotron) + tavily
    agent/               recon → planner → executor → triage → enrich → orchestrator
frontend/                Vite + React dashboard (SSE stream)
```

## Status

Backend pipeline is implemented and verified end-to-end (recon, heuristic +
LLM planning, real probes, triage, enrichment, SSE reporting). Frontend is a
complete Vite/React app (build it where Node 18+ is available).

## What's next

Broader OWASP coverage (SSRF, injection variants), authenticated multi-role
access-control testing, CI/CD integration (a security pass per pull request),
exportable compliance reports, and a teaching mode that walks through *why* each
vulnerability exists.
