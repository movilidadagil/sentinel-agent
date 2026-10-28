#!/usr/bin/env bash
# Convenience launcher for Sentinel's backend API.
# Frontend runs separately with `cd frontend && npm run dev` (needs Node 18+).
set -euo pipefail
cd "$(dirname "$0")/backend"

if [ ! -d .venv ]; then
  python3 -m venv .venv
  ./.venv/bin/pip install -q -r requirements.txt
fi

if [ ! -f .env ]; then
  echo "No backend/.env found — copying .env.example. Add your API keys + allowlist."
  cp .env.example .env
fi

exec ./.venv/bin/uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
