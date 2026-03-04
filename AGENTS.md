# PROJECT KNOWLEDGE BASE

**Generated:** 2026-02-20 17:51:37 +0800
**Commit:** 6400c8c
**Branch:** dev

## OVERVIEW
Phantom TrojanWalker is a modular malware-analysis pipeline: FastAPI backend + Ghidra services + LLM agents, with a React/Vite UI and Docker-first deployment.
The system enforces single-concurrency analysis because Ghidra maintains a global analyzer state.

## STRUCTURE
```
./
├── agents/             # AI orchestration (LLM agents, prompts, Ghidra client)
├── backend/            # API + worker + SQLite persistence
├── frontend/           # React UI + dev/production proxy
├── module/             # ghidra_pipe + ghidra_mcp services
├── docker/             # service Dockerfiles
├── data/               # runtime uploads + SQLite (gitignored)
├── .github/            # CI workflows (docker build/push)
├── docker-compose.yml  # full-stack orchestration
└── requirements*.txt   # Python deps (backend + ghidra)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Upload + sha256 dedupe + size limits | `backend/api/endpoints.py` | streaming upload, sha256-based filenames |
| Task queue + single-concurrency lock | `backend/worker/worker.py` | `_analysis_lock` enforces global Ghidra constraint |
| Analysis pipeline + function filtering | `agents/analysis_coordinator.py` | FUN_* + entrypoints + exports, ATT&CK filter |
| LLM agents + JSON enforcement | `agents/agent_core.py` | JSON object required, per-function batch analysis |
| Agent prompts + schema contract | `agents/prompt/*.md` | strict "no fabrication" rules |
| Ghidra HTTP service | `module/ghidra_pipe/main.py` | global analyzer state |
| Ghidra core analysis logic | `module/ghidra_pipe/analyzer.py` | largest complexity hotspot |
| MCP tools (decompile/xrefs) | `module/ghidra_mcp/main.py` | `/mcp` tool server |
| UI flow + polling | `frontend/src/App.jsx` | upload, poll, render results |
| Report rendering | `frontend/src/components/ReportView.jsx` | ATT&CK + IOC display |
| Dev/Prod API proxy | `frontend/vite.config.js`, `frontend/server.mjs` | `/api` always same-origin |

## CONVENTIONS
- API contracts for Ghidra are driven by `agents/config.yaml` (`plugins.ghidra.endpoints`); update config + client when routes change.
- LLM responses must be **JSON object** (prompt + `response_format`); parse failures raise `LLMResponseError`.
- Uploads are streamed to temp files, hashed, and stored under `data/uploads/<sha256>` (no raw filenames).
- Results are **split across DB columns** (`metadata_info`, `functions`, `strings`, `decompiled_code`, etc.), not a single blob.
- Frontend always calls **relative** `/api` paths; dev/prod proxy handles the real backend URL.

## ANTI-PATTERNS (THIS PROJECT)
- Do **not** run concurrent analyses; Ghidra uses a single global analyzer state.
- Do **not** bypass the backend API from the frontend (never call ghidra_pipe or agents directly).
- Do **not** collapse analysis results into one JSON blob; keep split columns.
- Do **not** change Ghidra endpoints without updating `agents/config.yaml` and `agents/ghidra_client.py`.
- Do **not** leak or commit `api_key`/secrets; keep `config.yaml` and `.env` out of git.
- Do **not** fabricate LLM outputs; prompts require evidence-based ATT&CK mapping only.

## UNIQUE STYLES
- Inline "Refactor note:" comments are used to justify helper extraction and guard clauses -- preserve or extend when refactoring.
- Prompts define the output schema contract; treat prompt edits as API changes (requires backend/worker restart).

## COMMANDS
```bash
# Full stack (recommended)
docker compose up --build

# Local dev (4 processes)
export GHIDRA_INSTALL_DIR=/path/to/ghidra
python module/ghidra_pipe/main.py
python module/ghidra_mcp/main.py
python backend/main.py
cd frontend && npm install && npm run dev

# Frontend build/preview
cd frontend && npm run build
cd frontend && npm run preview
```

## NOTES
- Ports: ghidra_pipe `:8000`, backend `:8001` (`/api`), frontend dev `:5173`, frontend prod `:8080`, MCP `:9000`.
- `data/` holds uploads + SQLite (`analysis.db`) and is gitignored; expect large files.
- CI only builds Docker images (no tests). Pytest deps exist but no test suite yet.
- `agents/main.py` is a legacy entrypoint; `backend/main.py` is the supported API.
