# Sentinel — Security Investigation Platform

A portfolio project demonstrating reverse engineering, static application
security testing, secure application design, and AI-assisted (never
AI-decided) investigation workflows.

Two capabilities:

* **Investigate Software** — "What is this software doing?" Static analysis
  of Windows PE files (hashes, entropy, strings, headers, sections, imports,
  exports, suspicious-API correlation) that produces investigation
  hypotheses with reasoning, benign explanations, confidence, and
  limitations — never a malware verdict.
* **Secure Software** — "Is this software built securely?" A deterministic,
  AST-based scanner for Python source that finds hardcoded secrets, command
  and SQL injection, unsafe deserialization, weak crypto, and more, each
  with severity, evidence, impact, remediation, confidence, and limitations.

Everything a human decision needs is FACT, EVIDENCE, INFERENCE, or
RECOMMENDATION — an AI assistant can explain any of it, but never
independently declares something malicious or "secure."

## Quick start

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
pytest                                  # 78 tests, no network required
uvicorn main:app --reload               # http://localhost:8000

# Frontend (separate terminal)
cd frontend
npm install
npm run dev                             # http://localhost:5173

# Or both, containerized:
docker compose up --build
```

Copy `.env.example` to `.env` and set `ANTHROPIC_API_KEY` to enable the AI
assistant (`Ask AI` tab). Without it, the API still works fully — the
assistant just reports that no provider is configured.

## Project layout

```
backend/app/
  api/          FastAPI routes, request/response schemas
  core/         config, structured security logging, the analysis sandbox
  ingestion/    upload validation, filename sanitisation, safe zip extraction
  analyzers/pe/ custom PE parser, PE analyzers, suspicious-API catalogue
  analyzers/code/ AST-based Python security scanner, rule catalogue, secret detection
  evidence/     the FACT/EVIDENCE/INFERENCE/RECOMMENDATION data model
  correlation/  deterministic evidence -> hypothesis / recommendation rules
  workflow/     the end-to-end investigation orchestration + sandboxed worker
  storage/      file-based investigation store (no database)
  ai/           prompt construction, prompt-injection defences, output validation
  reports/      escaped HTML + JSON report rendering
backend/tests/  78 pytest tests covering all of the above
frontend/src/   React + TypeScript + Tailwind UI
docs/           ARCHITECTURE.md, THREAT_MODEL.md
```

## What's implemented vs. what's next

**Implemented and tested (78/78 passing):**
PE parsing and analyzers, suspicious-API correlation, hypothesis/recommendation
generation, the Python AST security scanner, all ingestion defences (path
traversal, zip bombs, symlinks, oversized uploads, filename sanitisation),
file-based storage with export/import, the AI prompt/validation boundary, and
the full FastAPI route layer.

**Built but not executable in the environment this was built in** (no network
access to install packages): the FastAPI route layer and the React frontend
could not be run end-to-end here — install `requirements-dev.txt` and
`npm install` locally to verify them. The core deterministic logic (parsers,
analyzers, scanner, workflow, storage, AI boundary) *was* run and tested
directly with the standard library, so that part carries real confidence;
the API/frontend wiring is written to the same patterns but is unverified
until you run it.

**Deliberate architecture deviation from the Stage 1 plan:** the PE parser is
a custom, bounds-checked implementation rather than `pefile`, because
`pefile` could not be installed in this sandbox (see `docs/ARCHITECTURE.md`
for the reasoning and what to check before relying on it further).

**Not yet built (flagged, not hidden):** authentication/authorization,
frontend automated tests (Playwright), CI pipeline, and dependency
vulnerability scanning (`pip-audit`) in CI. See `docs/THREAT_MODEL.md` for
the full list of known limitations.

## Security model

See `docs/THREAT_MODEL.md`. In short: uploaded artifacts and source code are
always untrusted, are never executed, are analysed in a resource-limited
child process, and the AI layer only ever receives structured, escaped
evidence — never raw artifact bytes — with its output validated before it
reaches you.
