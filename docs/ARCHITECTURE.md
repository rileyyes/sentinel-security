# Architecture

## Layers

```
API (FastAPI, api/)               <- HTTP only, no security logic
Ingestion (ingestion/)            <- validation, sanitisation, safe extraction, safe temp dirs
Sandbox (core/sandbox.py)         <- runs analysis in a resource-limited child process
Analyzers (analyzers/pe, analyzers/code) <- deterministic, produce Evidence/Finding only
Evidence model (evidence/models.py)      <- FACT / EVIDENCE / INFERENCE / RECOMMENDATION
Correlation (correlation/)        <- deterministic rules -> Hypothesis / Recommendation
Storage (storage/)                <- JSON files on disk, no database
AI (ai/)                          <- prompt building, output validation; explains, never decides
Reports (reports/)                <- escaped HTML + JSON rendering
```

## Data flow — Investigate Software

```
Upload -> validate_pe_upload (magic + PE signature, cheap gate)
       -> safe_workspace (0700 temp dir, fixed filename)
       -> sandboxed worker process (rlimits + timeout)
            -> generic analyzers (hash, file type, entropy, strings)
            -> parse_pe (bounds-checked custom parser)
            -> structural analyzers (headers, sections, imports, exports, suspicious APIs)
       -> Investigation.evidence
       -> correlate_pe -> hypotheses + recommendations
       -> store.save -> report.json / report.html / metadata.json
```

## Data flow — Secure Software

```
Upload -> validate_code_upload (.py or .zip)
       -> safe_extract_zip (path-traversal / bomb / symlink checks) if zip
       -> sandboxed worker
            -> scan_project -> ast-based rule engine (rules.py, secrets.py)
       -> Investigation.findings
       -> recommend_for_findings
       -> store.save
```

## Why a custom PE parser instead of `pefile`

Stage 1 planned to use `pefile`. The build environment for this project had no
package-installation or network access, so `pefile` could not be installed or
tested here. `analyzers/pe/pe_parser.py` is a small, bounds-checked
replacement covering headers, sections, imports, exports and overlay only.
It was validated against real PE binaries found on disk (Python's own
`setuptools` launcher stubs) and against a synthetic-PE test fixture. Before
depending on this further, install `pefile` in your own environment and
cross-check its output against this parser's output on the same files —
`pefile` is more complete (resources, certificates, .NET metadata,
delay-load imports) and is the safer long-term choice once installable.

## Why per-analyzer error isolation

Each analyzer runs individually (`workflow/investigate.py::_run`); one
throwing an exception is recorded in `analyzer_results` and `errors` but does
not stop the rest. A malformed or adversarial file should degrade the
investigation, not crash it.

## Storage layout

```
data/investigations/<32-hex-id>/
  metadata.json      # for listing
  report.json         # canonical, reloaded on GET
  report.html          # regenerated on save, never trusted from import
  evidence/evidence.json
  findings/findings.json
  analysis/analyzers.json
data/artifacts/<sha256>.bin   # only if retention is explicitly requested (not wired up by default)
```

## What was NOT built, and why

* **Database** — not needed at this scale; the store module isolates the
  decision so swapping in Postgres later touches one file, not the analyzers.
* **Celery/Redis** — FastAPI `BackgroundTasks` is enough for single-worker
  synchronous analysis; a queue is a real need only past a certain concurrency,
  which the MVP doesn't have evidence of yet.
* **Authentication** — explicitly out of scope for the MVP per the original
  brief, but flagged in the threat model as required before any public
  deployment.
