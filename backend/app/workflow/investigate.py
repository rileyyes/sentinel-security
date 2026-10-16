"""The investigation workflow.

Upload -> Validate -> Analyze -> Collect evidence -> Indicators -> Correlate
-> Hypotheses -> Recommendations -> Report

``run_analysis`` is a pure function over a file path (used inside the isolated
worker). ``investigate`` is the orchestrator: ingestion in the parent process,
analysis in a resource-limited child.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Callable

from app.analyzers.code.python_scanner import scan_project
from app.analyzers.pe import analyzers as pe_an
from app.analyzers.pe.pe_parser import PEParseError, parse_pe
from app.core.config import Settings
from app.core.logging import log_event
from app.core.sandbox import MAX_RESULT_BYTES, SandboxError, run_limited
from app.correlation.code_rules import recommend_for_findings
from app.correlation.pe_rules import correlate_pe
from app.evidence.models import AnalyzerResult, EvidenceCollector, Investigation
from app.ingestion.archive import safe_extract_zip
from app.ingestion.validators import (
    IngestionError, read_limited, sanitize_filename, validate_code_upload, validate_pe_upload,
)
from app.ingestion.workspace import safe_workspace, write_private

_GENERIC = [("hashes", pe_an.analyze_hashes), ("file_type", pe_an.analyze_file_type),
            ("entropy", pe_an.analyze_entropy), ("strings", pe_an.analyze_strings)]
_STRUCTURAL = [("pe_headers", pe_an.analyze_headers), ("pe_sections", pe_an.analyze_sections),
               ("pe_imports", pe_an.analyze_imports), ("pe_exports", pe_an.analyze_exports),
               ("suspicious_apis", pe_an.analyze_suspicious_apis)]


def _run(inv: Investigation, ctx: pe_an.PEContext, name: str, fn: Callable[[pe_an.PEContext], None]) -> None:
    before = len(ctx.collector.items)
    try:
        fn(ctx)
        status, err = "ok", None
    except Exception as exc:  # noqa: BLE001 - one analyzer failing must not stop the rest
        status, err = "error", f"{type(exc).__name__}: analyzer failed"
        inv.errors.append(f"Analyzer '{name}' failed ({type(exc).__name__}).")
    inv.analyzer_results.append(AnalyzerResult(name, status, [e.id for e in ctx.collector.items[before:]], err))
    inv.log("analyze", f"{name}: {status}")


def run_analysis(mode: str, path: Path, display_name: str, settings: Settings) -> Investigation:
    inv = Investigation.new(mode)
    inv.log("analyze", "analysis started")
    if mode == "software":
        _analyze_software(inv, path, display_name, settings)
    elif mode == "code":
        _analyze_code(inv, path, settings)
    else:
        raise ValueError("unknown mode")
    inv.log("report", "analysis complete")
    return inv


def _analyze_software(inv: Investigation, path: Path, display_name: str, settings: Settings) -> None:
    data = path.read_bytes()
    collector = EvidenceCollector()
    ctx = pe_an.PEContext(data, display_name, collector, settings)
    for name, fn in _GENERIC:
        _run(inv, ctx, name, fn)
    try:
        ctx.pe = parse_pe(data)
    except PEParseError as exc:
        inv.errors.append(f"PE structure could not be parsed: {exc}. Structural analyzers were skipped.")
        for name, _ in _STRUCTURAL:
            inv.analyzer_results.append(AnalyzerResult(name, "skipped", [], "PE parse failed"))
    else:
        for name, fn in _STRUCTURAL:
            _run(inv, ctx, name, fn)
        inv.warnings.extend(ctx.notes)
    inv.evidence = collector.items
    inv.log("correlate", "correlating evidence")
    inv.hypotheses, inv.recommendations = correlate_pe(inv.evidence)
    inv.log("recommend", f"{len(inv.hypotheses)} hypothesis(es), {len(inv.recommendations)} recommendation(s)")


def _analyze_code(inv: Investigation, path: Path, settings: Settings) -> None:
    result = scan_project(path, settings)
    inv.analyzer_results.append(AnalyzerResult("python_scanner", "ok"))
    inv.findings = result.findings
    inv.warnings.extend(result.warnings)
    inv.artifact["files_scanned"] = result.files_scanned
    inv.log("analyze", f"scanned {result.files_scanned} file(s), {len(result.findings)} finding(s)")
    inv.recommendations = recommend_for_findings(inv.findings)
    inv.log("recommend", f"{len(inv.recommendations)} recommendation(s)")


def investigate(
    mode: str, stream, filename: str | None, settings: Settings, *, isolated: bool = True,
) -> Investigation:
    """Ingest an upload and produce an Investigation. Raises IngestionError on rejection."""
    events: list[tuple[str, str]] = [("upload", "artifact received")]
    display = sanitize_filename(filename)
    data = read_limited(stream, settings.max_upload_bytes)
    sha = hashlib.sha256(data).hexdigest()

    if mode == "software":
        validate_pe_upload(data)
        kind = "pe"
    elif mode == "code":
        kind = validate_code_upload(data, display)
    else:
        raise IngestionError("bad_mode", "Unknown investigation mode.")
    events.append(("validate", f"validated as {kind}"))
    log_event("ingest_accepted", mode=mode, kind=kind, size=len(data))

    with safe_workspace(settings.data_dir / "tmp") as ws:
        if mode == "software":
            target = ws / "artifact.bin"            # fixed name: user filename never touches the disk
            write_private(target, data)
        elif kind == "zip":
            write_private(ws / "upload.zip", data)
            report = safe_extract_zip(ws / "upload.zip", ws / "src", settings)
            target = ws / "src"
            events.append(("validate", f"extracted {len(report.extracted)} source file(s) safely"))
        else:
            (ws / "src").mkdir()
            target = ws / "src" / "upload.py"
            write_private(target, data)

        if isolated:
            inv = _run_isolated(mode, target, display, ws, settings)
        else:
            inv = run_analysis(mode, target, display, settings)
        if mode == "code" and kind == "zip":
            inv.warnings.extend(report.warnings)

    inv.artifact.update({"filename": display, "size_bytes": len(data), "sha256": sha, "detected_type": kind})
    inv.timeline = [_event(s, m) for s, m in events] + inv.timeline
    log_event("investigation_complete", id=inv.id, mode=mode, errors=len(inv.errors))
    return inv


def _event(stage: str, message: str):
    from app.evidence.models import TimelineEvent, utc_now
    return TimelineEvent(utc_now(), stage, message)


def _run_isolated(mode: str, target: Path, display: str, ws: Path, settings: Settings) -> Investigation:
    out = ws / "result.json"
    try:
        res = run_limited(
            ["-m", "app.workflow.worker", mode, str(target), display, str(out),
             str(settings.max_strings)],
            workdir=ws, timeout_s=settings.analysis_timeout_s, memory_bytes=settings.analysis_memory_bytes,
        )
    except SandboxError as exc:
        log_event("analysis_sandbox_failure", kind=exc.kind)
        raise IngestionError("analysis_timeout", "Analysis exceeded its time limit and was stopped.") from exc
    if res.returncode != 0 or not out.exists():
        log_event("analysis_sandbox_failure", kind="crash", code=res.returncode)
        raise IngestionError("analysis_failed", "Analysis could not be completed for this file.")
    if out.stat().st_size > MAX_RESULT_BYTES:
        raise IngestionError("analysis_failed", "Analysis output was too large.")
    return Investigation.from_dict(json.loads(out.read_text("utf-8")))
