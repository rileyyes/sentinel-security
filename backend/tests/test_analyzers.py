import pytest

from app.analyzers.pe import analyzers as A
from app.analyzers.pe.pe_parser import parse_pe
from app.evidence.models import EvidenceCollector, Kind
from conftest import build_minimal_pe


def make_ctx(data: bytes, settings, name="sample.exe") -> A.PEContext:
    ctx = A.PEContext(data, name, EvidenceCollector(), settings)
    ctx.pe = parse_pe(data)
    return ctx


def run_all(ctx: A.PEContext) -> None:
    for fn in (A.analyze_hashes, A.analyze_file_type, A.analyze_entropy, A.analyze_strings,
               A.analyze_headers, A.analyze_sections, A.analyze_imports, A.analyze_exports,
               A.analyze_suspicious_apis):
        fn(ctx)


def test_hashes_present(settings, minimal_pe_bytes):
    ctx = make_ctx(minimal_pe_bytes, settings)
    A.analyze_hashes(ctx)
    ev = ctx.collector.items[0]
    assert len(ev.data["sha256"]) == 64


def test_entropy_flags_high_entropy_data(settings):
    import os
    data = build_minimal_pe(sections=[(".text", 0x1000, 0x1000, 0x400, True, True, False)]) + os.urandom(4000)
    ctx = make_ctx(data, settings)
    A.analyze_entropy(ctx)
    ev = ctx.collector.items[0]
    assert ev.data["entropy"] > 6.0


def test_suspicious_apis_flag_injection_category(settings):
    data = build_minimal_pe(imports={"KERNEL32.dll": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"]})
    ctx = make_ctx(data, settings)
    run_all(ctx)
    cats = {e.data["category"] for e in ctx.collector.items if e.evidence_type == "suspicious_api_category"}
    assert "process_injection" in cats


def test_no_analyzer_declares_malicious(settings, minimal_pe_bytes):
    """Core safety property: analyzer evidence never contains a verdict field."""
    ctx = make_ctx(minimal_pe_bytes, settings)
    run_all(ctx)
    for ev in ctx.collector.items:
        assert "is_malicious" not in ev.data
        assert "malware" not in ev.description.lower()
        assert ev.kind in (Kind.FACT, Kind.EVIDENCE)


def test_rwx_section_flagged(settings):
    data = build_minimal_pe(sections=[(".text", 0x1000, 0x1000, 0x400, True, True, True)])
    ctx = make_ctx(data, settings)
    A.analyze_sections(ctx)
    types_ = {e.evidence_type for e in ctx.collector.items}
    assert "rwx_section" in types_


def test_extension_mismatch_detected(settings, minimal_pe_bytes):
    ctx = make_ctx(minimal_pe_bytes, settings, name="invoice.pdf")
    A.analyze_file_type(ctx)
    types_ = {e.evidence_type for e in ctx.collector.items}
    assert "extension_mismatch" in types_
