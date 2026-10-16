"""PE analyzers. Each takes a context and adds structured evidence.

No analyzer decides that a file is malicious. They record facts and
observations, with confidence and limitations, for the correlation stage.
"""
from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.analyzers.pe import suspicious_apis
from app.analyzers.pe.pe_parser import PEInfo
from app.core.config import Settings
from app.evidence.models import Confidence, EvidenceCollector, Kind, Severity
from app.ingestion.validators import detect_file_type

HIGH_ENTROPY = 7.2
_STANDARD_SECTIONS = {
    ".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".edata", ".pdata", ".bss",
    ".tls", ".crt", ".didat", ".gfids", ".xdata", ".sdata", ".00cfg", "code", "data", "text",
}
_MACHINES = {0x14C: "x86", 0x8664: "x64", 0x1C0: "ARM", 0xAA64: "ARM64", 0x200: "IA-64"}
_SUBSYSTEMS = {1: "Native (driver)", 2: "Windows GUI", 3: "Windows console", 9: "Windows CE", 10: "EFI application"}
_EXT_MISMATCH = {".txt", ".pdf", ".jpg", ".jpeg", ".png", ".gif", ".doc", ".docx", ".xls", ".xlsx", ".zip", ".mp3", ".mp4"}


@dataclass
class PEContext:
    data: bytes
    display_name: str
    collector: EvidenceCollector
    settings: Settings
    pe: PEInfo | None = None
    notes: list[str] = field(default_factory=list)


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


# ---- generic analyzers -----------------------------------------------------

def analyze_hashes(ctx: PEContext) -> None:
    ctx.collector.add(
        "hashes", "hash", "Cryptographic hashes of the artifact",
        {"sha256": hashlib.sha256(ctx.data).hexdigest(), "sha1": hashlib.sha1(ctx.data).hexdigest(),
         "md5": hashlib.md5(ctx.data).hexdigest(), "size_bytes": len(ctx.data)},  # noqa: S324 - lookup ids only
        limitations=["MD5/SHA-1 are provided only as lookup identifiers, not as integrity guarantees."],
    )


def analyze_file_type(ctx: PEContext) -> None:
    detected = detect_file_type(ctx.data[:4096])
    ctx.collector.add(
        "file_type", "file_type", "File type determined from content",
        {"detected_type": detected, "magic": ctx.data[:2].hex()},
    )
    ext = "." + ctx.display_name.rsplit(".", 1)[-1].lower() if "." in ctx.display_name else ""
    if detected == "pe" and ext in _EXT_MISMATCH:
        ctx.collector.add(
            "file_type", "extension_mismatch",
            "File extension suggests a non-executable type, but the content is a Windows executable",
            {"claimed_extension": ext, "detected_type": detected},
            kind=Kind.EVIDENCE, severity=Severity.LOW, confidence=Confidence.HIGH,
            limitations=["Mismatched extensions occur in mis-named files as well as deliberate disguise."],
            untrusted_content=True,
        )


def analyze_entropy(ctx: PEContext) -> None:
    value = shannon_entropy(ctx.data)
    high = value >= HIGH_ENTROPY
    ctx.collector.add(
        "entropy", "entropy", f"Whole-file Shannon entropy is {value:.2f} bits/byte",
        {"entropy": round(value, 3), "scale_max": 8.0, "high_entropy": high},
        kind=Kind.EVIDENCE if high else Kind.FACT,
        severity=Severity.LOW if high else Severity.INFO,
        confidence=Confidence.LOW if high else None,
        limitations=["High entropy indicates compressed, encrypted or packed data; it also occurs in "
                     "legitimate installers, embedded resources and media."] if high else [],
    )


_ASCII = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_CATEGORIES = {
    "urls": re.compile(r"https?://[^\s\"'<>]{4,}", re.I),
    "ip_addresses": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "registry_keys": re.compile(r"(?:HKEY_[A-Z_]+|HKLM|HKCU)\\[^\x00]{3,}|Software\\Microsoft\\Windows\\CurrentVersion\\Run", re.I),
    "file_paths": re.compile(r"\b[a-z]:\\[^\x00\r\n]{3,}", re.I),
    "emails": re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b"),
    "command_tools": re.compile(r"\b(?:powershell|cmd\.exe|wscript|cscript|rundll32|regsvr32|mshta|certutil|bitsadmin)\b", re.I),
}


def _valid_ip(text: str) -> bool:
    return all(0 <= int(p) <= 255 for p in text.split("."))


def analyze_strings(ctx: PEContext) -> None:
    cap = ctx.settings.max_strings
    ascii_strings = [m.group().decode("ascii") for m in _ASCII.finditer(ctx.data)]
    wide_strings = [m.group()[::2].decode("ascii") for m in _UTF16.finditer(ctx.data)]
    total = len(ascii_strings) + len(wide_strings)
    ctx.collector.add(
        "strings", "strings_summary", "Printable string extraction summary",
        {"ascii_count": len(ascii_strings), "utf16_count": len(wide_strings),
         "min_length": 6, "categorised_up_to": cap},
        limitations=["Strings can be obfuscated, encrypted or built at runtime and then never appear here."],
    )
    notable: dict[str, list[str]] = {k: [] for k in _CATEGORIES}
    for s in (ascii_strings + wide_strings)[:cap]:
        for cat, rx in _CATEGORIES.items():
            m = rx.search(s)
            if not m:
                continue
            if cat == "ip_addresses" and not _valid_ip(m.group()):
                continue
            if len(notable[cat]) < 25:
                notable[cat].append(s[:200])
    notable = {k: v for k, v in notable.items() if v}
    if notable:
        ctx.collector.add(
            "strings", "notable_strings", "Strings resembling network, registry, path or command indicators",
            {"categories": notable, "total_strings": total},
            kind=Kind.EVIDENCE, severity=Severity.LOW, confidence=Confidence.LOW,
            limitations=["Presence of a string does not show it is used. Strings are attacker-controlled "
                         "text and are shown as data only."],
            untrusted_content=True,
        )


# ---- PE-structure analyzers -------------------------------------------------

def analyze_headers(ctx: PEContext) -> None:
    pe = ctx.pe
    assert pe is not None
    ts = datetime.fromtimestamp(pe.timestamp, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if pe.timestamp else None
    ctx.collector.add(
        "pe_headers", "pe_headers", "PE header summary",
        {"machine": _MACHINES.get(pe.machine, hex(pe.machine)), "bits": 64 if pe.is_64bit else 32,
         "type": "DLL" if pe.is_dll else "EXE/other", "subsystem": _SUBSYSTEMS.get(pe.subsystem, str(pe.subsystem)),
         "timestamp_utc": ts, "entry_point_rva": hex(pe.entry_point), "image_base": hex(pe.image_base),
         "size_of_image": pe.size_of_image, "aslr": bool(pe.dll_characteristics & 0x40),
         "dep_nx": bool(pe.dll_characteristics & 0x100)},
        location="PE header",
    )
    if pe.timestamp == 0:
        ctx.collector.add("pe_headers", "timestamp_anomaly", "Compile timestamp is zero", {"timestamp": 0},
                          kind=Kind.EVIDENCE, confidence=Confidence.LOW,
                          limitations=["Zero timestamps are normal for reproducible builds."])
    elif pe.timestamp > datetime.now(timezone.utc).timestamp() + 86400:
        ctx.collector.add("pe_headers", "timestamp_anomaly", "Compile timestamp is in the future",
                          {"timestamp_utc": ts}, kind=Kind.EVIDENCE, severity=Severity.LOW,
                          confidence=Confidence.MEDIUM,
                          limitations=["Timestamps are trivially forgeable and unreliable as provenance."])
    sec = pe.section_for_rva(pe.entry_point)
    if pe.entry_point and (sec is None or not sec.characteristics & 0x20000000):
        ctx.collector.add(
            "pe_headers", "entry_point_anomaly",
            "Entry point is outside any section or in a non-executable section",
            {"entry_point_rva": hex(pe.entry_point), "section": sec.name if sec else None},
            kind=Kind.EVIDENCE, severity=Severity.MEDIUM, confidence=Confidence.MEDIUM,
            limitations=["Malformed but benign files and some drivers/resources-only DLLs can trigger this."],
            location="PE header",
        )
    for w in pe.warnings:
        ctx.notes.append(w)


def analyze_sections(ctx: PEContext) -> None:
    pe = ctx.pe
    assert pe is not None
    rows = []
    for s in pe.sections:
        chunk = ctx.data[s.raw_offset:s.raw_offset + s.raw_size] if s.raw_size else b""
        ent = shannon_entropy(chunk)
        rows.append({"name": s.name, "virtual_size": s.virtual_size, "raw_size": s.raw_size,
                     "entropy": round(ent, 3), "readable": bool(s.characteristics & 0x40000000),
                     "writable": bool(s.characteristics & 0x80000000),
                     "executable": bool(s.characteristics & 0x20000000)})
        loc = f"section {s.name}"
        if s.characteristics & 0x80000000 and s.characteristics & 0x20000000:
            ctx.collector.add("pe_sections", "rwx_section", f"Section {s.name} is both writable and executable",
                              {"section": s.name}, kind=Kind.EVIDENCE, severity=Severity.MEDIUM,
                              confidence=Confidence.MEDIUM, location=loc, untrusted_content=True,
                              limitations=["Some legitimate packers, JIT code and old toolchains produce RWX sections."])
        if ent >= HIGH_ENTROPY and s.raw_size >= 512:
            ctx.collector.add("pe_sections", "high_entropy_section",
                              f"Section {s.name} has high entropy ({ent:.2f})",
                              {"section": s.name, "entropy": round(ent, 3)}, kind=Kind.EVIDENCE,
                              severity=Severity.LOW, confidence=Confidence.LOW, location=loc, untrusted_content=True,
                              limitations=["Compressed or encrypted resources are common in legitimate software."])
        if s.name.lower() not in _STANDARD_SECTIONS:
            ctx.collector.add("pe_sections", "nonstandard_section_name",
                              f"Section name {s.name!r} is not a conventional compiler section",
                              {"section": s.name}, kind=Kind.EVIDENCE, confidence=Confidence.LOW,
                              location=loc, untrusted_content=True,
                              limitations=["Packers and some toolchains use custom names; many benign products do too."])
        if s.raw_size == 0 and s.virtual_size > 4096 and s.characteristics & 0x20000000:
            ctx.collector.add("pe_sections", "empty_executable_section",
                              f"Executable section {s.name} has no raw data but a large virtual size",
                              {"section": s.name, "virtual_size": s.virtual_size}, kind=Kind.EVIDENCE,
                              severity=Severity.LOW, confidence=Confidence.MEDIUM, location=loc,
                              untrusted_content=True,
                              limitations=["Consistent with runtime unpacking, but also with uninitialised code regions."])
    ctx.collector.add("pe_sections", "pe_sections", f"{len(rows)} section(s) parsed",
                      {"sections": rows}, untrusted_content=True, location="section table")
    if pe.overlay_size:
        ctx.collector.add("pe_sections", "overlay", f"{pe.overlay_size} bytes follow the last section (overlay)",
                          {"offset": pe.overlay_offset, "size": pe.overlay_size,
                           "entropy": round(shannon_entropy(ctx.data[pe.overlay_offset:pe.overlay_offset + 1_000_000]), 3)},
                          kind=Kind.EVIDENCE, confidence=Confidence.LOW,
                          limitations=["Overlays hold installers' payloads, signatures and appended data; "
                                       "context is needed to interpret them."])


def analyze_imports(ctx: PEContext) -> None:
    pe = ctx.pe
    assert pe is not None
    dlls = [{"dll": d.name, "count": len(d.functions), "functions": d.functions[:200]} for d in pe.imports]
    total = sum(len(d.functions) for d in pe.imports)
    ctx.collector.add("pe_imports", "pe_imports", f"{len(pe.imports)} imported DLL(s), {total} function(s)",
                      {"dlls": dlls, "total_functions": total}, untrusted_content=True, location="import table",
                      limitations=["Delay-load and dynamically resolved imports are not visible here."])
    if total and total <= 10:
        ctx.collector.add("pe_imports", "few_imports", f"Very small import table ({total} functions)",
                          {"total_functions": total}, kind=Kind.EVIDENCE, severity=Severity.LOW,
                          confidence=Confidence.LOW,
                          limitations=["Minimal imports are typical of packed files but also of tiny tools."])


def analyze_exports(ctx: PEContext) -> None:
    pe = ctx.pe
    assert pe is not None
    if pe.exports or pe.export_function_count:
        ctx.collector.add("pe_exports", "pe_exports", f"{pe.export_function_count} exported function(s)",
                          {"dll_name": pe.export_dll_name, "names": pe.exports[:200],
                           "function_count": pe.export_function_count},
                          untrusted_content=True, location="export table")


def analyze_suspicious_apis(ctx: PEContext) -> None:
    pe = ctx.pe
    assert pe is not None
    hits: dict[str, dict[str, str]] = {}
    for d in pe.imports:
        for fn in d.functions:
            m = suspicious_apis.match(fn)
            if m:
                api, cat, desc = m
                hits.setdefault(cat, {})[api] = desc
    for cat, apis in sorted(hits.items()):
        ctx.collector.add(
            "suspicious_apis", "suspicious_api_category",
            f"Imports associated with {cat.replace('_', ' ')}: {', '.join(sorted(apis))}",
            {"category": cat, "apis": [{"api": a, "purpose": p} for a, p in sorted(apis.items())]},
            kind=Kind.EVIDENCE, severity=Severity.LOW, confidence=Confidence.LOW,
            location="import table", untrusted_content=True,
            limitations=["An import shows the binary references an API, not that it calls it or why. "
                         "These APIs are widely used by legitimate software."],
        )
