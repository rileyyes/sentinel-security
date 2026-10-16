"""A small, defensive PE parser built on ``struct``.

Why custom (and not ``pefile``)?  This is a deliberate, documented deviation
from the Stage-1 plan: the sandbox this was built in had no package access, so
a dependency could not be installed or tested. The parser is bounds-checked
everywhere, caps every loop, and never raises anything except PEParseError.
It covers only what the MVP needs: headers, sections, imports, exports,
overlay. It does NOT handle delay-load imports, bound imports, resources,
certificates, or .NET metadata. ``pefile`` remains a good cross-check later.
"""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

MAX_SECTIONS = 96
MAX_IMPORT_DLLS = 512
MAX_FUNCS_PER_DLL = 4096
MAX_TOTAL_FUNCS = 20000
MAX_EXPORT_NAMES = 10000
_PRINTABLE = re.compile(rb"^[\x20-\x7e]+$")


class PEParseError(ValueError):
    pass


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int


@dataclass
class ImportedDll:
    name: str
    functions: list[str]


@dataclass
class PEInfo:
    machine: int
    number_of_sections: int
    timestamp: int
    characteristics: int
    is_64bit: bool
    entry_point: int
    image_base: int
    subsystem: int
    dll_characteristics: int
    size_of_image: int
    size_of_headers: int
    checksum: int
    sections: list[Section] = field(default_factory=list)
    imports: list[ImportedDll] = field(default_factory=list)
    export_dll_name: str | None = None
    exports: list[str] = field(default_factory=list)
    export_function_count: int = 0
    overlay_offset: int | None = None
    overlay_size: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def is_dll(self) -> bool:
        return bool(self.characteristics & 0x2000)

    def section_for_rva(self, rva: int) -> Section | None:
        for s in self.sections:
            if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size, 1):
                return s
        return None


def _unpack(fmt: str, data: bytes, off: int) -> tuple:
    try:
        return struct.unpack_from(fmt, data, off)
    except struct.error as exc:
        raise PEParseError("truncated or malformed structure") from exc


def _cstr(data: bytes, off: int | None, limit: int = 256) -> str | None:
    if off is None or off < 0 or off >= len(data):
        return None
    chunk = data[off:off + limit]
    end = chunk.find(b"\x00")
    raw = chunk if end < 0 else chunk[:end]
    if raw and _PRINTABLE.match(raw):
        return raw.decode("ascii")
    return None  # non-printable names are dropped, never echoed


def parse_pe(data: bytes) -> PEInfo:
    n = len(data)
    if n < 64 or data[:2] != b"MZ":
        raise PEParseError("missing MZ header")
    (e_lfanew,) = _unpack("<I", data, 0x3C)
    if e_lfanew > n - 24 or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise PEParseError("missing PE signature")

    coff = e_lfanew + 4
    machine, nsec, timestamp, _sym, _nsym, size_opt, characteristics = _unpack("<HHIIIHH", data, coff)
    opt = coff + 20
    (magic,) = _unpack("<H", data, opt)
    if magic == 0x10B:
        is64 = False
        entry, = _unpack("<I", data, opt + 16)
        image_base, = _unpack("<I", data, opt + 28)
        dd_off, numrva_off = opt + 96, opt + 92
    elif magic == 0x20B:
        is64 = True
        entry, = _unpack("<I", data, opt + 16)
        image_base, = _unpack("<Q", data, opt + 24)
        dd_off, numrva_off = opt + 112, opt + 108
    else:
        raise PEParseError("unknown optional header magic")
    size_of_image, size_of_headers, checksum = _unpack("<III", data, opt + 56)
    subsystem, dll_chars = _unpack("<HH", data, opt + 68)
    (numrva,) = _unpack("<I", data, numrva_off)

    info = PEInfo(
        machine=machine, number_of_sections=nsec, timestamp=timestamp,
        characteristics=characteristics, is_64bit=is64, entry_point=entry,
        image_base=image_base, subsystem=subsystem, dll_characteristics=dll_chars,
        size_of_image=size_of_image, size_of_headers=size_of_headers, checksum=checksum,
    )

    # data directories (only the ones we use: export=0, import=1)
    avail = max(0, min(numrva, 16, (opt + size_opt - dd_off) // 8))
    dirs = [_unpack("<II", data, dd_off + 8 * i) for i in range(avail)]

    # section table
    sec_off = opt + size_opt
    count = nsec
    if count > MAX_SECTIONS:
        info.warnings.append(f"Header declares {nsec} sections; only {MAX_SECTIONS} were parsed.")
        count = MAX_SECTIONS
    for i in range(count):
        off = sec_off + 40 * i
        if off + 40 > n:
            info.warnings.append("Section table extends past end of file.")
            break
        raw_name = data[off:off + 8].split(b"\x00")[0]
        name = raw_name.decode("ascii") if raw_name and _PRINTABLE.match(raw_name) else "<non-printable>"
        vsize, vaddr, rsize, roff = _unpack("<IIII", data, off + 8)
        (chars,) = _unpack("<I", data, off + 36)
        info.sections.append(Section(name, vsize, vaddr, rsize, roff, chars))

    def rva_to_off(rva: int) -> int | None:
        if rva <= 0:
            return None
        if rva < size_of_headers and rva < n:
            return rva
        for s in info.sections:
            if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
                off = rva - s.virtual_address + s.raw_offset
                return off if off < n else None
        return None

    # overlay (data after the last section's raw data)
    ends = [s.raw_offset + s.raw_size for s in info.sections if s.raw_size > 0 and s.raw_offset < n]
    if ends:
        end = min(max(ends), n)
        if end < n:
            info.overlay_offset, info.overlay_size = end, n - end

    _parse_imports(data, info, dirs, rva_to_off)
    _parse_exports(data, info, dirs, rva_to_off)
    return info


def _parse_imports(data, info: PEInfo, dirs, rva_to_off) -> None:
    if len(dirs) < 2 or dirs[1][0] == 0:
        return
    off = rva_to_off(dirs[1][0])
    if off is None:
        info.warnings.append("Import directory RVA does not map to file data.")
        return
    step, flag = (8, 1 << 63) if info.is_64bit else (4, 1 << 31)
    fmt = "<Q" if info.is_64bit else "<I"
    total = 0
    for i in range(MAX_IMPORT_DLLS):
        d = off + 20 * i
        if d + 20 > len(data):
            info.warnings.append("Import descriptor table is truncated.")
            break
        orig_thunk, _ts, _fwd, name_rva, first_thunk = _unpack("<IIIII", data, d)
        if orig_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break
        dll_name = _cstr(data, rva_to_off(name_rva)) or "<unreadable>"
        funcs: list[str] = []
        toff = rva_to_off(orig_thunk or first_thunk)
        if toff is not None:
            for j in range(MAX_FUNCS_PER_DLL):
                p = toff + j * step
                if p + step > len(data) or total >= MAX_TOTAL_FUNCS:
                    break
                (val,) = _unpack(fmt, data, p)
                if val == 0:
                    break
                if val & flag:
                    funcs.append(f"ord#{val & 0xFFFF}")
                else:
                    name_off = rva_to_off(val & 0x7FFFFFFF)
                    fn = _cstr(data, name_off + 2) if name_off is not None else None  # skip 2-byte hint
                    funcs.append(fn or "<unreadable>")
                total += 1
        info.imports.append(ImportedDll(dll_name, funcs))
    else:
        info.warnings.append("Import table hit the descriptor limit.")


def _parse_exports(data, info: PEInfo, dirs, rva_to_off) -> None:
    if not dirs or dirs[0][0] == 0:
        return
    off = rva_to_off(dirs[0][0])
    if off is None or off + 40 > len(data):
        info.warnings.append("Export directory RVA does not map to file data.")
        return
    name_rva, _base, nfuncs, nnames, _af, addr_names, _ao = _unpack("<IIIIIII", data, off + 12)
    info.export_dll_name = _cstr(data, rva_to_off(name_rva))
    info.export_function_count = nfuncs
    names_off = rva_to_off(addr_names)
    if names_off is None:
        return
    for i in range(min(nnames, MAX_EXPORT_NAMES)):
        p = names_off + 4 * i
        if p + 4 > len(data):
            break
        (nrva,) = _unpack("<I", data, p)
        nm = _cstr(data, rva_to_off(nrva))
        if nm:
            info.exports.append(nm)
