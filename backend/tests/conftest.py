import struct
import zipfile
from pathlib import Path

import pytest

from app.core.config import Settings


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(data_dir=tmp_path / "data")


def build_minimal_pe(*, machine=0x14C, is_dll=False, sections=None, imports=None,
                      entry=0x1000, timestamp=0x5F000000, overlay=b"") -> bytes:
    """Construct a tiny, syntactically valid 32-bit PE for tests."""
    sections = sections if sections is not None else [(".text", 0x1000, 0x1000, 0x200, True, True, False)]
    imports = imports if imports is not None else {"KERNEL32.dll": ["CreateProcessA", "VirtualAllocEx"]}

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    e_lfanew = 0x80
    struct.pack_into("<I", dos, 0x3C, e_lfanew)
    dos += b"\x00" * (e_lfanew - len(dos))

    n_sections = len(sections)
    opt_size = 224  # PE32 optional header + 16 data dirs
    coff = struct.pack("<4sHHIIIHH", b"PE\x00\x00", machine, n_sections, timestamp, 0, 0, opt_size,
                       0x2002 if is_dll else 0x0102)

    header_size = e_lfanew + len(coff) + opt_size + 40 * n_sections
    file_align = 0x200
    size_of_headers = ((header_size + file_align - 1) // file_align) * file_align

    body_chunks = {}
    raw_cursor = size_of_headers
    layout = []
    for name, vsize, vaddr, rsize, readable, executable, writable in sections:
        raw_size = ((rsize + file_align - 1) // file_align) * file_align if rsize else 0
        layout.append((name, vsize, vaddr, raw_size, raw_cursor, readable, executable, writable))
        raw_cursor += raw_size

    import_rva = import_off = 0
    if imports:
        first = layout[0]
        import_rva = first[2]  # place at the very start of the section's virtual range
        idata = bytearray(20 * (len(imports) + 1))
        strtab = bytearray()
        thunk_area = bytearray()
        cursor_str = import_rva + len(idata)
        cursor_thunk = None
        entries = []
        func_blobs = []
        for i, (dll, funcs) in enumerate(imports.items()):
            name_off = cursor_str + len(strtab)
            strtab += dll.encode() + b"\x00"
            func_rvas = []
            for fn in funcs:
                func_rvas.append((cursor_str + len(strtab), fn))
                strtab += b"\x00\x00" + fn.encode() + b"\x00"
            entries.append((name_off, func_rvas))
        thunk_base = cursor_str + len(strtab)
        thunk_bytes = bytearray()
        descriptors = bytearray()
        offset_cursor = thunk_base
        for name_off, func_rvas in entries:
            this_thunk_rva = offset_cursor
            for frva, _ in func_rvas:
                thunk_bytes += struct.pack("<I", frva)
            thunk_bytes += struct.pack("<I", 0)
            offset_cursor += 4 * (len(func_rvas) + 1)
            descriptors += struct.pack("<IIIII", this_thunk_rva, 0, 0, name_off, this_thunk_rva)
        descriptors += b"\x00" * 20
        blob = bytes(descriptors) + bytes(strtab) + bytes(thunk_bytes)
        body_chunks[layout[0][4]] = blob  # raw_offset of first section == file offset of import_rva
        import_off = import_rva

    dd = bytearray(16 * 8)
    if import_rva:
        struct.pack_into("<II", dd, 8, import_rva, 64)

    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 16, entry)
    struct.pack_into("<I", opt, 28, 0x400000)
    struct.pack_into("<III", opt, 56, raw_cursor, size_of_headers, 0)
    struct.pack_into("<HH", opt, 68, 3, 0)
    struct.pack_into("<I", opt, 92, 16)
    opt[96:96 + len(dd)] = dd

    sect_table = bytearray()
    for name, vsize, vaddr, rsize, roff, readable, executable, writable in layout:
        chars = 0
        if readable: chars |= 0x40000000
        if writable: chars |= 0x80000000
        if executable: chars |= 0x20000000
        sect_table += name.encode()[:8].ljust(8, b"\x00") + struct.pack("<IIIIIIHHI", vsize, vaddr, rsize, roff, 0, 0, 0, 0, chars)

    header = bytes(dos) + coff + bytes(opt) + bytes(sect_table)
    header = header.ljust(size_of_headers, b"\x00")

    body = bytearray(raw_cursor - size_of_headers)
    for offset, blob in body_chunks.items():
        start = offset - size_of_headers
        body[start:start + len(blob)] = blob

    return header + bytes(body) + overlay


@pytest.fixture
def minimal_pe_bytes() -> bytes:
    return build_minimal_pe()


def make_zip(files: dict) -> bytes:
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buf.getvalue()
