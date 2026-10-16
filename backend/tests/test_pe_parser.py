import pytest

from app.analyzers.pe.pe_parser import PEParseError, parse_pe
from conftest import build_minimal_pe


def test_parses_minimal_pe(minimal_pe_bytes):
    info = parse_pe(minimal_pe_bytes)
    assert info.machine == 0x14C
    assert not info.is_64bit
    assert info.sections[0].name == ".text"
    assert info.imports[0].name == "KERNEL32.dll"
    assert "CreateProcessA" in info.imports[0].functions


def test_detects_dll_flag():
    info = parse_pe(build_minimal_pe(is_dll=True))
    assert info.is_dll is True


def test_detects_overlay():
    info = parse_pe(build_minimal_pe(overlay=b"X" * 500))
    assert info.overlay_size == 500


def test_no_overlay_when_absent(minimal_pe_bytes):
    info = parse_pe(minimal_pe_bytes)
    assert info.overlay_size == 0


def test_rejects_missing_mz():
    with pytest.raises(PEParseError):
        parse_pe(b"not a pe" * 20)


def test_rejects_truncated_file(minimal_pe_bytes):
    with pytest.raises(PEParseError):
        parse_pe(minimal_pe_bytes[:100])


def test_rejects_bad_pe_signature():
    data = bytearray(minimal_pe_bytes_helper())
    data[0x3C:0x40] = (len(data) - 4).to_bytes(4, "little")
    with pytest.raises(PEParseError):
        parse_pe(bytes(data))


def minimal_pe_bytes_helper():
    return build_minimal_pe()


@pytest.mark.parametrize("machine", [0x14C, 0x8664, 0xAA64])
def test_various_machines(machine):
    info = parse_pe(build_minimal_pe(machine=machine))
    assert info.machine == machine


def test_section_table_bounds_are_checked():
    """A file whose header claims far more sections than fit must not crash."""
    data = bytearray(build_minimal_pe())
    # Corrupt number-of-sections in the COFF header to a huge value.
    import struct
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    struct.pack_into("<H", data, e_lfanew + 6, 5000)
    info = parse_pe(bytes(data))
    assert len(info.sections) <= 96
    assert info.warnings
