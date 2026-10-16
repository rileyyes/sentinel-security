"""Upload validation: size, real file type, filename sanitisation.

Principles
* Content decides file type, never the extension or client-supplied MIME type.
* The user's filename is display-only. It is sanitised and NEVER used to build
  a filesystem path (artifacts are stored under fixed names).
"""
from __future__ import annotations

import re
import unicodedata
from typing import BinaryIO


class IngestionError(Exception):
    """Raised for rejected input. ``code`` is stable; ``message`` is safe to show."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]")
_MAX_NAME = 100


def sanitize_filename(name: str | None, default: str = "artifact.bin") -> str:
    if not name:
        return default
    name = name.replace("\x00", "")
    name = name.replace("\\", "/").split("/")[-1]      # drop any directory part
    name = unicodedata.normalize("NFKC", name)
    name = _UNSAFE.sub("_", name)
    name = re.sub(r"_+", "_", name).lstrip("._-")       # no hidden / dash-leading names
    if not name:
        return default
    if len(name) > _MAX_NAME:
        stem, dot, ext = name.rpartition(".")
        keep = _MAX_NAME - len(ext) - 1 if dot else _MAX_NAME
        name = (stem[:keep] + "." + ext[:10]) if dot else name[:_MAX_NAME]
    if name.split(".")[0].lower() in _RESERVED:
        name = "_" + name
    return name


def read_limited(stream: BinaryIO, max_bytes: int, chunk: int = 64 * 1024) -> bytes:
    """Read a stream fully but abort as soon as it exceeds ``max_bytes``."""
    buf = bytearray()
    while True:
        part = stream.read(chunk)
        if not part:
            return bytes(buf)
        buf += part
        if len(buf) > max_bytes:
            raise IngestionError("too_large", f"File exceeds the {max_bytes // (1024 * 1024)} MB limit.")


def detect_file_type(head: bytes) -> str:
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[:4] == b"\x7fELF":
        return "elf"
    sample = head[:4096]
    if sample and b"\x00" not in sample:
        try:
            sample.decode("utf-8")
            return "text"
        except UnicodeDecodeError:
            # A multi-byte character may be cut at the 4096 boundary.
            try:
                sample[:-3].decode("utf-8")
                return "text"
            except UnicodeDecodeError:
                return "unknown"
    return "unknown"


def validate_pe_upload(data: bytes) -> None:
    """Cheap structural gate; full parsing happens later in the isolated worker."""
    if len(data) < 64:
        raise IngestionError("too_small", "File is too small to be a Windows executable.")
    if detect_file_type(data) != "pe":
        raise IngestionError("not_pe", "Only Windows PE files (EXE/DLL/SYS) are supported for software investigation.")
    e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
    if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise IngestionError("not_pe", "File has an MZ header but no valid PE signature.")


def validate_code_upload(data: bytes, filename: str) -> str:
    """Return 'zip' or 'py'. Rejects anything else."""
    kind = detect_file_type(data)
    if kind == "zip":
        return "zip"
    if kind == "text" and filename.lower().endswith(".py"):
        return "py"
    raise IngestionError("unsupported_type", "Upload a .py file or a .zip archive of a Python project.")
