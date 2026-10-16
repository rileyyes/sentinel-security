"""Safe ZIP extraction for source-code uploads.

Defends against: zip-slip / path traversal, absolute paths, symlink members,
decompression bombs (declared AND actual size), compression-ratio abuse,
file-count floods, encrypted members, and duplicate members.

Only source/config file types are extracted; everything else is skipped.
Nothing is ever executed or imported.
"""
from __future__ import annotations

import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from app.core.config import Settings
from app.ingestion.validators import IngestionError

_ALLOWED_SUFFIXES = {".py", ".txt", ".cfg", ".ini", ".toml", ".yaml", ".yml", ".json", ".env", ".conf"}
_ALLOWED_NAMES = {".env", "dockerfile", "requirements.txt"}
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}
_DRIVE = re.compile(r"^[A-Za-z]:")


@dataclass
class ExtractionReport:
    extracted: list[str] = field(default_factory=list)
    skipped: int = 0
    warnings: list[str] = field(default_factory=list)


def _check_member_name(name: str) -> PurePosixPath:
    if "\x00" in name:
        raise IngestionError("bad_archive", "Archive contains an invalid member name.")
    norm = name.replace("\\", "/")
    if norm.startswith("/") or _DRIVE.match(norm):
        raise IngestionError("path_traversal", "Archive contains an absolute path.")
    parts = PurePosixPath(norm).parts
    if ".." in parts:
        raise IngestionError("path_traversal", "Archive contains a path-traversal entry.")
    return PurePosixPath(norm)


def _wanted(path: PurePosixPath) -> bool:
    if any(p in _SKIP_DIRS for p in path.parts[:-1]):
        return False
    base = path.name.lower()
    return base in _ALLOWED_NAMES or path.suffix.lower() in _ALLOWED_SUFFIXES


def safe_extract_zip(archive: Path, dest: Path, settings: Settings) -> ExtractionReport:
    dest.mkdir(parents=True, exist_ok=True)
    dest_resolved = dest.resolve()
    report = ExtractionReport()
    try:
        zf = zipfile.ZipFile(archive)
    except zipfile.BadZipFile as exc:
        raise IngestionError("bad_archive", "The archive is corrupt or not a valid ZIP.") from exc

    with zf:
        infos = zf.infolist()
        if len(infos) > settings.max_archive_files:
            raise IngestionError("too_many_files", "Archive contains too many files.")
        if sum(i.file_size for i in infos) > settings.max_archive_uncompressed_bytes:
            raise IngestionError("archive_too_large", "Archive expands beyond the allowed size.")

        total = 0
        for info in infos:
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                raise IngestionError("encrypted_archive", "Encrypted archives are not supported.")
            path = _check_member_name(info.filename)

            if (info.external_attr >> 16) & 0o170000 == 0o120000:  # symlink member
                report.warnings.append("Skipped a symbolic-link entry in the archive.")
                report.skipped += 1
                continue
            if not _wanted(path):
                report.skipped += 1
                continue
            if info.file_size > settings.max_archive_member_bytes:
                report.warnings.append(f"Skipped oversized member ({info.file_size} bytes).")
                report.skipped += 1
                continue
            if info.compress_size > 0 and info.file_size / info.compress_size > settings.max_compression_ratio:
                raise IngestionError("compression_ratio", "Archive has a suspicious compression ratio.")

            target = (dest_resolved / str(path)).resolve()
            if not target.is_relative_to(dest_resolved):  # belt and braces after name checks
                raise IngestionError("path_traversal", "Archive entry escapes the workspace.")
            target.parent.mkdir(parents=True, exist_ok=True)

            written = 0
            try:
                fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError as exc:
                raise IngestionError("bad_archive", "Archive contains duplicate entries.") from exc
            with os.fdopen(fd, "wb") as out, zf.open(info) as src:
                while True:
                    chunk = src.read(64 * 1024)
                    if not chunk:
                        break
                    written += len(chunk)  # count ACTUAL bytes; headers can lie
                    if (
                        written > settings.max_archive_member_bytes
                        or total + written > settings.max_archive_uncompressed_bytes
                    ):
                        raise IngestionError("archive_too_large", "Archive expands beyond the allowed size.")
                    out.write(chunk)
            total += written
            report.extracted.append(str(path))
    return report
