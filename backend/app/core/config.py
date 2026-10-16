"""Environment-based configuration. No secrets live in source code.

Every limit is an explicit, bounded integer so that a bad environment value
fails loudly at startup instead of silently disabling a protection.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    max_upload_bytes: int = 25 * 1024 * 1024
    max_archive_files: int = 2000
    max_archive_uncompressed_bytes: int = 100 * 1024 * 1024
    max_archive_member_bytes: int = 2 * 1024 * 1024
    max_compression_ratio: int = 100
    analysis_timeout_s: int = 60
    analysis_memory_bytes: int = 1024 * 1024 * 1024
    max_strings: int = 5000
    retention_days: int = 30

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            data_dir=Path(os.environ.get("SENTINEL_DATA_DIR", "./data")).resolve(),
            max_upload_bytes=_int_env("SENTINEL_MAX_UPLOAD_BYTES", cls.max_upload_bytes),
            max_archive_files=_int_env("SENTINEL_MAX_ARCHIVE_FILES", cls.max_archive_files),
            max_archive_uncompressed_bytes=_int_env(
                "SENTINEL_MAX_ARCHIVE_UNCOMPRESSED_BYTES", cls.max_archive_uncompressed_bytes
            ),
            max_archive_member_bytes=_int_env(
                "SENTINEL_MAX_ARCHIVE_MEMBER_BYTES", cls.max_archive_member_bytes
            ),
            max_compression_ratio=_int_env("SENTINEL_MAX_COMPRESSION_RATIO", cls.max_compression_ratio),
            analysis_timeout_s=_int_env("SENTINEL_ANALYSIS_TIMEOUT_S", cls.analysis_timeout_s),
            analysis_memory_bytes=_int_env("SENTINEL_ANALYSIS_MEMORY_BYTES", cls.analysis_memory_bytes),
            max_strings=_int_env("SENTINEL_MAX_STRINGS", cls.max_strings),
            retention_days=_int_env("SENTINEL_RETENTION_DAYS", cls.retention_days),
        )
