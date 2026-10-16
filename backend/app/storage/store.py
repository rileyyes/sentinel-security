"""File-based investigation storage (no database).

Layout (under ``<data_dir>/investigations/<id>/``)
    metadata.json        summary for listing
    report.json          CANONICAL full investigation (loaded by the app)
    report.html          rendered report (regenerated, never trusted from imports)
    evidence/evidence.json, findings/findings.json, analysis/analyzers.json
                         convenience views of the same data
Uploaded artifacts are NOT stored by default. If retention is requested they
go to ``<data_dir>/artifacts/<sha256>.bin`` (0600, separate from reports).

Security properties
* IDs are server-generated 32-hex strings and are re-validated on every access
  (path traversal impossible: ids never contain separators).
* Directories 0700, files 0600; writes are atomic (temp file + rename).
* Imports never trust HTML, never reuse the supplied id, and are size/shape limited.
"""
from __future__ import annotations

import json
import re
import os
import shutil
import time
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from app.core.config import Settings
from app.core.logging import log_event
from app.evidence.models import INVESTIGATION_ID_RE, Investigation
from app.ingestion.validators import IngestionError
from app.reports.html_report import render_html, render_json

_EXPORT_FILES = {"metadata.json", "report.json", "report.html", "evidence/evidence.json",
                 "findings/findings.json", "analysis/analyzers.json"}


class NotFound(Exception):
    pass


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)


class InvestigationStore:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.root = settings.data_dir / "investigations"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)

    # ---- paths -----------------------------------------------------------
    def _dir(self, inv_id: str) -> Path:
        if not isinstance(inv_id, str) or not INVESTIGATION_ID_RE.match(inv_id):
            raise NotFound("invalid id")
        path = (self.root / inv_id).resolve()
        if not path.is_relative_to(self.root.resolve()):
            raise NotFound("invalid id")
        return path

    # ---- write -----------------------------------------------------------
    def save(self, inv: Investigation) -> None:
        d = self._dir(inv.id)
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        plain = inv.to_dict()
        meta = {
            "id": inv.id, "mode": inv.mode, "created_at": inv.created_at, "schema_version": inv.schema_version,
            "artifact": {k: plain["artifact"].get(k) for k in ("filename", "sha256", "size_bytes")},
            "counts": {"evidence": len(inv.evidence), "findings": len(inv.findings),
                       "hypotheses": len(inv.hypotheses), "recommendations": len(inv.recommendations)},
        }
        _atomic_write(d / "evidence" / "evidence.json", json.dumps(plain["evidence"], indent=2))
        _atomic_write(d / "findings" / "findings.json", json.dumps(plain["findings"], indent=2))
        _atomic_write(d / "analysis" / "analyzers.json", json.dumps(plain["analyzer_results"], indent=2))
        _atomic_write(d / "report.json", render_json(inv))
        _atomic_write(d / "report.html", render_html(inv))
        _atomic_write(d / "metadata.json", json.dumps(meta, indent=2))
        log_event("investigation_saved", id=inv.id)

    def retain_artifact(self, sha256: str, data: bytes) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", sha256):
            raise ValueError("bad hash")
        art = self.settings.data_dir / "artifacts"
        art.mkdir(parents=True, exist_ok=True, mode=0o700)
        target = art / f"{sha256}.bin"
        if not target.exists():
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)

    # ---- read ------------------------------------------------------------
    def load(self, inv_id: str) -> Investigation:
        path = self._dir(inv_id) / "report.json"
        if not path.is_file():
            raise NotFound("investigation not found")
        return Investigation.from_dict(json.loads(path.read_text("utf-8")))

    def report_html(self, inv_id: str) -> str:
        path = self._dir(inv_id) / "report.html"
        if not path.is_file():
            raise NotFound("investigation not found")
        return path.read_text("utf-8")

    def list(self) -> list[dict]:
        items = []
        for child in sorted(self.root.iterdir()):
            meta = child / "metadata.json"
            if INVESTIGATION_ID_RE.match(child.name) and meta.is_file():
                try:
                    items.append(json.loads(meta.read_text("utf-8")))
                except (OSError, ValueError):
                    continue
        return sorted(items, key=lambda m: m.get("created_at", ""), reverse=True)

    def delete(self, inv_id: str) -> None:
        d = self._dir(inv_id)
        if not d.is_dir():
            raise NotFound("investigation not found")
        shutil.rmtree(d)
        log_event("investigation_deleted", id=inv_id)

    # ---- retention -------------------------------------------------------
    def cleanup(self, max_age_days: int | None = None, now: float | None = None) -> list[str]:
        days = max_age_days if max_age_days is not None else self.settings.retention_days
        cutoff = (now if now is not None else time.time()) - days * 86400
        removed = []
        for meta in self.list():
            try:
                created = datetime.strptime(meta["created_at"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
            except (KeyError, ValueError):
                continue
            if created < cutoff:
                self.delete(meta["id"])
                removed.append(meta["id"])
        return removed

    # ---- export / import --------------------------------------------------
    def export_zip(self, inv_id: str, dest: Path) -> Path:
        d = self._dir(inv_id)
        if not d.is_dir():
            raise NotFound("investigation not found")
        with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in sorted(_EXPORT_FILES):
                src = d / name
                if src.is_file():
                    zf.write(src, arcname=name)
        os.chmod(dest, 0o600)
        return dest

    def import_zip(self, archive: Path) -> Investigation:
        limit = self.settings.max_archive_uncompressed_bytes
        try:
            zf = zipfile.ZipFile(archive)
        except zipfile.BadZipFile as exc:
            raise IngestionError("bad_archive", "Not a valid export archive.") from exc
        with zf:
            names = {i.filename for i in zf.infolist()}
            if not names <= _EXPORT_FILES or "report.json" not in names:
                raise IngestionError("bad_archive", "Archive does not look like an investigation export.")
            info = zf.getinfo("report.json")
            if info.file_size > limit:
                raise IngestionError("archive_too_large", "Export is too large.")
            with zf.open(info) as fh:
                raw = fh.read(limit + 1)
            if len(raw) > limit:
                raise IngestionError("archive_too_large", "Export is too large.")
        try:
            inv = Investigation.from_dict(json.loads(raw.decode("utf-8")))
        except (ValueError, UnicodeDecodeError) as exc:
            raise IngestionError("bad_archive", "Export content is invalid.") from exc
        inv.id = uuid.uuid4().hex                                  # never trust the imported id
        inv.log("import", "imported from export archive")
        self.save(inv)                                              # HTML is regenerated, not copied
        return inv
