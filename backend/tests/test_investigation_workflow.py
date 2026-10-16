import io

import pytest

from app.ingestion.validators import IngestionError
from app.workflow.investigate import investigate
from conftest import build_minimal_pe, make_zip


def test_software_investigation_end_to_end(settings, minimal_pe_bytes):
    inv = investigate("software", io.BytesIO(minimal_pe_bytes), "sample.exe", settings, isolated=False)
    assert inv.mode == "software"
    assert inv.artifact["sha256"]
    assert len(inv.evidence) > 0
    assert inv.errors == []


def test_code_investigation_end_to_end(settings):
    src = b"import os\ncmd = input()\nos.system(cmd)\n"
    inv = investigate("code", io.BytesIO(src), "app.py", settings, isolated=False)
    assert inv.mode == "code"
    assert any(f.rule_id == "PY-CMD-001" for f in inv.findings)
    assert inv.recommendations


def test_zip_code_investigation(settings):
    z = make_zip({"pkg/a.py": "eval(input())\n", "pkg/b.py": "x = 1\n"})
    inv = investigate("code", io.BytesIO(z), "proj.zip", settings, isolated=False)
    assert inv.artifact["files_scanned"] == 2
    assert any(f.rule_id == "PY-EXEC-001" for f in inv.findings)


def test_rejects_oversized_upload(settings):
    settings2 = settings.__class__(data_dir=settings.data_dir, max_upload_bytes=100)
    with pytest.raises(IngestionError):
        investigate("code", io.BytesIO(b"x" * 1000), "a.py", settings2, isolated=False)


def test_filename_never_used_as_path(settings, minimal_pe_bytes):
    inv = investigate("software", io.BytesIO(minimal_pe_bytes), "../../../evil.exe", settings, isolated=False)
    assert inv.artifact["filename"] == "evil.exe"


def test_investigation_serialises_round_trip(settings, minimal_pe_bytes):
    from app.evidence.models import Investigation

    inv = investigate("software", io.BytesIO(minimal_pe_bytes), "sample.exe", settings, isolated=False)
    restored = Investigation.from_dict(inv.to_dict())
    assert restored.id == inv.id
    assert len(restored.evidence) == len(inv.evidence)


def test_malformed_pe_produces_errors_not_crash(settings):
    junk = b"MZ" + b"\x00" * 100  # has MZ but no valid PE signature after e_lfanew games
    with pytest.raises(IngestionError):
        investigate("software", io.BytesIO(junk), "bad.exe", settings, isolated=False)
