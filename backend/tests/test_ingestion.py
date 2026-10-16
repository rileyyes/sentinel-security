import io

import pytest

from app.ingestion.archive import safe_extract_zip
from app.ingestion.validators import (
    IngestionError, detect_file_type, sanitize_filename, validate_code_upload, validate_pe_upload,
)
from conftest import build_minimal_pe, make_zip


@pytest.mark.parametrize("raw,expected", [
    ("../../etc/passwd", "passwd"),
    ("..\\..\\windows\\system32\\evil.exe", "evil.exe"),
    ("con.py", "_con.py"),
    ("normal_file.py", "normal_file.py"),
    ("", "artifact.bin"),
    ("a" * 300 + ".py", None),  # just check length below
])
def test_sanitize_filename(raw, expected):
    result = sanitize_filename(raw)
    assert "/" not in result and "\\" not in result
    assert ".." not in result
    if expected is not None:
        assert result == expected
    assert len(result) <= 100


def test_detect_pe_vs_text():
    assert detect_file_type(b"MZ\x90\x00") == "pe"
    assert detect_file_type(b"print('hi')\n") == "text"
    assert detect_file_type(b"PK\x03\x04") == "zip"


def test_validate_pe_upload_accepts_real_pe(minimal_pe_bytes):
    validate_pe_upload(minimal_pe_bytes)  # should not raise


def test_validate_pe_upload_rejects_text():
    with pytest.raises(IngestionError):
        validate_pe_upload(b"not a pe file" * 10)


def test_validate_code_upload_accepts_py_and_zip():
    assert validate_code_upload(b"import os\n", "a.py") == "py"
    z = make_zip({"a.py": "x = 1"})
    assert validate_code_upload(z, "proj.zip") == "zip"


def test_validate_code_upload_rejects_pe(minimal_pe_bytes):
    with pytest.raises(IngestionError):
        validate_code_upload(minimal_pe_bytes, "app.py")


def test_zip_slip_is_blocked(tmp_path, settings):
    z = make_zip({"../../evil.py": "x = 1"})
    (tmp_path / "up.zip").write_bytes(z)
    with pytest.raises(IngestionError) as exc:
        safe_extract_zip(tmp_path / "up.zip", tmp_path / "dest", settings)
    assert exc.value.code == "path_traversal"


def test_absolute_path_member_is_blocked(tmp_path, settings):
    z = make_zip({"/etc/passwd": "x"})
    (tmp_path / "up.zip").write_bytes(z)
    with pytest.raises(IngestionError):
        safe_extract_zip(tmp_path / "up.zip", tmp_path / "dest", settings)


def test_normal_zip_extracts_cleanly(tmp_path, settings):
    z = make_zip({"pkg/main.py": "print(1)", "pkg/util.py": "x = 2", "README.md": "hi"})
    (tmp_path / "up.zip").write_bytes(z)
    report = safe_extract_zip(tmp_path / "up.zip", tmp_path / "dest", settings)
    assert "pkg/main.py" in report.extracted
    assert (tmp_path / "dest" / "pkg" / "main.py").read_text() == "print(1)"


def test_oversized_member_is_skipped_not_fatal(tmp_path, settings):
    big = "x" * (settings.max_archive_member_bytes + 1000)
    z = make_zip({"big.py": big, "small.py": "y = 1"})
    (tmp_path / "up.zip").write_bytes(z)
    report = safe_extract_zip(tmp_path / "up.zip", tmp_path / "dest", settings)
    assert "small.py" in report.extracted
    assert "big.py" not in report.extracted
    assert report.skipped >= 1


def test_bad_zip_raises():
    import pathlib
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = pathlib.Path(d) / "bad.zip"
        p.write_bytes(b"not a zip")
        with pytest.raises(IngestionError):
            safe_extract_zip(p, pathlib.Path(d) / "dest", __import__("app.core.config", fromlist=["Settings"]).Settings(data_dir=pathlib.Path(d)))
