import pytest

from app.evidence.models import Investigation
from app.storage.store import InvestigationStore, NotFound


def make_inv() -> Investigation:
    inv = Investigation.new("code", {"filename": "a.py", "sha256": "x" * 64, "size_bytes": 10})
    inv.log("analyze", "done")
    return inv


def test_save_and_load_round_trip(settings):
    store = InvestigationStore(settings)
    inv = make_inv()
    store.save(inv)
    loaded = store.load(inv.id)
    assert loaded.id == inv.id
    assert loaded.artifact["filename"] == "a.py"


def test_missing_investigation_raises(settings):
    store = InvestigationStore(settings)
    with pytest.raises(NotFound):
        store.load("0" * 32)


def test_invalid_id_rejected(settings):
    store = InvestigationStore(settings)
    with pytest.raises(NotFound):
        store.load("../../etc/passwd")


def test_list_returns_newest_first(settings):
    store = InvestigationStore(settings)
    import time

    a, b = make_inv(), make_inv()
    store.save(a)
    time.sleep(0.01)
    store.save(b)
    listed = store.list()
    assert listed[0]["id"] in (a.id, b.id)
    assert len(listed) == 2


def test_delete_removes_investigation(settings):
    store = InvestigationStore(settings)
    inv = make_inv()
    store.save(inv)
    store.delete(inv.id)
    with pytest.raises(NotFound):
        store.load(inv.id)


def test_export_then_import_round_trip(settings, tmp_path):
    store = InvestigationStore(settings)
    inv = make_inv()
    store.save(inv)
    out = tmp_path / "export.zip"
    store.export_zip(inv.id, out)
    restored = store.import_zip(out)
    assert restored.id != inv.id  # re-ids on import
    assert restored.artifact["filename"] == "a.py"


def test_import_rejects_non_export_zip(settings, tmp_path):
    import zipfile

    from app.ingestion.validators import IngestionError

    p = tmp_path / "bad.zip"
    with zipfile.ZipFile(p, "w") as zf:
        zf.writestr("random.txt", "hi")
    store = InvestigationStore(settings)
    with pytest.raises(IngestionError):
        store.import_zip(p)


def test_report_html_is_escaped(settings):
    store = InvestigationStore(settings)
    inv = make_inv()
    from app.evidence.models import EvidenceCollector

    c = EvidenceCollector()
    c.add("strings", "notable_strings", "test", {"x": "<script>alert(1)</script>"}, untrusted_content=True)
    inv.evidence = c.items
    store.save(inv)
    html = store.report_html(inv.id)
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
