"""Private temporary workspaces that are always cleaned up."""
from __future__ import annotations

import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


@contextmanager
def safe_workspace(base: Path) -> Iterator[Path]:
    """Create ``base/inv-XXXX`` (mode 0700), yield it, delete it afterwards.

    mkdtemp gives an unpredictable name and atomic creation, which avoids the
    classic predictable-temp-file race.
    """
    base.mkdir(parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    path = Path(tempfile.mkdtemp(prefix="inv-", dir=base))
    os.chmod(path, 0o700)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def write_private(path: Path, data: bytes) -> None:
    """Exclusive-create a file with owner-only permissions (never executable)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
