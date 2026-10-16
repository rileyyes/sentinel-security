"""Entry point executed inside the resource-limited child process.

argv: mode target display_name out_path max_strings
Runs analysis and writes the Investigation JSON to out_path. It reads only the
paths it is handed and never imports, executes or evals anything from them.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from app.core.config import Settings
from app.workflow.investigate import run_analysis


def main(argv: list[str]) -> int:
    mode, target, display, out_path, max_strings = argv
    settings = Settings(data_dir=Path("."), max_strings=int(max_strings))
    inv = run_analysis(mode, Path(target), display, settings)
    Path(out_path).write_text(json.dumps(inv.to_dict()), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
