"""Run analysis in a separate, resource-limited process.

Why: even *static* analysis feeds hostile bytes to parsers. A parser bug or a
resource bomb must not be able to take down the API process.

Design:
* No shell; argv list only.
* A tiny launcher applies POSIX rlimits (memory, CPU, file size, open files,
  no core dumps) and then execv()s the worker, so we avoid ``preexec_fn``
  (which is unsafe in multi-threaded servers).
* Minimal environment: no inherited secrets such as API keys.
* stdout/stderr go to files inside the workspace (bounded by RLIMIT_FSIZE)
  so a noisy child cannot exhaust parent memory.
* Hard wall-clock timeout; the child is killed on expiry.

Limitation: rlimits are not a security sandbox. In deployment the container
(non-root, read-only rootfs, dropped capabilities) is the outer boundary.
POSIX only; on Windows this module would need a different implementation.
"""
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

_LAUNCHER = r"""
import os, resource, sys
mem, cpu, fsize = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
resource.setrlimit(resource.RLIMIT_AS, (mem, mem))
resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
resource.setrlimit(resource.RLIMIT_FSIZE, (fsize, fsize))
resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
os.execv(sys.executable, [sys.executable] + sys.argv[4:])
"""

BACKEND_ROOT = Path(__file__).resolve().parents[2]
MAX_RESULT_BYTES = 50 * 1024 * 1024


class SandboxError(Exception):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind  # "timeout" | "crash"


@dataclass
class SandboxResult:
    returncode: int
    stderr_tail: str


def run_limited(
    args: list[str],
    *,
    workdir: Path,
    timeout_s: int,
    memory_bytes: int,
) -> SandboxResult:
    out_path, err_path = workdir / "stdout.txt", workdir / "stderr.txt"
    cmd = [
        sys.executable, "-c", _LAUNCHER,
        str(memory_bytes), str(timeout_s + 5), str(MAX_RESULT_BYTES), *args,
    ]
    env = {
        "PATH": "/usr/bin:/bin",
        "PYTHONPATH": str(BACKEND_ROOT),
        "PYTHONDONTWRITEBYTECODE": "1",
        "LANG": "C.UTF-8",
    }
    with open(out_path, "wb") as out, open(err_path, "wb") as err:
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, shell=False
                cmd, cwd=workdir, env=env, stdin=subprocess.DEVNULL,
                stdout=out, stderr=err, timeout=timeout_s, shell=False, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise SandboxError("timeout", "analysis exceeded its time limit") from exc
    tail = err_path.read_bytes()[-500:].decode("utf-8", "replace")
    return SandboxResult(proc.returncode, tail)
