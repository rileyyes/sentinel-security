"""Secret detection helpers. Secrets are ALWAYS redacted before storage."""
from __future__ import annotations

import re

PLACEHOLDERS = {
    "", "changeme", "change_me", "password", "secret", "xxx", "xxxx", "your_password", "todo", "none",
    "null", "example", "test", "dummy", "placeholder", "your-secret-here",
}
NAME_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|auth[_-]?token|token)"
)
TOKEN_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
]
GENERIC_ASSIGN = re.compile(
    r"""(?i)\b([a-z0-9_.-]*(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key)[a-z0-9_.-]*)"""
    r"""\s*[:=]\s*['"]?([^\s'"#,;]{6,})"""
)


def is_placeholder(value: str) -> bool:
    v = value.strip().lower()
    if v in PLACEHOLDERS or len(v) < 4:
        return True
    if v.startswith(("<", "${", "{{", "%(", "$(", "os.environ", "getenv")):
        return True
    return "your" in v and "here" in v


def redact(value: str) -> str:
    return f"{value[:4]}…[redacted, {len(value)} chars]" if len(value) > 4 else "[redacted]"
