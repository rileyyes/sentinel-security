"""Security logging that cannot leak artifact content or be forged by it.

Rules enforced here:
* Only short scalar fields are logged.
* Control characters are stripped (prevents log injection via crafted filenames).
* Field names that suggest content/secrets are dropped outright.
"""
from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_FORBIDDEN_KEYS = {"content", "data", "body", "secret", "password", "token", "api_key", "strings", "evidence"}
_LOGGER_NAME = "sentinel.security"


def clean(value: Any, limit: int = 200) -> str:
    text = _CONTROL.sub("?", str(value))
    return text if len(text) <= limit else text[:limit] + "..."


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "event": record.getMessage(),
        }
        payload.update(getattr(record, "fields", {}))
        return json.dumps(payload, ensure_ascii=True)


def get_logger() -> logging.Logger:
    logger = logging.getLogger(_LOGGER_NAME)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


def log_event(event: str, level: int = logging.INFO, **fields: Any) -> None:
    safe: dict[str, Any] = {}
    for key, value in fields.items():
        if key.lower() in _FORBIDDEN_KEYS:
            continue
        safe[clean(key, 40)] = value if isinstance(value, (int, float, bool)) else clean(value)
    get_logger().log(level, clean(event, 80), extra={"fields": safe})
