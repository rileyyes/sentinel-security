"""Validate LLM output before showing it. LLM text is untrusted until checked."""
from __future__ import annotations

import re
from dataclasses import dataclass, field

MAX_CHARS = 4000
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CITE = re.compile(r"\[((?:E|H|F|R)-\d{2,4})\]")
_VERDICT = re.compile(
    r"(?i)\b(?:this|the)\s+(?:file|sample|binary|software|program|executable|code|application)\s+"
    r"(?:is|was|are)\s+(?:\w+\s+)?(?:malware|malicious|a virus|a trojan|ransomware|a backdoor|safe|secure|clean)\b"
    r"|\b(?:definitely|certainly|confirmed|undoubtedly)\s+(?:malware|malicious)\b"
)
_LINKS = re.compile(r"!?\[[^\]]*\]\((?:https?:)?//[^)]*\)|https?://\S+")


@dataclass
class ValidatedAnswer:
    ok: bool
    text: str
    issues: list[str] = field(default_factory=list)


REFUSAL = ("The assistant's answer was withheld because it failed validation. "
           "Review the structured evidence directly or rephrase your question.")


def validate_answer(text: str, allowed_ids: set[str]) -> ValidatedAnswer:
    issues: list[str] = []
    text = _CTRL.sub("", text or "").strip()
    if not text:
        return ValidatedAnswer(False, REFUSAL, ["empty answer"])
    if len(text) > MAX_CHARS:
        text = text[:MAX_CHARS] + " …[truncated]"
        issues.append("answer truncated")
    unknown = sorted({c for c in _CITE.findall(text) if c not in allowed_ids})
    if unknown:
        return ValidatedAnswer(False, REFUSAL, [f"cited unknown id(s): {', '.join(unknown)}"])
    if _VERDICT.search(text):
        return ValidatedAnswer(False, REFUSAL, ["contains a definitive verdict"])
    if _LINKS.search(text):
        text = _LINKS.sub("[link removed]", text)
        issues.append("links removed")
    return ValidatedAnswer(True, text, issues)
