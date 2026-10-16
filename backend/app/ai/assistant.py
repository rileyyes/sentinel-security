from __future__ import annotations

from app.ai.prompt import build_messages, known_ids
from app.ai.provider import LLMProvider
from app.ai.validate import REFUSAL, ValidatedAnswer, validate_answer
from app.core.logging import log_event
from app.evidence.models import Investigation


def ask(inv: Investigation, question: str, provider: LLMProvider) -> ValidatedAnswer:
    system, user = build_messages(inv, question)
    try:
        raw = provider.complete(system, user)
    except Exception as exc:  # noqa: BLE001 - never leak provider errors/keys to the client
        log_event("llm_error", kind=type(exc).__name__)
        return ValidatedAnswer(False, "The AI assistant is currently unavailable.", ["provider error"])
    result = validate_answer(raw, known_ids(inv))
    if not result.ok:
        log_event("llm_output_rejected", reason=result.issues[0] if result.issues else "unknown")
    return result


__all__ = ["ask", "REFUSAL"]
