"""LLM providers. The model can only receive text and return text: no tools,
no code execution, no file access."""
from __future__ import annotations

import os
from typing import Protocol


class LLMProvider(Protocol):
    def complete(self, system: str, user: str) -> str: ...


class StubProvider:
    """Deterministic provider for tests and offline demos."""

    def __init__(self, reply: str = "No model configured."):
        self.reply, self.last_system, self.last_user = reply, "", ""

    def complete(self, system: str, user: str) -> str:
        self.last_system, self.last_user = system, user
        return self.reply


class AnthropicProvider:
    """Uses the Anthropic SDK. NOTE: not exercised by tests in this repo's build
    environment (no SDK/network there); verify with a real key before relying on it."""

    def __init__(self, model: str | None = None):
        import anthropic  # lazy: keeps the SDK optional

        key = os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise RuntimeError("ANTHROPIC_API_KEY is not set")
        self._client = anthropic.Anthropic(api_key=key, timeout=30.0, max_retries=1)
        self._model = model or os.environ.get("SENTINEL_LLM_MODEL", "claude-sonnet-5")

    def complete(self, system: str, user: str) -> str:
        msg = self._client.messages.create(
            model=self._model, max_tokens=800, system=system,
            messages=[{"role": "user", "content": user}],
        )
        return "".join(b.text for b in msg.content if getattr(b, "type", "") == "text")
