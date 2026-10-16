from __future__ import annotations

from functools import lru_cache

from app.ai.provider import LLMProvider, StubProvider
from app.core.config import Settings
from app.storage.store import InvestigationStore


@lru_cache
def get_settings() -> Settings:
    return Settings.from_env()


@lru_cache
def get_store() -> InvestigationStore:
    return InvestigationStore(get_settings())


def get_llm_provider() -> LLMProvider:
    import os

    if os.environ.get("ANTHROPIC_API_KEY"):
        from app.ai.provider import AnthropicProvider

        try:
            return AnthropicProvider()
        except Exception:  # noqa: BLE001 - fall back rather than break the endpoint
            pass
    return StubProvider("No AI provider is configured in this environment. "
                        "Set ANTHROPIC_API_KEY to enable AI explanations.")
