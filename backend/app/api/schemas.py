"""Pydantic models at the API boundary only. Internal logic uses plain dataclasses."""
from __future__ import annotations

from pydantic import BaseModel, Field


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)


class AskResponse(BaseModel):
    ok: bool
    answer: str
    issues: list[str] = []


class ErrorResponse(BaseModel):
    code: str
    message: str


class InvestigationSummary(BaseModel):
    id: str
    mode: str
    created_at: str
    artifact: dict
    counts: dict
