"""The shared evidence model.

Every claim the system makes is one of four kinds:

FACT            - a measured/observed property (a hash, a size, an entropy value)
EVIDENCE        - an observation that *may* indicate something (an imported API,
                  a URL string). It is not a conclusion.
INFERENCE       - a hypothesis or finding derived by deterministic rules from
                  evidence, always with reasoning and limitations.
RECOMMENDATION  - a suggested human next step.

No analyzer may declare a file malicious; only a human investigator decides.
Plain dataclasses keep the security-critical core free of framework code;
Pydantic is used only at the API boundary.
"""
from __future__ import annotations

import enum
import re
import uuid
from dataclasses import dataclass, field, fields, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
INVESTIGATION_ID_RE = re.compile(r"^[0-9a-f]{32}$")


class Kind(str, enum.Enum):
    FACT = "FACT"
    EVIDENCE = "EVIDENCE"
    INFERENCE = "INFERENCE"
    RECOMMENDATION = "RECOMMENDATION"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


SEVERITY_ORDER = {s: i for i, s in enumerate(Severity)}


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Evidence:
    id: str
    analyzer: str
    evidence_type: str
    description: str
    data: dict[str, Any]
    kind: Kind = Kind.FACT
    severity: Severity = Severity.INFO
    confidence: Confidence | None = None
    location: str | None = None
    limitations: list[str] = field(default_factory=list)
    # True when `data` embeds text taken from the artifact (strings, names).
    # Such text is attacker-controlled and must never be treated as instructions.
    untrusted_content: bool = False


@dataclass
class Finding:
    id: str
    rule_id: str
    category: str
    severity: Severity
    file: str
    line: int | None
    evidence: str
    explanation: str
    impact: str
    remediation: str
    confidence: Confidence
    limitations: list[str]
    kind: Kind = Kind.INFERENCE


@dataclass
class Hypothesis:
    id: str
    title: str
    statement: str
    reasoning: list[str]
    supporting_evidence: list[str]
    confidence: Confidence
    benign_explanations: list[str]
    limitations: list[str]
    kind: Kind = Kind.INFERENCE


@dataclass
class Recommendation:
    id: str
    action: str
    rationale: str
    related: list[str]
    kind: Kind = Kind.RECOMMENDATION


@dataclass
class TimelineEvent:
    timestamp: str
    stage: str
    message: str


@dataclass
class AnalyzerResult:
    analyzer: str
    status: str  # "ok" | "error" | "skipped"
    evidence_ids: list[str] = field(default_factory=list)
    error: str | None = None


@dataclass
class Investigation:
    id: str
    mode: str  # "software" | "code"
    created_at: str
    artifact: dict[str, Any]
    analyzer_results: list[AnalyzerResult] = field(default_factory=list)
    evidence: list[Evidence] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    recommendations: list[Recommendation] = field(default_factory=list)
    timeline: list[TimelineEvent] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    @staticmethod
    def new(mode: str, artifact: dict[str, Any] | None = None) -> "Investigation":
        return Investigation(
            id=uuid.uuid4().hex, mode=mode, created_at=utc_now(), artifact=artifact or {}
        )

    def log(self, stage: str, message: str) -> None:
        self.timeline.append(TimelineEvent(utc_now(), stage, message))

    def to_dict(self) -> dict[str, Any]:
        return to_plain(self)

    @staticmethod
    def from_dict(raw: dict[str, Any]) -> "Investigation":
        """Rebuild and validate an investigation from untrusted JSON."""
        if not isinstance(raw, dict):
            raise ValueError("investigation must be an object")
        if raw.get("schema_version") != SCHEMA_VERSION:
            raise ValueError("unsupported schema_version")
        inv_id = raw.get("id")
        if not isinstance(inv_id, str) or not INVESTIGATION_ID_RE.match(inv_id):
            raise ValueError("invalid investigation id")
        if raw.get("mode") not in ("software", "code"):
            raise ValueError("invalid mode")
        try:
            return Investigation(
                id=inv_id,
                mode=raw["mode"],
                created_at=str(raw["created_at"]),
                artifact=dict(raw.get("artifact", {})),
                analyzer_results=[_build(AnalyzerResult, r) for r in raw.get("analyzer_results", [])],
                evidence=[_build(Evidence, r) for r in raw.get("evidence", [])],
                findings=[_build(Finding, r) for r in raw.get("findings", [])],
                hypotheses=[_build(Hypothesis, r) for r in raw.get("hypotheses", [])],
                recommendations=[_build(Recommendation, r) for r in raw.get("recommendations", [])],
                timeline=[_build(TimelineEvent, r) for r in raw.get("timeline", [])],
                warnings=[str(w) for w in raw.get("warnings", [])],
                errors=[str(e) for e in raw.get("errors", [])],
            )
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError("malformed investigation data") from exc


_ENUM_FIELDS = {"kind": Kind, "severity": Severity, "confidence": Confidence}


def _build(cls: type, raw: dict[str, Any]) -> Any:
    if not isinstance(raw, dict):
        raise TypeError("expected object")
    known = {f.name for f in fields(cls)}
    kwargs = {k: v for k, v in raw.items() if k in known}
    for name, enum_cls in _ENUM_FIELDS.items():
        if name in kwargs and kwargs[name] is not None:
            kwargs[name] = enum_cls(kwargs[name])  # ValueError on bad value
    return cls(**kwargs)


def to_plain(obj: Any) -> Any:
    if is_dataclass(obj) and not isinstance(obj, type):
        return {f.name: to_plain(getattr(obj, f.name)) for f in fields(obj)}
    if isinstance(obj, enum.Enum):
        return obj.value
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, (list, tuple)):
        return [to_plain(x) for x in obj]
    if isinstance(obj, dict):
        return {str(k): to_plain(v) for k, v in obj.items()}
    return obj


class EvidenceCollector:
    """Assigns stable ids (E-001, E-002...) so later stages can cite evidence."""

    def __init__(self) -> None:
        self.items: list[Evidence] = []

    def add(
        self,
        analyzer: str,
        evidence_type: str,
        description: str,
        data: dict[str, Any],
        *,
        kind: Kind = Kind.FACT,
        severity: Severity = Severity.INFO,
        confidence: Confidence | None = None,
        location: str | None = None,
        limitations: list[str] | None = None,
        untrusted_content: bool = False,
    ) -> Evidence:
        item = Evidence(
            id=f"E-{len(self.items) + 1:03d}",
            analyzer=analyzer,
            evidence_type=evidence_type,
            description=description,
            data=data,
            kind=kind,
            severity=severity,
            confidence=confidence,
            location=location,
            limitations=limitations or [],
            untrusted_content=untrusted_content,
        )
        self.items.append(item)
        return item
