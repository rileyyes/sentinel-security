"""Turn code findings into prioritised remediation recommendations."""
from __future__ import annotations

from collections import defaultdict

from app.evidence.models import SEVERITY_ORDER, Finding, Recommendation

_PRIORITY_NOTES = {
    "Hardcoded secret": "Rotate the exposed credential first; removing it from code does not revoke it.",
    "Command injection": "Fix injectable command construction before other classes: it usually means remote code execution.",
    "Unsafe deserialization": "Replace the loader or restrict it to trusted, authenticated data.",
    "SQL injection": "Convert to parameterised queries; verify no other string-built SQL exists.",
    "Dangerous dynamic execution": "Remove eval/exec on non-constant data.",
}


def recommend_for_findings(findings: list[Finding]) -> list[Recommendation]:
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        grouped[f.category].append(f)
    ordered = sorted(grouped.items(), key=lambda kv: (-max(SEVERITY_ORDER[f.severity] for f in kv[1]), kv[0]))
    recs: list[Recommendation] = []
    for i, (category, items) in enumerate(ordered, 1):
        top = max(items, key=lambda f: SEVERITY_ORDER[f.severity])
        note = _PRIORITY_NOTES.get(category, "")
        recs.append(Recommendation(
            f"R-{i:02d}",
            f"{category}: {top.remediation} ({len(items)} finding(s))",
            note or "Address higher-severity, higher-confidence findings first and re-scan.",
            [f.id for f in items],
        ))
    if findings:
        recs.append(Recommendation(
            f"R-{len(recs) + 1:02d}",
            "Manually review each finding's data source; this scan cannot follow data across functions or files.",
            "Static analysis produces leads with stated confidence, not proofs of exploitability.",
            [],
        ))
    return recs
