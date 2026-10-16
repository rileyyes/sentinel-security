"""Self-contained HTML report.

Everything derived from an artifact is HTML-escaped. The document ships a
restrictive CSP meta tag (no scripts, no network) and the API additionally
serves it with a CSP header + sandbox, so even a missed escape cannot run code.
"""
from __future__ import annotations

import json
from html import escape as e
from typing import Any

from app.evidence.models import SEVERITY_ORDER, Investigation

_CSS = """
body{font:14px/1.5 system-ui,sans-serif;margin:0;background:#0f1419;color:#d7dde4}
main{max-width:960px;margin:0 auto;padding:24px}h1{font-size:22px}h2{font-size:16px;border-bottom:1px solid #2a3440;padding-bottom:4px;margin-top:28px}
.card{background:#171e26;border:1px solid #2a3440;border-radius:6px;padding:10px 12px;margin:8px 0}
.tag{display:inline-block;font:11px monospace;padding:1px 6px;border-radius:3px;background:#243040;margin-right:6px}
.FACT{background:#1d3b2f}.EVIDENCE{background:#3b3a1d}.INFERENCE{background:#1d2f3b}.RECOMMENDATION{background:#33234a}
.sev-high,.sev-critical{color:#ff7b72}.sev-medium{color:#e3b341}.sev-low{color:#79c0ff}.sev-info{color:#8b949e}
code,pre{font:12px monospace;background:#0b0f13;padding:2px 4px;border-radius:3px;white-space:pre-wrap;word-break:break-word}
.note{color:#8b949e;font-size:12px}
"""
_CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"


def _tag(kind: str) -> str:
    return f'<span class="tag {e(kind)}">{e(kind)}</span>'


def _list(items: list[str]) -> str:
    return "<ul>" + "".join(f"<li>{e(str(i))}</li>" for i in items) + "</ul>" if items else ""


def render_html(inv: Investigation) -> str:
    a = inv.artifact
    out: list[str] = [
        f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
        f'<meta http-equiv="Content-Security-Policy" content="{_CSP}">'
        f"<title>Investigation {e(inv.id[:8])}</title><style>{_CSS}</style></head><body><main>",
        f"<h1>Investigation report — {'Software analysis' if inv.mode == 'software' else 'Secure-code scan'}</h1>",
        f'<p class="note">ID {e(inv.id)} · created {e(inv.created_at)}. This report presents evidence and '
        "inferences. It does <b>not</b> determine whether the software is malicious or secure; that decision "
        "belongs to the human investigator.</p>",
        "<h2>Artifact</h2><div class='card'>"
        + "".join(f"<div><b>{e(str(k))}</b>: <code>{e(str(v))}</code></div>" for k, v in a.items())
        + "</div>",
    ]
    if inv.hypotheses:
        out.append("<h2>Hypotheses</h2>")
        for h in inv.hypotheses:
            out.append(
                f"<div class='card'>{_tag(h.kind.value)}<b>{e(h.id)} · {e(h.title)}</b> "
                f"<span class='note'>confidence: {e(h.confidence.value)}</span><p>{e(h.statement)}</p>"
                f"<b>Why this was raised</b>{_list(h.reasoning)}"
                f"<div class='note'>Supporting evidence: {e(', '.join(h.supporting_evidence))}</div>"
                f"<b>Benign explanations</b>{_list(h.benign_explanations)}"
                f"<b>Limitations</b>{_list(h.limitations)}</div>"
            )
    if inv.findings:
        out.append(f"<h2>Findings ({len(inv.findings)})</h2>")
        for f in inv.findings:
            out.append(
                f"<div class='card'>{_tag(f.kind.value)}<b>{e(f.id)} · {e(f.category)}</b> "
                f"<span class='sev-{e(f.severity.value)}'>{e(f.severity.value.upper())}</span> "
                f"<span class='note'>confidence: {e(f.confidence.value)} · rule {e(f.rule_id)}</span>"
                f"<div><code>{e(f.file)}:{e(str(f.line))}</code></div><pre>{e(f.evidence)}</pre>"
                f"<p>{e(f.explanation)}</p><p><b>Impact:</b> {e(f.impact)}</p>"
                f"<p><b>Remediation:</b> {e(f.remediation)}</p><b>Limitations</b>{_list(f.limitations)}</div>"
            )
    if inv.evidence:
        out.append(f"<h2>Evidence ({len(inv.evidence)})</h2>")
        for ev in sorted(inv.evidence, key=lambda x: (-SEVERITY_ORDER[x.severity], x.id)):
            conf = f" · confidence {e(ev.confidence.value)}" if ev.confidence else ""
            warn = " · <b>contains artifact-controlled text</b>" if ev.untrusted_content else ""
            data = json.dumps(ev.data, indent=1, ensure_ascii=True)[:4000]
            out.append(
                f"<div class='card'>{_tag(ev.kind.value)}<b>{e(ev.id)} · {e(ev.evidence_type)}</b> "
                f"<span class='sev-{e(ev.severity.value)}'>{e(ev.severity.value)}</span>"
                f"<span class='note'>{conf}{warn}</span><p>{e(ev.description)}</p>"
                f"<pre>{e(data)}</pre>{_list(ev.limitations)}</div>"
            )
    if inv.recommendations:
        out.append("<h2>Recommended next steps</h2>")
        for r in inv.recommendations:
            out.append(
                f"<div class='card'>{_tag(r.kind.value)}<b>{e(r.id)}</b> {e(r.action)}"
                f"<div class='note'>{e(r.rationale)}</div></div>"
            )
    out.append("<h2>Timeline</h2><div class='card'>" + "".join(
        f"<div class='note'>{e(t.timestamp)} · {e(t.stage)} · {e(t.message)}</div>" for t in inv.timeline) + "</div>")
    if inv.warnings or inv.errors:
        out.append("<h2>Warnings and errors</h2>" + _list(inv.warnings + inv.errors))
    out.append("</main></body></html>")
    return "".join(out)


def render_json(inv: Investigation) -> str:
    return json.dumps(inv.to_dict(), indent=2, ensure_ascii=True)


def csp_header() -> dict[str, Any]:
    return {"Content-Security-Policy": _CSP + "; sandbox", "X-Content-Type-Options": "nosniff"}
