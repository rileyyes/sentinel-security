import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { api, ApiError, Investigation, Severity } from "../api/client";
import { KindBadge, SeverityBadge, ConfidenceLabel } from "../components/Badge";

const SEV_ORDER: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

type Tab = "hypotheses" | "findings" | "evidence" | "recommendations" | "timeline" | "ask";

export default function InvestigationDetail() {
  const { id } = useParams();
  const [inv, setInv] = useState<Investigation | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<Tab>("hypotheses");
  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState<{ ok: boolean; answer: string; issues: string[] } | null>(null);
  const [asking, setAsking] = useState(false);

  useEffect(() => {
    if (!id) return;
    api.getInvestigation(id).then(setInv).catch((e) => setError(e instanceof ApiError ? e.message : "Failed to load."));
  }, [id]);

  if (error) return <div className="p-8 text-danger">{error}</div>;
  if (!inv) return <div className="p-8 text-muted">Loading…</div>;

  const findings = inv.findings.filter((f) => severityFilter === "all" || f.severity === severityFilter)
    .sort((a, b) => SEV_ORDER[b.severity] - SEV_ORDER[a.severity]);

  async function ask() {
    if (!id || !question.trim()) return;
    setAsking(true);
    setAnswer(null);
    try { setAnswer(await api.ask(id, question)); }
    catch (e) { setAnswer({ ok: false, answer: e instanceof ApiError ? e.message : "Request failed.", issues: [] }); }
    finally { setAsking(false); }
  }

  const tabs: { key: Tab; label: string; count: number }[] = [
    { key: "hypotheses", label: "Hypotheses", count: inv.hypotheses.length },
    { key: "findings", label: "Findings", count: inv.findings.length },
    { key: "evidence", label: "Evidence", count: inv.evidence.length },
    { key: "recommendations", label: "Next steps", count: inv.recommendations.length },
    { key: "timeline", label: "Timeline", count: inv.timeline.length },
    { key: "ask", label: "Ask AI", count: 0 },
  ].filter((t) => t.count > 0 || t.key === "ask" || t.key === "timeline");

  return (
    <div className="p-8 max-w-4xl">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-xl font-semibold font-mono">{String(inv.artifact.filename ?? inv.id.slice(0, 8))}</h1>
          <div className="text-[11px] text-muted mt-1">
            {inv.mode === "software" ? "Software investigation" : "Secure-code scan"} ·{" "}
            {new Date(inv.created_at).toLocaleString()} · sha256 {String(inv.artifact.sha256).slice(0, 16)}…
          </div>
        </div>
        <div className="flex gap-2">
          <a className="btn-ghost" href={api.reportUrl(inv.id)} target="_blank" rel="noreferrer">Full report</a>
          <a className="btn-ghost" href={api.exportUrl(inv.id)}>Export</a>
        </div>
      </div>

      {(inv.warnings.length > 0 || inv.errors.length > 0) && (
        <div className="card mt-4 border-warn/30 text-sm">
          {inv.errors.map((e, i) => <div key={`e${i}`} className="text-danger">{e}</div>)}
          {inv.warnings.map((w, i) => <div key={`w${i}`} className="text-warn">{w}</div>)}
        </div>
      )}

      <div className="flex gap-1 mt-6 border-b border-base-600">
        {tabs.map((t) => (
          <button key={t.key} onClick={() => setTab(t.key)}
            className={`px-3 py-2 text-sm ${tab === t.key ? "border-b-2 border-accent text-accent" : "text-muted hover:text-slate-200"}`}>
            {t.label}{t.count > 0 ? ` (${t.count})` : ""}
          </button>
        ))}
      </div>

      <div className="mt-4 space-y-3">
        {tab === "hypotheses" && (inv.hypotheses.length === 0
          ? <Empty text="No correlated hypotheses were raised for this artifact." />
          : inv.hypotheses.map((h) => (
            <div key={h.id} className="card">
              <div className="flex items-center gap-2 mb-1">
                <KindBadge kind={h.kind} /><span className="font-medium">{h.id} · {h.title}</span>
                <ConfidenceLabel confidence={h.confidence} />
              </div>
              <p className="text-sm text-slate-300">{h.statement}</p>
              <Section title="Why this was raised" items={h.reasoning} />
              <div className="text-[11px] text-muted mt-1">Supporting evidence: {h.supporting_evidence.join(", ")}</div>
              <Section title="Benign explanations" items={h.benign_explanations} />
              <Section title="Limitations" items={h.limitations} muted />
            </div>
          )))}

        {tab === "findings" && (
          <>
            <div className="flex gap-2 mb-2">
              {(["all", "critical", "high", "medium", "low", "info"] as const).map((s) => (
                <button key={s} onClick={() => setSeverityFilter(s)}
                  className={`badge cursor-pointer ${severityFilter === s ? "border-accent text-accent" : "border-base-600 text-muted"}`}>
                  {s}
                </button>
              ))}
            </div>
            {findings.length === 0 ? <Empty text="No findings at this severity." /> : findings.map((f) => (
              <div key={f.id} className="card">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <KindBadge kind={f.kind} /><SeverityBadge severity={f.severity} />
                  <span className="font-medium">{f.id} · {f.category}</span>
                  <ConfidenceLabel confidence={f.confidence} />
                  <span className="text-[11px] text-muted font-mono ml-auto">{f.rule_id}</span>
                </div>
                <div className="font-mono text-xs text-muted">{f.file}{f.line ? `:${f.line}` : ""}</div>
                <pre className="text-xs bg-base-900 rounded p-2 mt-1 overflow-x-auto">{f.evidence}</pre>
                <p className="text-sm text-slate-300 mt-2">{f.explanation}</p>
                <p className="text-sm text-slate-400 mt-1"><span className="text-slate-300">Impact:</span> {f.impact}</p>
                <p className="text-sm text-slate-400 mt-1"><span className="text-slate-300">Remediation:</span> {f.remediation}</p>
                <Section title="Limitations" items={f.limitations} muted />
              </div>
            ))}
          </>
        )}

        {tab === "evidence" && inv.evidence.map((e) => (
          <div key={e.id} className="card">
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <KindBadge kind={e.kind} /><SeverityBadge severity={e.severity} />
              <span className="font-medium">{e.id} · {e.evidence_type}</span>
              <ConfidenceLabel confidence={e.confidence} />
              {e.untrusted_content && <span className="text-[11px] text-warn">contains artifact-derived text</span>}
            </div>
            <p className="text-sm text-slate-300">{e.description}</p>
            <pre className="text-xs bg-base-900 rounded p-2 mt-1 overflow-x-auto max-h-64">{JSON.stringify(e.data, null, 1)}</pre>
            <Section title="Limitations" items={e.limitations} muted />
          </div>
        ))}

        {tab === "recommendations" && inv.recommendations.map((r) => (
          <div key={r.id} className="card">
            <div className="flex items-center gap-2 mb-1"><KindBadge kind={r.kind} /><span className="font-medium">{r.id}</span></div>
            <p className="text-sm text-slate-300">{r.action}</p>
            <p className="text-[11px] text-muted mt-1">{r.rationale}</p>
          </div>
        ))}

        {tab === "timeline" && (
          <div className="card">
            {inv.timeline.map((t, i) => (
              <div key={i} className="text-xs font-mono text-muted py-0.5">
                {new Date(t.timestamp).toLocaleTimeString()} · {t.stage} · {t.message}
              </div>
            ))}
          </div>
        )}

        {tab === "ask" && (
          <div className="card">
            <p className="text-sm text-muted mb-2">Ask about this investigation's evidence. The assistant only
              describes what was collected — it cannot declare a verdict.</p>
            <div className="flex gap-2">
              <input className="flex-1 bg-base-900 border border-base-600 rounded px-3 py-2 text-sm"
                value={question} onChange={(e) => setQuestion(e.target.value)}
                placeholder="e.g. What does the network evidence suggest?"
                onKeyDown={(e) => e.key === "Enter" && ask()} />
              <button className="btn" onClick={ask} disabled={asking || !question.trim()}>{asking ? "Asking…" : "Ask"}</button>
            </div>
            {answer && (
              <div className={`mt-3 text-sm whitespace-pre-wrap ${answer.ok ? "text-slate-300" : "text-danger"}`}>
                {answer.answer}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function Section({ title, items, muted }: { title: string; items: string[]; muted?: boolean }) {
  if (items.length === 0) return null;
  return (
    <div className="mt-2">
      <div className={`text-[11px] font-medium ${muted ? "text-muted" : "text-slate-300"}`}>{title}</div>
      <ul className="text-[13px] text-muted list-disc list-inside">
        {items.map((it, i) => <li key={i}>{it}</li>)}
      </ul>
    </div>
  );
}

function Empty({ text }: { text: string }) {
  return <div className="text-sm text-muted italic">{text}</div>;
}
