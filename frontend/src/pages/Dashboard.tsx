import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, InvestigationSummary } from "../api/client";

export default function Dashboard() {
  const [items, setItems] = useState<InvestigationSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.listInvestigations().then(setItems).catch((e) => setError(String(e.message ?? e)));
  }, []);

  return (
    <div className="p-8 max-w-5xl">
      <h1 className="text-xl font-semibold">Dashboard</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
        <Link to="/investigate" className="card hover:border-accent/50 transition-colors">
          <div className="text-accent text-sm font-mono mb-1">INVESTIGATE SOFTWARE</div>
          <div className="text-lg">“What is this software doing?”</div>
        </Link>
        <Link to="/secure" className="card hover:border-accent/50 transition-colors">
          <div className="text-accent text-sm font-mono mb-1">SECURE SOFTWARE</div>
          <div className="text-lg">“Is this software built securely?”</div>
        </Link>
      </div>

      <h2 className="text-sm font-medium text-muted mt-10 mb-3 uppercase tracking-wide">Recent investigations</h2>
      {error && <div className="card border-danger/40 text-danger text-sm">{error}</div>}
      {items === null && !error && <div className="text-muted text-sm">Loading…</div>}
      {items?.length === 0 && <div className="text-muted text-sm">No investigations yet.</div>}
      <div className="space-y-2">
        {items?.map((it) => (
          <Link key={it.id} to={`/investigations/${it.id}`} className="card flex items-center justify-between hover:border-accent/50">
            <div>
              <div className="font-mono text-sm">{String(it.artifact.filename ?? it.id.slice(0, 8))}</div>
              <div className="text-[11px] text-muted">{it.mode} · {new Date(it.created_at).toLocaleString()}</div>
            </div>
            <div className="text-[11px] text-muted font-mono">
              {it.counts.evidence} evidence · {it.counts.findings} findings · {it.counts.hypotheses} hypotheses
            </div>
          </Link>
        ))}
      </div>
    </div>
  );
}
