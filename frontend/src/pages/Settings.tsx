export default function Settings() {
  return (
    <div className="p-8 max-w-2xl">
      <h1 className="text-xl font-semibold mb-4">Settings</h1>
      <div className="card space-y-3 text-sm">
        <div><span className="text-muted">AI provider:</span> configured via <code className="font-mono">ANTHROPIC_API_KEY</code> on the backend.</div>
        <div><span className="text-muted">Retention:</span> investigations are kept for <code className="font-mono">SENTINEL_RETENTION_DAYS</code> (default 30) before cleanup.</div>
        <div><span className="text-muted">Storage:</span> local JSON files under the server's data directory — no database.</div>
      </div>
    </div>
  );
}
