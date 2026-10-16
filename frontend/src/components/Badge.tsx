export function KindBadge({ kind }: { kind: string }) {
  return <span className={`badge kind-${kind}`}>{kind}</span>;
}
export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge sev-${severity}`}>{severity.toUpperCase()}</span>;
}
export function ConfidenceLabel({ confidence }: { confidence: string | null }) {
  if (!confidence) return null;
  return <span className="text-[11px] text-muted">confidence: {confidence}</span>;
}
