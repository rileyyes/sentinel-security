export type Kind = "FACT" | "EVIDENCE" | "INFERENCE" | "RECOMMENDATION";
export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";

export interface Evidence {
  id: string; analyzer: string; evidence_type: string; description: string;
  data: Record<string, unknown>; kind: Kind; severity: Severity;
  confidence: Confidence | null; location: string | null; limitations: string[];
  untrusted_content: boolean;
}
export interface Finding {
  id: string; rule_id: string; category: string; severity: Severity; file: string;
  line: number | null; evidence: string; explanation: string; impact: string;
  remediation: string; confidence: Confidence; limitations: string[]; kind: Kind;
}
export interface Hypothesis {
  id: string; title: string; statement: string; reasoning: string[];
  supporting_evidence: string[]; confidence: Confidence; benign_explanations: string[];
  limitations: string[]; kind: Kind;
}
export interface Recommendation { id: string; action: string; rationale: string; related: string[]; kind: Kind; }
export interface TimelineEvent { timestamp: string; stage: string; message: string; }
export interface AnalyzerResult { analyzer: string; status: string; evidence_ids: string[]; error: string | null; }
export interface Investigation {
  id: string; mode: "software" | "code"; created_at: string; artifact: Record<string, unknown>;
  analyzer_results: AnalyzerResult[]; evidence: Evidence[]; findings: Finding[];
  hypotheses: Hypothesis[]; recommendations: Recommendation[]; timeline: TimelineEvent[];
  warnings: string[]; errors: string[];
}
export interface InvestigationSummary {
  id: string; mode: string; created_at: string; artifact: Record<string, unknown>;
  counts: { evidence: number; findings: number; hypotheses: number; recommendations: number };
}

const BASE = "/api";

class ApiError extends Error {
  constructor(public code: string, message: string, public status: number) { super(message); }
}

async function handle<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let body: { code?: string; message?: string } = {};
    try { body = await res.json(); } catch { /* ignore */ }
    throw new ApiError(body.code ?? "error", body.message ?? res.statusText, res.status);
  }
  return res.status === 204 ? (undefined as T) : res.json();
}

export const api = {
  health: () => fetch(`${BASE}/health`).then((r) => handle<{ status: string }>(r)),

  listInvestigations: () => fetch(`${BASE}/investigations`).then((r) => handle<InvestigationSummary[]>(r)),

  getInvestigation: (id: string) => fetch(`${BASE}/investigations/${id}`).then((r) => handle<Investigation>(r)),

  createInvestigation: (mode: "software" | "code", file: File, onProgress?: (pct: number) => void) => {
    return new Promise<Investigation>((resolve, reject) => {
      const form = new FormData();
      form.append("file", file);
      const xhr = new XMLHttpRequest();
      xhr.open("POST", `${BASE}/investigations/${mode}`);
      xhr.upload.onprogress = (e) => { if (e.lengthComputable && onProgress) onProgress(Math.round((e.loaded / e.total) * 100)); };
      xhr.onload = () => {
        try {
          const body = JSON.parse(xhr.responseText);
          if (xhr.status >= 200 && xhr.status < 300) resolve(body);
          else reject(new ApiError(body.code ?? "error", body.message ?? "Upload failed", xhr.status));
        } catch { reject(new ApiError("parse_error", "Could not parse server response", xhr.status)); }
      };
      xhr.onerror = () => reject(new ApiError("network_error", "Network error during upload", 0));
      xhr.send(form);
    });
  },

  deleteInvestigation: (id: string) => fetch(`${BASE}/investigations/${id}`, { method: "DELETE" }).then((r) => handle<void>(r)),

  exportUrl: (id: string) => `${BASE}/investigations/${id}/export`,
  reportUrl: (id: string) => `${BASE}/investigations/${id}/report.html`,

  ask: (id: string, question: string) =>
    fetch(`${BASE}/investigations/${id}/ask`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question }),
    }).then((r) => handle<{ ok: boolean; answer: string; issues: string[] }>(r)),
};

export { ApiError };
