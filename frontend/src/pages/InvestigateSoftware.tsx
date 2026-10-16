import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, ApiError } from "../api/client";

export default function InvestigateSoftware() {
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [stage, setStage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const nav = useNavigate();

  async function submit() {
    if (!file) return;
    setError(null);
    setProgress(0);
    setStage("Uploading…");
    try {
      const inv = await api.createInvestigation("software", file, (p) => {
        setProgress(p);
        if (p >= 100) setStage("Validating and analysing…");
      });
      nav(`/investigations/${inv.id}`);
    } catch (e) {
      setStage(null);
      setProgress(null);
      setError(e instanceof ApiError ? e.message : "Upload failed.");
    }
  }

  return (
    <div className="p-8 max-w-2xl">
      <h1 className="text-xl font-semibold">Investigate Software</h1>
      <p className="text-sm text-muted mt-1">“What is this software doing?” Upload a Windows PE file
        (EXE, DLL, SYS). It is never executed — only statically analysed.</p>

      <div
        className="mt-6 border-2 border-dashed border-base-600 rounded-lg p-10 text-center cursor-pointer hover:border-accent/50"
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => { e.preventDefault(); if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]); }}
      >
        <input ref={inputRef} type="file" className="hidden" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        {file ? (
          <div>
            <div className="font-mono text-sm">{file.name}</div>
            <div className="text-[11px] text-muted mt-1">{(file.size / 1024).toFixed(1)} KB — click to change</div>
          </div>
        ) : (
          <div className="text-muted text-sm">Drop a file here, or click to browse. Max 25 MB.</div>
        )}
      </div>

      {progress !== null && (
        <div className="mt-4">
          <div className="h-1.5 bg-base-700 rounded overflow-hidden">
            <div className="h-full bg-accent transition-all" style={{ width: `${progress}%` }} />
          </div>
          <div className="text-[11px] text-muted mt-1">{stage}</div>
        </div>
      )}
      {error && <div className="mt-4 card border-danger/40 text-danger text-sm">{error}</div>}

      <button className="btn mt-6" disabled={!file || progress !== null} onClick={submit}>
        {progress !== null ? "Working…" : "Run investigation"}
      </button>
    </div>
  );
}
