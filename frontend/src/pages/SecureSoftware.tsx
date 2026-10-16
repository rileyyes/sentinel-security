import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, ApiError } from "../api/client";

export default function SecureSoftware() {
  const [file, setFile] = useState<File | null>(null);
  const [progress, setProgress] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const nav = useNavigate();

  async function submit() {
    if (!file) return;
    setError(null);
    setProgress(0);
    try {
      const inv = await api.createInvestigation("code", file, setProgress);
      nav(`/investigations/${inv.id}`);
    } catch (e) {
      setProgress(null);
      setError(e instanceof ApiError ? e.message : "Upload failed.");
    }
  }

  return (
    <div className="p-8 max-w-2xl">
      <h1 className="text-xl font-semibold">Secure Software</h1>
      <p className="text-sm text-muted mt-1">“Is this software built securely?” Upload a single
        .py file or a .zip of a Python project. Nothing is executed or imported.</p>

      <div
        className="mt-6 border-2 border-dashed border-base-600 rounded-lg p-10 text-center cursor-pointer hover:border-accent/50"
        onClick={() => inputRef.current?.click()}
        onDragOver={(e) => e.preventDefault()}
        onDrop={(e) => { e.preventDefault(); if (e.dataTransfer.files[0]) setFile(e.dataTransfer.files[0]); }}
      >
        <input ref={inputRef} type="file" accept=".py,.zip" className="hidden" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        {file ? (
          <div>
            <div className="font-mono text-sm">{file.name}</div>
            <div className="text-[11px] text-muted mt-1">{(file.size / 1024).toFixed(1)} KB — click to change</div>
          </div>
        ) : (
          <div className="text-muted text-sm">Drop a .py or .zip here, or click to browse.</div>
        )}
      </div>

      {progress !== null && (
        <div className="mt-4">
          <div className="h-1.5 bg-base-700 rounded overflow-hidden">
            <div className="h-full bg-accent transition-all" style={{ width: `${progress}%` }} />
          </div>
        </div>
      )}
      {error && <div className="mt-4 card border-danger/40 text-danger text-sm">{error}</div>}

      <button className="btn mt-6" disabled={!file || progress !== null} onClick={submit}>
        {progress !== null ? "Working…" : "Run scan"}
      </button>
    </div>
  );
}
