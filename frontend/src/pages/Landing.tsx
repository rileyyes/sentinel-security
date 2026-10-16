import { Link } from "react-router-dom";

export default function Landing() {
  return (
    <div className="min-h-screen bg-base-900 text-slate-200 flex flex-col">
      <header className="px-8 py-6 flex items-center justify-between border-b border-base-600">
        <div className="font-mono text-accent">SENTINEL</div>
        <Link to="/dashboard" className="btn">Open workbench</Link>
      </header>
      <section className="flex-1 flex flex-col items-center justify-center text-center px-6 py-24">
        <h1 className="text-4xl font-semibold max-w-2xl leading-tight">
          A security investigation workbench, not a verdict machine.
        </h1>
        <p className="mt-4 max-w-xl text-muted">
          Sentinel turns raw artifacts and source code into structured evidence, deterministic
          findings, and investigation leads — and leaves the decision to you.
        </p>
        <div className="mt-8 flex gap-4">
          <Link to="/investigate" className="btn">Investigate Software</Link>
          <Link to="/secure" className="btn-ghost">Secure Software</Link>
        </div>
      </section>
      <section className="grid grid-cols-1 md:grid-cols-2 gap-6 px-8 pb-16 max-w-4xl mx-auto w-full">
        <div className="card">
          <h2 className="font-medium text-slate-100">Investigate Software</h2>
          <p className="text-sm text-muted mt-2">“What is this software doing?” — static analysis of
            Windows PE files: hashes, entropy, headers, sections, imports/exports, suspicious APIs,
            and correlated investigation hypotheses with reasoning and benign explanations.</p>
        </div>
        <div className="card">
          <h2 className="font-medium text-slate-100">Secure Software</h2>
          <p className="text-sm text-muted mt-2">“Is this software built securely?” — deterministic
            AST-based scanning of Python source for injection, unsafe deserialization, weak crypto,
            hardcoded secrets and more, each with severity, evidence, and remediation.</p>
        </div>
      </section>
    </div>
  );
}
