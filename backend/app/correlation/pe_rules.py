"""Deterministic correlation: evidence -> hypotheses -> recommended next steps.

Each rule looks for a *combination* of evidence, states an INFERENCE with the
reasoning that produced it, lists benign explanations, and names limitations.
A hypothesis is a lead for a human investigator, never a verdict.
"""
from __future__ import annotations

from app.evidence.models import Confidence, Evidence, Hypothesis, Recommendation


def _apis(evidence: list[Evidence]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for e in evidence:
        if e.evidence_type == "suspicious_api_category":
            out[e.data["category"]] = {a["api"] for a in e.data["apis"]}
    return out


def _ids(evidence: list[Evidence], *types: str, category: str | None = None) -> list[str]:
    return [
        e.id for e in evidence
        if e.evidence_type in types and (category is None or e.data.get("category") == category)
    ]


def _strings(evidence: list[Evidence], cat: str) -> list[str]:
    for e in evidence:
        if e.evidence_type == "notable_strings":
            return list(e.data["categories"].get(cat, []))
    return []


def correlate_pe(evidence: list[Evidence]) -> tuple[list[Hypothesis], list[Recommendation]]:
    apis = _apis(evidence)
    hyps: list[Hypothesis] = []
    counter = iter(range(1, 100))

    def add(title, statement, reasoning, ids, conf, benign, limits) -> Hypothesis:
        h = Hypothesis(f"H-{next(counter):02d}", title, statement, reasoning, ids, conf, benign, limits)
        hyps.append(h)
        return h

    inj = apis.get("process_injection", set())
    if len(inj) >= 2:
        classic = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"} <= inj
        add(
            "Possible process-injection capability",
            "The binary imports several APIs that, together, allow writing code into another process and running it.",
            [f"Imported injection-related APIs: {', '.join(sorted(inj))}.",
             "These APIs are typically used together in the allocate → write → execute-remotely pattern."],
            _ids(evidence, "suspicious_api_category", category="process_injection"),
            Confidence.MEDIUM if classic else Confidence.LOW,
            ["Debuggers, profilers, accessibility tools, game overlays and security software use the same APIs."],
            ["Imports show capability, not execution. Dynamic resolution could hide additional APIs."],
        )

    packed_ev = _ids(evidence, "high_entropy_section", "rwx_section", "nonstandard_section_name",
                     "few_imports", "empty_executable_section")
    resolver = "dynamic_api_resolution" in apis
    if len(packed_ev) >= 2 or (packed_ev and resolver):
        ids = packed_ev + _ids(evidence, "suspicious_api_category", category="dynamic_api_resolution")
        add(
            "Possible packing or obfuscation",
            "Structural signs are consistent with a packed or self-modifying executable whose real code is unpacked at runtime.",
            [f"{len(packed_ev)} structural indicator(s) present (entropy, RWX/non-standard/empty sections, minimal imports).",
             "Runtime API resolution (LoadLibrary/GetProcAddress) is present." if resolver
             else "No runtime API resolution imports were seen."],
            ids, Confidence.MEDIUM if len(packed_ev) >= 3 else Confidence.LOW,
            ["Commercial packers, installers, DRM and legitimately compressed resources look similar."],
            ["Static analysis cannot see unpacked code; the true behaviour may differ substantially."],
        )

    urls, ips = _strings(evidence, "urls"), _strings(evidence, "ip_addresses")
    if ("network" in apis) and (urls or ips) and "process_execution" in apis:
        add(
            "Possible download-and-execute behaviour",
            "The binary has network APIs, embedded network locations and the ability to start processes.",
            [f"Network APIs: {', '.join(sorted(apis['network']))}.",
             f"{len(urls)} URL-like and {len(ips)} IP-like string(s) found.",
             f"Process-launch APIs: {', '.join(sorted(apis['process_execution']))}."],
            _ids(evidence, "suspicious_api_category", category="network")
            + _ids(evidence, "suspicious_api_category", category="process_execution")
            + _ids(evidence, "notable_strings"),
            Confidence.LOW,
            ["Updaters, installers and launchers legitimately download and run programs."],
            ["Strings may be unused or decoys; the URL may be unrelated to the network code."],
        )

    reg = _strings(evidence, "registry_keys")
    if ("persistence" in apis) and (reg or "CreateService" in apis["persistence"]):
        add(
            "Possible persistence mechanism",
            "The binary can modify the registry or install services, and references autorun-style locations.",
            [f"Persistence-related APIs: {', '.join(sorted(apis['persistence']))}.",
             f"{len(reg)} registry-path string(s) found."],
            _ids(evidence, "suspicious_api_category", category="persistence") + _ids(evidence, "notable_strings"),
            Confidence.LOW,
            ["Installers and update agents register services and Run keys as normal behaviour."],
            ["No proof the registry code is reachable or writes those keys."],
        )

    if "anti_analysis" in apis and len(apis["anti_analysis"]) >= 2:
        add(
            "Possible anti-analysis / debugger detection",
            "The binary references several APIs used to detect a debugger.",
            [f"Anti-analysis APIs: {', '.join(sorted(apis['anti_analysis']))}."],
            _ids(evidence, "suspicious_api_category", category="anti_analysis"),
            Confidence.LOW,
            ["Copy-protection, anti-cheat and some runtimes use debugger checks."],
            ["A single check cannot show intent to evade analysis."],
        )

    if "input_capture" in apis:
        add(
            "Possible input-capture capability",
            "The binary references hooks or key-state APIs that can observe keyboard input.",
            [f"Input-capture APIs: {', '.join(sorted(apis['input_capture']))}."],
            _ids(evidence, "suspicious_api_category", category="input_capture"),
            Confidence.LOW,
            ["Games, accessibility tools, hotkey utilities and remote-control software use them."],
            ["Capability only; no evidence of what is done with the input."],
        )
    return hyps, _recommend_pe(evidence, hyps)


def _recommend_pe(evidence: list[Evidence], hyps: list[Hypothesis]) -> list[Recommendation]:
    recs: list[Recommendation] = []
    n = iter(range(1, 100))

    def rec(action: str, why: str, related: list[str]) -> None:
        recs.append(Recommendation(f"R-{next(n):02d}", action, why, related))

    hash_ids = _ids(evidence, "hash")
    rec("Look up the SHA-256 in trusted reputation sources (e.g. VirusTotal, internal threat intel) and check for a valid code signature.",
        "Existing knowledge about this exact file is the cheapest and fastest signal.", hash_ids)
    for h in hyps:
        if h.title.startswith("Possible packing"):
            rec("Identify the packer (section names, entry-point stub) and unpack it in an isolated analysis VM before drawing conclusions.",
                "Static data from a packed file mostly describes the packer, not the payload.", [h.id])
        elif h.title.startswith("Possible process-injection"):
            rec("Disassemble the call sites of the injection APIs in a disassembler (Ghidra/IDA) to see targets and payload source.",
                "Cross-references show whether the APIs are actually used and against what.", [h.id])
        elif h.title.startswith("Possible download"):
            rec("Review the embedded URLs/IPs in context and check them against blocklists WITHOUT visiting them from an unprotected host.",
                "Network indicators can be verified safely through reputation services.", [h.id])
        elif h.title.startswith("Possible persistence"):
            rec("Inspect the registry-path strings and service names referenced by the binary, and check whether the file was installed by a known product.",
                "Legitimate installers share this behaviour; provenance separates them.", [h.id])
        elif h.title.startswith("Possible anti-analysis"):
            rec("Note that dynamic analysis may be detected; use a hardened VM and a debugger that hides itself, if dynamic work is needed.",
                "Debugger checks change how safely the sample can be observed.", [h.id])
    rec("If deeper behavioural insight is required, perform dynamic analysis ONLY in an isolated, disposable environment outside this tool.",
        "This platform never executes artifacts; dynamic analysis is a separate human decision.", [])
    return recs
