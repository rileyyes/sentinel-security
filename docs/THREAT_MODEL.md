# Threat model

## Trust boundaries

1. **Browser ↔ API.** The browser is untrusted input (arbitrary requests, headers, payload sizes).
2. **API ↔ uploaded artifact/source.** The uploaded content is fully untrusted: it can be a hostile file crafted to exploit a parser, a decompression bomb, a path-traversal archive, or source code containing secrets or malicious constructs.
3. **API ↔ analysis worker.** The worker parses the untrusted artifact. It runs as a separate, resource-limited child process so a parser crash or resource exhaustion cannot take down the API.
4. **Investigation data ↔ AI provider.** Structured evidence (which may embed attacker-chosen strings) is sent to an LLM. The LLM's output is untrusted until validated.
5. **API ↔ storage.** Investigation IDs and file paths are server-generated and validated on every read; nothing derived from user input is used to build a filesystem path.

## STRIDE-style walk-through (selected)

| Threat | Where | Mitigation |
|---|---|---|
| Spoofing | Investigation ID guessing | 128-bit random hex IDs; add auth before multi-tenant deployment (documented gap) |
| Tampering | Zip-slip, symlink members | `safe_extract_zip` rejects `..`, absolute paths, symlinks; writes with `O_EXCL` |
| Tampering | Log injection via filenames | `core/logging.py` strips control characters, allow-lists fields |
| Repudiation | No audit trail | Structured JSON security log (`core/logging.py`) + investigation timeline |
| Info. disclosure | Secrets in code | Detected and redacted (`analyzers/code/secrets.py`); never logged in full |
| Info. disclosure | Verbose error leaking internals | API catches broad exceptions, returns generic messages (`api/routes.py`) |
| DoS | Decompression bomb / zip bomb | File-count, uncompressed-size, per-member-size and compression-ratio caps |
| DoS | Malformed PE causing infinite loop | Every parser loop has a hard iteration cap (`MAX_SECTIONS`, `MAX_IMPORT_DLLS`, ...) |
| DoS | CPU/memory exhaustion in worker | POSIX rlimits + wall-clock timeout in `core/sandbox.py` |
| Elevation of privilege | Executing the uploaded artifact | Never executed; only parsed. Container runs as non-root with dropped capabilities |
| Prompt injection | Strings/comments instructing the LLM | Untrusted data wrapped in an escaped block; system prompt states it is inert; output validated for verdicts/unknown citations |

## Known limitations (explicit, not hidden)

* No authentication/authorization layer yet — required before multi-user or public deployment (Stage 8 gap, flagged to the user).
* The custom PE parser (built because the sandbox had no package access) covers headers, sections, imports, exports and overlay only — no resources, certificates, delay-load imports, or .NET metadata; cross-checking with `pefile` is recommended before relying on it further.
* The Python scanner does intra-function taint tracking only; it cannot follow data across function or file boundaries, so both false negatives and false positives are expected.
* rlimits are a defence-in-depth layer, not a full sandbox; container isolation is the real boundary and must be present in any real deployment.
* No dynamic/behavioural analysis is performed or planned inside this tool — this is a static-analysis platform.
