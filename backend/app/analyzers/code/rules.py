"""Rule catalogue: the human-readable text for each finding.

Keeping the prose out of the scanner logic makes rules reviewable and lets the
AI layer explain findings from *our* wording rather than inventing its own.
"""
from __future__ import annotations

RULES: dict[str, dict[str, object]] = {
    "PY-EXEC-001": {
        "category": "Dangerous dynamic execution",
        "explanation": "eval()/exec() runs a string as Python code.",
        "impact": "If attacker-influenced data reaches the call, the attacker can run arbitrary code with the application's privileges.",
        "remediation": "Avoid eval/exec. Use ast.literal_eval for literals, a dispatch table for behaviours, or a purpose-built parser.",
        "limitations": ["Static analysis cannot prove the argument is attacker-controlled; check where the value originates."],
    },
    "PY-CMD-001": {
        "category": "Command injection",
        "explanation": "A shell command is built from non-constant data (or shell=True is used with dynamic input).",
        "impact": "Shell metacharacters in the data can append attacker-chosen commands (command injection / RCE).",
        "remediation": "Pass arguments as a list with shell=False, validate against an allow-list, and use shlex.quote only as a last resort.",
        "limitations": ["Only intra-function data flow is tracked; input arriving via other functions or files is not followed."],
    },
    "PY-CMD-002": {
        "category": "Unsafe subprocess usage",
        "explanation": "A subprocess is launched with shell=True or through os.system/os.popen.",
        "impact": "Shell invocation widens the attack surface; any later change that adds dynamic input becomes command injection.",
        "remediation": "Use subprocess.run([...], shell=False) with a fixed argument list.",
        "limitations": ["The command here is constant, so exploitation requires a code change or environment influence."],
    },
    "PY-DESER-001": {
        "category": "Unsafe deserialization",
        "explanation": "pickle/marshal/dill/unsafe YAML loading can execute code embedded in the data.",
        "impact": "Deserializing untrusted data can give the attacker remote code execution.",
        "remediation": "Use JSON or another data-only format; for YAML use yaml.safe_load; sign/verify data if pickle is unavoidable.",
        "limitations": ["Risk depends on whether the data source is trusted; this scan cannot tell."],
    },
    "PY-SQLI-001": {
        "category": "SQL injection",
        "explanation": "A SQL string is assembled with f-strings, %, +, or .format() before being executed.",
        "impact": "Crafted input can change the query's meaning, exposing or modifying data.",
        "remediation": "Use parameterised queries (cursor.execute(sql, params)) or an ORM's bound parameters.",
        "limitations": ["Identifier interpolation from a fixed allow-list can be safe; review the source of each interpolated value."],
    },
    "PY-CRYPTO-001": {
        "category": "Weak cryptography",
        "explanation": "MD5/SHA-1, DES/RC4, ECB mode or obsolete TLS versions are considered broken or unsafe.",
        "impact": "Attackers may forge signatures, recover plaintext or downgrade connections.",
        "remediation": "Use SHA-256+ (or a password KDF like scrypt/argon2 for passwords), AES-GCM/ChaCha20-Poly1305, and TLS 1.2+.",
        "limitations": ["Non-security uses (cache keys, checksums) are harmless; confirm the purpose."],
    },
    "PY-SECRET-001": {
        "category": "Hardcoded secret",
        "explanation": "A credential-like value is written directly in source or configuration.",
        "impact": "Anyone with repository or artifact access gains the credential, and it persists in version history.",
        "remediation": "Load secrets from environment/secret manager, rotate the exposed value, and purge it from history.",
        "limitations": ["Name-based detection can flag test values or placeholders; values are redacted in this report."],
    },
    "PY-FILE-001": {
        "category": "Unsafe file handling",
        "explanation": "File paths, archives or temp files are handled in a way that can be abused (path traversal, archive slip, temp-file races).",
        "impact": "Attackers may read/write files outside the intended directory or hijack predictable temp files.",
        "remediation": "Resolve and verify paths stay inside a base directory, use tempfile.mkstemp/TemporaryDirectory, and use tarfile filter='data'.",
        "limitations": ["Cannot confirm the path or archive is attacker-controlled."],
    },
    "PY-CFG-001": {
        "category": "Insecure configuration",
        "explanation": "Debug mode, disabled TLS verification, permissive file modes or wildcard hosts weaken security defaults.",
        "impact": "Can expose debuggers (remote code execution), allow man-in-the-middle attacks, or leak data.",
        "remediation": "Disable debug in production, keep certificate verification on, use least-privilege permissions.",
        "limitations": ["Development-only settings may be intentional; confirm they cannot reach production."],
    },
}
