"""Deterministic Python security scanner built on the standard-library ``ast``.

Approach
* Parse (never import/execute) each file into a syntax tree.
* Resolve import aliases so ``import subprocess as sp; sp.run(...)`` is caught.
* Track a *small* amount of intra-function taint: values that originate from
  input()/sys.argv/request.* and flow through assignments and string
  operations into dangerous sinks raise confidence to HIGH.
* Every finding carries category, severity, file, line, evidence, explanation,
  impact, remediation, confidence and limitations.

What it does NOT do: inter-procedural or cross-file data flow, type
inference, framework-specific sanitiser knowledge, or reasoning about
runtime configuration. Absence of findings is not proof of security.
"""
from __future__ import annotations

import ast
import os
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from app.analyzers.code import secrets as sec
from app.analyzers.code.rules import RULES
from app.core.config import Settings
from app.evidence.models import SEVERITY_ORDER, Confidence, Finding, Severity

_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".tox"}
_TEXT_SUFFIXES = {".py", ".env", ".cfg", ".ini", ".toml", ".yaml", ".yml", ".json", ".conf", ".txt"}
_MAX_FILE_BYTES = 1_000_000
_SUBPROCESS = {"run", "call", "check_call", "check_output", "Popen", "getoutput", "getstatusoutput"}
_SANITIZERS = {"int", "float", "bool", "len", "shlex.quote", "os.path.basename", "secure_filename",
               "werkzeug.utils.secure_filename", "html.escape", "escape"}
_TAINT_CALLS = {"input", "sys.stdin.read", "sys.stdin.readline"}
_UNSAFE_LOADERS = {"pickle.load", "pickle.loads", "pickle.Unpickler", "cPickle.load", "cPickle.loads",
                   "dill.load", "dill.loads", "marshal.load", "marshal.loads", "yaml.unsafe_load",
                   "jsonpickle.decode"}
_WEAK_TLS = {"PROTOCOL_SSLv2", "PROTOCOL_SSLv3", "PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1"}


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    warnings: list[str] = field(default_factory=list)


def _dotted(node: ast.AST) -> str | None:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


class _FileScanner(ast.NodeVisitor):
    def __init__(self, rel: str, lines: list[str], out: list[Finding]):
        self.rel, self.lines, self.out = rel, lines, out
        self.aliases: dict[str, str] = {}
        self.scopes: list[set[str]] = [set()]
        self.built_sql: set[str] = set()
        self.seen: set[tuple[str, int]] = set()

    # ---- helpers ----------------------------------------------------------
    def _name(self, func: ast.AST) -> str | None:
        d = _dotted(func)
        if d is None:
            return None
        head, _, rest = d.partition(".")
        head = self.aliases.get(head, head)
        return f"{head}.{rest}" if rest else head

    def _is_const(self, n: ast.AST) -> bool:
        if isinstance(n, ast.Constant):
            return True
        if isinstance(n, ast.JoinedStr):
            return all(isinstance(v, ast.Constant) for v in n.values)
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            return self._is_const(n.left) and self._is_const(n.right)
        if isinstance(n, (ast.List, ast.Tuple)):
            return all(self._is_const(e) for e in n.elts)
        return False

    def _tainted(self, n: ast.AST) -> bool:
        if isinstance(n, ast.Name):
            return n.id in self.scopes[-1] or n.id in self.scopes[0]
        d = self._name(n) if isinstance(n, (ast.Attribute, ast.Name)) else None
        if d and (d == "sys.argv" or d.startswith("request.") or d.startswith("flask.request.")):
            return True
        if isinstance(n, ast.Call):
            name = self._name(n.func)
            if name in _SANITIZERS:
                return False
            if name in _TAINT_CALLS:
                return True
            return self._tainted(n.func) or any(self._tainted(a) for a in n.args) or any(
                self._tainted(k.value) for k in n.keywords
            )
        return any(self._tainted(c) for c in ast.iter_child_nodes(n))

    def _dynamic_sql(self, n: ast.AST) -> bool:
        if isinstance(n, ast.JoinedStr):
            return any(isinstance(v, ast.FormattedValue) for v in n.values)
        if isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Mod, ast.Add)):
            return not self._is_const(n)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "format":
            return True
        return False

    def _add(self, rule: str, node: ast.AST, severity: Severity, confidence: Confidence,
             evidence: str | None = None, extra_limit: str | None = None) -> None:
        line = getattr(node, "lineno", 0)
        if (rule, line) in self.seen:
            return
        self.seen.add((rule, line))
        meta = RULES[rule]
        text = evidence if evidence is not None else (self.lines[line - 1].strip() if 0 < line <= len(self.lines) else "")
        limits = list(meta["limitations"])  # type: ignore[arg-type]
        if extra_limit:
            limits.append(extra_limit)
        self.out.append(Finding(
            id="", rule_id=rule, category=str(meta["category"]), severity=severity, file=self.rel,
            line=line or None, evidence=text[:200], explanation=str(meta["explanation"]),
            impact=str(meta["impact"]), remediation=str(meta["remediation"]),
            confidence=confidence, limitations=limits,
        ))

    # ---- scope / alias tracking --------------------------------------------
    def visit_Import(self, node: ast.Import) -> None:
        for a in node.names:
            if a.asname:
                self.aliases[a.asname] = a.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for a in node.names:
            self.aliases[a.asname or a.name] = f"{node.module}.{a.name}" if node.module else a.name
        self.generic_visit(node)

    def _function(self, node: ast.AST) -> None:
        self.scopes.append(set())
        self.generic_visit(node)
        self.scopes.pop()

    visit_FunctionDef = _function
    visit_AsyncFunctionDef = _function

    def _bind(self, targets: list[ast.expr], value: ast.AST | None) -> None:
        if value is None:
            return
        names = [n.id for t in targets for n in ast.walk(t) if isinstance(n, ast.Name)]
        if self._tainted(value):
            self.scopes[-1].update(names)
        if self._dynamic_sql(value):
            self.built_sql.update(names)

    def visit_Assign(self, node: ast.Assign) -> None:
        self._bind(node.targets, node.value)
        self._check_secret_assign(node.targets, node.value, node)
        self._check_debug_flag(node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._bind([node.target], node.value)
        if node.value is not None:
            self._check_secret_assign([node.target], node.value, node)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._bind([node.target], node.iter)
        self.generic_visit(node)

    # ---- rule checks -------------------------------------------------------
    def _check_secret_assign(self, targets, value, node) -> None:
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            return
        for t in targets:
            name = t.id if isinstance(t, ast.Name) else t.attr if isinstance(t, ast.Attribute) else None
            if name and sec.NAME_RE.search(name) and not sec.is_placeholder(value.value):
                self._add("PY-SECRET-001", node, Severity.HIGH, Confidence.MEDIUM,
                          evidence=f"{name} = {sec.redact(value.value)!r}")

    def _check_debug_flag(self, node: ast.Assign) -> None:
        for t in node.targets:
            if isinstance(t, ast.Name) and t.id == "DEBUG" and isinstance(node.value, ast.Constant) and node.value.value is True:
                self._add("PY-CFG-001", node, Severity.MEDIUM, Confidence.MEDIUM)
            if isinstance(t, ast.Name) and t.id == "ALLOWED_HOSTS" and "'*'" in ast.dump(node.value).replace('"', "'"):
                self._add("PY-CFG-001", node, Severity.LOW, Confidence.MEDIUM)

    def visit_Dict(self, node: ast.Dict) -> None:
        for k, v in zip(node.keys, node.values):
            if (isinstance(k, ast.Constant) and isinstance(k.value, str) and sec.NAME_RE.search(k.value)
                    and isinstance(v, ast.Constant) and isinstance(v.value, str) and not sec.is_placeholder(v.value)):
                self._add("PY-SECRET-001", node, Severity.HIGH, Confidence.MEDIUM,
                          evidence=f"{k.value!r}: {sec.redact(v.value)!r}")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        d = self._name(node)
        if d and node.attr in _WEAK_TLS:
            self._add("PY-CRYPTO-001", node, Severity.MEDIUM, Confidence.HIGH)
        if d and node.attr == "MODE_ECB":
            self._add("PY-CRYPTO-001", node, Severity.MEDIUM, Confidence.HIGH)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        name = self._name(node.func) or ""
        kw = {k.arg: k.value for k in node.keywords if k.arg}
        first = node.args[0] if node.args else None
        tainted = any(self._tainted(a) for a in node.args) or any(self._tainted(v) for v in kw.values())

        # dangerous dynamic execution
        if name in ("eval", "exec"):
            if first is not None and not self._is_const(first):
                self._add("PY-EXEC-001", node, Severity.HIGH,
                          Confidence.HIGH if tainted else Confidence.MEDIUM)
            else:
                self._add("PY-EXEC-001", node, Severity.LOW, Confidence.HIGH)

        # command execution
        shell_true = isinstance(kw.get("shell"), ast.Constant) and kw["shell"].value is True
        is_sub = name.startswith("subprocess.") and name.split(".")[-1] in _SUBPROCESS
        if name in ("os.system", "os.popen") or (is_sub and shell_true):
            if first is not None and not self._is_const(first):
                self._add("PY-CMD-001", node, Severity.HIGH, Confidence.HIGH if tainted else Confidence.MEDIUM)
            else:
                self._add("PY-CMD-002", node, Severity.LOW, Confidence.HIGH)
        elif is_sub and tainted:
            self._add("PY-CMD-001", node, Severity.MEDIUM, Confidence.MEDIUM,
                      extra_limit="shell=False limits injection to argument injection.")

        # deserialization
        if name in _UNSAFE_LOADERS:
            self._add("PY-DESER-001", node, Severity.HIGH if tainted else Severity.MEDIUM,
                      Confidence.HIGH if tainted else Confidence.MEDIUM)
        if name == "yaml.load":
            loader = _dotted(kw["Loader"]) if "Loader" in kw else None
            if loader is None or not loader.endswith(("SafeLoader", "CSafeLoader")):
                self._add("PY-DESER-001", node, Severity.HIGH if tainted else Severity.MEDIUM,
                          Confidence.HIGH if tainted else Confidence.MEDIUM)

        # SQL
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("execute", "executemany", "executescript") and first is not None:
            built = self._dynamic_sql(first) or (isinstance(first, ast.Name) and first.id in self.built_sql)
            if built:
                self._add("PY-SQLI-001", node, Severity.HIGH, Confidence.HIGH if tainted else Confidence.MEDIUM)

        # weak crypto
        if name in ("hashlib.md5", "hashlib.sha1") or (
            name == "hashlib.new" and isinstance(first, ast.Constant) and str(first.value).lower() in ("md5", "sha1")
        ):
            ufs = kw.get("usedforsecurity")
            if not (isinstance(ufs, ast.Constant) and ufs.value is False):
                self._add("PY-CRYPTO-001", node, Severity.MEDIUM, Confidence.MEDIUM)
        if name.endswith(("DES.new", "ARC4.new", "Blowfish.new", "ARC2.new")):
            self._add("PY-CRYPTO-001", node, Severity.MEDIUM, Confidence.HIGH)

        # insecure configuration
        if isinstance(kw.get("verify"), ast.Constant) and kw["verify"].value is False:
            self._add("PY-CFG-001", node, Severity.MEDIUM, Confidence.HIGH)
        if name == "ssl._create_unverified_context":
            self._add("PY-CFG-001", node, Severity.MEDIUM, Confidence.HIGH)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "run":
            if isinstance(kw.get("debug"), ast.Constant) and kw["debug"].value is True:
                self._add("PY-CFG-001", node, Severity.HIGH, Confidence.MEDIUM)
            host = kw.get("host")
            if isinstance(host, ast.Constant) and host.value == "0.0.0.0":  # noqa: S104
                self._add("PY-CFG-001", node, Severity.LOW, Confidence.MEDIUM)
        if name == "os.chmod" and len(node.args) > 1 and isinstance(node.args[1], ast.Constant) and node.args[1].value in (0o777, 0o666):
            self._add("PY-CFG-001", node, Severity.MEDIUM, Confidence.HIGH)

        # file handling
        if name == "tempfile.mktemp":
            self._add("PY-FILE-001", node, Severity.MEDIUM, Confidence.HIGH)
        if isinstance(node.func, ast.Attribute) and node.func.attr == "extractall" and "filter" not in kw:
            self._add("PY-FILE-001", node, Severity.MEDIUM, Confidence.LOW,
                      extra_limit="Cannot tell whether this is a tar or zip object, or whether members are validated.")
        if name in ("open", "io.open", "os.remove", "os.unlink", "shutil.rmtree") and first is not None and self._tainted(first):
            self._add("PY-FILE-001", node, Severity.MEDIUM, Confidence.HIGH)

        # secrets passed as keyword arguments
        for k in node.keywords:
            if (k.arg and sec.NAME_RE.search(k.arg) and isinstance(k.value, ast.Constant)
                    and isinstance(k.value.value, str) and not sec.is_placeholder(k.value.value)):
                self._add("PY-SECRET-001", node, Severity.HIGH, Confidence.MEDIUM,
                          evidence=f"{k.arg}={sec.redact(k.value.value)!r}")
        self.generic_visit(node)


def _scan_token_patterns(rel: str, text: str, out: list[Finding]) -> None:
    for lineno, line in enumerate(text.splitlines(), 1):
        for label, rx in sec.TOKEN_PATTERNS:
            m = rx.search(line)
            if m:
                meta = RULES["PY-SECRET-001"]
                out.append(Finding(
                    id="", rule_id="PY-SECRET-001", category=str(meta["category"]), severity=Severity.HIGH,
                    file=rel, line=lineno, evidence=f"{label}: {sec.redact(m.group())}",
                    explanation=str(meta["explanation"]), impact=str(meta["impact"]),
                    remediation=str(meta["remediation"]), confidence=Confidence.HIGH,
                    limitations=list(meta["limitations"]),  # type: ignore[arg-type]
                ))


def _scan_config_text(rel: str, text: str, out: list[Finding]) -> None:
    meta = RULES["PY-SECRET-001"]
    for lineno, line in enumerate(text.splitlines(), 1):
        m = sec.GENERIC_ASSIGN.search(line)
        if m and not sec.is_placeholder(m.group(2)):
            out.append(Finding(
                id="", rule_id="PY-SECRET-001", category=str(meta["category"]), severity=Severity.HIGH,
                file=rel, line=lineno, evidence=f"{m.group(1)} = {sec.redact(m.group(2))}",
                explanation=str(meta["explanation"]), impact=str(meta["impact"]),
                remediation=str(meta["remediation"]), confidence=Confidence.MEDIUM,
                limitations=list(meta["limitations"]),  # type: ignore[arg-type]
            ))


def scan_source(rel: str, text: str) -> list[Finding]:
    """Scan one Python source string. Raises SyntaxError/ValueError on unparsable input."""
    out: list[Finding] = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tree = ast.parse(text, filename=rel)
    _FileScanner(rel, text.splitlines(), out).visit(tree)
    _scan_token_patterns(rel, text, out)
    return out


def scan_project(root: Path, settings: Settings) -> ScanResult:
    result = ScanResult()
    root = root.resolve()
    entries: list[Path] = []
    if root.is_file():
        entries = [root]
    else:
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            entries.extend(Path(dirpath) / f for f in filenames)
    for path in sorted(entries):
        rel = path.name if root.is_file() else path.relative_to(root).as_posix()
        if path.is_symlink():
            result.warnings.append(f"Skipped symbolic link: {rel}")
            continue
        if path.suffix.lower() not in _TEXT_SUFFIXES and path.name.lower() != ".env":
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                result.warnings.append(f"Skipped file over 1 MB: {rel}")
                continue
            text = path.read_bytes().decode("utf-8", errors="replace")
        except OSError:
            result.warnings.append(f"Could not read file: {rel}")
            continue
        result.files_scanned += 1
        try:
            if path.suffix.lower() == ".py":
                result.findings.extend(scan_source(rel, text))
            else:
                _scan_token_patterns(rel, text, result.findings)
                _scan_config_text(rel, text, result.findings)
        except (SyntaxError, ValueError):
            result.warnings.append(f"Could not parse {rel} (syntax error); file was not analysed.")
        except (RecursionError, MemoryError):
            result.warnings.append(f"{rel} is too deeply nested to analyse safely; file was not analysed.")
        if result.files_scanned >= 5000:
            result.warnings.append("File limit reached; remaining files were not scanned.")
            break

    result.findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line or 0))
    for i, f in enumerate(result.findings, 1):
        f.id = f"F-{i:03d}"
    return result
