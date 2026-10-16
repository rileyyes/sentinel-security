import pytest

from app.analyzers.code.python_scanner import scan_project, scan_source


def rules_for(src):
    return {f.rule_id for f in scan_source("t.py", src)}


def test_flags_eval_on_tainted_input():
    assert "PY-EXEC-001" in rules_for("x = input()\neval(x)\n")


def test_does_not_flag_eval_on_constant():
    findings = scan_source("t.py", "eval('1+1')\n")
    assert findings[0].severity.value == "low"


def test_flags_os_system_with_concatenation():
    assert "PY-CMD-001" in rules_for("import os\ncmd = input()\nos.system('ls ' + cmd)\n")


def test_flags_subprocess_shell_true_constant_as_lower_severity():
    findings = scan_source("t.py", "import subprocess\nsubprocess.run('ls -la', shell=True)\n")
    assert findings[0].rule_id == "PY-CMD-002"
    assert findings[0].severity.value == "low"


def test_does_not_flag_safe_subprocess_list():
    assert rules_for("import subprocess\nsubprocess.run(['ls', '-la'])\n") == set()


def test_flags_sql_fstring():
    src = 'import sqlite3\nc = sqlite3.connect("x").cursor()\nuser = input()\nc.execute(f"SELECT * FROM t WHERE u={user}")\n'
    assert "PY-SQLI-001" in rules_for(src)


def test_does_not_flag_parameterised_sql():
    src = 'import sqlite3\nc = sqlite3.connect("x").cursor()\nc.execute("SELECT * FROM t WHERE u=?", (1,))\n'
    assert rules_for(src) == set()


def test_flags_pickle_loads():
    assert "PY-DESER-001" in rules_for("import pickle\npickle.loads(b'x')\n")


def test_flags_yaml_load_without_safe_loader():
    assert "PY-DESER-001" in rules_for("import yaml\nyaml.load(open('x').read())\n")


def test_yaml_safe_load_not_flagged():
    assert rules_for("import yaml\nyaml.safe_load(open('x').read())\n") == set()


def test_flags_md5():
    assert "PY-CRYPTO-001" in rules_for("import hashlib\nhashlib.md5(b'x')\n")


def test_md5_not_flagged_when_usedforsecurity_false():
    assert rules_for("import hashlib\nhashlib.md5(b'x', usedforsecurity=False)\n") == set()


def test_flags_hardcoded_secret_assignment():
    findings = list(scan_source("t.py", 'API_KEY = "sk_live_1234567890abcdef"\n'))
    assert any(f.rule_id == "PY-SECRET-001" for f in findings)
    assert "sk_live_1234567890abcdef" not in findings[0].evidence  # must be redacted


def test_placeholder_secret_not_flagged():
    assert rules_for('PASSWORD = "changeme"\n') == set()


def test_flags_aws_key_pattern():
    assert "PY-SECRET-001" in rules_for('key = "AKIAABCDEFGHIJKLMNOP"\n')


def test_flags_verify_false():
    assert "PY-CFG-001" in rules_for("import requests\nrequests.get('https://x', verify=False)\n")


def test_flags_flask_debug_true():
    assert "PY-CFG-001" in rules_for("app.run(debug=True)\n")


def test_flags_tempfile_mktemp():
    assert "PY-FILE-001" in rules_for("import tempfile\ntempfile.mktemp()\n")


def test_syntax_error_does_not_crash_scanner():
    with pytest.raises(SyntaxError):
        scan_source("t.py", "def f(:\n")


def test_scan_project_handles_syntax_error_gracefully(tmp_path, settings):
    (tmp_path / "bad.py").write_text("def f(:\n")
    (tmp_path / "good.py").write_text("import os\nos.system(input())\n")
    result = scan_project(tmp_path, settings)
    assert result.files_scanned == 2
    assert any("bad.py" in w for w in result.warnings)
    assert any(f.file == "good.py" for f in result.findings)


def test_scan_project_skips_vcs_and_venv_dirs(tmp_path, settings):
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "config.py").write_text("SECRET='sk_live_1234567890abcdef'")
    (tmp_path / "venv").mkdir()
    (tmp_path / "venv" / "lib.py").write_text("SECRET='sk_live_1234567890abcdef'")
    (tmp_path / "real.py").write_text("x = 1\n")
    result = scan_project(tmp_path, settings)
    assert result.files_scanned == 1


def test_findings_are_sorted_by_severity(tmp_path, settings):
    (tmp_path / "a.py").write_text("import hashlib\nhashlib.md5(b'x')\n")  # medium
    (tmp_path / "b.py").write_text("eval(input())\n")  # high
    result = scan_project(tmp_path, settings)
    assert result.findings[0].severity.value == "high"
