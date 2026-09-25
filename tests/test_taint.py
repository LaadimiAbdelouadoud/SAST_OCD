"""Integration tests — taint analysis end-to-end against ground-truth samples."""
from pathlib import Path

from pysast.ingestion import discover_files, read_source
from pysast.knowledge.loader import default_rules
from pysast.parser import parse_module
from pysast.symbols import build_symbol_table
from pysast.taint.engine import analyse_module

RULES = default_rules()

VULN = Path(__file__).parent / "vulnerable_samples"
SAFE = Path(__file__).parent / "safe_samples"


def _scan(folder: Path) -> list:
    findings = []
    for path in discover_files(folder):
        source = read_source(path)
        tree = parse_module(source, filename=str(path))
        st = build_symbol_table(tree)
        findings.extend(analyse_module(tree, st, RULES, filename=str(path)))
    return findings


def _inline(source: str) -> list:
    tree = parse_module(source, filename="<test>")
    st = build_symbol_table(tree)
    return analyse_module(tree, st, RULES, filename="<test>")


# ── Phase 1: SQLi + CmdI (regression) ─────────────────────────────────────────

def test_sqli_vulnerable_detected() -> None:
    findings = _scan(VULN / "flask_sqli")
    assert any("SQL" in f.vulnerability for f in findings)


def test_cmdi_vulnerable_detected() -> None:
    findings = _scan(VULN / "flask_cmdi")
    assert any("Command" in f.vulnerability for f in findings)


def test_sqli_safe_no_findings() -> None:
    findings = _scan(SAFE / "flask_sqli_safe")
    assert not [f for f in findings if "SQL" in f.vulnerability]


def test_cmdi_safe_no_findings() -> None:
    findings = _scan(SAFE / "flask_cmdi_safe")
    assert not [f for f in findings if "Command" in f.vulnerability]


# ── Phase 2: XSS ──────────────────────────────────────────────────────────────

def test_xss_vulnerable_detected() -> None:
    findings = _scan(VULN / "flask_xss")
    assert any("XSS" in f.vulnerability or "Cross-Site" in f.vulnerability for f in findings), (
        f"Expected ≥1 XSS finding, got: {findings}"
    )


def test_xss_safe_no_findings() -> None:
    findings = _scan(SAFE / "flask_xss_safe")
    xss = [f for f in findings if "XSS" in f.vulnerability or "Cross-Site" in f.vulnerability]
    assert xss == [], f"False positive on XSS safe sample: {xss}"


def test_xss_inline() -> None:
    source = """
from flask import render_template_string, request
def view():
    name = request.args.get('name')
    return render_template_string('<h1>' + name + '</h1>')
"""
    findings = _inline(source)
    assert any("XSS" in f.vulnerability or "Cross-Site" in f.vulnerability for f in findings)


# ── Phase 2: Code Injection ────────────────────────────────────────────────────

def test_code_injection_vulnerable_detected() -> None:
    findings = _scan(VULN / "flask_code_injection")
    assert any("Code Injection" in f.vulnerability for f in findings), (
        f"Expected ≥1 Code Injection finding, got: {findings}"
    )


def test_code_injection_safe_no_findings() -> None:
    findings = _scan(SAFE / "flask_code_injection_safe")
    ci = [f for f in findings if "Code Injection" in f.vulnerability]
    assert ci == [], f"False positive on code injection safe sample: {ci}"


def test_eval_inline() -> None:
    source = """
from flask import request
def view():
    expr = request.args.get('expr')
    result = eval(expr)
    return str(result)
"""
    findings = _inline(source)
    assert any("Code Injection" in f.vulnerability for f in findings)


# ── Phase 2: Path Traversal ────────────────────────────────────────────────────

def test_path_traversal_vulnerable_detected() -> None:
    findings = _scan(VULN / "flask_path_traversal")
    assert any("Path Traversal" in f.vulnerability for f in findings), (
        f"Expected ≥1 Path Traversal finding, got: {findings}"
    )


def test_path_traversal_safe_no_findings() -> None:
    findings = _scan(SAFE / "flask_path_traversal_safe")
    pt = [f for f in findings if "Path Traversal" in f.vulnerability]
    assert pt == [], f"False positive on path traversal safe sample: {pt}"


def test_path_traversal_inline() -> None:
    source = """
from flask import request
def view():
    filename = request.args.get('file')
    fh = open(filename)
    return fh.read()
"""
    findings = _inline(source)
    assert any("Path Traversal" in f.vulnerability for f in findings)


# ── Phase 2: SSRF ─────────────────────────────────────────────────────────────

def test_ssrf_vulnerable_detected() -> None:
    findings = _scan(VULN / "flask_ssrf")
    ssrf_found = any(
        "SSRF" in f.vulnerability or "Request Forgery" in f.vulnerability for f in findings
    )
    assert ssrf_found, f"Expected ≥1 SSRF finding, got: {findings}"


def test_ssrf_safe_no_findings() -> None:
    findings = _scan(SAFE / "flask_ssrf_safe")
    ssrf = [
        f for f in findings
        if "SSRF" in f.vulnerability or "Request Forgery" in f.vulnerability
    ]
    assert ssrf == [], f"False positive on SSRF safe sample: {ssrf}"


def test_ssrf_inline() -> None:
    source = """
import requests
from flask import request
def view():
    url = request.args.get('url')
    resp = requests.get(url)
    return resp.text
"""
    findings = _inline(source)
    assert any("SSRF" in f.vulnerability or "Request Forgery" in f.vulnerability for f in findings)


# ── Phase 2: Insecure Deserialization ─────────────────────────────────────────

def test_deserialization_pickle_detected() -> None:
    findings = _scan(VULN / "flask_deserialization")
    assert any("Deserialization" in f.vulnerability for f in findings), (
        f"Expected ≥1 Deserialization finding, got: {findings}"
    )


def test_deserialization_safe_no_findings() -> None:
    findings = _scan(SAFE / "flask_deserialization_safe")
    deser = [f for f in findings if "Deserialization" in f.vulnerability]
    assert deser == [], f"False positive on deserialization safe sample: {deser}"


def test_yaml_load_unsafe_detected() -> None:
    source = """
import yaml
from flask import request
def view():
    data = request.data
    obj = yaml.load(data)
    return str(obj)
"""
    findings = _inline(source)
    assert any("Deserialization" in f.vulnerability for f in findings)


def test_yaml_safe_load_no_findings() -> None:
    source = """
import yaml
from flask import request
def view():
    data = request.data
    obj = yaml.safe_load(data)
    return str(obj)
"""
    findings = _inline(source)
    deser = [f for f in findings if "Deserialization" in f.vulnerability]
    assert deser == [], f"yaml.safe_load should not trigger: {deser}"


# ── Phase 2: Open Redirect ────────────────────────────────────────────────────

def test_open_redirect_vulnerable_detected() -> None:
    findings = _scan(VULN / "flask_open_redirect")
    assert any("Redirect" in f.vulnerability for f in findings), (
        f"Expected ≥1 Open Redirect finding, got: {findings}"
    )


def test_open_redirect_safe_no_findings() -> None:
    findings = _scan(SAFE / "flask_open_redirect_safe")
    redir = [f for f in findings if "Redirect" in f.vulnerability]
    assert redir == [], f"False positive on open redirect safe sample: {redir}"


def test_open_redirect_inline() -> None:
    source = """
from flask import redirect, request
def view():
    next_url = request.args.get('next')
    return redirect(next_url)
"""
    findings = _inline(source)
    assert any("Redirect" in f.vulnerability for f in findings)


# ── Propagation edge cases ─────────────────────────────────────────────────────

def test_taint_propagates_through_concat() -> None:
    source = """
from flask import request
def view():
    uid = request.args.get('id')
    query = "SELECT * FROM users WHERE id=" + uid
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(query)
"""
    assert any("SQL" in f.vulnerability for f in _inline(source))


def test_taint_propagates_through_fstring() -> None:
    source = """
from flask import request
def view():
    name = request.args.get('name')
    query = f"SELECT * FROM users WHERE name='{name}'"
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(query)
"""
    assert any("SQL" in f.vulnerability for f in _inline(source))


def test_taint_propagates_through_format() -> None:
    source = """
from flask import request
def view():
    uid = request.args.get('id')
    query = "SELECT * FROM users WHERE id={}".format(uid)
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(query)
"""
    assert any("SQL" in f.vulnerability for f in _inline(source))


def test_taint_propagates_through_percent_format() -> None:
    source = """
from flask import request
def view():
    uid = request.args.get('id')
    query = "SELECT * FROM users WHERE id=%s" % uid
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute(query)
"""
    assert any("SQL" in f.vulnerability for f in _inline(source))


def test_int_cast_clears_sqli_taint() -> None:
    source = """
from flask import request
def view():
    uid_raw = request.args.get('id')
    uid = int(uid_raw)
    import sqlite3
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=" + str(uid))
"""
    sqli = [f for f in _inline(source) if "SQL" in f.vulnerability]
    assert sqli == [], f"int() cast should clear SQLi taint: {sqli}"
