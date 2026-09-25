"""HTML reporter — generates a self-contained human report."""

from __future__ import annotations

import html
from datetime import datetime

from pysast.findings import Finding

_SEV_CLASS = {"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low"}

_CSS = (
    "body{font-family:sans-serif;margin:2rem;background:#f8f9fa;color:#212529}"
    "h1{color:#c0392b}"
    "table{border-collapse:collapse;width:100%}"
    "th,td{border:1px solid #dee2e6;padding:.5rem .75rem;"
    "text-align:left;vertical-align:top}"
    "th{background:#343a40;color:#fff}"
    "tr:nth-child(even){background:#f2f2f2}"
    ".crit{background:#f8d7da;font-weight:bold}"
    ".high{background:#fff3cd}"
    ".med{background:#d1ecf1}"
    ".low{background:#d4edda}"
    "pre{margin:0;font-size:.85em;white-space:pre-wrap}"
)

_TABLE_HEADER = (
    "<table><thead><tr>"
    "<th>#</th><th>Severity</th><th>Vulnerability</th><th>CWE</th>"
    "<th>File:Line</th><th>Sink</th><th>Data Flow</th><th>Remediation</th>"
    "</tr></thead><tbody>"
)


def format_findings(findings: list[Finding]) -> str:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    count = len(findings)
    body_parts = [
        "<h1>pysast Security Report</h1>",
        f"<p>Generated: {ts} &mdash; <strong>{count}</strong> finding(s)</p>",
    ]
    if not findings:
        body_parts.append("<p><em>No findings.</em></p>")
    else:
        rows = "".join(_finding_row(f) for f in findings)
        body_parts.append(_TABLE_HEADER + rows + "</tbody></table>")

    body = "\n".join(body_parts)
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n'
        "<head>\n"
        '<meta charset="utf-8">\n'
        "<title>pysast — Security Report</title>\n"
        f"<style>{_CSS}</style>\n"
        "</head>\n"
        f"<body>\n{body}\n</body>\n</html>\n"
    )


def _finding_row(f: Finding) -> str:
    sev_class = _SEV_CLASS.get(f.severity, "")
    flow_html = "<br>".join(
        f"<code>{html.escape(s.file)}:{s.line}</code>"
        f" — <code>{html.escape(s.code)}</code>"
        for s in f.data_flow
    )
    return (
        f'<tr class="{sev_class}">'
        f"<td>{html.escape(f.rule_id)}</td>"
        f"<td>{html.escape(f.severity)}</td>"
        f"<td>{html.escape(f.vulnerability)}</td>"
        f"<td>{html.escape(f.cwe)}</td>"
        f"<td>{html.escape(f.file)}:{f.sink_line}</td>"
        f"<td><pre>{html.escape(f.sink_snippet)}</pre></td>"
        f"<td>{flow_html}</td>"
        f"<td><pre>{html.escape(f.remediation)}</pre></td>"
        "</tr>"
    )
