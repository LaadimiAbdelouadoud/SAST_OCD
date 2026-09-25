"""Human-readable text reporter."""

from __future__ import annotations

from pysast.findings import Finding

_SEV_COLOR = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[94m", "LOW": "\033[92m"}
_RESET = "\033[0m"


def format_findings(findings: list[Finding], color: bool = True) -> str:
    if not findings:
        return "No findings.\n"

    lines: list[str] = []
    for i, f in enumerate(findings, 1):
        sev_prefix = (_SEV_COLOR.get(f.severity, "") + f.severity + _RESET) if color else f.severity
        lines.append(f"[{i}] {sev_prefix} — {f.vulnerability} ({f.cwe})")
        lines.append(f"    File  : {f.file}:{f.sink_line}")
        lines.append(f"    Rule  : {f.rule_id}")
        lines.append(f"    OWASP : {f.owasp}")
        lines.append(f"    Sink  : {f.sink_snippet}")
        lines.append("    Flow  :")
        for step in f.data_flow:
            lines.append(f"      {step.file}:{step.line}  {step.code}")
        if f.remediation:
            lines.append(f"    Fix   : {f.remediation}")
        lines.append("")
    lines.append(f"{len(findings)} finding(s).")
    return "\n".join(lines) + "\n"
