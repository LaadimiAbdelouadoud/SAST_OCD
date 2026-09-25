"""Finding model — the output of the taint engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class FlowStep:
    """A single step in a source-to-sink data-flow path."""

    file: str
    line: int
    code: str

    def to_dict(self) -> dict[str, Any]:
        return {"file": self.file, "line": self.line, "code": self.code}


@dataclass
class Finding:
    """A reported vulnerability."""

    rule_id: str
    vulnerability: str
    cwe: str
    owasp: str
    severity: str
    cvss_v31: float
    file: str
    sink_line: int
    sink_snippet: str
    source: FlowStep
    data_flow: list[FlowStep] = field(default_factory=list)
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "vulnerability": self.vulnerability,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "severity": self.severity,
            "cvss_v31": self.cvss_v31,
            "file": self.file,
            "sink_line": self.sink_line,
            "sink_snippet": self.sink_snippet,
            "source": self.source.to_dict(),
            "data_flow": [s.to_dict() for s in self.data_flow],
            "remediation": self.remediation,
        }
