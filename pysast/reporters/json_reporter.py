"""JSON reporter."""

from __future__ import annotations

import json

from pysast.findings import Finding


def format_findings(findings: list[Finding], indent: int = 2) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=indent, ensure_ascii=False)
