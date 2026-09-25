"""SARIF 2.1.0 reporter."""

from __future__ import annotations

import json
from typing import Any

from pysast.findings import Finding

_SARIF_SCHEMA = "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json"
_SARIF_VERSION = "2.1.0"


def _severity_to_sarif(severity: str) -> str:
    return {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}.get(
        severity, "warning"
    )


def format_findings(findings: list[Finding]) -> str:
    rules: list[dict[str, Any]] = []
    seen_rules: set[str] = set()
    results: list[dict[str, Any]] = []

    for f in findings:
        if f.rule_id not in seen_rules:
            seen_rules.add(f.rule_id)
            rules.append(
                {
                    "id": f.rule_id,
                    "name": f.vulnerability.replace(" ", ""),
                    "shortDescription": {"text": f.vulnerability},
                    "helpUri": f"https://cwe.mitre.org/data/definitions/{f.cwe.lstrip('CWE-')}.html",
                    "properties": {"tags": [f.cwe, f.owasp]},
                }
            )

        code_flows: list[dict[str, Any]] = []
        if f.data_flow:
            thread_flow_locs = [
                {
                    "location": {
                        "physicalLocation": {
                            "artifactLocation": {"uri": step.file},
                            "region": {"startLine": step.line},
                        },
                        "message": {"text": step.code},
                    }
                }
                for step in f.data_flow
            ]
            code_flows = [{"threadFlows": [{"locations": thread_flow_locs}]}]

        results.append(
            {
                "ruleId": f.rule_id,
                "level": _severity_to_sarif(f.severity),
                "message": {"text": f"{f.vulnerability} — {f.remediation}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.file},
                            "region": {"startLine": f.sink_line},
                        }
                    }
                ],
                "codeFlows": code_flows,
            }
        )

    sarif: dict[str, Any] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "pysast",
                        "informationUri": "https://github.com/orangecyberdefense/pysast",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)
