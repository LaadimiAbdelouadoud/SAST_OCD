"""Load and validate the YAML security knowledge base."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class SourceRule:
    id: str
    framework: str
    vuln_classes: list[str]
    patterns: list[str]


@dataclass
class SinkRule:
    id: str
    vulnerability: str
    cwe: str
    owasp: str
    severity: str
    cvss_v31: float
    vuln_class: str
    remediation: str
    patterns: list[str]
    tainted_args: list[int] = field(default_factory=list)
    conditions: list[dict[str, Any]] = field(default_factory=list)
    negate_conditions: bool = False


@dataclass
class SanitizerRule:
    id: str
    patterns: list[str]
    clears: list[str]


@dataclass
class RuleSet:
    sources: list[SourceRule] = field(default_factory=list)
    sinks: list[SinkRule] = field(default_factory=list)
    sanitizers: list[SanitizerRule] = field(default_factory=list)


def _parse_sources(raw: list[dict[str, Any]]) -> list[SourceRule]:
    return [
        SourceRule(
            id=r["id"],
            framework=r.get("framework", ""),
            vuln_classes=r.get("vuln_classes", []),
            patterns=r.get("patterns", []),
        )
        for r in raw
    ]


def _parse_sinks(raw: list[dict[str, Any]]) -> list[SinkRule]:
    return [
        SinkRule(
            id=r["id"],
            vulnerability=r["vulnerability"],
            cwe=r["cwe"],
            owasp=r["owasp"],
            severity=r["severity"],
            cvss_v31=float(r.get("cvss_v31", 0.0)),
            vuln_class=r.get("vuln_class", ""),
            remediation=r.get("remediation", ""),
            patterns=r.get("patterns", []),
            tainted_args=r.get("tainted_args", []),
            conditions=r.get("conditions", []),
            negate_conditions=bool(r.get("negate_conditions", False)),
        )
        for r in raw
    ]


def _parse_sanitizers(raw: list[dict[str, Any]]) -> list[SanitizerRule]:
    return [
        SanitizerRule(
            id=r["id"],
            patterns=r.get("patterns", []),
            clears=r.get("clears", []),
        )
        for r in raw
    ]


def load_rules(path: Path) -> RuleSet:
    """Load a YAML rules file and return a validated RuleSet."""
    with path.open(encoding="utf-8") as fh:
        data: dict[str, Any] = yaml.safe_load(fh) or {}
    return RuleSet(
        sources=_parse_sources(data.get("sources", [])),
        sinks=_parse_sinks(data.get("sinks", [])),
        sanitizers=_parse_sanitizers(data.get("sanitizers", [])),
    )


def default_rules() -> RuleSet:
    """Load the bundled default_rules.yaml shipped with pysast."""
    pkg_path = Path(__file__).parent / "default_rules.yaml"
    return load_rules(pkg_path)
