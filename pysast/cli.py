"""CLI entrypoint for pysast."""

from __future__ import annotations

import sys
from pathlib import Path

import click

from pysast import __version__
from pysast.findings import Finding
from pysast.ingestion import discover_files, read_source
from pysast.knowledge.loader import RuleSet, default_rules, load_rules
from pysast.parser import ParseError, parse_module
from pysast.symbols import build_symbol_table
from pysast.taint.engine import analyse_module


@click.group()
@click.version_option(__version__, prog_name="pysast")
def main() -> None:
    """pysast — AST-based SAST for Python web applications."""


@main.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--format",
    "fmt",
    type=click.Choice(["text", "json", "sarif", "html"]),
    default="text",
    show_default=True,
    help="Output format.",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to FILE instead of stdout.",
)
@click.option(
    "--rules",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to a custom rules YAML file (overrides built-in rules).",
)
@click.option("--no-color", is_flag=True, default=False, help="Disable ANSI colour in text output.")
def scan(target: Path, fmt: str, output: Path | None, rules: Path | None, no_color: bool) -> None:
    """Scan TARGET (file or directory) for security vulnerabilities."""
    rule_set: RuleSet = load_rules(rules) if rules else default_rules()

    paths = discover_files(target) if target.is_dir() else [target]
    if not paths:
        click.echo("No Python files found.", err=True)
        sys.exit(0)

    all_findings: list[Finding] = []
    for path in paths:
        source = read_source(path)
        try:
            tree = parse_module(source, filename=str(path))
        except ParseError as exc:
            click.echo(f"[WARN] Parse error: {exc}", err=True)
            continue
        sym_table = build_symbol_table(tree)
        findings = analyse_module(tree, sym_table, rule_set, filename=str(path))
        all_findings.extend(findings)

    result = _render(all_findings, fmt, color=not no_color)

    if output:
        output.write_text(result, encoding="utf-8")
        click.echo(f"Results written to {output}", err=True)
    else:
        click.echo(result, nl=False)

    sys.exit(1 if all_findings else 0)


def _render(findings: list[Finding], fmt: str, color: bool = True) -> str:

    if fmt == "json":
        from pysast.reporters import json_reporter
        return json_reporter.format_findings(findings)
    if fmt == "sarif":
        from pysast.reporters import sarif
        return sarif.format_findings(findings)
    if fmt == "html":
        from pysast.reporters import html
        return html.format_findings(findings)
    from pysast.reporters import text
    return text.format_findings(findings, color=color)
