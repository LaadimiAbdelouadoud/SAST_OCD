# pysast

An AST-based Static Application Security Testing (SAST) tool for Python web applications.

Built during an internship at Orange Cyberdefense.

## What it does

1. Parses `.py` files into an AST.
2. Builds a Control Flow Graph (CFG) per function.
3. Runs intraprocedural taint analysis (worklist fixed-point over the CFG).
4. Reports web vulnerabilities with file/line, the source→sink data-flow path, CWE/OWASP mapping, severity, and remediation advice.

**Supported frameworks:** Flask (MVP), Django sources.

**Detected vulnerability classes:** SQL Injection, Command Injection, Code Injection, XSS, Path Traversal, SSRF, Insecure Deserialization, Open Redirect.

## Quick start

```bash
pip install -e ".[dev]"
pysast scan path/to/your/flask/app
pysast scan path/to/your/flask/app --format json --output results.json
```

## Development

```bash
ruff check .
mypy pysast
pytest tests/ -v
```

## Architecture

```
Ingestion → Parser → Symbol Table → CFG Builder → Taint Engine → Reporter
```

Detection rules (sources / sinks / sanitizers) live in `pysast/knowledge/default_rules.yaml`.
Propagation rules (how taint moves through expressions) live in `pysast/taint/transfer.py`.

## Phased roadmap

- **Phase 0:** Scaffold, ground-truth test corpus. ← *current*
- **Phase 1:** MVP — intraprocedural taint, SQLi + CmdI.
- **Phase 2:** Breadth — all 8 vuln classes, multi-file projects.
- **Phase 3:** Depth — interprocedural taint, function summaries.
- **Phase 4:** Productionization — SARIF, CI integration, evaluation harness.
- **Phase 5:** Stretch — Django/FastAPI packs, Jinja2 template analysis.
