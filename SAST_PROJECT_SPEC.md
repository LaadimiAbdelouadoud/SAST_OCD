# Python Web SAST — Project Specification

> **Purpose of this file:** North-star specification for an AST-based Static Application Security Testing (SAST) tool for Python web applications, built during an internship at Orange Cyberdefense. Hand this file to Claude (Claude Code) as project context. It defines the concepts, architecture, scope, phased roadmap, and the security knowledge base. Build incrementally — respect the phases.

---

## 1. Goal

Build a SAST tool that:
1. Takes a Python web application (a directory of `.py` files) as input.
2. Parses each module into an **AST** (Abstract Syntax Tree).
3. Builds a **CFG** (Control Flow Graph) per function.
4. Runs **taint analysis** by traversing the CFG and propagating taint along data-flow relations (def-use), from **sources** to dangerous **sinks**, accounting for **sanitizers**.
5. Reports **web vulnerabilities** (SQLi, command injection, code injection, XSS, path traversal, SSRF, insecure deserialization, open redirect) with file/line, the source→sink data-flow path, CWE/OWASP mapping, severity, and remediation advice.

**Initial framework target:** Flask. **Stretch:** Django, FastAPI.

---

## 2. Non-goals (keep scope honest)

- Not a runtime/DAST tool — purely static.
- Not aiming for zero false positives (impossible for SAST). Aim for measurable precision/recall.
- Path-sensitivity, full alias analysis, and Jinja2 template analysis are **stretch goals**, not MVP.

---

## 3. Reference projects to study first

- **PyT (Python Taint)** — the canonical AST-based taint analysis tool for Python web apps. Study its architecture (CFG construction, trigger/source/sink definitions, fixed-point analysis). This is the closest blueprint.
- **Bandit** — pattern-based AST scanner (no taint). Shows the baseline we want to beat.
- **Semgrep** (taint mode) — modern dataflow taint engine; study its source/sink/sanitizer model.
- **CodeQL** — for inspiration on dataflow modeling (out of scope to replicate).

---

## 4. Core concepts (read this before building)

These four representations build on each other. Getting the relationship right is what separates a real taint engine from a glorified grep.

### AST — what the program *is*
The parse tree of the code: nodes are syntactic constructs (`Assign`, `Call`, `If`, `BinOp`…). It captures **structure**, not execution. Produced directly by Python's `ast` module.

### CFG — how the program *executes*
A graph where nodes are statements/basic blocks and edges are possible execution transitions. An `if` splits into two branches that later re-converge; a loop creates a back-edge. The CFG captures **control flow** — which block can run after which.

### DFG / def-use chains — how *data* moves
A relation linking each **definition** of a variable (where it gets a value) to each **use** of it (where it is read). Taint conceptually travels along these edges: if `id` is tainted and `q = "..." + id`, then `q` is tainted. The DFG captures **data dependence**, independent of line order.

### How the taint engine uses all of this — the key clarification
**The engine physically traverses the CFG. Data flow is computed *during* that traversal by transfer functions; the DFG is usually implicit, not a separate object in memory.**

This resolves the common confusion ("does it use the CFG or the DFG?"). Both, but at different levels:
- The **CFG provides the traversal skeleton**: which nodes to visit, in what order, and where branches merge (so taint states from multiple incoming paths get **joined / unioned** at convergence points, and loops force iteration).
- At each node, a **transfer function** applies data-flow logic (`q` depends on `id` → propagate taint). These transfer functions *are* the data-flow rules. The def-use relation they encode is the DFG.

Pipeline, conceptually:

```
AST  →  CFG  →  reaching definitions (computed over the CFG)
                      │
                      ▼
              def-use chains (the DFG, often implicit)
                      │
                      ▼
              taint propagation (worklist fixed-point)
```

> **Reaching definitions** is the dataflow analysis (run over the CFG, so it respects branches and loops) that determines, at each use of a variable, which definitions can reach it. Its result *is* the set of def-use edges. This is why the CFG is mandatory even though taint "travels" along data edges: without it, with branches present, you wouldn't know *which* definition of a variable actually reaches a given use.

In code, this maps to two collaborating modules: `taint/engine.py` (the CFG traversal) and `taint/transfer.py` (the per-statement data-flow rules).

---

## 5. Architecture

```
                ┌──────────────┐
  Project dir → │  Ingestion   │  walk .py files, build module map
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │   Parser     │  Python `ast` module → AST per module
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │ Symbol table │  resolve imports → local name → qualified name
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │ CFG Builder  │  AST → control flow graph per function
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │ Taint Engine │  worklist fixed-point over the CFG;
                │              │  transfer functions propagate taint (def-use);
                │              │  matches sources / sinks / sanitizers from YAML
                └──────┬───────┘
                       ▼
                ┌──────────────┐
                │  Reporter    │  findings → text / JSON / SARIF / HTML
                └──────────────┘
```

### Library choices
- **AST:** Python stdlib `ast` for the MVP (matches PyT, pedagogically clear). Upgrade path: `astroid` (used by pylint) for name resolution and cross-module inference once interprocedural analysis is needed.
- **CFG:** roll your own (best for learning) or start from `staticfg` as reference.
- **Config:** `PyYAML` for the sources/sinks/sanitizers knowledge base.
- **CLI:** `click` or `argparse`.
- **Output:** `json` stdlib; SARIF is just a JSON schema.

---

## 6. Suggested module layout

```
pysast/
├── pysast/
│   ├── __init__.py
│   ├── cli.py                 # entrypoint, argument parsing
│   ├── ingestion.py           # discover & read project files
│   ├── parser.py              # source → AST
│   ├── symbols.py             # import resolution: local name → qualified name
│   ├── cfg/
│   │   ├── builder.py         # AST → CFG
│   │   └── node.py            # CFG node/edge data structures
│   ├── taint/
│   │   ├── engine.py          # worklist fixed-point; CFG traversal
│   │   ├── lattice.py         # taint state (taint labels per variable)
│   │   ├── transfer.py        # transfer functions per AST stmt type (data-flow rules)
│   │   └── matching.py        # match AST nodes against rule patterns
│   ├── knowledge/
│   │   ├── loader.py          # load + validate YAML knowledge base
│   │   └── default_rules.yaml # sources / sinks / sanitizers catalog
│   ├── findings.py            # Finding model (file, line, path, CWE…)
│   └── reporters/
│       ├── text.py
│       ├── json_reporter.py
│       ├── sarif.py
│       └── html.py
├── tests/
│   ├── vulnerable_samples/    # intentionally vulnerable apps (ground truth)
│   ├── safe_samples/          # should produce ZERO findings
│   └── test_*.py
├── pyproject.toml
└── README.md
```

---

## 7. Writing detection rules (the most important section)

Two kinds of "rules" exist in this tool. **Do not confuse them:**

| | Detection rules | Propagation rules |
|---|---|---|
| What | sources / sinks / sanitizers catalog | how taint moves through expressions |
| Form | **data** — YAML (`default_rules.yaml`) | **code** — transfer functions (`taint/transfer.py`) |
| Changes | edited/extended for every new vuln class | mostly fixed; rarely touched |
| Section | this section (7) + catalog (8) | section 9 |

This section is about the **detection rules** (YAML). The engine stays generic: it loads this YAML and the matching logic never changes. Adding a vuln class = one YAML entry + one test. Zero engine code.

### 7.1 Rule schema

A rule describes a **pattern to recognize in the AST**.

```yaml
sources:
  - id: flask-request
    framework: flask
    patterns:
      - "flask.request.args"
      - "flask.request.form"
      - "flask.request.values"
      - "flask.request.json"
      - "flask.request.cookies"
      - "flask.request.headers"

sinks:
  - id: sqli-execute
    vulnerability: "SQL Injection"
    cwe: CWE-89
    owasp: "A03:2021-Injection"
    severity: HIGH
    patterns:
      - "*.execute"          # any receiver's .execute(...) (heuristic, see 7.3)
      - "*.executemany"
      - "*.raw"              # Django QuerySet.raw
      - "*.extra"
    tainted_args: [0]        # ONLY arg 0 (the SQL string) is dangerous — see 7.2

  - id: cmdi-subprocess
    vulnerability: "Command Injection"
    cwe: CWE-78
    owasp: "A03:2021-Injection"
    severity: CRITICAL
    patterns:
      - "subprocess.call"
      - "subprocess.run"
      - "subprocess.Popen"
    tainted_args: [0]
    conditions:              # sink ONLY when shell=True — see 7.4
      - kwarg: shell
        equals: true

sanitizers:
  - id: int-cast
    patterns: ["int", "float"]
    clears: [sqli, cmdi, xss, path-traversal, code-injection]
  - id: shlex-quote
    patterns: ["shlex.quote"]
    clears: [cmdi]
  - id: markupsafe-escape
    patterns: ["markupsafe.escape", "flask.escape"]
    clears: [xss]
  - id: secure-filename
    patterns: ["werkzeug.utils.secure_filename"]
    clears: [path-traversal]
```

### 7.2 `tainted_args` — which argument is the dangerous one
The single biggest false-positive reducer for SQLi. Same function, same tainted variable, opposite verdicts:

```python
cursor.execute("SELECT * FROM u WHERE id=" + uid)      # VULNERABLE — uid is in arg 0
cursor.execute("SELECT * FROM u WHERE id=%s", (uid,))  # SAFE — uid is in arg 1 (parameterized)
```

With `tainted_args: [0]`, a finding fires only when taint reaches argument 0. The parameterized form passes silently — exactly what we want.

### 7.3 Two pattern philosophies (the precision/recall tradeoff)
- **Qualified name** (`os.system`, `pickle.loads`, `flask.request.args`): precise, few false positives, but requires import resolution (7.5). Use for module-level functions.
- **Method name** (`*.execute`, `*.raw`): heuristic — you cannot statically prove `cursor` is a SQL cursor, so `something.execute()` may match unrelated objects. Higher recall, more false positives. Necessary for methods on objects.

Default policy: qualified names everywhere possible; a small curated set of `*.method` heuristics where unavoidable.

### 7.4 Conditional sinks
Some sinks are dangerous only under a condition. The `conditions` field gates the rule:

```python
subprocess.run(cmd)                  # not a sink (no shell)
subprocess.run(cmd, shell=True)      # sink fires
yaml.load(data)                      # sink fires
yaml.load(data, Loader=SafeLoader)   # condition not met → no finding
```

### 7.5 Import resolution (mandatory before matching)
A rule says `os.system`, but the same call appears in many disguises:

```python
import os;              os.system(x)    # → "os.system"
from os import system;  system(x)       # → bare Name "system", NOT an Attribute
import os as o;         o.system(x)      # → "o.system" (alias)
from flask import request               # vs  import flask; flask.request
```

Naive text matching on `"os.system"` misses the last three. **Solution:** before matching, walk the module's `import` / `from ... import` nodes and build a symbol table `local_name → qualified_name`, then resolve each call to its qualified name before comparing to patterns. `astroid` does this for free (reason to adopt it in Phase 3); a small hand-rolled table suffices for the MVP. This lives in `pysast/symbols.py`.

```
symbol_table = { "system": "os.system", "o": "os", "request": "flask.request" }
```

Matching sketch (`taint/matching.py`):
```python
def matches(call_node, pattern, symbol_table):
    if pattern.startswith("*."):                 # method-name heuristic
        return getattr(call_node.func, "attr", None) == pattern[2:]
    qname = resolve_qualified_name(call_node.func, symbol_table)
    return qname == pattern                       # qualified-name match
```

### 7.6 Golden rule
**No rule without a test.** Every new entry ships with a vulnerable sample (must be flagged) and a safe counterpart (must stay silent).

---

## 8. Security knowledge base (starter catalog)

The data to encode into `default_rules.yaml` using the schema above.

### Sources (untrusted input — Flask)
- `flask.request.args`, `request.args.get`, `request.values`
- `flask.request.form`, `request.form.get`
- `flask.request.json`, `request.get_json`
- `flask.request.data`, `request.files`, `request.cookies`, `request.headers`
- Route function parameters bound from URL (`@app.route('/<path:p>')` → `p`)
- (Django stretch) `request.GET`, `request.POST`, `request.body`, `request.META`

### Sinks (by vulnerability class)
| Vuln | CWE | OWASP | Sinks | tainted_args / condition |
|------|-----|-------|-------|--------------------------|
| SQL Injection | CWE-89 | A03 | `*.execute`, `*.executemany`, `*.raw`, `*.extra` | arg 0 |
| Command Injection | CWE-78 | A03 | `os.system`, `os.popen`, `subprocess.call/run/Popen`, `commands.*` | arg 0; `subprocess.*` only if `shell=True` |
| Code Injection | CWE-94 | A03 | `eval`, `exec`, `compile` | arg 0 |
| XSS | CWE-79 | A03 | `flask.render_template_string`, `flask.Markup`, `make_response`, Django `HttpResponse` | arg 0 |
| Path Traversal | CWE-22 | A01 | `open`, `flask.send_file`, `flask.send_from_directory`, file ops via `os.path.join` | path arg |
| SSRF | CWE-918 | A10 | `requests.get/post`, `urllib.request.urlopen`, `httpx.*` | url arg |
| Insecure Deserialization | CWE-502 | A08 | `pickle.loads`, `yaml.load`, `marshal.loads` | arg 0; `yaml.load` safe if `Loader=SafeLoader` |
| Open Redirect | CWE-601 | A01 | `flask.redirect` | url arg |

### Sanitizers (clear taint for specific vuln classes)
- Parameterized queries (tainted value in the params arg, not the SQL string) → handled by `tainted_args`, clears SQLi
- `markupsafe.escape`, `flask.escape`, Jinja2 autoescaping → clears XSS
- `shlex.quote` → clears command injection
- `int()`, `float()`, explicit type casts → clears most injection
- `os.path.abspath` + allowlist check, `werkzeug.utils.secure_filename` → clears path traversal
- `yaml.safe_load` / `Loader=SafeLoader` → clears deserialization

> A sanitizer is **vuln-class-specific**: `int()` clears SQLi taint but is irrelevant to SSRF. The `clears:` list in each sanitizer encodes this.

---

## 9. Taint propagation rules (transfer functions — code, not data)

These live in `taint/transfer.py` and define how the engine updates taint state at each node while traversing the CFG. The engine tracks, per CFG node, a state mapping `variable → set of taint labels` (a label identifies the originating source + vuln relevance).

Propagation:
- **Assignment** `x = expr`: `x` becomes tainted iff `expr` is tainted.
- **Augmented assignment** `x += expr`: union of `x`'s and `expr`'s taint.
- **String building** — taint propagates through: concatenation `a + b`, f-strings `f"...{x}..."`, `.format()`, `%` formatting, `.join()`.
- **Subscript / attribute** `x[i]`, `x.attr`: tainted if base is tainted (conservative).
- **Function call** `f(args)`:
  - If `f` is a **sanitizer** for class C → result is cleaned for C.
  - If `f` is a **sink** and taint reaches a position in its `tainted_args` (and any `conditions` are met) → **report a finding**.
  - Otherwise (intraprocedural MVP): conservatively taint the result if any arg is tainted. (Interprocedural phase replaces this with function summaries.)
- **Container ops** (list/dict append/update with tainted value) → container becomes tainted.

**Execution model:** a **worklist fixed-point** over the CFG. Taint flows forward; visit nodes, apply transfer functions, push successors whose input state changed, and iterate until states stabilize. At control-flow merge points, **join** incoming states by union. Loops are handled naturally because the back-edge keeps re-adding nodes to the worklist until nothing changes.

---

## 10. Finding output schema

```json
{
  "rule_id": "PYSAST-SQLI",
  "vulnerability": "SQL Injection",
  "cwe": "CWE-89",
  "owasp": "A03:2021-Injection",
  "severity": "HIGH",
  "cvss_v31": 8.6,
  "file": "app/views.py",
  "sink_line": 42,
  "sink_snippet": "cursor.execute(query)",
  "source": { "file": "app/views.py", "line": 38, "expr": "request.args.get('id')" },
  "data_flow": [
    {"file": "app/views.py", "line": 38, "code": "uid = request.args.get('id')"},
    {"file": "app/views.py", "line": 40, "code": "query = 'SELECT * FROM users WHERE id=' + uid"},
    {"file": "app/views.py", "line": 42, "code": "cursor.execute(query)"}
  ],
  "remediation": "Use parameterized queries: cursor.execute('SELECT ... WHERE id=%s', (uid,))."
}
```

The `data_flow` array is the def-use path reconstructed from the analysis — it's what makes a finding actionable. Reporters: `text` (CLI), `json`, **`sarif`** (for CI / GitHub code scanning), `html` (human report). Map severity to CVSS v3.1 where sensible.

---

## 11. Phased roadmap

### Phase 0 — Setup & research
- Repo scaffold, `pyproject.toml`, CI lint/test.
- Read PyT, Bandit, Semgrep taint docs. Write a 1-page design note.
- Build `tests/vulnerable_samples/` with **labeled** ground-truth vulns (small Flask snippets) and `tests/safe_samples/` (must yield zero findings).

### Phase 1 — MVP (intraprocedural, single concern)
- Ingestion + `ast` parsing + symbol table (import resolution).
- CFG builder for functions (handle `if`/`while`/`for`/`return`).
- Taint engine: intraprocedural, worklist fixed-point with join at merges.
- Two vuln classes: **SQL Injection** + **Command Injection** (with `tainted_args` and `conditions`).
- Sources/sinks/sanitizers loaded from YAML.
- `text` + `json` reporters.
- **Exit criterion:** detects the SQLi/cmd-injection samples, zero findings on matching safe samples (incl. the parameterized-query and `shell=False` cases).

### Phase 2 — Breadth
- Add vuln classes: XSS, code injection, path traversal, SSRF, insecure deserialization, open redirect.
- Multi-file project handling (module map).
- Robust string-building propagation (f-strings, `.format`, `%`).
- HTML reporter.

### Phase 3 — Depth (interprocedural)
- Call graph construction.
- Interprocedural taint via **function summaries** (taint-in → taint-out).
- Proper sanitizer modeling per vuln class.
- Migrate to `astroid` for name resolution and cross-module inference.

### Phase 4 — Productionization
- **SARIF** output + GitHub Action / CI integration.
- Severity/CVSS mapping, suppression comments (`# nosast`), baseline diffing.
- Evaluation harness: precision / recall / F1 against ground truth.
- CLI UX polish, README, usage docs.

### Phase 5 — Stretch
- Django + FastAPI source/sink packs.
- Jinja2 template analysis for XSS (`|safe`, autoescape off).
- Path-sensitivity, basic alias analysis.

---

## 12. Testing & evaluation strategy

- **Ground truth corpus:** each vulnerable sample annotated with expected `(file, line, vuln_class)`. Each safe sample must produce zero findings.
- **Safe samples must include the tricky negatives:** parameterized queries, `shell=False`, `yaml.safe_load`, escaped output. These are where precision is won or lost.
- **Metrics:** precision, recall, F1 per vuln class; track false-positive rate as a first-class metric.
- **Regression:** run the full corpus in CI on every commit.
- Optionally validate against a known intentionally-vulnerable Flask app for realism.

---

## 13. Conventions for Claude Code

- Build **strictly phase by phase**; do not jump ahead to interprocedural analysis before the MVP works end-to-end.
- Keep the **engine generic and data-driven**: detection logic comes from YAML, never hardcoded in the engine.
- Keep **detection rules (YAML)** and **propagation rules (transfer functions, code)** clearly separated — section 7 vs section 9.
- The taint engine **traverses the CFG**; data flow is computed by transfer functions during traversal. Don't build a separate DFG object in the MVP unless a clear need appears.
- Every new vuln class = a YAML entry + a labeled vulnerable sample + a safe counterpart. No rule without a test.
- Always resolve imports (symbol table) before matching patterns — never match on raw source text.
- Prefer small, well-typed functions; type hints throughout; docstrings on public functions.
- When unsure about a propagation edge case, default to the **conservative (over-tainting)** choice and note it as a potential false positive.
