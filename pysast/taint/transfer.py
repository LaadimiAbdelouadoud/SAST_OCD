"""Transfer functions — how taint propagates through each AST statement."""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from pysast.findings import Finding, FlowStep
from pysast.symbols import SymbolTable
from pysast.taint.lattice import TaintLabel, TaintState, copy_state
from pysast.taint.matching import check_conditions, matches_attr_access, matches_pattern

if TYPE_CHECKING:
    from pysast.knowledge.loader import RuleSet


def apply_transfer(
    stmt: ast.stmt,
    state: TaintState,
    table: SymbolTable,
    rules: "RuleSet",
    filename: str = "<unknown>",
) -> tuple[TaintState, list[Finding]]:
    """Apply the transfer function for *stmt* to *state*.

    Returns (new_state, findings_emitted).
    The returned state is a new copy — never mutates the input.
    """
    new_state = copy_state(state)
    findings: list[Finding] = []

    if isinstance(stmt, ast.Assign):
        if isinstance(stmt.value, ast.Call):
            findings.extend(_handle_call(stmt.value, state, table, rules, filename, lhs_name=None))
        for target in stmt.targets:
            labels = taint_expr(stmt.value, state, table, rules, filename)
            _assign_target(target, labels, new_state)

    elif isinstance(stmt, ast.AugAssign):
        existing = state.get(_target_name(stmt.target), set())
        labels = taint_expr(stmt.value, state, table, rules, filename) | existing
        _assign_target(stmt.target, labels, new_state)

    elif isinstance(stmt, ast.AnnAssign):
        if stmt.value is not None:
            if isinstance(stmt.value, ast.Call):
                findings.extend(
                    _handle_call(stmt.value, state, table, rules, filename, lhs_name=None)
                )
            labels = taint_expr(stmt.value, state, table, rules, filename)
            if stmt.target is not None:
                _assign_target(stmt.target, labels, new_state)

    elif isinstance(stmt, ast.Expr):
        if isinstance(stmt.value, ast.Call):
            call_findings = _handle_call(
                stmt.value, state, table, rules, filename, lhs_name=None
            )
            findings.extend(call_findings)

    elif isinstance(stmt, ast.Return):
        # Check if the returned call is a sink (e.g. return render_template_string(...))
        if isinstance(stmt.value, ast.Call):
            findings.extend(
                _handle_call(stmt.value, state, table, rules, filename, lhs_name=None)
            )

    return new_state, findings


# ──────────────────────────────────────────────────────────────────────────────
# Expression taint computation
# ──────────────────────────────────────────────────────────────────────────────


def taint_expr(
    expr: ast.expr,
    state: TaintState,
    table: SymbolTable,
    rules: "RuleSet",
    filename: str = "<unknown>",
) -> set[TaintLabel]:
    """Compute the set of taint labels that reach *expr*."""

    if isinstance(expr, ast.Name):
        # Source: check if this name is a source pattern (e.g. bare 'request')
        labels = _source_labels_for_expr(expr, state, table, rules, filename)
        labels |= state.get(expr.id, set())
        return labels

    if isinstance(expr, ast.Attribute):
        # Source patterns like flask.request.args
        labels = _source_labels_for_expr(expr, state, table, rules, filename)
        # Propagate: if the base object is tainted, the attribute is too
        labels |= taint_expr(expr.value, state, table, rules, filename)
        return labels

    if isinstance(expr, ast.Subscript):
        # x[i] — tainted if x is tainted
        return taint_expr(expr.value, state, table, rules, filename)

    if isinstance(expr, ast.BinOp):
        # String concatenation and arithmetic propagate taint
        left = taint_expr(expr.left, state, table, rules, filename)
        right = taint_expr(expr.right, state, table, rules, filename)
        return left | right

    if isinstance(expr, (ast.JoinedStr,)):
        # f-strings: taint union of all interpolated values
        fstr_labels: set[TaintLabel] = set()
        for val in expr.values:
            if isinstance(val, ast.FormattedValue):
                fstr_labels |= taint_expr(val.value, state, table, rules, filename)
        return fstr_labels

    if isinstance(expr, ast.Call):
        return _taint_call_result(expr, state, table, rules, filename)

    if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
        labels = set()
        for elt in expr.elts:
            labels |= taint_expr(elt, state, table, rules, filename)
        return labels

    if isinstance(expr, ast.Dict):
        labels = set()
        for k in expr.keys:
            if k is not None:
                labels |= taint_expr(k, state, table, rules, filename)
        for v in expr.values:
            labels |= taint_expr(v, state, table, rules, filename)
        return labels

    if isinstance(expr, ast.IfExp):
        # ternary: taint union of both branches (conservative)
        return taint_expr(expr.body, state, table, rules, filename) | taint_expr(
            expr.orelse, state, table, rules, filename
        )

    # Constant, NameConstant, Num, Str — no taint
    return set()


def _source_labels_for_expr(
    expr: ast.expr,
    state: TaintState,
    table: SymbolTable,
    rules: "RuleSet",
    filename: str,
) -> set[TaintLabel]:
    """Return taint labels if *expr* matches any source pattern."""
    labels: set[TaintLabel] = set()
    line = getattr(expr, "lineno", 0)
    for src in rules.sources:
        for pattern in src.patterns:
            if matches_attr_access(expr, pattern, table):
                labels.add(
                    TaintLabel(
                        source_id=src.id,
                        vuln_classes=frozenset(src.vuln_classes),
                        origin_file=filename,
                        origin_line=line,
                    )
                )
    return labels


def _taint_call_result(
    call: ast.Call,
    state: TaintState,
    table: SymbolTable,
    rules: "RuleSet",
    filename: str,
) -> set[TaintLabel]:
    """Compute taint for the *result* of a call expression.

    - Source call (e.g. request.args.get()) → return source taint labels.
    - Sanitizer → clears specific vuln_classes from all arg taint.
    - Otherwise → conservative: union of all arg taint.
    """
    # Check if the call itself is a source (e.g. request.args.get('id'))
    line = getattr(call, "lineno", 0)
    for src in rules.sources:
        for pattern in src.patterns:
            if matches_attr_access(call.func, pattern, table):
                return {
                    TaintLabel(
                        source_id=src.id,
                        vuln_classes=frozenset(src.vuln_classes),
                        origin_file=filename,
                        origin_line=line,
                    )
                }

    all_arg_taint: set[TaintLabel] = set()
    for arg in call.args:
        all_arg_taint |= taint_expr(arg, state, table, rules, filename)
    for kw in call.keywords:
        all_arg_taint |= taint_expr(kw.value, state, table, rules, filename)

    # Check sanitizers
    for san in rules.sanitizers:
        for pattern in san.patterns:
            if matches_pattern(call, pattern, table):
                clears = frozenset(san.clears)
                # Remove cleared vuln classes from all taint labels
                cleaned: set[TaintLabel] = set()
                for lbl in all_arg_taint:
                    remaining = lbl.vuln_classes - clears
                    if remaining:
                        cleaned.add(
                            TaintLabel(
                                source_id=lbl.source_id,
                                vuln_classes=remaining,
                                origin_file=lbl.origin_file,
                                origin_line=lbl.origin_line,
                            )
                        )
                return cleaned

    return all_arg_taint


def _handle_call(
    call: ast.Call,
    state: TaintState,
    table: SymbolTable,
    rules: "RuleSet",
    filename: str,
    lhs_name: str | None,
) -> list[Finding]:
    """Check whether *call* is a sink whose tainted_args receive tainted values."""
    findings: list[Finding] = []
    line = getattr(call, "lineno", 0)

    for sink in rules.sinks:
        for pattern in sink.patterns:
            if not matches_pattern(call, pattern, table):
                continue

            # Check conditions (e.g. shell=True for subprocess)
            if sink.conditions:
                cond_met = check_conditions(call, sink.conditions)
                if sink.negate_conditions:
                    if cond_met:
                        continue  # condition met means safe (e.g. yaml.load with SafeLoader)
                elif not cond_met:
                    continue

            # Check each tainted_arg position
            for arg_idx in sink.tainted_args:
                if arg_idx >= len(call.args):
                    continue
                arg_expr = call.args[arg_idx]
                labels = taint_expr(arg_expr, state, table, rules, filename)
                # Filter labels relevant to this sink's vuln_class
                relevant = {lbl for lbl in labels if sink.vuln_class in lbl.vuln_classes}
                if not relevant:
                    continue

                # Build data-flow path from the first matching label
                lbl = next(iter(relevant))
                source_step = FlowStep(
                    file=lbl.origin_file,
                    line=lbl.origin_line,
                    code=ast.unparse(arg_expr),
                )
                sink_step = FlowStep(
                    file=filename,
                    line=line,
                    code=ast.unparse(call),
                )
                findings.append(
                    Finding(
                        rule_id=f"PYSAST-{sink.id.upper()}",
                        vulnerability=sink.vulnerability,
                        cwe=sink.cwe,
                        owasp=sink.owasp,
                        severity=sink.severity,
                        cvss_v31=sink.cvss_v31,
                        file=filename,
                        sink_line=line,
                        sink_snippet=ast.unparse(call),
                        source=source_step,
                        data_flow=[source_step, sink_step],
                        remediation=sink.remediation.strip(),
                    )
                )
    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────


def _assign_target(target: ast.expr, labels: set[TaintLabel], state: TaintState) -> None:
    """Write *labels* into *state* for whatever variable(s) *target* names."""
    if isinstance(target, ast.Name):
        if labels:
            state[target.id] = labels
        else:
            state.pop(target.id, None)
    elif isinstance(target, (ast.Tuple, ast.List)):
        # Unpack: conservatively taint all targets if any label exists
        for elt in target.elts:
            _assign_target(elt, labels, state)


def _target_name(target: ast.expr) -> str:
    if isinstance(target, ast.Name):
        return target.id
    return ""
