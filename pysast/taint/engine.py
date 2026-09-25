"""Worklist fixed-point taint engine — traverses the CFG and runs transfer functions."""

from __future__ import annotations

from collections import deque
from typing import TYPE_CHECKING

from pysast.cfg.node import CFG
from pysast.findings import Finding
from pysast.symbols import SymbolTable
from pysast.taint.lattice import TaintState, copy_state, join, states_equal
from pysast.taint.transfer import apply_transfer

if TYPE_CHECKING:
    from pysast.knowledge.loader import RuleSet


def run_taint(
    cfg: CFG,
    table: SymbolTable,
    rules: "RuleSet",
    filename: str = "<unknown>",
) -> list[Finding]:
    """Run the worklist fixed-point taint analysis over *cfg*.

    Algorithm:
    1. Start with an empty taint state at the entry node.
    2. Process each node: apply transfer functions for every statement.
    3. At successors, join the outgoing state with the existing in-state.
    4. Re-enqueue successors if their in-state changed.
    5. Collect and return all findings from all transfer-function invocations.
    """
    if not cfg.nodes:
        return []

    # in_states[node_id] = taint state on entry to that node
    in_states: dict[int, TaintState] = {nid: {} for nid in cfg.nodes}
    all_findings: list[Finding] = []

    worklist: deque[int] = deque([cfg.entry])
    enqueued: set[int] = {cfg.entry}

    while worklist:
        node_id = worklist.popleft()
        enqueued.discard(node_id)

        node = cfg.nodes[node_id]
        state = copy_state(in_states[node_id])

        # Process each statement in the basic block
        for stmt in node.stmts:
            state, findings = apply_transfer(stmt, state, table, rules, filename)
            all_findings.extend(findings)

        # Propagate out-state to successors
        for succ_id in node.successors:
            old_in = in_states[succ_id]
            new_in = join(old_in, state)
            if not states_equal(old_in, new_in):
                in_states[succ_id] = new_in
                if succ_id not in enqueued:
                    worklist.append(succ_id)
                    enqueued.add(succ_id)

    return all_findings


def analyse_module(
    module_ast: "object",
    table: SymbolTable,
    rules: "RuleSet",
    filename: str = "<unknown>",
) -> list[Finding]:
    """Analyse all functions in a module AST and return aggregated findings."""
    import ast

    from pysast.cfg.builder import build_cfg

    if not isinstance(module_ast, ast.Module):
        return []

    findings: list[Finding] = []
    for node in ast.walk(module_ast):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            cfg = build_cfg(node)
            findings.extend(run_taint(cfg, table, rules, filename))
    return findings
