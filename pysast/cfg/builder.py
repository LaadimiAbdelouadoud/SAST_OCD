"""Build a CFG from a Python function AST node."""

from __future__ import annotations

import ast

from pysast.cfg.node import CFG, CFGNode


class CFGBuilder:
    """Constructs a CFG for a single function definition."""

    def __init__(self, func_name: str) -> None:
        self._func_name = func_name
        self._counter = 0
        self._cfg = CFG(func_name=func_name)

    def _new_node(self) -> CFGNode:
        node = CFGNode(id=self._counter)
        self._counter += 1
        self._cfg.add_node(node)
        return node

    def build(self, stmts: list[ast.stmt]) -> tuple[CFGNode, list[CFGNode]]:
        """Build blocks for *stmts*.

        Returns (entry_block, exit_blocks) where exit_blocks are blocks that
        have no explicit successor yet (caller must wire them up).
        """
        entry = self._new_node()
        current = entry
        exits: list[CFGNode] = []

        for stmt in stmts:
            if isinstance(stmt, ast.Return):
                current.add_stmt(stmt)
                self._cfg.exits.append(current.id)
                exits = []
                current = self._new_node()
                return entry, exits

            elif isinstance(stmt, (ast.If,)):
                # Flush current into the if-test block, then branch
                current.add_stmt(stmt)
                then_entry, then_exits = self.build(stmt.body)
                self._cfg.add_edge(current.id, then_entry.id)

                if stmt.orelse:
                    else_entry, else_exits = self.build(stmt.orelse)
                    self._cfg.add_edge(current.id, else_entry.id)
                    merge = self._new_node()
                    for b in then_exits:
                        self._cfg.add_edge(b.id, merge.id)
                    for b in else_exits:
                        self._cfg.add_edge(b.id, merge.id)
                    current = merge
                else:
                    merge = self._new_node()
                    for b in then_exits:
                        self._cfg.add_edge(b.id, merge.id)
                    self._cfg.add_edge(current.id, merge.id)
                    current = merge

            elif isinstance(stmt, (ast.While, ast.For)):
                # Loop: header → body back-edge → exit
                header = self._new_node()
                header.add_stmt(stmt)
                self._cfg.add_edge(current.id, header.id)

                body_stmts = stmt.body
                body_entry, body_exits = self.build(body_stmts)
                self._cfg.add_edge(header.id, body_entry.id)
                for b in body_exits:
                    self._cfg.add_edge(b.id, header.id)

                after_loop = self._new_node()
                self._cfg.add_edge(header.id, after_loop.id)
                current = after_loop

            elif isinstance(stmt, ast.Try):
                # Conservative: treat try body as straight-line, link to after
                try_entry, try_exits = self.build(stmt.body)
                self._cfg.add_edge(current.id, try_entry.id)
                after_try = self._new_node()
                for b in try_exits:
                    self._cfg.add_edge(b.id, after_try.id)
                if stmt.finalbody:
                    fin_entry, fin_exits = self.build(stmt.finalbody)
                    self._cfg.add_edge(after_try.id, fin_entry.id)
                    after_try = self._new_node()
                    for b in fin_exits:
                        self._cfg.add_edge(b.id, after_try.id)
                current = after_try

            else:
                current.add_stmt(stmt)

        return entry, [current]


def build_cfg(func: ast.FunctionDef | ast.AsyncFunctionDef) -> CFG:
    """Build and return a CFG for *func*."""
    builder = CFGBuilder(func.name)
    entry_block, exit_blocks = builder.build(func.body)
    builder._cfg.entry = entry_block.id
    for b in exit_blocks:
        if b.id not in builder._cfg.exits:
            builder._cfg.exits.append(b.id)
    return builder._cfg
