"""CFG data structures."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class CFGNode:
    """A basic block in the control flow graph."""

    id: int
    stmts: list[ast.stmt] = field(default_factory=list)
    successors: list[int] = field(default_factory=list)
    predecessors: list[int] = field(default_factory=list)

    def add_stmt(self, stmt: ast.stmt) -> None:
        self.stmts.append(stmt)


@dataclass
class CFG:
    """Control flow graph for a single function."""

    func_name: str
    nodes: dict[int, CFGNode] = field(default_factory=dict)
    entry: int = 0
    exits: list[int] = field(default_factory=list)

    def add_node(self, node: CFGNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, src: int, dst: int) -> None:
        self.nodes[src].successors.append(dst)
        self.nodes[dst].predecessors.append(src)

    def __len__(self) -> int:
        return len(self.nodes)
