"""Import resolution — build a symbol table mapping local names to qualified names."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field


@dataclass
class SymbolTable:
    """Maps local variable/alias names to their fully-qualified module paths.

    Examples after ``from flask import request`` and ``import os as o``:
        table["request"] == "flask.request"
        table["o"]       == "os"
    """

    table: dict[str, str] = field(default_factory=dict)

    def get(self, name: str) -> str | None:
        return self.table.get(name)

    def qualify(self, name: str) -> str:
        """Return the qualified name for *name*, or *name* unchanged if unknown."""
        return self.table.get(name, name)


def build_symbol_table(module: ast.Module) -> SymbolTable:
    """Walk top-level and function-level import statements and populate a SymbolTable."""
    st = SymbolTable()
    for node in ast.walk(module):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name
                st.table[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            module_name = node.module or ""
            for alias in node.names:
                local = alias.asname if alias.asname else alias.name
                qualified = f"{module_name}.{alias.name}" if module_name else alias.name
                st.table[local] = qualified
    return st


def resolve_qualified_name(node: ast.expr, table: SymbolTable) -> str | None:
    """Resolve an AST expression to a dotted qualified name using *table*.

    Handles:
    - ``ast.Name``       — bare name (``system``, ``request``)
    - ``ast.Attribute``  — attribute access (``os.system``, ``request.args``)

    Returns ``None`` for unresolvable expressions.
    """
    if isinstance(node, ast.Name):
        return table.qualify(node.id)
    if isinstance(node, ast.Attribute):
        base = resolve_qualified_name(node.value, table)
        if base is not None:
            return f"{base}.{node.attr}"
    return None
