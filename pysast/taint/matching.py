"""Pattern matching — test whether a call node matches a source/sink/sanitizer pattern."""

from __future__ import annotations

import ast
from typing import Any

from pysast.symbols import SymbolTable, resolve_qualified_name


def matches_pattern(call: ast.Call, pattern: str, table: SymbolTable) -> bool:
    """Return True if *call* matches *pattern*.

    Two pattern philosophies (spec §7.3):
    - ``*.method``       — heuristic: match on the attribute name only.
    - ``qualified.name`` — precise: resolve the call target and compare exactly.
    """
    if pattern.startswith("*."):
        method = pattern[2:]
        return isinstance(call.func, ast.Attribute) and call.func.attr == method

    qname = resolve_qualified_name(call.func, table)
    return qname == pattern


def matches_attr_access(node: ast.expr, pattern: str, table: SymbolTable) -> bool:
    """Return True if an attribute-access expression (not a call) matches *pattern*.

    Used to detect source patterns like ``flask.request.args`` which are accesses,
    not calls.
    """
    qname = resolve_qualified_name(node, table)
    return qname == pattern


def check_conditions(call: ast.Call, conditions: list[dict[str, Any]]) -> bool:
    """Return True if all *conditions* are satisfied by *call*'s keyword arguments.

    Each condition has the form ``{kwarg: "shell", equals: true}``.
    A condition is met when the matching keyword argument has the expected value.
    Missing keyword arguments cause the condition to fail.
    """
    for cond in conditions:
        kwarg_name: str = cond["kwarg"]
        expected: Any = cond["equals"]
        value = _get_kwarg_value(call, kwarg_name)
        if value is None:
            return False
        if not _literal_equals(value, expected):
            return False
    return True


def _get_kwarg_value(call: ast.Call, name: str) -> ast.expr | None:
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _literal_equals(node: ast.expr, expected: Any) -> bool:
    """Compare a literal AST node against a Python value.

    Handles constants (True/False, numbers, strings) and bare Name nodes
    so that conditions like ``Loader=SafeLoader`` work correctly.
    """
    if isinstance(expected, bool):
        return isinstance(node, ast.Constant) and node.value is expected
    if isinstance(expected, (int, float, str)):
        if isinstance(node, ast.Constant) and node.value == expected:
            return True
        # Name node: e.g. Loader=SafeLoader where expected == "SafeLoader"
        if isinstance(node, ast.Name) and node.id == str(expected):
            return True
    return False
