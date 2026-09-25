"""Tests for pysast.symbols — import resolution."""
import ast

from pysast.parser import parse_module
from pysast.symbols import build_symbol_table, resolve_qualified_name


def _table(source: str):  # type: ignore[return]
    tree = parse_module(source)
    return build_symbol_table(tree)


def test_import_simple() -> None:
    st = _table("import os")
    assert st.qualify("os") == "os"


def test_import_alias() -> None:
    st = _table("import os as o")
    assert st.qualify("o") == "os"
    assert st.get("os") is None


def test_from_import() -> None:
    st = _table("from os import system")
    assert st.qualify("system") == "os.system"


def test_from_import_alias() -> None:
    st = _table("from os import system as sys_call")
    assert st.qualify("sys_call") == "os.system"


def test_flask_request() -> None:
    st = _table("from flask import request")
    assert st.qualify("request") == "flask.request"


def test_resolve_attribute_node() -> None:
    st = _table("import os")
    # Build an ast.Attribute node for "os.system"
    call_src = "os.system('x')"
    tree = parse_module(call_src)
    call_node = tree.body[0].value  # type: ignore[attr-defined]
    assert isinstance(call_node, ast.Call)
    result = resolve_qualified_name(call_node.func, st)
    assert result == "os.system"


def test_resolve_unknown_returns_name() -> None:
    st = _table("")
    node = ast.Name(id="unknown", ctx=ast.Load())
    assert resolve_qualified_name(node, st) == "unknown"
