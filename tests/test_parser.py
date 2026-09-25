"""Tests for pysast.parser."""
import ast

import pytest

from pysast.parser import ParseError, parse_module


def test_parse_valid_module() -> None:
    tree = parse_module("x = 1 + 2\n", filename="test.py")
    assert isinstance(tree, ast.Module)


def test_parse_syntax_error_raises() -> None:
    with pytest.raises(ParseError, match="test.py"):
        parse_module("def broken(\n", filename="test.py")


def test_parse_preserves_lineno() -> None:
    source = "a = 1\nb = 2\n"
    tree = parse_module(source)
    assign = tree.body[1]
    assert isinstance(assign, ast.Assign)
    assert assign.lineno == 2
