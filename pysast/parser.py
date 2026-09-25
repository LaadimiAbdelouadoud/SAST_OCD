"""Source code → AST."""

from __future__ import annotations

import ast


class ParseError(Exception):
    """Raised when a source file cannot be parsed."""


def parse_module(source: str, filename: str = "<unknown>") -> ast.Module:
    """Parse *source* into an AST module node.

    Raises ParseError wrapping the underlying SyntaxError.
    """
    try:
        tree = ast.parse(source, filename=filename, type_comments=False)
    except SyntaxError as exc:
        raise ParseError(f"{filename}: {exc}") from exc
    return tree
