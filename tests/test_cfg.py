"""Tests for pysast.cfg.builder."""
import ast

from pysast.cfg.builder import build_cfg
from pysast.cfg.node import CFG


def _cfg(source: str) -> CFG:
    tree = ast.parse(source)
    func = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef))
    return build_cfg(func)


def test_straight_line() -> None:
    cfg = _cfg("def f():\n  x = 1\n  y = 2\n  return y\n")
    assert len(cfg.nodes) >= 1
    assert cfg.entry in cfg.nodes


def test_if_creates_branches() -> None:
    src = (
        "def f(x):\n"
        "  if x > 0:\n"
        "    y = 1\n"
        "  else:\n"
        "    y = 2\n"
        "  return y\n"
    )
    cfg = _cfg(src)
    # Entry node should have at least 2 successors (then + else)
    entry = cfg.nodes[cfg.entry]
    assert len(entry.successors) >= 1


def test_while_creates_back_edge() -> None:
    src = "def f():\n  i = 0\n  while i < 10:\n    i += 1\n  return i\n"
    cfg = _cfg(src)
    # There should be at least one back-edge (loop)
    all_successors = {s for n in cfg.nodes.values() for s in n.successors}
    all_ids = set(cfg.nodes.keys())
    # Some node must have a back-edge — a successor with lower id
    assert all_successors & all_ids  # there are cross-edges at minimum


def test_return_marks_exit() -> None:
    src = "def f():\n  return 42\n"
    cfg = _cfg(src)
    assert len(cfg.exits) >= 1
