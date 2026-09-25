"""Taint lattice — the abstract state tracked at each CFG node."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class TaintLabel:
    """Identifies taint flowing from a specific source, relevant to specific vuln classes."""

    source_id: str
    vuln_classes: frozenset[str]
    origin_file: str
    origin_line: int

    def __repr__(self) -> str:
        classes = set(self.vuln_classes)
        return f"TaintLabel({self.source_id!r}, {classes}, {self.origin_file}:{self.origin_line})"


# Maps variable name → set of taint labels reaching it at this program point.
TaintState = dict[str, set[TaintLabel]]


def join(a: TaintState, b: TaintState) -> TaintState:
    """Union two taint states at a CFG merge point."""
    result: TaintState = {k: set(v) for k, v in a.items()}
    for var, labels in b.items():
        if var in result:
            result[var] = result[var] | labels
        else:
            result[var] = set(labels)
    return result


def states_equal(a: TaintState, b: TaintState) -> bool:
    """Return True iff *a* and *b* contain the same taint labels for every variable."""
    if set(a.keys()) != set(b.keys()):
        return False
    return all(a[k] == b[k] for k in a)


def is_tainted(var: str, state: TaintState) -> bool:
    return bool(state.get(var))


def copy_state(state: TaintState) -> TaintState:
    return {k: set(v) for k, v in state.items()}
