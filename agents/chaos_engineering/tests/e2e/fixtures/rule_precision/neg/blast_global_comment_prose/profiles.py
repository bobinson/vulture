"""Builtin profiles for the path-sink roles."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Builtin:
    families: frozenset[str]


# A builtin that takes a path on every argument.
EVERY_ARG_PATH = Builtin(frozenset({"path"}))
# A language global that only shadows a sink word: its empty family set makes
# the callee no sink at all. Global names are resolved before this table.
NO_FAMILY = Builtin(frozenset())


def families_of(table: dict[str, Builtin], key: str) -> frozenset[str]:
    return table.get(key, NO_FAMILY).families
