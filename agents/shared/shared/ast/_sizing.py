"""What a footprint counts (feature 0102, LLD §6.2, A17, A35): the rules both estimates share.

``FileModel.bytes_estimate`` (A17), ``FlowAnalysis.bytes_estimate`` (A35) and
``FileAnswer.bytes_estimate`` (§4.1 item 3) each sum ``sys.getsizeof`` over what their object
holds of its own. An int is one only above the range CPython shares, a string only when it is
longer than the one character CPython shares, and an object held twice is one object: every
estimate reads those three facts here, and the two that hold flows count a flow's parts by one
rule (``flow_parts``). This module imports only ``sys``, ``itertools`` and ``typing``.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterable, Iterator
from itertools import chain
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from shared.ast._records import Flow

__all__ = [
    "INT_SIZE",
    "SHARED_INTS",
    "flow_parts",
    "own_int_count",
    "own_ints",
    "own_strs",
    "sized_once",
]

# CPython shares the small ints (-5..256): a node index, line or offset above them is an int
# object of its own, held by the record that names it.
SHARED_INTS = 256
INT_SIZE = sys.getsizeof(SHARED_INTS + 1)


def own_ints(values: Iterable[int]) -> Iterator[int]:
    """The ints of ``values`` that are objects of their own (above ``SHARED_INTS``)."""
    return filter(SHARED_INTS.__lt__, values)


def own_int_count(values: Iterable[int]) -> int:
    """How many ints of ``values`` are objects of their own."""
    return sum(map(SHARED_INTS.__lt__, values))


def own_strs(values: Iterable[str]) -> Iterator[str]:
    """The strings of ``values`` that are objects of their own: longer than one character
    (CPython shares the empty and the one-character strings)."""
    return (value for value in values if len(value) > 1)


def sized_once(objects: Iterable[object]) -> int:
    """``sys.getsizeof`` summed over ``objects``, each object once (by identity: a record
    another record also holds is counted once)."""
    held = {id(kept): kept for kept in objects}
    return sum(map(sys.getsizeof, held.values()))


def flow_parts(flow: Flow, own_name: Callable[[str], bool]) -> Iterator[object]:
    """One flow's own objects, an object held twice yielded twice: the record, its span, origin
    set and hops, its guards (a flow with none holds the shared ``()``), each hop and guard, the
    strings it holds of its own (``own_strs``) — each hop name ``own_name`` says is its holder's,
    and its sink key — and its own ints (``_flow_ints``). Origins and role sets are shared
    (``_records``)."""
    held = (flow, flow.span, flow.origins, flow.hops, *flow.hops, *flow.guards)
    guards = (flow.guards,) if flow.guards else ()
    names = filter(own_name, (hop.name for hop in flow.hops))
    return chain(held, guards, own_strs(chain(names, (flow.sink_key,))), _flow_ints(flow))


def _flow_ints(flow: Flow) -> Iterator[int]:
    """The ints a flow holds that are objects of their own (``own_ints``): its sink, sink line,
    argument and span, each hop's line, each guard's node."""
    lines = (hop.line for hop in flow.hops)
    nodes = (guard.node for guard in flow.guards)
    return own_ints(chain((flow.sink, flow.sink_line, flow.arg, *flow.span), lines, nodes))
