"""What a footprint counts (feature 0102, LLD §6.2, A17, A35): the rules both estimates share.

``FileModel.bytes_estimate`` (A17) and ``FlowAnalysis.bytes_estimate`` (A35) each sum
``sys.getsizeof`` over what their object holds of its own. An int is one only above the range
CPython shares, and an object held twice is one object: both estimates read those two facts
here, so they count by one rule. This module imports only ``sys``.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable, Iterator

__all__ = ["INT_SIZE", "SHARED_INTS", "own_int_count", "own_ints", "sized_once"]

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


def sized_once(objects: Iterable[object]) -> int:
    """``sys.getsizeof`` summed over ``objects``, each object once (by identity: a record
    another record also holds is counted once)."""
    held = {id(kept): kept for kept in objects}
    return sum(map(sys.getsizeof, held.values()))
