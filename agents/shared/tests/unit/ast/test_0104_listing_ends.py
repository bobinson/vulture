"""Feature 0104 WS-C (LLD §4.3): a use that is no listing keeps the hinted function's probe.

``_Entries`` accounts a use of the function's name for a listing only when the nearest
listing end above it is an EXPORT or a CommonJS ASSIGN. A reference held by a class field, an
argument of a call or a function's return value is no listing, so the function stays reachable
another way and its bare probe still reports. A mutant that lists CLASS, CALL or FUNCTION among
the listing ends would decline these probes (``probe:param_hint``) and silence a real flow.

PINS (green on the tree that built WS-C): each shape reports the existence probe.
"""

from __future__ import annotations

import pytest

from tests.unit.ast._analysis import REPORT, subject, verdicts_at

pytestmark = pytest.mark.usefixtures("real_pool")

SINK = "fs.existsSync"
DEFINITION = """
    import fs from "node:fs";

    function present(filePath: string): boolean {
      return fs.existsSync(filePath);
    }
"""
REACHED = {
    "a class field holds it": "export class Shelf { static check = present; }",
    "a call takes it": "export default wrap(present);",
    "a function returns it": "export function lookup() { return present; }",
}


@pytest.mark.parametrize("shape", sorted(REACHED))
def test_a_reference_that_is_no_listing_keeps_the_probe(shape: str) -> None:
    source = f"{DEFINITION}\n    {REACHED[shape]}\n"
    assert verdicts_at(subject(("ts", source)), "path", SINK) == REPORT
