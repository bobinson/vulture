"""Feature 0102, A44 (1) (b) as refined after its first acceptance measurement (LLD §8.2, §8.8).

(b) makes a generic container word a request source only in request context — a member of a
request-rooted chain, or a parameter of a function in handler context — and leaves the
implementer to find every word that behaves like ``params`` in the evidence. Measuring the
rules on real public code found the same shape twice more:

- a container word among a parameter's TYPE words (W4; in TypeScript an inline object type's
  member names, ``opts: { target: string; payload: string }``) named a request outside
  handler context. From a bare name it now counts only where the parameter's name would; from
  a qualified type path (an extractor type, ``web::Query<T>``) and from a decorator or
  default-call mark it is unchanged, each being the framework's own request annotation;
- ``cookie``/``cookies`` and ``header``/``headers`` name a request's containers as ``query``
  and ``body`` do: a helper's ``cookieName`` or ``headers`` parameter is ``unknown(param)``,
  while ``req.cookies.theme`` and a handler's parameter stay requests.

Each case is an ``ast_v1`` row (identifiers renamed). RED until the refinement lands: each
negative is reported today; each positive passes today and pins the recall it must keep.
"""

from __future__ import annotations

import pytest

from tests.unit.ast._analysis import Spec, external, externals, unknown

# the (b) readers of the rule's own module: one reading of "origins at" and "reported"
from tests.unit.ast.test_0102_precision_a44 import _origins_at, _reported

pytestmark = pytest.mark.usefixtures("real_pool")

# (subject, family, the sink CALL's head as ``call_head`` reads it)
_OUTSIDE: dict[str, tuple[Spec, str, str]] = {
    "inline_type_member": ("cwe_22_67_clean", "path", "fs.writeFile"),
    "cookie_name": ("cwe_22_69_clean", "path", "fs.unlink"),
    "headers": ("cwe_918_25_clean", "request", "fetch"),
}
_INSIDE: dict[str, tuple[Spec, str, str]] = {
    "inline_type_member_in_a_handler": ("cwe_22_68", "path", "fs.appendFile"),
    "cookies_in_a_request_chain": ("cwe_22_70", "path", "res.sendFile"),
    # a qualified extractor type path is the framework's request annotation itself
    "qualified_extractor_type": ("cwe_22_rs_1", "path", "fs::read_to_string"),
}


@pytest.mark.parametrize("case", list(_OUTSIDE))
def test_a_container_word_outside_handler_context_is_unknown_param(case: str) -> None:
    """Negative: the sink stays a sink, its argument is ``unknown(param)`` with no external
    origin, so ``decide`` reports nothing."""
    spec, family, head = _OUTSIDE[case]
    origins = _origins_at(spec, family, head)
    assert (externals(origins), unknown("param") in origins) == (frozenset(), True)
    assert not _reported(spec, family, head)


@pytest.mark.parametrize("case", list(_INSIDE))
def test_a_container_word_in_request_context_stays_a_request(case: str) -> None:
    """Positive: in handler context, or as a member of a request-rooted chain, it is a request."""
    spec, family, head = _INSIDE[case]
    assert external("request") in _origins_at(spec, family, head)
    assert _reported(spec, family, head)
