"""Bound what a generate tool loop adds to each model request.

``VULTURE_LLM_MAX_BODY_BYTES`` bounds the source a generate request carries, but
every tool turn appended its output (a whole file read) with no bound, so the
conversation grew past the broker's own 1 MiB request cap: a 413, after which
the size retry halved a source that was not the cause (0074 verification item
15). ``bounded_model_input`` is the Agents SDK ``call_model_input_filter`` that
gives the tool outputs of a conversation the same byte budget the source gets:

1. a single output larger than a quarter of that budget is cut where it stands,
   with a marker asking for a narrower range;
2. while the outputs together exceed the budget, the OLDEST are replaced in
   place by an elision marker, so the newest reads survive.

A request is therefore at most its source plus one budget of tool output (twice
the cap, 256 KB by default), far below the broker's 1 MiB. Items are never
removed (a call without its output is rejected by providers), and the source
turn and the instructions are never touched. A cap of 0 or less disables it.
Each item is measured once per call.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

# No single output may take more than this share of the tool-output budget.
_PER_OUTPUT_SHARE = 4
_OUTPUT = "function_call_output"
_CUT_MARKER = "\n[... {n} bytes cut to keep the request under the size cap; read a narrower line range]"
_ELIDED = "[tool output elided: {n} bytes, to keep the request under the size cap]"


def _size(obj: Any) -> int:
    return len(json.dumps(obj, ensure_ascii=False, default=str).encode("utf-8"))


def _is_output(item: Any) -> bool:
    """A tool result: its ``output`` is a string or (structured) content parts."""
    return isinstance(item, dict) and item.get("type") == _OUTPUT and isinstance(item.get("output"), (str, list))


def _output_bytes(item: dict) -> int:
    output = item["output"]
    return len(output.encode("utf-8")) if isinstance(output, str) else _size(output)


def _with_output(item: dict, output: str) -> tuple[dict, int]:
    new = {**item, "output": output}
    return new, _size(new)


def _cut(item: dict, size: int, limit: int) -> tuple[dict, int]:
    """``item`` with its output shortened so the whole item fits ``limit``."""
    encoded = item["output"].encode("utf-8")
    keep = max(len(encoded) - (size - limit) - 128, 0)
    new, new_size = _kept(item, encoded, keep)
    for _ in range(3):  # JSON escaping can grow the kept text; shrink until it fits
        if new_size <= limit or keep == 0:
            break
        keep = max(keep - (new_size - limit) - 64, 0)
        new, new_size = _kept(item, encoded, keep)
    return new, new_size


def _kept(item: dict, encoded: bytes, keep: int) -> tuple[dict, int]:
    kept = encoded[:keep].decode("utf-8", errors="ignore")
    return _with_output(item, kept + _CUT_MARKER.format(n=len(encoded) - len(kept.encode("utf-8"))))


def bounded_model_input(data: Any) -> Any:
    """The ``call_model_input_filter``: tool outputs kept within one cap."""
    from shared.audit_runner import _get_max_body_bytes

    model_data = data.model_data
    budget = _get_max_body_bytes()
    if budget <= 0:
        return model_data
    outputs = [i for i, item in enumerate(model_data.input) if _is_output(item)]
    sizes = {i: _size(model_data.input[i]) for i in outputs}
    if sum(sizes.values()) <= budget:
        return model_data
    items = list(model_data.input)
    cut = _cut_oversized(items, sizes, max(budget // _PER_OUTPUT_SHARE, 1024))
    elided = _elide_oldest(items, sizes, budget)
    logger.info("llm_tool_output_bounded cut=%d elided=%d tool_bytes=%d budget=%d",
                cut, elided, sum(sizes.values()), budget)
    from agents.run_config import ModelInputData

    return ModelInputData(input=items, instructions=model_data.instructions)


def _cut_oversized(items: list, sizes: dict[int, int], limit: int) -> int:
    count = 0
    for i, size in sizes.items():
        if size > limit and isinstance(items[i]["output"], str):  # parts are elided whole
            items[i], sizes[i] = _cut(items[i], size, limit)
            count += 1
    return count


def _elide_oldest(items: list, sizes: dict[int, int], budget: int) -> int:
    total, count = sum(sizes.values()), 0
    for i, size in list(sizes.items()):  # conversation order: oldest first
        if total <= budget:
            break
        items[i], new_size = _with_output(items[i], _ELIDED.format(n=_output_bytes(items[i])))
        total += new_size - size
        sizes[i] = new_size
        count += 1
    return count
