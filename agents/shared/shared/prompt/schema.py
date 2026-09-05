"""OutputSchema — the single authority for the fields a prompt may ask for.

Feature 0089 §3.5. Today the same field list exists three times: as the prose
sentence in ``_field_contract()``, as the pydantic projection in
``_model_visible_output()``, and again as the unstructured branch's own
hand-written copy (``audit_runner.py:3295``). Three copies drift, and the way
they drift is silent — the prompt asks for a field the parser discards, or the
parser accepts one the prompt never named.

One definition here, three renderings out:

* ``as_required_field_list()`` — the prose contract, for ``Structured.NONE``
* ``as_json_schema()``         — the dict for ``response_format`` json_schema
* ``field_names()``            — what ``lint.check_01_orphan_field`` reads

(``as_field_list()`` renders the full surface including optional fields; it is
not the prose sentence — see its docstring.)

The two real schemas below are transcribed from the CODE that owns them:
``audit_runner._MODEL_VISIBLE_FIELDS`` (+ ``evidence_quote``) and the
whitelist ``llm_judge._coerce_verdict`` rebuilds. They are transcribed rather
than imported so that this library stays free of the audit runtime; the
transcription is guarded against drift by
``tests/unit/prompt/test_0089_schema_budget.py``, which asserts against the
imported constant.
"""

from __future__ import annotations

from dataclasses import dataclass

# JSON Schema types, spelled once. A field's `type` must be one of these.
STRING = "string"
INTEGER = "integer"
NUMBER = "number"
BOOLEAN = "boolean"


@dataclass(frozen=True)
class Field:
    """One field the model may emit."""

    name: str
    type: str = STRING
    description: str = ""
    required: bool = True
    enum: tuple[str, ...] = ()

    def as_property(self) -> dict:
        """This field as a JSON Schema property node."""
        node: dict = {"type": self.type}
        if self.description:
            node["description"] = self.description
        if self.enum:
            node["enum"] = list(self.enum)
        return node


@dataclass(frozen=True)
class OutputSchema:
    """A named list of fields, rendered three ways.

    ``array_key`` is the object key holding the array of items — ``findings``
    for GENERATE, ``verdicts`` for VALIDATE — because both call sites return a
    list wrapped in an object, never a bare array.
    """

    id: str
    array_key: str
    fields: tuple[Field, ...]

    def __post_init__(self) -> None:
        if not self.fields:
            raise ValueError(f"OutputSchema {self.id!r}: no fields")
        names = [f.name for f in self.fields]
        if len(set(names)) != len(names):
            raise ValueError(f"OutputSchema {self.id!r}: duplicate field name")

    # ── the three renderings ───────────────────────────────────────────────

    def field_names(self) -> frozenset[str]:
        """The field set, for ``lint.check_01_orphan_field``."""
        return frozenset(f.name for f in self.fields)

    def as_field_list(self) -> str:
        """EVERY field, in declaration order — the schema's full surface.

        NOT the prose contract sentence: that sentence names only the fields
        the model must always emit. Use :meth:`as_required_field_list` to
        render prose; this one is for describing the whole shape.
        """
        return ", ".join(f.name for f in self.fields)

    def as_required_field_list(self) -> str:
        """The prose contract sentence's field list, in declaration order.

        Only the ``required`` fields. The shipped sentence
        (``audit_runner.py:3295``, and ``_field_contract()``) names exactly
        these eight, and an optional field is *not* a member of it: the quote
        is asked for by its own ``_quote_required()``-gated obligation
        sentence, so folding it in here would both change the bytes Phase 1
        must reproduce and request it when the switch is off.
        """
        return ", ".join(f.name for f in self.fields if f.required)

    def as_json_schema(self) -> dict:
        """A ``response_format`` json_schema payload for this shape."""
        return {
            "name": self.id,
            "schema": {
                "type": "object",
                "properties": {self.array_key: {
                    "type": "array",
                    "items": self._item_schema(),
                }},
                "required": [self.array_key],
                "additionalProperties": False,
            },
        }

    # ── internals ──────────────────────────────────────────────────────────

    def _item_schema(self) -> dict:
        return {
            "type": "object",
            "properties": {f.name: f.as_property() for f in self.fields},
            "required": [f.name for f in self.fields if f.required],
            "additionalProperties": False,
        }


# ── The two real schemas ───────────────────────────────────────────────────

# GENERATE. The eight fields of ``audit_runner._MODEL_VISIBLE_FIELDS``, in that
# order, plus ``evidence_quote`` (0076 §5.2) — which is admitted here because
# the field IS asked of the model; it is stripped at the parse choke point, not
# at the prompt. ``code_snippet`` and ``check_id`` are deliberately ABSENT: the
# first is a source-read artefact and a model-authored copy is indistinguishable
# from a real read, the second keys the dedup identity and is never persisted.
FINDING_SCHEMA = OutputSchema(
    id="finding",
    array_key="findings",
    fields=(
        Field("severity", STRING),
        Field("category", STRING),
        Field("title", STRING),
        Field("description", STRING),
        Field("file_path", STRING),
        Field("line_start", INTEGER),
        Field("line_end", INTEGER),
        Field("recommendation", STRING),
        # Not `required`: a finding without a quote is reported as unverified,
        # never suppressed (0076 AC20), so the schema must admit its absence.
        Field("evidence_quote", STRING, required=False),
    ),
)

# VALIDATE (L5). Exactly the keys ``llm_judge._coerce_verdict`` rebuilds; a key
# not named there is dropped in silence, which is how the closure gate first
# shipped inert. ``id`` and ``exploitable`` are the two the coercion refuses a
# verdict without.
VERDICT_SCHEMA = OutputSchema(
    id="verdict",
    array_key="verdicts",
    fields=(
        Field("id", STRING),
        Field("exploitable", NUMBER),
        Field("window_sufficient", BOOLEAN, required=False),
        Field("evidence_line", INTEGER, required=False),
        Field("reasoning", STRING, required=False),
    ),
)

SCHEMAS: dict[str, OutputSchema] = {
    FINDING_SCHEMA.id: FINDING_SCHEMA,
    VERDICT_SCHEMA.id: VERDICT_SCHEMA,
}

__all__ = [
    "BOOLEAN", "FINDING_SCHEMA", "INTEGER", "NUMBER", "SCHEMAS", "STRING",
    "VERDICT_SCHEMA", "Field", "OutputSchema",
]
