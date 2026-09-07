"""PromptSpec — what one call site asks for. Feature 0089 §3.3.

Fragment ids are listed EXPLICITLY, one per line, at every call site. No
tier-level inheritance: a prior shared-resolver design in this repo lost on
its own metrics partly because it hid what each call site actually passed
(`shared/audit_kwargs.py:10-15`). The library shares the TEXT; the call site
stays greppable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class PromptSpec:
    id: str
    tier: str
    fragments: tuple[str, ...]
    version: int = 1
    user_fragments: tuple[str, ...] = ()
    schema_fields: tuple[str, ...] = ()
    vocabulary: tuple[tuple[str, tuple[str, ...]], ...] = ()
    tools: tuple[str, ...] = ()
    slots: tuple[Any, ...] = ()
    # Untrusted channels this call site feeds, by `slots.KINDS` name, declared
    # even when the bytes are supplied at runtime. Feature 0089 item 4.3.
    #
    # `slots` cannot serve: it carries CONTENT, and the judge's DESC/CODE bytes
    # are built per finding inside `_render_user_message` while its TOOL bytes
    # arrive mid-loop from an executor. None of the three can be a value in a
    # module-level spec, so a linter reading only `slots` sees a judge with no
    # untrusted input at all — which is how a policy naming two marker pairs
    # went four tiers without anyone noticing it named neither of the channels
    # carrying the most attacker-controlled bytes.
    #
    # A declaration rather than an inference for the reason `declares_fields`
    # is one: `check_05_slot_marking` compares what the call site says it feeds
    # against what the render's MARKS_UNTRUSTED fragment says it covers, and
    # neither side can be derived from the other.
    channels: tuple[str, ...] = ()
    variables: dict[str, Any] = field(default_factory=dict)
    # Owned, explained exemptions from promptlint — `lint.LintAllow` entries,
    # read by `lint.gate()`. Typed `Any` for the same reason `slots` is: this
    # module is the call-site contract and imports nothing from the package, so
    # the lint layer can depend on the spec without the spec depending back.
    #
    # On the SPEC rather than in one central table because the exemption and
    # the fragment list it excuses have to be edited together: a fragment
    # removed from a manifest whose allow entry stays behind is exactly the
    # stale annotation `gate()` reports.
    allow: tuple[Any, ...] = ()
