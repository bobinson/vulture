"""Manifest registry — every call site's PromptSpec, keyed by spec id.

Discovered by walking this package rather than by a hand-maintained import
list. Six tiers are transcribed independently, and an explicit list is the one
place all six of them would have to edit: the manifest that never got added to
it renders fine in its own test and is invisible to the golden gate and to the
lint sweep, which is exactly the failure those two are supposed to catch.

Keyed on `spec.id`, not the module name, so the golden filename and the lint
report name the same thing the call site does. A duplicate id is fatal at
import, matching `registry.py`'s rule for fragment ids.

Manifests are Python, not YAML: a `PromptSpec(...)` literal is checked by the
type system and greppable, and `pyyaml` is not a dependency of this package.
"""

from __future__ import annotations

import importlib
import pkgutil

from ..spec import PromptSpec


def _specs_in(module) -> list[PromptSpec]:
    """Module-level PromptSpec literals, in definition order."""
    return [v for v in vars(module).values() if isinstance(v, PromptSpec)]


def _claim(out: dict[str, PromptSpec], spec: PromptSpec, where: str) -> None:
    if out.get(spec.id, spec) is not spec:
        raise RuntimeError(f"duplicate manifest id {spec.id!r}: {where}")
    out[spec.id] = spec


def _load() -> dict[str, PromptSpec]:
    out: dict[str, PromptSpec] = {}
    for info in sorted(pkgutil.iter_modules(__path__), key=lambda i: i.name):
        mod = importlib.import_module(f"{__name__}.{info.name}")
        for spec in _specs_in(mod):
            _claim(out, spec, info.name)
    return out


MANIFESTS: dict[str, PromptSpec] = _load()

__all__ = ["MANIFESTS"]
