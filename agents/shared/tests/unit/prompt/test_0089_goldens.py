"""Feature 0089 — the golden byte gate over EVERY manifest.

One test for all of them. A per-manifest test would let a set be added with no
golden and still be green; iterating `MANIFESTS` means a manifest that ships
without a committed golden fails here, naming the command that writes one.
"""

from __future__ import annotations

import importlib
import importlib.util
from pathlib import Path

import pytest

from shared.prompt import Mode, profile_for, render
from shared.prompt.manifests import MANIFESTS
from shared.prompt.spec import PromptSpec

_MANIFEST_ROOT = (
    Path(__file__).resolve().parents[3] / "shared" / "prompt" / "manifests"
)


def _load_capture():
    """Load the sibling capture script by path.

    `tests/unit/prompt/` is not a package, so a relative import would not
    resolve; loading by path also guarantees the test and the writer share one
    formatter — two copies of the layout would drift and the golden would then
    be testing the test.
    """
    path = Path(__file__).with_name("capture_goldens.py")
    spec = importlib.util.spec_from_file_location("_capture_goldens", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


_capture = _load_capture()


@pytest.mark.parametrize("manifest_id", sorted(MANIFESTS))
def test_golden_bytes_default_profile(manifest_id):
    """Re-render and compare bytes against the committed golden."""
    spec = MANIFESTS[manifest_id]
    path = _capture.golden_path(manifest_id)
    assert path.exists(), (
        f"no golden for manifest {manifest_id!r} at {path}; write it with:\n"
        f"    {_capture.CAPTURE_CMD}"
    )
    rp = render(spec, profile_for("gpt-4o"), mode=Mode.TRANSCRIBE)
    assert _capture.golden_text(spec, rp) == path.read_text(encoding="utf-8"), (
        f"{manifest_id} no longer renders to its golden; if the change is "
        f"intended, re-run:\n    {_capture.CAPTURE_CMD}"
    )


def _manifest_modules() -> list[Path]:
    """Every manifest module on disk, found recursively.

    Recursive on purpose: `MANIFESTS` is built with `pkgutil.iter_modules`,
    which is NOT, so a manifest added inside a subpackage
    (`manifests/generate/cwe.py`) would be absent from the registry, absent
    from the golden gate, and absent from the lint sweep while its own test
    stayed green. That is the exact hole the registry docstring says it
    closes, so it is asserted here rather than assumed.
    """
    return [p for p in sorted(_MANIFEST_ROOT.rglob("*.py")) if p.name != "__init__.py"]


def _dotted(path: Path) -> str:
    rel = path.relative_to(_MANIFEST_ROOT).with_suffix("")
    return "shared.prompt.manifests." + ".".join(rel.parts)


def _module_specs(path: Path) -> list[PromptSpec] | str:
    """This module's module-level specs, or why they could not be collected."""
    try:
        mod = importlib.import_module(_dotted(path))
    except ImportError as exc:                       # e.g. subpackage with no __init__
        return f"not importable ({exc})"
    specs = [v for v in vars(mod).values() if isinstance(v, PromptSpec)]
    return specs or "defines no module-level PromptSpec"


def _unreachable(path: Path) -> list[str]:
    """Spec ids this module defines that `MANIFESTS` does not resolve to it."""
    specs = _module_specs(path)
    if isinstance(specs, str):
        return [f"{path.name}: {specs}"]
    return [f"{path.name}: {s.id!r}" for s in specs if MANIFESTS.get(s.id) is not s]


def test_every_manifest_module_reaches_the_registry():
    """No module under `manifests/` may define specs the registry cannot see.

    Imports each module and compares by IDENTITY, not by id string, so a
    module whose spec is shadowed by a same-id spec from another module fails
    here too — that is the duplicate `_claim` is meant to make fatal.
    """
    missing = [m for path in _manifest_modules() for m in _unreachable(path)]
    assert not missing, (
        "manifest module(s) not reachable via shared.prompt.manifests.MANIFESTS: "
        f"{missing}"
    )
