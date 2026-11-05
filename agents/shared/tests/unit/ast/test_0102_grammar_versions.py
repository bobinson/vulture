"""Feature 0102 (LLD D15, D5, D19): the grammar version stamp.

The AST layer depends on ten wheels: the ``tree-sitter`` core and nine
grammars (D15, O7), declared once in ``agents/shared/pyproject.toml`` and
pinned in ``agents/requirements-frozen.txt``. ``shared.ast.profile`` reads
their installed versions ONCE (``GRAMMAR_VERSIONS``, D19) and derives
``GRAMMAR_PACK_VERSION`` from them. That stamp is part of the model-cache key
(D5), so a model built by one grammar can never be served after another is
installed. This module pins:

* ``GRAMMAR_VERSIONS`` holds exactly the ten packages, each at its installed
  ``importlib.metadata`` version; the ten are the declared and the locked set,
  and the installed versions are the locked pins (the versions the goldens were
  reviewed against);
* every profile's grammar module is a member of the pack;
* ``GRAMMAR_PACK_VERSION`` changes when ANY one of the ten changes, even by a
  post-release, and when two of them swap versions; it does not change for a
  package outside the pack, even a ``tree-sitter-*`` near-miss; it is the same
  in every interpreter (no ``hash()`` randomisation);
* the versions are computed in the parent only, lazily and once (A16): importing
  ``shared.ast.profile`` reads no distribution's metadata, the first access reads each
  package once, and a second reads nothing.

A version change is simulated without touching the environment: a FRESH
interpreter gets a temporary directory first on ``sys.path`` holding a
``<name>-<version>.dist-info`` for the package, which is the distribution
``importlib.metadata`` resolves first, exactly as Python resolves the shadowing
package's code first. ``shared.ast.profile`` never imports ``tree_sitter``
(D1), so nothing else is needed to import it there.
"""

from __future__ import annotations

import importlib.metadata
import itertools
import json
import os
import re
import subprocess
import sys
import tomllib
from collections.abc import Mapping
from pathlib import Path

import pytest

import shared.ast
from shared.ast.profile import GRAMMAR_PACK_VERSION, GRAMMAR_VERSIONS, PROFILES

# The ten locked packages (D15): the core and the nine v1 grammars.
PACK = (
    "tree-sitter",
    "tree-sitter-c",
    "tree-sitter-cpp",
    "tree-sitter-go",
    "tree-sitter-java",
    "tree-sitter-javascript",
    "tree-sitter-php",
    "tree-sitter-python",
    "tree-sitter-rust",
    "tree-sitter-typescript",
)

# agents/: this file is agents/shared/tests/unit/ast/test_0102_grammar_versions.py.
_AGENTS = Path(__file__).resolve().parents[4]
_SHARED_ROOT = _AGENTS / "shared"
_PYPROJECT = _SHARED_ROOT / "pyproject.toml"
_LOCKFILE = _AGENTS / "requirements-frozen.txt"

_PROBE = (
    "import json\n"
    "from shared.ast import profile\n"
    "print(json.dumps({'pack': repr(profile.GRAMMAR_PACK_VERSION),"
    " 'versions': dict(profile.GRAMMAR_VERSIONS)}))\n"
)


def _canonical(name: str) -> str:
    """PEP 503 name: lowercase, runs of ``-_.`` folded to ``-``."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _by_canonical_name(versions: Mapping[str, str]) -> dict[str, str]:
    return {_canonical(name): version for name, version in versions.items()}


def _installed() -> dict[str, str]:
    return {name: importlib.metadata.version(name) for name in PACK}


def _declared() -> set[str]:
    """The ``tree-sitter*`` requirements of ``agents/shared/pyproject.toml``."""
    requirements = tomllib.loads(_PYPROJECT.read_text(encoding="utf-8"))["project"]["dependencies"]
    names = {_canonical(re.split(r"[\s<>=!~;\[]", req, maxsplit=1)[0]) for req in requirements}
    return {name for name in names if name.startswith("tree-sitter")}


def _locked() -> dict[str, str]:
    """The ``tree-sitter*`` pins of ``agents/requirements-frozen.txt``."""
    pins = re.findall(
        r"^(tree[-_.]sitter[A-Za-z0-9._-]*)==([^\s;\\]+)",
        _LOCKFILE.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    return {_canonical(name): version for name, version in pins}


def _grammar_distribution(module: str) -> str:
    """The distribution that installs a grammar module (an independent mapping)."""
    owners = importlib.metadata.packages_distributions().get(module, [])
    assert len(owners) == 1, f"grammar module {module!r} is installed by {owners}"
    return _canonical(owners[0])


def _shadow(site: Path, versions: Mapping[str, str]) -> Path:
    """A sys.path entry whose dist-info makes ``name`` report ``version``."""
    site.mkdir(parents=True, exist_ok=True)
    for name, version in versions.items():
        info = site / f"{_canonical(name).replace('-', '_')}-{version}.dist-info"
        info.mkdir()
        (info / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n", encoding="utf-8"
        )
    return site


def _probe_env(site: Path, hash_seed: str) -> dict[str, str]:
    """This environment with ``site`` first on ``sys.path`` and a fixed hash seed.

    PYTHONSAFEPATH would drop the cwd and let an installed ``shared`` answer for
    this checkout.
    """
    env = {key: value for key, value in os.environ.items() if key != "PYTHONSAFEPATH"}
    entries = (str(site), str(_SHARED_ROOT), env.get("PYTHONPATH", ""))
    env["PYTHONPATH"] = os.pathsep.join(filter(None, entries))
    env["PYTHONHASHSEED"] = hash_seed
    return env


def _probe(site: Path, hash_seed: str = "0") -> dict[str, object]:
    """``GRAMMAR_PACK_VERSION`` (repr) and ``GRAMMAR_VERSIONS`` in a fresh interpreter."""
    proc = subprocess.run(
        [sys.executable, "-c", _PROBE],
        cwd=str(_SHARED_ROOT),
        env=_probe_env(site, hash_seed),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"probe failed to import shared.ast.profile:\n{proc.stderr}"
    return json.loads(proc.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def baseline(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    """The stamp of the real installation, read in a fresh interpreter."""
    return _probe(_shadow(tmp_path_factory.mktemp("no_shadow"), {}))


# ── the ten packages ──────────────────────────────────────────────────────────


def test_pack_is_the_declared_and_locked_set() -> None:
    """D15: ten packages, declared once in shared's pyproject and locked."""
    assert (len(PACK), set(PACK), set(PACK)) == (10, _declared(), set(_locked()))


def test_grammar_versions_are_the_installed_versions_of_the_pack() -> None:
    """``GRAMMAR_VERSIONS`` = ``importlib.metadata`` versions of exactly the ten."""
    assert len(GRAMMAR_VERSIONS) == len(PACK)
    assert _by_canonical_name(GRAMMAR_VERSIONS) == _installed()


def test_installed_pack_is_the_locked_pins() -> None:
    """The environment runs the locked versions the goldens were reviewed against."""
    assert _installed() == _locked()


def test_every_profile_grammar_is_in_the_pack() -> None:
    """The pack is the core plus exactly the grammars the nine profiles load."""
    grammars = {_grammar_distribution(p.grammar_module) for p in PROFILES.values()}
    assert {"tree-sitter"} | grammars == set(PACK)


def test_public_version_stamps() -> None:
    """LLD §5: both cache-key stamps are public; the pack stamp is hashable (D5)."""
    assert shared.ast.GRAMMAR_PACK_VERSION == GRAMMAR_PACK_VERSION
    assert shared.ast.MODEL_SCHEMA == 2  # A28 (9)
    assert isinstance(hash((GRAMMAR_PACK_VERSION, shared.ast.MODEL_SCHEMA)), int)


# ── the pack stamp follows the ten, and only the ten ──────────────────────────


def test_pack_version_is_identical_across_interpreters(
    baseline: dict[str, object], tmp_path: Path
) -> None:
    """D14: no per-process hash seed reaches the stamp."""
    other = _probe(_shadow(tmp_path / "site", {}), hash_seed="4242")
    expected = {"pack": repr(GRAMMAR_PACK_VERSION), "versions": dict(GRAMMAR_VERSIONS)}
    assert baseline == other == expected


@pytest.mark.parametrize("name", PACK)
def test_pack_version_changes_when_one_package_changes(
    name: str, baseline: dict[str, object], tmp_path: Path
) -> None:
    """A post-release of any ONE of the ten moves the stamp (a major.minor
    truncation, or a stamp over the grammars alone, would miss it)."""
    bumped = f"{importlib.metadata.version(name)}.post1"
    shadowed = _probe(_shadow(tmp_path / "site", {name: bumped}))
    versions = _by_canonical_name(shadowed["versions"])
    assert (versions[_canonical(name)], shadowed["pack"] != baseline["pack"]) == (bumped, True)


def test_pack_version_changes_when_two_versions_swap(
    baseline: dict[str, object], tmp_path: Path
) -> None:
    """The stamp binds each version to its package: a stamp over the sorted
    version strings alone would not see two packages trade versions."""
    installed = _installed()
    first, second = next(
        pair for pair in itertools.combinations(PACK, 2) if installed[pair[0]] != installed[pair[1]]
    )
    swap = {first: installed[second], second: installed[first]}
    shadowed = _probe(_shadow(tmp_path / "site", swap))
    assert shadowed["pack"] != baseline["pack"], swap


@pytest.mark.parametrize("name", ["tree-sitter-ruby", "tree-sitter-languages"])
def test_pack_version_ignores_packages_outside_the_pack(
    name: str, baseline: dict[str, object], tmp_path: Path
) -> None:
    """A ``tree-sitter-*`` distribution outside the ten (here newly "installed")
    neither joins ``GRAMMAR_VERSIONS`` nor moves the stamp."""
    shadowed = _probe(_shadow(tmp_path / "site", {name: "9.9.9"}))
    observed = (shadowed["pack"], sorted(_by_canonical_name(shadowed["versions"])))
    assert observed == (baseline["pack"], sorted(PACK))


# ── A16: computed once, lazily, in the parent ────────────────────────────────

# A fresh interpreter counts every TOP-LEVEL distribution lookup (``Distribution.from_name``,
# which ``version``/``distribution``/``metadata`` reach, and ``Distribution.discover``, which
# ``distributions``/``packages_distributions`` reach; a lookup one makes inside the other is
# the same read), then imports ``shared.ast.profile`` and reads both stamps twice.
_LAZY_PROBE = """\
import importlib.metadata as metadata
import json
import sys

sys.path.insert(0, {root!r})
reads = []
depth = [0]


def counted(kind, original):
    def lookup(cls, *args, **kwargs):
        if depth[0] == 0:
            reads.append(str(args[0]) if args else kind)
        depth[0] += 1
        try:
            return original(cls, *args, **kwargs)
        finally:
            depth[0] -= 1
    return classmethod(lookup)


metadata.Distribution.from_name = counted("from_name", metadata.Distribution.from_name.__func__)
metadata.Distribution.discover = counted("discover", metadata.Distribution.discover.__func__)

import shared.ast.profile as profile

on_import = list(reads)
first = (dict(profile.GRAMMAR_VERSIONS), profile.GRAMMAR_PACK_VERSION)
on_first = reads[len(on_import):]
import shared.ast

again = (dict(profile.GRAMMAR_VERSIONS), profile.GRAMMAR_PACK_VERSION, shared.ast.GRAMMAR_PACK_VERSION)
on_second = reads[len(on_import) + len(on_first):]
print(json.dumps({{
    "import": on_import, "first": on_first, "second": on_second,
    "same": [again[0], again[1], again[2]] == [first[0], first[1], first[1]],
}}))
"""


def _repeated(reads: list[str]) -> list[str]:
    """The distributions ``reads`` names more than once, sorted."""
    return sorted({read for read in reads if reads.count(read) > 1})


def test_versions_are_computed_once_lazily_in_the_parent(tmp_path: Path) -> None:
    """A16: importing ``shared.ast.profile`` reads no distribution version; the first access
    to ``GRAMMAR_VERSIONS`` / ``GRAMMAR_PACK_VERSION`` reads each package once; a second
    access — through the module or the package's lazy export — reads nothing and answers the
    same stamps."""
    proc = subprocess.run(
        [sys.executable, "-I", "-c", _LAZY_PROBE.format(root=str(_SHARED_ROOT))],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    seen = json.loads(proc.stdout.strip().splitlines()[-1])
    first = seen["first"]
    observed = {
        "read on import": seen["import"],
        "first access reads": bool(first),
        "read twice on first access": _repeated(first),
        "read on second access": seen["second"],
        "same stamps": seen["same"],
    }
    assert observed == {
        "read on import": [],
        "first access reads": True,
        "read twice on first access": [],
        "read on second access": [],
        "same stamps": True,
    }
