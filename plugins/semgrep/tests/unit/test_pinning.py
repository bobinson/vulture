"""Feature 0058 T8 (R8, P2c) — reproducibility pins. RED-phase TDD.

Contract pinned by these tests:

(a) ``plugins/semgrep/Dockerfile`` pins the Semgrep engine version
    EXACTLY: the literal pattern ``semgrep==<major>.<minor>.<patch>``
    must be present in the Dockerfile text.

(b) ``plugins/semgrep/rules/RULESET_SNAPSHOT.json`` exists with shape::

        {
          "packs":    ["p/<name>", ...],                # non-empty
          "vendored": {"<relpath>": "<sha256-hex>", ...} # non-empty
        }

    * ``packs``: non-empty list of pinned registry pack ids, each
      matching ``^p/[a-z0-9._-]+$``.
    * ``vendored``: non-empty map of paths (relative to
      ``rules/vulture/``, POSIX separators) -> lowercase sha256 hex
      digest of the file's exact byte content. Every entry must match
      the on-disk file, and every file under ``rules/vulture/`` must
      have an entry (no unpinned rule drift).

(c) The plugin ``GET /info`` version equals the ``[project] version``
    in ``pyproject.toml`` (single source of truth for the pin).

(d) Feature 0102: every ``pip install`` in the Dockerfile pins each
    requirement exactly and runs under a constraint file of the packages the
    base already ships, so no package the wrapper adds can replace one Semgrep
    imports; and a later ``RUN`` starts the engine (``semgrep --version``), so
    a build whose engine cannot start fails before anything is pushed.
"""

from __future__ import annotations

import hashlib
import json
import re
import shlex
import tomllib
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = PLUGIN_ROOT / "Dockerfile"
SNAPSHOT_PATH = PLUGIN_ROOT / "rules" / "RULESET_SNAPSHOT.json"
VENDORED_DIR = PLUGIN_ROOT / "rules" / "vulture"

_PACK_ID_RE = re.compile(r"^p/[a-z0-9._-]+$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def _load_snapshot() -> dict:
    return json.loads(SNAPSHOT_PATH.read_text())


# ---------------------------------------------------------------------------
# (a) Semgrep engine version pinned exactly in the Dockerfile
# ---------------------------------------------------------------------------


def test_dockerfile_pins_semgrep_version_exactly():
    content = DOCKERFILE.read_text()
    assert re.search(r"semgrep==\d+\.\d+\.\d+", content), (
        "Dockerfile must pin the Semgrep engine to an exact version "
        "(literal `semgrep==X.Y.Z` present) so the deterministic tier is "
        "reproducible run-to-run (R8/P2c)."
    )


# ---------------------------------------------------------------------------
# (b) Ruleset snapshot exists, has the pinned shape, hashes match reality
# ---------------------------------------------------------------------------


def test_ruleset_snapshot_file_exists():
    assert SNAPSHOT_PATH.is_file(), (
        f"missing ruleset snapshot {SNAPSHOT_PATH} — the ruleset pin (R8) "
        "requires rules/RULESET_SNAPSHOT.json"
    )


def test_ruleset_snapshot_packs_shape():
    snap = _load_snapshot()
    packs = snap["packs"]
    assert isinstance(packs, list) and packs, "snapshot `packs` must be a non-empty list"
    for p in packs:
        assert isinstance(p, str) and _PACK_ID_RE.match(p), (
            f"snapshot pack {p!r} must be a pinned registry pack id matching ^p/[a-z0-9._-]+$"
        )


def test_ruleset_snapshot_vendored_shape():
    snap = _load_snapshot()
    vendored = snap["vendored"]
    assert isinstance(vendored, dict) and vendored, (
        "snapshot `vendored` must be a non-empty {relpath: sha256} map"
    )
    for relpath, digest in vendored.items():
        assert isinstance(relpath, str) and relpath, "vendored keys must be non-empty relpaths"
        assert not relpath.startswith("/") and ".." not in relpath.split("/"), (
            f"vendored key {relpath!r} must be relative to rules/vulture/ with no traversal"
        )
        assert isinstance(digest, str) and _SHA256_HEX_RE.match(digest), (
            f"vendored[{relpath!r}] must be a lowercase sha256 hex digest, got {digest!r}"
        )


def test_ruleset_snapshot_vendored_hashes_match_files():
    snap = _load_snapshot()
    for relpath, digest in snap["vendored"].items():
        rule_file = VENDORED_DIR / relpath
        assert rule_file.is_file(), (
            f"snapshot pins {relpath!r} but rules/vulture/{relpath} does not exist"
        )
        actual = hashlib.sha256(rule_file.read_bytes()).hexdigest()
        assert actual == digest, (
            f"rules/vulture/{relpath} content drifted from its pinned sha256 "
            f"(pinned {digest}, actual {actual}) — update the snapshot via the "
            "documented bump procedure, never silently"
        )


def test_ruleset_snapshot_covers_every_vendored_rule_file():
    snap = _load_snapshot()
    assert VENDORED_DIR.is_dir(), f"vendored rules dir {VENDORED_DIR} must exist (P2d)"
    on_disk = {
        p.relative_to(VENDORED_DIR).as_posix()
        for p in VENDORED_DIR.rglob("*")
        if p.is_file()
    }
    pinned = set(snap["vendored"].keys())
    assert on_disk == pinned, (
        f"every file under rules/vulture/ must be pinned in the snapshot; "
        f"unpinned={sorted(on_disk - pinned)}, stale={sorted(pinned - on_disk)}"
    )


# ---------------------------------------------------------------------------
# (c) /info version == pyproject version
# ---------------------------------------------------------------------------


def test_info_version_matches_pyproject_version():
    from fastapi.testclient import TestClient
    from src.wrapper import app

    pyproject = tomllib.loads((PLUGIN_ROOT / "pyproject.toml").read_text())
    expected = pyproject["project"]["version"]

    resp = TestClient(app).get("/info")
    assert resp.status_code == 200
    assert resp.json()["version"] == expected, (
        "GET /info `version` must equal pyproject.toml [project] version "
        f"({expected!r}) — one source of truth for the plugin pin"
    )


# ---------------------------------------------------------------------------
# (d) Wrapper packages cannot replace the engine's; the build starts the engine
# ---------------------------------------------------------------------------

_EXACT_REQ_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,._-]+\])?==\d+(\.\d+)*$")
_BASE_FREEZE_RE = re.compile(r"pip list --format=freeze > (\S+)")


def _run_instructions() -> list[str]:
    """Each RUN instruction of the Dockerfile, continuation lines joined."""
    joined = re.sub(r"\\\n", " ", DOCKERFILE.read_text())
    return [line[4:] for line in joined.splitlines() if line.startswith("RUN ")]


def _pip_install_args(run: str) -> list[list[str]]:
    """The arguments of every `pip install` command in one RUN instruction."""
    commands = re.split(r"&&|;", run)
    return [shlex.split(c.split("pip install", 1)[1]) for c in commands if "pip install" in c]


def _requirements(args: list[str]) -> list[str]:
    """The requirements of one `pip install`: neither an option nor an option's value."""
    values = {args[i + 1] for i, a in enumerate(args[:-1]) if a in ("-c", "--constraint")}
    return [a for a in args if not a.startswith("-") and a not in values]


def test_dockerfile_pip_installs_pin_every_requirement_exactly():
    installs = [args for run in _run_instructions() for args in _pip_install_args(run)]
    assert installs, "the Dockerfile no longer installs anything with pip"
    for args in installs:
        loose = [r for r in _requirements(args) if not _EXACT_REQ_RE.match(r)]
        assert not loose, f"pip requirements must be pinned `name==X.Y.Z`, got {loose}"


def test_dockerfile_pip_installs_are_constrained_to_the_base_packages():
    for run in (r for r in _run_instructions() if "pip install" in r):
        freeze = _BASE_FREEZE_RE.search(run)
        assert freeze, (
            f"RUN {run!r} must first freeze the base's packages (`pip list --format=freeze > FILE`)"
        )
        for args in _pip_install_args(run):
            assert f"-c {freeze.group(1)}" in shlex.join(args), (
                f"pip install {shlex.join(args)!r} must run with `-c {freeze.group(1)}`, so it "
                "can never replace a package Semgrep imports"
            )


def test_dockerfile_starts_the_engine_after_the_last_install():
    runs = _run_instructions()
    last_install = max(i for i, r in enumerate(runs) if "pip install" in r)
    assert any("semgrep --version" in r for r in runs[last_install + 1 :]), (
        "a RUN after the last pip install must run `semgrep --version`, so an image "
        "whose engine cannot start never builds"
    )
