"""Feature 0058 T8 (R8, P2c) — reproducibility pins. RED-phase TDD.

Contract pinned by these tests:

(a) Feature 0102: ``plugins/opengrep/Dockerfile`` pins the Opengrep engine
    EXACTLY: one release version and, for each of amd64 and arm64, the
    asset's sha256, checked with ``sha256sum -c`` before the binary is used;
    the base image is pinned by digest; nothing of Semgrep's is used.

(c) The plugin ``GET /info`` version equals the ``[project] version``
    in ``pyproject.toml`` (single source of truth for the pin).

(d) Feature 0102: every ``pip install`` in the Dockerfile installs a
    hash-locked requirements file (``--require-hashes -r FILE``) whose every
    line pins ``name==X.Y.Z`` with at least one ``--hash=sha256:``; and a
    later ``RUN`` starts the engine (``opengrep --version``), so a build whose
    engine cannot start fails.

(e) Feature 0102: the build fetches no Semgrep Registry rules (no
    ``--config p/...``): the image holds only the engine and Vulture's code.
"""

from __future__ import annotations

import re
import shlex
import tomllib
from pathlib import Path

PLUGIN_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = PLUGIN_ROOT / "Dockerfile"


# ---------------------------------------------------------------------------
# (a) Opengrep engine pinned by version and per-arch sha256 in the Dockerfile
# ---------------------------------------------------------------------------

_SHA256_LINE_RE = re.compile(r"\b(amd64|arm64)\)\s+asset=opengrep_manylinux_\w+;\s+sha=([0-9a-f]{64})\b")


def test_dockerfile_pins_opengrep_version_and_digests():
    content = DOCKERFILE.read_text()
    assert re.search(r"\bOPENGREP_VERSION=\d+\.\d+\.\d+\b", content), "pin one Opengrep release"
    arches = {m.group(1) for m in _SHA256_LINE_RE.finditer(content)}
    assert arches == {"amd64", "arm64"}, f"need a pinned sha256 for amd64 and arm64, found {arches}"
    assert "sha256sum -c" in content, "the downloaded engine must be checked against its pin"


def test_dockerfile_base_is_digest_pinned_and_not_semgrep():
    froms = [line for line in DOCKERFILE.read_text().splitlines() if line.startswith("FROM ")]
    assert froms and all(re.search(r"@sha256:[0-9a-f]{64}\b", f) for f in froms), froms
    body = "\n".join(_run_instructions() + froms).lower()
    assert "semgrep" not in body, "no Semgrep image, package or binary may be used"


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
# (d) Wrapper packages are hash-locked; the build starts the engine
# ---------------------------------------------------------------------------

_EXACT_REQ_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(\[[A-Za-z0-9,._-]+\])?==\d+(\.\d+)*$")


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
    with_value = ("-c", "--constraint", "-r", "--retries", "--timeout")
    values = {args[i + 1] for i, a in enumerate(args[:-1]) if a in with_value}
    return [a for a in args if not a.startswith("-") and a not in values]


_HASH_RE = re.compile(r"--hash=sha256:[0-9a-f]{64}")


def _requirement_lines(path: Path) -> list[str]:
    """Logical requirement lines of a requirements file (continuations joined)."""
    joined = re.sub(r"\\\n", " ", path.read_text())
    return [ln.strip() for ln in joined.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]


def test_dockerfile_pip_installs_are_hash_locked():
    installs = [args for run in _run_instructions() for args in _pip_install_args(run)]
    assert installs, "the Dockerfile no longer installs anything with pip"
    for args in installs:
        assert "--require-hashes" in args and "-r" in args, f"pip install {args} must be hash-locked"
        assert not _requirements(args), f"no requirement may be named on the command line: {args}"


def test_requirements_pin_every_package_with_a_hash():
    lines = _requirement_lines(PLUGIN_ROOT / "requirements.txt")
    assert lines, "requirements.txt is empty"
    for line in lines:
        name = line.split()[0]
        assert _EXACT_REQ_RE.match(name), f"not pinned exactly: {name}"
        assert _HASH_RE.search(line), f"no sha256 hash for {name}"


def test_dockerfile_starts_the_engine_after_the_last_install():
    runs = _run_instructions()
    last_install = max(i for i, r in enumerate(runs) if "pip install" in r)
    assert any("opengrep --version" in r for r in runs[last_install + 1 :]), (
        "a RUN after the last pip install must run `opengrep --version`, so an image "
        "whose engine cannot start never builds"
    )


def test_dockerfile_fetches_no_registry_rules():
    fetching = [r for r in _run_instructions() if re.search(r"--config[ =]+p/", r)]
    assert not fetching, f"the build must not fetch Semgrep Registry rules: {fetching}"
