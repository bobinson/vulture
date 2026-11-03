"""ASVS V3.3: a cookie is judged by the call that sets it and the routine that builds it.

Business contract
-----------------
V3.3.1 (Secure), V3.3.2 (SameSite) and V3.3.4 (HttpOnly) were judged on the
cookie call's LINE alone, so a call whose options sit on the following lines
(`res.cookie("sid", token, {\n httpOnly: true, ...})`) was reported whatever
they said, and `http.SetCookie(w, sessionCookie(r, token, maxAge))` was reported
although `sessionCookie`, defined in the same file, sets every attribute.

* The requirement reads the call through its closing paren and the definition
  of every routine of the same file the call uses (the same text the CWE agent's
  CWE-1004 / 614 / 1275 checks read).
* A call, or a builder, that sets none of the attributes is still reported for
  all three requirements.

Fixtures (`fixtures/cookie_attributes`): one site per unit, ``pos/`` reported for
every requirement, ``neg/`` for none. The tree is scanned from a copy outside the
test directory, because the skill skips test paths.
"""
from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

from asvs_agent.skills.asvs_requirements_check import check_asvs_requirements
from shared.tools.file_scanner import is_test_file

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "cookie_attributes"
REQUIREMENTS = ("ASVS-V3.3.1", "ASVS-V3.3.2", "ASVS-V3.3.4")
_MARKER = re.compile(r"EXPECT:\s*(finding|clean)\b")


def _sites() -> list[tuple[str, int, str]]:
    """(path relative to the fixture root, 1-based line, verdict) per marker."""
    return [
        (path.relative_to(FIXTURES).as_posix(), n, m.group(1))
        for path in sorted(FIXTURES.rglob("*")) if path.is_file()
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1)
        if (m := _MARKER.search(line))
    ]


SITES = _sites()


@pytest.fixture(scope="module")
def rows(tmp_path_factory) -> tuple[Path, list[dict]]:
    root = tmp_path_factory.mktemp("asvscookie") / "fixcorpus" / "app"
    shutil.copytree(FIXTURES, root)
    assert not any(is_test_file(p) for p in root.rglob("*") if p.is_file())
    found: list[dict] = []
    for unit in sorted(p for kind in ("pos", "neg") for p in (root / kind).iterdir()):
        found += check_asvs_requirements(str(unit))["findings"]
    return root, found


def test_population() -> None:
    """Every unit holds one site; pos units expect rows, neg units none."""
    units = {"/".join(rel.split("/")[:2]) for rel, _, _ in SITES}
    assert len(units) == len(SITES) == 8
    assert all(v == ("finding" if rel.startswith("pos/") else "clean") for rel, _, v in SITES)


@pytest.mark.parametrize("site", SITES, ids=lambda s: f"{s[0]}:{s[1]}")
def test_site_verdict(rows, site) -> None:
    root, found = rows
    rel, line, verdict = site
    got = {
        req: any(
            f["category"] == req and int(f.get("line_start") or 0) == line
            and Path(f["file_path"]).relative_to(root).as_posix() == rel
            for f in found
        )
        for req in REQUIREMENTS
    }
    expected = verdict == "finding"
    assert all(v == expected for v in got.values()), f"{rel}:{line} expected {verdict}, got {got}"
