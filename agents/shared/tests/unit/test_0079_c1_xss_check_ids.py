"""Feature 0079 C1: the xss agent emits a stable per-detector check_id.

Additive by construction. `category` is untouched — the xss agent's published
finding contract specifies CWE ids, a passing 0078 conformance test codifies
that shape, and 11 of its 16 sites reach the OWASP Top 10 manifest through
`parse_cwe_id` on the category field.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

AGENTS = pathlib.Path(__file__).resolve().parents[3]
XSS_SKILLS = AGENTS / "xss" / "xss_agent" / "skills"


def _emission_sites(path: pathlib.Path) -> list[dict]:
    """Every findings.append({...}) dict literal in a skill file."""
    out = []
    for node in ast.walk(ast.parse(path.read_text())):
        if not isinstance(node, ast.Dict):
            continue
        keys = {k.value for k in node.keys if isinstance(k, ast.Constant)}
        if {"severity", "category", "title"} <= keys:
            out.append(node)
    return out


def _has_cid_splat(d: ast.Dict) -> bool:
    """True when the dict splats **cid(...) — a None key is a ** entry."""
    for k, v in zip(d.keys, d.values):
        if k is None and isinstance(v, ast.Call) and isinstance(v.func, ast.Name) and v.func.id == "cid":
            return True
    return False


SKILL_FILES = sorted(XSS_SKILLS.glob("*_check.py"))


def test_discovery_is_not_vacuous():
    """A guard that enumerates nothing passes silently."""
    assert len(SKILL_FILES) >= 5, f"expected the five xss skills, found {SKILL_FILES}"
    total = sum(len(_emission_sites(p)) for p in SKILL_FILES)
    assert total >= 16, f"expected >=16 emission sites, found {total}"


@pytest.mark.parametrize("path", SKILL_FILES, ids=lambda p: p.name)
def test_every_xss_emission_site_carries_a_check_id(path):
    missing = [
        ast.unparse(d)[:70]
        for d in _emission_sites(path)
        if not _has_cid_splat(d)
    ]
    assert not missing, f"{path.name}: emission sites without a check_id: {missing}"


@pytest.mark.parametrize("path", SKILL_FILES, ids=lambda p: p.name)
def test_category_is_still_a_cwe_id(path):
    """The load-bearing invariant. Renaming the category would drop 11 of 16
    sites from the OWASP manifest at `if cwe_id is None: continue`, silently."""
    for d in _emission_sites(path):
        for k, v in zip(d.keys, d.values):
            if isinstance(k, ast.Constant) and k.value == "category":
                assert isinstance(v, ast.Constant) and v.value.startswith("CWE-"), (
                    f"{path.name}: category must stay a CWE id, got {ast.dump(v)[:60]}"
                )


def test_check_ids_are_unique_and_well_formed():
    seen: dict[str, str] = {}
    for path in SKILL_FILES:
        for d in _emission_sites(path):
            for k, v in zip(d.keys, d.values):
                if k is None and isinstance(v, ast.Call):
                    val = v.args[0].value
                    assert val.startswith("xss."), f"{val} should be namespaced xss.*"
                    assert val.count(".") >= 2, f"{val} should be domain.category.specific"
                    assert val not in seen, f"duplicate check_id {val} in {path.name} and {seen[val]}"
                    seen[val] = path.name
    assert len(seen) >= 16, f"expected >=16 distinct check_ids, got {len(seen)}"


def test_disabling_the_switch_restores_the_pre_feature_finding(monkeypatch):
    """VULTURE_XSS_CHECK_IDS=false must make **cid(...) contribute nothing, so
    the finding dict is byte-identical to its pre-0079 form."""
    import sys
    sys.path.insert(0, str(AGENTS / "xss"))
    from xss_agent.skills._check_id import cid

    monkeypatch.setenv("VULTURE_XSS_CHECK_IDS", "false")
    assert cid("xss.stored.db_render") == {}
    monkeypatch.setenv("VULTURE_XSS_CHECK_IDS", "true")
    assert cid("xss.stored.db_render") == {"check_id": "xss.stored.db_render"}


def test_the_switch_is_read_at_call_time(monkeypatch):
    """Never cached in a module-level var, or the rollback cannot be flipped."""
    import sys
    sys.path.insert(0, str(AGENTS / "xss"))
    from xss_agent.skills._check_id import cid

    monkeypatch.setenv("VULTURE_XSS_CHECK_IDS", "true")
    assert cid("a.b.c") != {}
    monkeypatch.setenv("VULTURE_XSS_CHECK_IDS", "false")
    assert cid("a.b.c") == {}
