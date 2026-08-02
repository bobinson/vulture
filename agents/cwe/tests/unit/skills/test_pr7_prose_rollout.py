"""Feature 0070 P7 — ``is_prose_file`` rolled out to the remaining guard chains.

``is_prose_file()`` was applied in only a minority of the skills. The rest
happily read documentation as executable source, because a markdown body
line carries no comment marker for ``COMMENT_INDICATORS`` to strip: a
hardening guide that writes ``os.chmod(path, 0o777)`` *in order to forbid it*
matches the same regex as the call itself.

Two properties are pinned here, one per direction, over the same construct
set:

* a tree containing nothing but prose yields **zero** rows from the guarded
  skills — including from a shadow copy (``guide.md.bak``), since the guard
  resolves the effective suffix rather than the literal one;
* the identical constructs in a real source file still fire, so the guard
  narrows by *file kind* and never by pattern.

One deliberate exception is pinned too. ``is_prose_file`` suppresses
pattern-shaped findings, never *exposed values*: a credential pasted into a
README is leaked whether or not anything executes. So the authentication
skill keeps its CWE-798 detector running on prose and drops only its
pattern-shaped checks, and the secret-scanning skill is not prose-guarded at
all.
"""

import pathlib

import pytest

from cwe_agent.agent import SKILL_MAP

# Skills whose per-file guard chain gained ``is_prose_file`` in this rollout.
PROSE_GUARDED_SKILLS = (
    "access_control",
    "authentication",
    "catalog_generic",
    "concurrency",
    "data_handling",
    "path_equivalence",
    "resource_management",
    "weak_entropy",
)

# One anti-pattern per rolled-out detector family. Every line below is a real
# instance when it lands in source and a mere mention when it lands in prose;
# the fixtures differ only in the file extension they are written to.
SOURCE = """import os
import random


def grant(path):
    os.chmod(path, 0o777)
    os.setuid(0)


@app.route('/admin')
def admin_panel():
    return dump_everything()


def issue():
    session_token = random.random()
    return session_token


def load(base):
    handle = open('/etc/passwd')
    target = os.path.join(base, '..', 'etc', 'passwd')
    return handle, target


def render(user_supplied_format):
    printf(user_supplied_format)


def replace(p):
    if os.path.exists(p):
        os.remove(p)
"""

PROSE = """# Hardening Guide

Do not widen permissions and do not drop into root:

    os.chmod(path, 0o777)
    os.setuid(0)

Never register an admin route with no authorization decorator:

    @app.route('/admin')
    def admin_panel():
        return dump_everything()

Never mint a session id from a non-cryptographic source:

    session_token = random.random()

Never leave a handle open, and never build a path this way:

    handle = open('/etc/passwd')
    target = os.path.join(base, '..', 'etc', 'passwd')

Never pass caller-controlled text as a format string:

    printf(user_supplied_format)

Never test for a file and then act on it as two steps:

    if os.path.exists(p):
        os.remove(p)
"""

# Categories the source fixture must still produce, and the guarded skill
# each one has to come from. Keeping the owner in the table is what makes the
# pairing meaningful: it is not enough that *something* reported CWE-269, the
# prose-guarded skill has to be the one that did.
EXPECTED_IN_SOURCE = (
    ("access_control", "CWE-269"),
    ("access_control", "CWE-862"),
    ("concurrency", "CWE-367"),
    ("data_handling", "CWE-134"),
    ("path_equivalence", "CWE-43"),
    ("resource_management", "CWE-404"),
    ("weak_entropy", "CWE-331"),
    ("weak_entropy", "CWE-332"),
)


def _rows(root: str) -> list[tuple[str, str, int]]:
    """Return ``(skill, category, line)`` for every finding in ``root``."""
    out: list[tuple[str, str, int]] = []
    for name, fn in SKILL_MAP.items():
        result = fn(root)
        for finding in result.get("findings", []):
            out.append((name, finding.get("category"), finding.get("line_start")))
    return out


@pytest.fixture
def prose_tree(tmp_path: pathlib.Path) -> str:
    """A tree of documentation only — no source file of any kind."""
    (tmp_path / "HARDENING.md").write_text(PROSE, encoding="utf-8")
    (tmp_path / "guide.rst").write_text(PROSE, encoding="utf-8")
    (tmp_path / "notes.txt").write_text(PROSE, encoding="utf-8")
    (tmp_path / "guide.md.bak").write_text(PROSE, encoding="utf-8")
    return str(tmp_path)


@pytest.fixture
def source_tree(tmp_path: pathlib.Path) -> str:
    """The same constructs, in a file that actually executes."""
    (tmp_path / "handlers.py").write_text(SOURCE, encoding="utf-8")
    return str(tmp_path)


def test_prose_tree_yields_no_rows_from_guarded_skills(prose_tree: str) -> None:
    """Documentation is a mention, never an instance."""
    offenders = [row for row in _rows(prose_tree) if row[0] in PROSE_GUARDED_SKILLS]
    assert offenders == [], f"prose produced pattern-shaped rows: {offenders}"


def test_shadow_copy_of_prose_is_prose(prose_tree: str) -> None:
    """``guide.md.bak`` resolves to ``.md``, so the guard covers it too.

    Pinned separately from the tree-wide assertion because a guard written
    against the literal suffix would pass that one on ``.md`` alone while
    still reading every backup copy as source.
    """
    rows = _rows(prose_tree)
    assert [r for r in rows if r[0] in PROSE_GUARDED_SKILLS] == []
    # The backup file itself is still *reported as exposed* by the skill that
    # owns artefact exposure — prose narrows pattern matching, not artefacts.
    assert any(category == "CWE-552" for _, category, _ in rows)


@pytest.mark.parametrize(("skill", "category"), EXPECTED_IN_SOURCE)
def test_same_construct_still_fires_in_source(source_tree: str, skill: str, category: str) -> None:
    """The guard narrows by file kind; every detector still works on code."""
    rows = _rows(source_tree)
    assert (skill, category) in [(s, c) for s, c, _ in rows], (
        f"{skill} lost {category} on real source; got {sorted({(s, c) for s, c, _ in rows})}"
    )


def test_credential_in_prose_is_still_reported(tmp_path: pathlib.Path) -> None:
    """Prose suppresses pattern-shaped findings, never exposed values.

    A credential pasted into a README is leaked whether or not anything
    executes it, so the CWE-798 detector is exempt from the rollout while its
    pattern-shaped siblings in the same skill are not.
    """
    doc = (
        "# Deployment\n\nUse the staging account:\n\n"
        '    DB_PASSWORD = "Tr0ub4dor-3x-staging"\n\n'
        "Never expose an endpoint with no authentication:\n\n"
        "    @app.route('/admin')\n"
        "    def admin_panel():\n"
        "        return dump()\n"
    )
    (tmp_path / "DEPLOY.md").write_text(doc, encoding="utf-8")
    categories = {c for s, c, _ in _rows(str(tmp_path)) if s == "authentication"}
    assert "CWE-798" in categories, "exposed credential must survive the prose guard"
    # Both halves are load-bearing: without the per-detector split this same
    # document yields CWE-306 as well, and with a blanket file-level guard it
    # would yield neither.
    assert "CWE-306" not in categories, "pattern-shaped auth mention must not survive"
