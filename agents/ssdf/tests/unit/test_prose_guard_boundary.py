"""F6 boundary: prose-guarding pattern skills must NOT touch document-evidence skills.

The guard `is_prose_file` stops a pattern detector firing on a README that
merely *describes* a control. Applying it blindly would have been a serious
regression, because several SSDF skills use a documentation file as their
EVIDENCE — the presence of SECURITY.md, a threat model, an RCA process doc.

`_PROSE_SUFFIXES` is an exact superset of the globs those skills search
(`*.md`, `*.rst`, `*.txt`, `*.adoc`), so guarding them would make their
evidence unfindable and the corresponding requirement fire on EVERY repository,
forever — a compliance auditor that reports a violation no one can ever fix.

These tests pin the boundary from the safe side: the document-evidence skills
must still find evidence that exists.
"""

import tempfile
from pathlib import Path

from ssdf_agent.skills.root_cause_analysis import check_root_cause_analysis
from ssdf_agent.skills.secure_design import check_secure_design
from ssdf_agent.skills.security_policy import check_security_policy


def _tree(files: dict[str, str]) -> str:
    d = tempfile.mkdtemp()
    for name, body in files.items():
        p = Path(d) / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body)
    return d


def _ids(result) -> set[str]:
    return {f.get("check_id", "") for f in result["findings"]}


def test_security_policy_is_found_in_a_prose_file():
    """SECURITY.md is prose BY DEFINITION — that is the whole point of the
    check. If the prose guard ever reaches this skill, the policy becomes
    invisible and the violation fires on every repo."""
    root = _tree({"SECURITY.md": "# Security Policy\n\nReport issues to security@example.com.\n"})
    assert not any("policy" in cid for cid in _ids(check_security_policy(root))), (
        "an existing SECURITY.md must satisfy the policy check"
    )


def test_missing_security_policy_still_reported():
    """The negative control: without the doc the finding must still fire, or the
    test above would pass for the wrong reason."""
    root = _tree({"main.py": "print('hi')\n"})
    assert any("policy" in cid for cid in _ids(check_security_policy(root))), (
        "a repo with no security policy must still be flagged"
    )


def test_threat_model_is_found_in_a_prose_file():
    root = _tree({"docs/threat-model.md": "# Threat Model\n\nSTRIDE analysis.\n"})
    assert not any("threat" in cid for cid in _ids(check_secure_design(root))), (
        "an existing threat model must satisfy the design check"
    )


def test_missing_threat_model_still_reported():
    root = _tree({"main.py": "print('hi')\n"})
    assert any("threat" in cid for cid in _ids(check_secure_design(root))), (
        "a repo with no threat model must still be flagged"
    )


def test_rca_docs_are_found_in_prose_files():
    """The highest-risk skill for this change: its evidence glob (*.md, *.rst,
    *.txt, *.adoc) is exactly the prose suffix set."""
    root = _tree({
        "docs/postmortem.md": (
            "# Incident Postmortem\n\nRoot cause analysis of the outage, with "
            "corrective actions and lessons learned.\n"
        ),
    })
    assert not any("rca" in cid for cid in _ids(check_root_cause_analysis(root))), (
        "RCA documentation in a .md file must count as evidence"
    )


def test_missing_rca_docs_still_reported():
    root = _tree({"main.py": "print('hi')\n"})
    assert any("rca" in cid for cid in _ids(check_root_cause_analysis(root))), (
        "a repo with no RCA process must still be flagged"
    )


def test_document_evidence_skills_do_not_import_the_prose_guard():
    """Structural guard: a future well-meaning sweep must not add the guard to
    these three files. Cheaper than rediscovering the outage."""
    import ssdf_agent.skills.root_cause_analysis as rca
    import ssdf_agent.skills.secure_design as sd
    import ssdf_agent.skills.security_policy as sp

    for mod in (rca, sd, sp):
        src = Path(mod.__file__).read_text()
        assert "is_prose_file" not in src, (
            f"{Path(mod.__file__).name} uses documentation as EVIDENCE; the prose "
            f"guard would make that evidence permanently unfindable"
        )
